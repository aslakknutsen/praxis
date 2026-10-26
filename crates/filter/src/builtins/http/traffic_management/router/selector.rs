// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Route-level cluster selection.
//!
//! A route may name one cluster (the `cluster:` shorthand) or several weighted
//! targets split into priority tiers (`weighted_clusters:`). The selector picks
//! one cluster per request using smooth weighted round-robin within the first
//! tier that has a healthy target, spilling to the next tier only when the
//! current one has none.
//!
//! Health is judged per cluster, not per endpoint: a target is eligible when
//! its cluster has at least one healthy endpoint. Endpoint weights inside the
//! selected cluster are applied later by the `load_balancer` filter, so the
//! effective share is `route_target_share * endpoint_share_within_cluster`.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use praxis_core::{config::WeightedTarget, health::HealthRegistry};

// -----------------------------------------------------------------------------
// ClusterSelector
// -----------------------------------------------------------------------------

/// A route's compiled cluster destinations.
#[derive(Debug)]
pub(crate) enum CompiledTargets {
    /// One cluster: selection is infallible and has no shared state.
    Single(Arc<str>),

    /// Weighted, priority-tiered cluster selection.
    Weighted(ClusterSelector),
}

impl CompiledTargets {
    /// Compile a route's canonical target set.
    pub(crate) fn new(targets: Arc<[WeightedTarget]>) -> Self {
        match targets.as_ref() {
            [target] => Self::Single(Arc::clone(&target.name)),
            _ => Self::Weighted(ClusterSelector::new(targets)),
        }
    }

    /// Select the cluster for one request.
    pub(crate) fn select(&self, registry: Option<&HealthRegistry>) -> Arc<str> {
        match self {
            Self::Single(cluster) => Arc::clone(cluster),
            Self::Weighted(selector) => selector.select(registry),
        }
    }
}

/// Selects one cluster from a route's weighted targets.
#[derive(Debug)]
pub(crate) struct ClusterSelector {
    /// Targets in configuration order; index order is the tie-break order.
    targets: Arc<[WeightedTarget]>,

    /// Target indices grouped by priority tier, lowest priority number first.
    ///
    /// Each tier pre-computes its total weight once, so request-time selection
    /// only visits the active tier's targets.
    tiers: Box<[Tier]>,

    /// First target name, used if a selector is built without targets.
    fallback: Arc<str>,

    /// Smooth weighted round-robin scores, one per target.
    ///
    /// A short critical section keeps score updates atomic per request without
    /// blocking unrelated routes (each selector owns its scores).
    state: Mutex<SelectorState>,
}

/// One priority tier and its pre-computed weight total.
#[derive(Debug)]
struct Tier {
    /// Target indices in configuration order.
    indices: Box<[usize]>,

    /// Sum of every target's configured weight.
    total_weight: i64,
}

/// Mutable per-selector score state.
#[derive(Debug)]
struct SelectorState {
    /// Smooth weighted round-robin scores, one per target.
    scores: Vec<i64>,

    /// Tier that owns the current score rotation.
    active_tier: Option<usize>,
}

/// Group targets by priority and pre-compute each tier's weight total.
fn build_tiers(targets: &[WeightedTarget]) -> Box<[Tier]> {
    let mut by_priority: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, target) in targets.iter().enumerate() {
        by_priority.entry(target.priority).or_default().push(index);
    }
    by_priority
        .into_values()
        .map(|indices| {
            let total_weight = indices.iter().fold(0_i64, |total, &index| {
                let weight = targets.get(index).map_or(0, |target| i64::from(target.weight.get()));
                total.saturating_add(weight)
            });
            Tier {
                indices: indices.into_boxed_slice(),
                total_weight,
            }
        })
        .collect()
}

impl ClusterSelector {
    /// Build a selector from canonical weighted targets.
    pub(crate) fn new<T: Into<Arc<[WeightedTarget]>>>(targets: T) -> Self {
        let targets: Arc<[WeightedTarget]> = targets.into();
        let tiers = build_tiers(&targets);
        let fallback = targets
            .first()
            .map_or_else(|| Arc::from(""), |target| Arc::clone(&target.name));
        let state = SelectorState {
            scores: vec![0; targets.len()],
            active_tier: None,
        };
        Self {
            targets,
            tiers,
            fallback,
            state: Mutex::new(state),
        }
    }

    /// Select a cluster, honoring cluster health when a registry is available.
    ///
    /// Tiers are tried in order, and the first one with an eligible target
    /// provides the cluster. A tier that cannot serve leaves the scores of
    /// other tiers alone, so a fallback tier keeps its rotation for the next
    /// request; a health change that empties a tier spills to the next one
    /// instead of failing the request. Once a tier serves, targets outside it
    /// have their scores reset so a skipped tier cannot win later on a stale
    /// score.
    ///
    /// Selection is infallible: a route target set is never empty.
    pub(crate) fn select(&self, registry: Option<&HealthRegistry>) -> Arc<str> {
        self.try_select(registry).unwrap_or_else(|| Arc::clone(&self.fallback))
    }

    /// Try each tier in order, then fan out to the primary tier in panic mode.
    fn try_select(&self, registry: Option<&HealthRegistry>) -> Option<Arc<str>> {
        for (tier_index, tier) in self.tiers.iter().enumerate() {
            if let Some(cluster) = self.weighted_select(tier_index, tier, registry) {
                return Some(cluster);
            }
        }

        // Panic mode mirrors endpoint priority handling: no tier has a healthy
        // target, so use the highest-priority tier regardless of health and let
        // the downstream load balancer panic too.
        let tier = self.tiers.first()?;
        self.weighted_select(0, tier, None)
    }

    /// Whether a target's cluster can serve traffic.
    ///
    /// No registry, or a cluster absent from it, means "eligible": untracked
    /// clusters are not health-gated. A tracked cluster needs at least one
    /// healthy endpoint. Total endpoint count is not otherwise weighed here;
    /// endpoint capacity and overprovisioning stay in the load balancer.
    fn eligible(&self, index: usize, registry: Option<&HealthRegistry>) -> bool {
        let Some(target) = self.targets.get(index) else {
            return false;
        };
        let Some(registry) = registry else {
            return true;
        };
        registry
            .get(&*target.name)
            .is_none_or(|state| state.endpoint_counts().0 > 0)
    }

    /// Smooth weighted round-robin across one pre-computed tier.
    ///
    /// `registry: None` disables eligibility filtering (panic mode). A tier
    /// with no eligible target returns `None` without touching the scores of
    /// other tiers: the caller may try a lower tier next, and resetting that
    /// tier here would restart its rotation on every request. When a different
    /// tier starts serving, all scores are reset once so a target that was
    /// skipped, or left an inactive tier, cannot win later on a stale score.
    fn weighted_select(&self, tier_index: usize, tier: &Tier, registry: Option<&HealthRegistry>) -> Option<Arc<str>> {
        if !tier.indices.iter().any(|&index| self.eligible(index, registry)) {
            return None;
        }
        // Recover a poisoned lock: scores are advisory, and failing the request
        // would be worse than continuing with possibly inconsistent state.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.active_tier != Some(tier_index) {
            state.scores.fill(0);
            state.active_tier = Some(tier_index);
        }
        let winner_index = self.award_scores(&mut state, tier, registry)?;
        drop(state);
        self.targets.get(winner_index).map(|target| Arc::clone(&target.name))
    }

    /// Update the active tier's scores and return its winner.
    fn award_scores(&self, state: &mut SelectorState, tier: &Tier, registry: Option<&HealthRegistry>) -> Option<usize> {
        let mut total = tier.total_weight;
        let mut best: Option<(usize, i64)> = None;

        for &index in &tier.indices {
            let weight = self
                .targets
                .get(index)
                .map_or(0, |target| i64::from(target.weight.get()));
            if !self.eligible(index, registry) {
                if let Some(score) = state.scores.get_mut(index) {
                    *score = 0;
                }
                total = total.saturating_sub(weight);
                continue;
            }
            let score = state.scores.get(index).copied().unwrap_or(0).saturating_add(weight);
            if let Some(slot) = state.scores.get_mut(index) {
                *slot = score;
            }
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((index, score));
            }
        }

        let (winner_index, _) = best?;
        if let Some(score) = state.scores.get_mut(winner_index) {
            *score = score.saturating_sub(total);
        }
        Some(winner_index)
    }

    /// Read a target's current smooth-WRR score (tests only).
    #[cfg(test)]
    fn score_of(&self, name: &str) -> Option<i64> {
        let index = self.targets.iter().position(|target| &*target.name == name)?;
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.scores.get(index).copied()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::{
        config::TargetWeight,
        health::{ClusterHealthEntry, EndpointHealth},
    };

    use super::*;

    fn target(name: &str, weight: u16, priority: u32) -> WeightedTarget {
        WeightedTarget {
            name: Arc::from(name),
            weight: TargetWeight::try_from(weight).unwrap(),
            priority,
        }
    }

    fn counts(selector: &ClusterSelector, registry: Option<&HealthRegistry>, runs: usize) -> HashMap<String, usize> {
        let mut seen = HashMap::new();
        for _ in 0..runs {
            let selected = selector.select(registry);
            *seen.entry(selected.to_string()).or_insert(0) += 1;
        }
        seen
    }

    /// Registry with `(cluster, total_endpoints, unhealthy_indices)` entries.
    fn registry(clusters: &[(&str, usize, &[usize])]) -> HealthRegistry {
        let map: HashMap<Arc<str>, Arc<ClusterHealthEntry>> = clusters
            .iter()
            .map(|(name, total, unhealthy)| {
                let endpoints: Vec<EndpointHealth> = std::iter::repeat_with(EndpointHealth::new).take(*total).collect();
                let addresses: Vec<Arc<str>> = (0..*total)
                    .map(|index| Arc::from(format!("10.0.0.{index}:80").as_str()))
                    .collect();
                for &index in *unhealthy {
                    endpoints[index].mark_unhealthy();
                }
                (
                    Arc::from(*name),
                    Arc::new(ClusterHealthEntry::new(endpoints, addresses, None, None)),
                )
            })
            .collect();
        Arc::new(map)
    }

    #[test]
    fn nine_to_one_weights_split_accordingly() {
        let selector = ClusterSelector::new(vec![target("stable", 9, 0), target("canary", 1, 0)]);
        let seen = counts(&selector, None, 100);
        assert_eq!(seen.get("stable"), Some(&90), "stable should take ~90%: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&10), "canary should take ~10%: {seen:?}");
    }

    #[test]
    fn primary_tier_is_used_while_healthy() {
        let selector = ClusterSelector::new(vec![target("stable", 9, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let seen = counts(&selector, None, 100);
        assert!(
            !seen.contains_key("dr"),
            "a healthy primary tier must not spill: {seen:?}"
        );
    }

    #[test]
    fn zero_healthy_canary_is_excluded_without_spilling() {
        let selector = ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[]), ("canary", 1, &[0]), ("dr", 1, &[])]);
        let seen = counts(&selector, Some(&registry), 20);
        assert_eq!(seen.get("stable"), Some(&20), "stable serves every request: {seen:?}");
        assert!(
            !seen.contains_key("canary"),
            "unhealthy target must be skipped: {seen:?}"
        );
        assert!(
            !seen.contains_key("dr"),
            "a partially healthy tier must not spill to the next tier: {seen:?}"
        );
    }

    #[test]
    fn fully_unhealthy_tier_spills_to_next() {
        let selector = ClusterSelector::new(vec![
            target("stable", 1, 0),
            target("canary", 1, 0),
            target("dr-a", 1, 1),
            target("dr-b", 1, 1),
        ]);
        let registry = registry(&[
            ("stable", 1, &[0]),
            ("canary", 1, &[0]),
            ("dr-a", 1, &[]),
            ("dr-b", 1, &[]),
        ]);
        let seen = counts(&selector, Some(&registry), 10);
        assert_eq!(
            seen.get("dr-a"),
            Some(&5),
            "the failover tier must keep its smooth-WRR rotation: {seen:?}"
        );
        assert_eq!(
            seen.get("dr-b"),
            Some(&5),
            "the failover tier must split evenly between its targets: {seen:?}"
        );
        assert_eq!(
            seen.get("stable"),
            None,
            "the unhealthy primary tier must not receive traffic: {seen:?}"
        );
    }

    #[test]
    fn all_unhealthy_enters_panic_mode_on_primary_tier() {
        let selector = ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[0]), ("canary", 1, &[0]), ("dr", 1, &[0])]);
        let seen = counts(&selector, Some(&registry), 10);
        assert_eq!(
            seen.get("stable"),
            Some(&5),
            "panic mode must rotate within the highest-priority tier: {seen:?}"
        );
        assert_eq!(
            seen.get("canary"),
            Some(&5),
            "panic mode must rotate within the highest-priority tier: {seen:?}"
        );
        assert_eq!(seen.get("dr"), None, "panic mode must not pick a lower tier: {seen:?}");
    }

    #[test]
    fn missing_registry_treats_all_targets_as_eligible() {
        let selector = ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0)]);
        let seen = counts(&selector, None, 10);
        assert_eq!(seen.get("stable"), Some(&5), "equal weights split evenly: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&5), "equal weights split evenly: {seen:?}");
    }

    #[test]
    fn untracked_cluster_is_eligible() {
        let selector = ClusterSelector::new(vec![target("stable", 1, 0)]);
        let registry = registry(&[("other", 1, &[0])]);
        assert_eq!(
            &*selector.select(Some(&registry)),
            "stable",
            "a cluster absent from the registry is not health-gated"
        );
    }

    #[test]
    fn equal_weights_alternate_deterministically() {
        let selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let mut picks = Vec::new();
        for _ in 0..4 {
            picks.push(selector.select(None).to_string());
        }
        assert_eq!(
            picks,
            vec!["a", "b", "a", "b"],
            "ties resolve to the lowest target index"
        );
    }

    #[test]
    fn ineligible_target_forfeits_its_stale_score() {
        let selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let both_healthy = registry(&[("a", 1, &[]), ("b", 1, &[])]);

        // The opening tie goes to `a`, which pays the tier total and starts the
        // next turn with a negative score.
        assert_eq!(&*selector.select(Some(&both_healthy)), "a");
        assert!(
            selector.score_of("a").is_some_and(|score| score < 0),
            "the winner should carry a negative score into the next turn"
        );

        // While `a` is unhealthy every turn goes to `b`; `a`'s score must be
        // reset rather than kept for its recovery.
        let only_b = registry(&[("a", 1, &[0]), ("b", 1, &[])]);
        assert_eq!(&*selector.select(Some(&only_b)), "b");
        assert_eq!(
            selector.score_of("a"),
            Some(0),
            "an ineligible target must not carry its old score"
        );

        // `b` holds the higher score after the reset, so it wins the first
        // recovered turn and `a` follows on the next one.
        assert_eq!(&*selector.select(Some(&both_healthy)), "b");
        assert_eq!(&*selector.select(Some(&both_healthy)), "a");
    }
}
