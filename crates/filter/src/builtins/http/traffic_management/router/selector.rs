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

/// Selects one cluster from a route's weighted targets.
#[derive(Debug)]
pub(crate) struct ClusterSelector {
    /// Targets in configuration order; index order is the tie-break order.
    targets: Vec<WeightedTarget>,

    /// Target indices grouped by priority tier, lowest priority number first.
    tiers: Vec<Vec<usize>>,

    /// Smooth weighted round-robin scores, one per target.
    ///
    /// A short critical section keeps score updates atomic per request without
    /// blocking unrelated routes (each selector owns its scores).
    scores: Mutex<Vec<i64>>,
}

impl ClusterSelector {
    /// Build a selector from canonical weighted targets.
    pub(crate) fn new(targets: Vec<WeightedTarget>) -> Self {
        let mut by_priority: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (index, target) in targets.iter().enumerate() {
            by_priority.entry(target.priority).or_default().push(index);
        }
        let scores = vec![0; targets.len()];
        Self {
            targets,
            tiers: by_priority.into_values().collect(),
            scores: Mutex::new(scores),
        }
    }

    /// Select a cluster, honoring cluster health when a registry is available.
    ///
    /// Tiers are tried in order, and the first one that yields an eligible
    /// target provides the cluster. Because eligibility is re-checked while the
    /// scores are held, a health change that empties a tier spills to the next
    /// one instead of failing the request. Targets outside the winning tier
    /// have their scores reset, so a skipped tier cannot win later on a stale
    /// score.
    ///
    /// Returns `None` only when the selector was built with no targets, which
    /// route validation rejects.
    pub(crate) fn select(&self, registry: Option<&HealthRegistry>) -> Option<Arc<str>> {
        if self.targets.is_empty() {
            return None;
        }

        for tier in &self.tiers {
            if let Some(cluster) = self.weighted_select(tier, registry) {
                return Some(cluster);
            }
        }

        // Panic mode mirrors endpoint priority handling: no tier has a healthy
        // target, so use the highest-priority tier regardless of health and let
        // the downstream load balancer panic too.
        self.tiers.first().and_then(|tier| self.weighted_select(tier, None))
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

    /// Smooth weighted round-robin across `tier`.
    ///
    /// `registry: None` disables eligibility filtering (panic mode). Targets
    /// outside the active set have their score zeroed so a target that was
    /// skipped, or left an inactive tier, cannot win later on a stale score.
    fn weighted_select(&self, tier: &[usize], registry: Option<&HealthRegistry>) -> Option<Arc<str>> {
        // Recover a poisoned lock: scores are advisory, and failing the request
        // would be worse than continuing with possibly inconsistent state.
        let mut scores = self.scores.lock().unwrap_or_else(PoisonError::into_inner);
        let mut total: i64 = 0;
        let mut best: Option<(usize, i64)> = None;

        for (index, score) in scores.iter_mut().enumerate() {
            if !tier.contains(&index) || !self.eligible(index, registry) {
                *score = 0;
                continue;
            }
            let weight = self.targets.get(index).map_or(0, |target| i64::from(target.weight));
            *score = score.saturating_add(weight);
            total = total.saturating_add(weight);
            if best.is_none_or(|(_, best_score)| *score > best_score) {
                best = Some((index, *score));
            }
        }

        let (winner_index, _) = best?;
        if let Some(score) = scores.get_mut(winner_index) {
            *score = score.saturating_sub(total);
        }
        drop(scores);
        self.targets.get(winner_index).map(|target| Arc::clone(&target.name))
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

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    fn target(name: &str, weight: u32, priority: u32) -> WeightedTarget {
        WeightedTarget {
            name: Arc::from(name),
            weight,
            priority,
        }
    }

    fn counts(selector: &ClusterSelector, registry: Option<&HealthRegistry>, runs: usize) -> HashMap<String, usize> {
        let mut seen = HashMap::new();
        for _ in 0..runs {
            let selected = selector.select(registry).expect("selector should pick a target");
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
        let selector = ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[0]), ("canary", 1, &[0]), ("dr", 1, &[])]);
        let seen = counts(&selector, Some(&registry), 10);
        assert_eq!(seen.get("dr"), Some(&10), "only the failover tier is healthy: {seen:?}");
        assert_eq!(
            seen.get("stable"),
            None,
            "the unhealthy primary tier must not receive traffic: {seen:?}"
        );
    }

    #[test]
    fn all_unhealthy_enters_panic_mode_on_primary_tier() {
        let selector = ClusterSelector::new(vec![target("stable", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[0]), ("dr", 1, &[0])]);
        let seen = counts(&selector, Some(&registry), 10);
        assert_eq!(
            seen.get("stable"),
            Some(&10),
            "panic mode must use the highest-priority tier: {seen:?}"
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
            selector.select(Some(&registry)).as_deref(),
            Some("stable"),
            "a cluster absent from the registry is not health-gated"
        );
    }

    #[test]
    fn equal_weights_alternate_deterministically() {
        let selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let mut picks = Vec::new();
        for _ in 0..4 {
            picks.push(selector.select(None).unwrap().to_string());
        }
        assert_eq!(
            picks,
            vec!["a", "b", "a", "b"],
            "ties resolve to the lowest target index"
        );
    }

    #[test]
    fn recovered_target_does_not_win_on_stale_score() {
        let selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let unhealthy_a = registry(&[("a", 1, &[0]), ("b", 1, &[])]);
        // `b` accumulates score while `a` is excluded.
        for _ in 0..5 {
            assert_eq!(selector.select(Some(&unhealthy_a)).as_deref(), Some("b"));
        }
        let both_healthy = registry(&[("a", 1, &[]), ("b", 1, &[])]);
        let first = selector.select(Some(&both_healthy));
        assert_eq!(
            first.as_deref(),
            Some("a"),
            "a recovered target starts from zero, not a stale negative or positive score"
        );
    }

    #[test]
    fn empty_targets_return_none() {
        let selector = ClusterSelector::new(Vec::new());
        assert!(selector.select(None).is_none(), "no targets means no selection");
    }
}
