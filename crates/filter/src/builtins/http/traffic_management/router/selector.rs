// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Route-level cluster selection.
//!
//! A route may name one cluster (the `cluster:` shorthand) or several weighted
//! targets split into priority tiers (`weighted_clusters:`). The selector picks
//! one cluster per request using weighted round-robin within the first tier that
//! has a healthy target, spilling to the next tier only when the current one has
//! none.
//!
//! Health is judged per cluster, not per endpoint: a target is eligible when
//! its cluster has at least one healthy endpoint. Endpoint weights inside the
//! selected cluster are applied later by the `load_balancer` filter, so the
//! effective share is `route_target_share * endpoint_share_within_cluster`.

use std::sync::Arc;

use praxis_core::{
    config::WeightedTarget,
    health::{ClusterHealthEntry, HealthRegistry},
};

use crate::load_balancing::weighted_cycle::{WeightedCycle, pick_weighted};

// -----------------------------------------------------------------------------
// CompiledTargets
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
            [target] => Self::Single(target.name.shared()),
            _ => Self::Weighted(ClusterSelector::new(targets)),
        }
    }

    /// Bind the pipeline's health handles, once per pipeline instance.
    pub(crate) fn bind_health(&mut self, registry: &HealthRegistry) {
        if let Self::Weighted(selector) = self {
            selector.bind_health(registry);
        }
    }

    /// Select the cluster for one request.
    pub(crate) fn select(&self) -> Arc<str> {
        match self {
            Self::Single(cluster) => Arc::clone(cluster),
            Self::Weighted(selector) => selector.select(),
        }
    }
}

// -----------------------------------------------------------------------------
// ClusterSelector
// -----------------------------------------------------------------------------

/// Health handles aligned with a selector's target list.
type HealthHandles = Box<[Option<Arc<ClusterHealthEntry>>]>;

/// Selects one cluster from a route's weighted targets.
#[derive(Debug)]
pub(crate) struct ClusterSelector {
    /// Targets in configuration order; index order is the tie-break order.
    targets: Arc<[WeightedTarget]>,

    /// Target indices grouped by priority tier, lowest priority number first.
    ///
    /// Each tier carries its own weight total and round-robin cycle, so
    /// request-time selection only visits the active tier's targets.
    tiers: Box<[Tier]>,

    /// First target name, used if a selector is built without targets.
    fallback: Arc<str>,

    /// Health handles resolved at pipeline install.
    ///
    /// Binding once removes a name-keyed registry lookup from the request path
    /// and makes the health source explicit: a target without a top-level
    /// health-checked cluster has no handle and stays eligible.
    health: Option<HealthHandles>,
}

/// One priority tier and its pre-computed weight total.
#[derive(Debug)]
struct Tier {
    /// Target indices and weights in configuration order.
    targets: Box<[(usize, u64)]>,

    /// Sum of every target's configured weight.
    total_weight: u64,

    /// Weighted round-robin cursor for this tier.
    cycle: WeightedCycle,
}

impl ClusterSelector {
    /// Build a selector from canonical weighted targets.
    pub(crate) fn new<T: Into<Arc<[WeightedTarget]>>>(targets: T) -> Self {
        let targets: Arc<[WeightedTarget]> = targets.into();
        let tiers = build_tiers(&targets);
        let fallback = targets
            .first()
            .map_or_else(|| Arc::from(""), |target| target.name.shared());
        Self {
            targets,
            tiers,
            fallback,
            health: None,
        }
    }

    /// Resolve every target's health handle from the pipeline registry.
    pub(crate) fn bind_health(&mut self, registry: &HealthRegistry) {
        self.health = Some(
            self.targets
                .iter()
                .map(|target| registry.get(&*target.name).cloned())
                .collect(),
        );
    }

    /// Select a cluster, honoring cluster health when it was bound.
    ///
    /// Tiers are tried in order, and the first one with an eligible target
    /// provides the cluster. A health change that empties a tier spills to the
    /// next one instead of failing the request.
    ///
    /// Selection is infallible: a route target set is never empty.
    pub(crate) fn select(&self) -> Arc<str> {
        self.try_select().unwrap_or_else(|| Arc::clone(&self.fallback))
    }

    /// Try each tier in order, then fan out to the primary tier in panic mode.
    fn try_select(&self) -> Option<Arc<str>> {
        for tier in &self.tiers {
            if let Some(cluster) = self.select_from_tier(tier, true) {
                return Some(cluster);
            }
        }

        // Panic mode mirrors endpoint priority handling: no tier has a healthy
        // target, so use the highest-priority tier regardless of health and let
        // the downstream load balancer panic too.
        let tier = self.tiers.first()?;
        self.select_from_tier(tier, false)
    }

    /// Whether a target's cluster can serve traffic.
    ///
    /// No bound handle, or a cluster absent from the registry, means
    /// "eligible": untracked clusters are not health-gated. A tracked cluster
    /// needs at least one healthy endpoint. Total endpoint count is not
    /// otherwise weighed here; endpoint capacity and overprovisioning stay in
    /// the load balancer.
    fn eligible(&self, index: usize, require_health: bool) -> bool {
        if self.targets.get(index).is_none() {
            return false;
        }
        if !require_health {
            return true;
        }
        self.health
            .as_ref()
            .and_then(|handles| handles.get(index))
            .and_then(Option::as_ref)
            .is_none_or(|entry| entry.endpoint_counts().0 > 0)
    }

    /// Weighted round-robin across one pre-computed tier.
    fn select_from_tier(&self, tier: &Tier, require_health: bool) -> Option<Arc<str>> {
        let total = self.eligible_weight(tier, require_health)?;
        let slot = tier.cycle.next().checked_rem(total)?;
        let winner = pick_weighted(
            slot,
            tier.targets
                .iter()
                .filter_map(|&(index, weight)| self.eligible(index, require_health).then_some((index, weight))),
        )?;
        self.targets.get(winner).map(|target| target.name.shared())
    }

    /// Sum the weights of the tier's eligible targets.
    fn eligible_weight(&self, tier: &Tier, require_health: bool) -> Option<u64> {
        let mut total = tier.total_weight;
        let mut any = false;
        for &(index, weight) in &tier.targets {
            if self.eligible(index, require_health) {
                any = true;
            } else {
                total = total.saturating_sub(weight);
            }
        }
        any.then_some(total)
    }
}

/// Group targets by priority and pre-compute each tier's weights and total.
fn build_tiers(targets: &[WeightedTarget]) -> Box<[Tier]> {
    let mut by_priority: std::collections::BTreeMap<u32, Vec<usize>> = std::collections::BTreeMap::new();
    for (index, target) in targets.iter().enumerate() {
        by_priority.entry(target.priority).or_default().push(index);
    }
    by_priority
        .into_values()
        .map(|indices| {
            let tier_targets: Box<[(usize, u64)]> = indices
                .into_iter()
                .map(|index| {
                    let weight = targets.get(index).map_or(0, |target| u64::from(target.weight.get()));
                    (index, weight)
                })
                .collect();
            let total_weight = tier_targets
                .iter()
                .fold(0_u64, |total, &(_, weight)| total.saturating_add(weight));
            Tier {
                targets: tier_targets,
                total_weight,
                cycle: WeightedCycle::new(),
            }
        })
        .collect()
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

    use praxis_core::{config::TargetWeight, health::EndpointHealth};

    use super::*;

    fn target(name: &str, weight: u16, priority: u32) -> WeightedTarget {
        WeightedTarget {
            name: name.into(),
            weight: TargetWeight::try_from(weight).unwrap(),
            priority,
        }
    }

    fn counts(
        selector: &mut ClusterSelector,
        registry: Option<&HealthRegistry>,
        runs: usize,
    ) -> HashMap<String, usize> {
        if let Some(registry) = registry {
            selector.bind_health(registry);
        }
        let mut seen = HashMap::new();
        for _ in 0..runs {
            let selected = selector.select();
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
        let mut selector = ClusterSelector::new(vec![target("stable", 9, 0), target("canary", 1, 0)]);
        let seen = counts(&mut selector, None, 100);
        assert_eq!(seen.get("stable"), Some(&90), "stable should take ~90%: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&10), "canary should take ~10%: {seen:?}");
    }

    #[test]
    fn primary_tier_is_used_while_healthy() {
        let mut selector =
            ClusterSelector::new(vec![target("stable", 9, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let seen = counts(&mut selector, None, 100);
        assert!(
            !seen.contains_key("dr"),
            "a healthy primary tier must not spill: {seen:?}"
        );
    }

    #[test]
    fn zero_healthy_canary_is_excluded_without_spilling() {
        let mut selector =
            ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[]), ("canary", 1, &[0]), ("dr", 1, &[])]);
        let seen = counts(&mut selector, Some(&registry), 20);
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
        let mut selector = ClusterSelector::new(vec![
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
        let seen = counts(&mut selector, Some(&registry), 10);
        assert_eq!(
            seen.get("dr-a"),
            Some(&5),
            "the failover tier must keep its rotation: {seen:?}"
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
        let mut selector =
            ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0), target("dr", 1, 1)]);
        let registry = registry(&[("stable", 1, &[0]), ("canary", 1, &[0]), ("dr", 1, &[0])]);
        let seen = counts(&mut selector, Some(&registry), 10);
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
        let mut selector = ClusterSelector::new(vec![target("stable", 1, 0), target("canary", 1, 0)]);
        let seen = counts(&mut selector, None, 10);
        assert_eq!(seen.get("stable"), Some(&5), "equal weights split evenly: {seen:?}");
        assert_eq!(seen.get("canary"), Some(&5), "equal weights split evenly: {seen:?}");
    }

    #[test]
    fn untracked_cluster_is_eligible() {
        let mut selector = ClusterSelector::new(vec![target("stable", 1, 0)]);
        let registry = registry(&[("other", 1, &[0])]);
        selector.bind_health(&registry);
        assert_eq!(
            &*selector.select(),
            "stable",
            "a cluster absent from the registry is not health-gated"
        );
    }

    #[test]
    fn equal_weights_alternate_deterministically() {
        let selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let mut picks = Vec::new();
        for _ in 0..4 {
            picks.push(selector.select().to_string());
        }
        assert_eq!(
            picks,
            vec!["a", "b", "a", "b"],
            "ties resolve to the lowest target index"
        );
    }

    #[test]
    fn rebinding_health_replaces_previous_handles() {
        let mut selector = ClusterSelector::new(vec![target("a", 1, 0), target("b", 1, 0)]);
        let healthy = registry(&[("a", 1, &[]), ("b", 1, &[])]);
        selector.bind_health(&healthy);

        // A later binding marks `a` dead; selection follows the latest handles
        // rather than sticking to the first install.
        let dead = registry(&[("a", 1, &[0]), ("b", 1, &[])]);
        selector.bind_health(&dead);
        let seen = counts(&mut selector, None, 10);
        assert_eq!(seen.get("a"), None, "the latest binding gates selection: {seen:?}");
        assert_eq!(seen.get("b"), Some(&10), "the latest binding gates selection: {seen:?}");
    }
}
