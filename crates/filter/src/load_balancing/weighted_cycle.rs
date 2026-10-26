// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Weighted round-robin cursor and bucket selection.
//!
//! Endpoint strategies and route-target selection share one weighting
//! primitive: a monotonically increasing slot modulo the candidate weight
//! total, resolved against cumulative weight buckets. Keeping it here means a
//! fix to distribution or overflow handling applies to both layers.

use std::sync::atomic::{AtomicU64, Ordering};

// -----------------------------------------------------------------------------
// WeightedCycle
// -----------------------------------------------------------------------------

/// A monotonic cursor for weighted round-robin selection.
#[derive(Debug, Default)]
pub(crate) struct WeightedCycle {
    /// Number of selection turns taken so far.
    counter: AtomicU64,
}

impl WeightedCycle {
    /// Create a cycle starting at slot zero.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Advance the cycle and return the raw turn number.
    ///
    /// Callers reduce it modulo their current candidate weight total, which can
    /// change with health. Reducing here instead would bias redistribution when
    /// the configured total is not a multiple of the healthy total.
    pub(crate) fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Bucket Selection
// -----------------------------------------------------------------------------

/// Return the candidate whose cumulative weight bucket contains `slot`.
///
/// `candidates` yields `(index, weight)` in configuration order. `slot` must be
/// less than the sum of the yielded weights; a slot outside that range returns
/// `None`.
pub(crate) fn pick_weighted<I>(slot: u64, candidates: I) -> Option<usize>
where
    I: IntoIterator<Item = (usize, u64)>,
{
    let mut remaining = slot;
    for (index, weight) in candidates {
        if remaining < weight {
            return Some(index);
        }
        remaining = remaining.saturating_sub(weight);
    }
    None
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn cycle_advances_one_turn_at_a_time() {
        let cycle = WeightedCycle::new();
        let turns: Vec<u64> = std::iter::repeat_with(|| cycle.next()).take(4).collect();
        assert_eq!(turns, vec![0, 1, 2, 3], "the cursor is monotonic");
    }

    #[test]
    fn bucket_picks_the_configured_share() {
        let candidates = [(0, 9_u64), (1, 1_u64)];
        let stable = (0..10)
            .filter(|slot| pick_weighted(*slot, candidates) == Some(0))
            .count();
        assert_eq!(stable, 9, "the first candidate owns 9 of 10 slots");
    }

    #[test]
    fn slot_past_the_total_selects_nothing() {
        assert_eq!(
            pick_weighted(9, [(0, 1_u64), (1, 1_u64)]),
            None,
            "a slot outside the cumulative total is invalid"
        );
    }
}
