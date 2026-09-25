// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Counters for JSON ingress benchmarks (`json-bench-metrics` feature).

use std::sync::atomic::{AtomicU64, Ordering};

static PREPASS_APPLY: AtomicU64 = AtomicU64::new(0);

/// Increment when the pipeline JSON extract pre-pass runs at body EOS.
#[inline]
pub fn prepass_apply() {
    #[cfg(feature = "json-bench-metrics")]
    PREPASS_APPLY.fetch_add(1, Ordering::Relaxed);
}

/// Reset the pre-pass counter.
pub fn reset() {
    #[cfg(feature = "json-bench-metrics")]
    PREPASS_APPLY.store(0, Ordering::Relaxed);
}

/// Pre-pass executions since last reset.
#[must_use]
pub fn prepass_apply_count() -> u64 {
    #[cfg(feature = "json-bench-metrics")]
    {
        return PREPASS_APPLY.load(Ordering::Relaxed);
    }
    #[cfg(not(feature = "json-bench-metrics"))]
    0
}
