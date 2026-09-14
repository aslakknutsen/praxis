// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! SSE2-accelerated scanner for JSON string delimiters (`x86_64`).
//!
//! SSE2 is baseline on every `x86_64` CPU, so no runtime feature detection is
//! needed.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128,
    _mm_subs_epu8,
};

/// Width of one SSE2 register in bytes.
const LANE: usize = 16;

/// Find the first `"`, `\`, or control-char (< 0x20) in `haystack`.
///
/// Processes 16 bytes per iteration using SSE2 intrinsics, falling back to
/// scalar for any remainder shorter than one lane.
pub(crate) fn find(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();

    if len < LANE {
        return crate::generic::find(haystack);
    }

    #[expect(unsafe_code, reason = "SSE2 intrinsics require unsafe")]
    // SAFETY: SSE2 is guaranteed available on every x86_64 CPU. The length
    // check above ensures at least LANE bytes are readable.
    unsafe {
        find_inner(haystack)
    }
}

/// Inner SIMD loop. Caller must guarantee `haystack.len() >= LANE`.
///
/// # Safety
///
/// The caller must ensure `haystack.len() >= LANE` and that SSE2 is available
/// (guaranteed on `x86_64`).
#[expect(unsafe_code, reason = "SSE2 intrinsics require unsafe")]
#[target_feature(enable = "sse2")]
unsafe fn find_inner(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();
    let ptr = haystack.as_ptr();

    let v_quote = _mm_set1_epi8(b'"'.cast_signed());
    let v_backslash = _mm_set1_epi8(b'\\'.cast_signed());
    let v_ctrl_max = _mm_set1_epi8(0x1F);
    let v_zero = _mm_setzero_si128();

    let mut offset: usize = 0;

    while offset.saturating_add(LANE) <= len {
        // SAFETY: `offset + LANE <= len`, so `ptr.add(offset)` is within
        // bounds and reading 16 bytes is valid.
        let chunk: __m128i = unsafe { _mm_loadu_si128(ptr.add(offset).cast::<__m128i>()) };

        // SAFETY: all arguments are valid SSE2 vectors produced above.
        let mask = unsafe { classify(chunk, v_quote, v_backslash, v_ctrl_max, v_zero) };

        if mask != 0 {
            let bit_offset = mask.trailing_zeros();
            return offset.checked_add(usize::try_from(bit_offset).ok()?);
        }
        offset = offset.checked_add(LANE)?;
    }

    let tail = haystack.get(offset..)?;
    crate::generic::find(tail).and_then(|pos| offset.checked_add(pos))
}

/// Classify 16 bytes, returning a bitmask where bit *i* is set when lane *i*
/// contains `"`, `\`, or a byte < 0x20.
///
/// # Safety
///
/// Requires SSE2. All arguments must be valid `__m128i` values.
#[expect(unsafe_code, reason = "SSE2 intrinsics require unsafe")]
#[inline(always)]
unsafe fn classify(
    chunk: __m128i,
    v_quote: __m128i,
    v_backslash: __m128i,
    v_ctrl_max: __m128i,
    v_zero: __m128i,
) -> i32 {
    // SAFETY: all intrinsics are SSE2 baseline, caller ensures valid vectors.
    unsafe {
        let m_quote = _mm_cmpeq_epi8(chunk, v_quote);
        let m_backslash = _mm_cmpeq_epi8(chunk, v_backslash);
        // `subs_epu8(byte, 0x1F)` saturates to 0 when byte <= 0x1F.
        // Comparing that result against zero produces 0xFF for control chars.
        let m_control = _mm_cmpeq_epi8(_mm_subs_epu8(chunk, v_ctrl_max), v_zero);
        let combined = _mm_or_si128(_mm_or_si128(m_quote, m_backslash), m_control);
        _mm_movemask_epi8(combined)
    }
}
