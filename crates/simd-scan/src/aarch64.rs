// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! NEON-accelerated scanner for JSON string delimiters (`aarch64`).
//!
//! NEON is baseline on `aarch64`, so no runtime feature detection is needed.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint8x16_t, vceqq_u8, vcltq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vmaxvq_u8, vorrq_u8, vreinterpret_u64_u8,
    vreinterpretq_u16_u8, vshrn_n_u16,
};

/// Width of one NEON register in bytes.
const LANE: usize = 16;

/// Find the first `"`, `\`, or control-char (< 0x20) in `haystack`.
///
/// Processes 16 bytes per iteration using NEON intrinsics, falling back to
/// scalar for any remainder shorter than one lane.
pub(crate) fn find(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();

    if len < LANE {
        return crate::generic::find(haystack);
    }

    #[expect(unsafe_code, reason = "NEON intrinsics require unsafe")]
    // SAFETY: NEON is guaranteed available on every aarch64 CPU. The length
    // check above ensures at least LANE bytes are readable.
    unsafe {
        find_inner(haystack)
    }
}

/// Inner NEON loop. Caller must guarantee `haystack.len() >= LANE`.
///
/// # Safety
///
/// The caller must ensure `haystack.len() >= LANE` and that NEON is available
/// (guaranteed on `aarch64`).
#[expect(unsafe_code, reason = "NEON intrinsics require unsafe")]
#[target_feature(enable = "neon")]
unsafe fn find_inner(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();
    let ptr = haystack.as_ptr();

    let v_quote = vdupq_n_u8(b'"');
    let v_backslash = vdupq_n_u8(b'\\');
    let v_ctrl_bound = vdupq_n_u8(0x20);

    let mut offset: usize = 0;

    while offset.saturating_add(LANE) <= len {
        // SAFETY: `offset + LANE <= len`, so 16-byte read is in bounds.
        let chunk: uint8x16_t = unsafe { vld1q_u8(ptr.add(offset)) };

        // SAFETY: all arguments are valid NEON vectors produced above.
        let combined = unsafe { classify(chunk, v_quote, v_backslash, v_ctrl_bound) };

        // Fast reject: if no lane matched, vmaxvq_u8 returns 0.
        // SAFETY: `combined` is a valid `uint8x16_t`.
        if unsafe { vmaxvq_u8(combined) } != 0 {
            // SAFETY: `combined` contains 0x00 or 0xFF per lane.
            let bit_offset = unsafe { neon_first_match(combined)? };
            return offset.checked_add(bit_offset);
        }
        offset = offset.checked_add(LANE)?;
    }

    let tail = haystack.get(offset..)?;
    crate::generic::find(tail).and_then(|pos| offset.checked_add(pos))
}

/// Classify 16 bytes, returning a mask vector (0xFF in matching lanes).
///
/// # Safety
///
/// Requires NEON. All arguments must be valid `uint8x16_t` values.
#[expect(unsafe_code, reason = "NEON intrinsics require unsafe")]
#[inline(always)]
unsafe fn classify(
    chunk: uint8x16_t,
    v_quote: uint8x16_t,
    v_backslash: uint8x16_t,
    v_ctrl_bound: uint8x16_t,
) -> uint8x16_t {
    // SAFETY: all intrinsics are NEON baseline, caller ensures valid vectors.
    unsafe {
        let m_quote = vceqq_u8(chunk, v_quote);
        let m_backslash = vceqq_u8(chunk, v_backslash);
        // `vcltq_u8` is unsigned less-than, directly available on NEON.
        let m_control = vcltq_u8(chunk, v_ctrl_bound);
        vorrq_u8(vorrq_u8(m_quote, m_backslash), m_control)
    }
}

/// Extract the byte offset of the first set lane from a NEON mask vector.
///
/// Uses the same movemask emulation as the `memchr` crate: narrow pairs via
/// `vshrn_n_u16`, extract as a scalar, and count trailing zeros of the sparse
/// bitmask.
///
/// # Safety
///
/// Requires NEON. `combined` must contain 0x00 or 0xFF per lane.
#[expect(unsafe_code, reason = "NEON movemask emulation")]
#[inline(always)]
unsafe fn neon_first_match(combined: uint8x16_t) -> Option<usize> {
    // SAFETY: all intrinsics are NEON baseline, `combined` is a valid mask.
    let scalar = unsafe {
        let narrowed = vshrn_n_u16(vreinterpretq_u16_u8(combined), 4);
        vget_lane_u64(vreinterpret_u64_u8(narrowed), 0)
    };
    // Only bit 3 of each nibble survives (0x8 per nibble position).
    let bits = scalar & 0x8888_8888_8888_8888;
    if bits == 0 {
        return None;
    }
    // Each nibble represents one byte lane; trailing_zeros / 4 = lane index.
    let tz = bits.trailing_zeros();
    let lane = tz.checked_div(4)?;
    usize::try_from(lane).ok()
}
