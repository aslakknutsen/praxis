// Derived from nosj v0.2.0 src/scalars.rs (MIT, Copyright (c) 2026 Yaroslav Markin).

//! Find the next `"`, `\`, or control byte in a JSON string body.

use crate::simd;

/// Scalar reference loop for [`find_special_impl`].
#[inline(always)]
fn find_special_scalar(input: &[u8], mut from: usize) -> Option<(usize, u8)> {
    while from < input.len() {
        let b = input[from];
        if b == b'"' || b == b'\\' || b < 0x20 {
            return Some((from, b));
        }
        from += 1;
    }
    None
}

/// Find the next `"`, `\`, or control character (`< 0x20`) at or after `from`.
///
/// SIMD-accelerated on aarch64 and x86_64; scalar fallback elsewhere.
#[inline(always)]
pub(crate) fn find_special_impl(input: &[u8], mut from: usize) -> Option<(usize, u8)> {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: every 16-byte load has `offset + 16 <= input.len()`; tail loads at `len - 16`.
    unsafe {
        use std::arch::aarch64::{vld1q_u8, vmaxvq_u8, vorrq_u8};

        if from + 16 <= input.len() {
            let mask = simd::neon::hit_mask(vld1q_u8(input.as_ptr().add(from)));
            if mask != 0 {
                let i = from + (mask.trailing_zeros() as usize) / 4;
                return Some((i, input[i]));
            }
            from += 16;
        }

        while from + 32 <= input.len() {
            let h0 = simd::neon::hit_vec(vld1q_u8(input.as_ptr().add(from)));
            let h1 = simd::neon::hit_vec(vld1q_u8(input.as_ptr().add(from + 16)));
            if vmaxvq_u8(vorrq_u8(h0, h1)) == 0 {
                from += 32;
                continue;
            }
            let m0 = simd::neon::nib_mask(h0);
            let i = if m0 != 0 {
                from + (m0.trailing_zeros() as usize) / 4
            } else {
                from + 16 + (simd::neon::nib_mask(h1).trailing_zeros() as usize) / 4
            };
            return Some((i, input[i]));
        }
        while from + 16 <= input.len() {
            let mask = simd::neon::hit_mask(vld1q_u8(input.as_ptr().add(from)));
            if mask != 0 {
                let i = from + (mask.trailing_zeros() as usize) / 4;
                return Some((i, input[i]));
            }
            from += 16;
        }

        if from < input.len() && input.len() >= 16 {
            return simd::neon::tail_find(input, from).map(|i| (i, input[i]));
        }
    }

    #[cfg(target_arch = "x86_64")]
    // SAFETY: same bounds argument as the aarch64 block.
    unsafe {
        use std::arch::x86_64::_mm_loadu_si128;

        if std::arch::is_x86_feature_detected!("avx2") {
            return find_special_avx2(input, from);
        }
        while from + 16 <= input.len() {
            let mask = simd::x86::sse2_hit_mask(_mm_loadu_si128(input.as_ptr().add(from).cast()));
            if mask != 0 {
                let i = from + mask.trailing_zeros() as usize;
                return Some((i, input[i]));
            }
            from += 16;
        }
        if from < input.len() && input.len() >= 16 {
            return simd::x86::sse2_tail_find(input, from).map(|i| (i, input[i]));
        }
    }

    find_special_scalar(input, from)
}

/// AVX2 variant of [`find_special_impl`]: 32 bytes per step.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn find_special_avx2(input: &[u8], mut from: usize) -> Option<(usize, u8)> {
    // SAFETY: every 32-byte load has `offset + 32 <= input.len()`; AVX2 checked by caller.
    unsafe {
        use std::arch::x86_64::_mm256_loadu_si256;

        while from + 32 <= input.len() {
            let mask = simd::x86::avx2_hit_mask(_mm256_loadu_si256(input.as_ptr().add(from).cast()));
            if mask != 0 {
                let i = from + mask.trailing_zeros() as usize;
                return Some((i, input[i]));
            }
            from += 32;
        }
        if from < input.len() && input.len() >= 32 {
            return simd::x86::avx2_tail_find(input, from).map(|i| (i, input[i]));
        }
        find_special_scalar(input, from)
    }
}
