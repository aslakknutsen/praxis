// Derived from nosj v0.2.0 src/scan.rs (MIT, Copyright (c) 2026 Yaroslav Markin).
// Stripped to MODE_STANDARD only: `"`, `\`, and bytes below 0x20.

//! SIMD primitives for the JSON string special-byte predicate.

#[cfg(target_arch = "aarch64")]
pub(crate) mod neon {
    use std::arch::aarch64::{
        uint8x16_t, vceqq_u8, vcltq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vorrq_u8, vreinterpret_u64_u8,
        vreinterpretq_u16_u8, vshrn_n_u16,
    };

    #[inline(always)]
    pub(crate) unsafe fn hit_vec(v: uint8x16_t) -> uint8x16_t {
        // SAFETY: register-only NEON on aarch64.
        unsafe {
            vorrq_u8(
                vorrq_u8(vceqq_u8(v, vdupq_n_u8(b'"')), vceqq_u8(v, vdupq_n_u8(b'\\'))),
                vcltq_u8(v, vdupq_n_u8(0x20)),
            )
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn nib_mask(hit: uint8x16_t) -> u64 {
        // SAFETY: register-only NEON on aarch64.
        unsafe { vget_lane_u64::<0>(vreinterpret_u64_u8(vshrn_n_u16::<4>(vreinterpretq_u16_u8(hit)))) }
    }

    #[inline(always)]
    pub(crate) unsafe fn hit_mask(v: uint8x16_t) -> u64 {
        // SAFETY: register-only composition.
        unsafe { nib_mask(hit_vec(v)) }
    }

    #[inline(always)]
    pub(crate) fn tail_find(input: &[u8], from: usize) -> Option<usize> {
        let back = input.len().checked_sub(16)?;
        debug_assert!(from > back && from < input.len());
        // SAFETY: `back + 16 == input.len()`.
        let mask = unsafe { hit_mask(vld1q_u8(input.as_ptr().add(back))) } & (u64::MAX << (4 * (from - back)));
        if mask == 0 {
            None
        } else {
            Some(back + (mask.trailing_zeros() as usize) / 4)
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86 {
    use std::arch::x86_64::{
        __m128i, __m256i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_min_epu8, _mm_movemask_epi8, _mm_or_si128,
        _mm_set1_epi8, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_min_epu8, _mm256_movemask_epi8, _mm256_or_si256,
        _mm256_set1_epi8,
    };

    #[inline(always)]
    pub(crate) unsafe fn sse2_hit_mask(v: __m128i) -> u32 {
        // SAFETY: register-only SSE2 on x86_64.
        unsafe {
            let is_ctrl = _mm_cmpeq_epi8(_mm_min_epu8(v, _mm_set1_epi8(0x1F)), v);
            _mm_movemask_epi8(_mm_or_si128(
                _mm_or_si128(
                    _mm_cmpeq_epi8(v, _mm_set1_epi8(b'"' as i8)),
                    _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\\' as i8)),
                ),
                is_ctrl,
            )) as u32
        }
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(crate) unsafe fn avx2_hit_mask(v: __m256i) -> u32 {
        let is_ctrl = _mm256_cmpeq_epi8(_mm256_min_epu8(v, _mm256_set1_epi8(0x1F)), v);
        _mm256_movemask_epi8(_mm256_or_si256(
            _mm256_or_si256(
                _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'"' as i8)),
                _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'\\' as i8)),
            ),
            is_ctrl,
        )) as u32
    }

    #[inline(always)]
    pub(crate) fn sse2_tail_find(input: &[u8], from: usize) -> Option<usize> {
        let back = input.len().checked_sub(16)?;
        debug_assert!(from > back && from < input.len());
        // SAFETY: `back + 16 == input.len()`.
        let mask =
            unsafe { sse2_hit_mask(_mm_loadu_si128(input.as_ptr().add(back).cast())) } & (u32::MAX << (from - back));
        if mask == 0 {
            None
        } else {
            Some(back + mask.trailing_zeros() as usize)
        }
    }

    #[target_feature(enable = "avx2")]
    #[inline]
    pub(crate) fn avx2_tail_find(input: &[u8], from: usize) -> Option<usize> {
        let back = input.len().checked_sub(32)?;
        debug_assert!(from > back && from < input.len());
        // SAFETY: `back + 32 == input.len()`.
        let mask =
            unsafe { avx2_hit_mask(_mm256_loadu_si256(input.as_ptr().add(back).cast())) } & (u32::MAX << (from - back));
        if mask == 0 {
            None
        } else {
            Some(back + mask.trailing_zeros() as usize)
        }
    }
}
