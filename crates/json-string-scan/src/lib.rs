// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fused SIMD scan for JSON string special bytes (`"`, `\`, controls).

mod find_special;
mod simd;

/// Find the next `"`, `\`, or unescaped control byte (`0x00..=0x1F`) at or after `from`.
#[inline]
pub fn find_special(input: &[u8], from: usize) -> Option<(usize, u8)> {
    find_special::find_special_impl(input, from)
}

#[cfg(test)]
mod tests {
    use super::find_special;

    #[test]
    fn finds_closing_quote() {
        let input = b"hello\"";
        assert_eq!(find_special(input, 0), Some((5, b'"')));
    }

    #[test]
    fn finds_backslash() {
        let input = b"he\\llo";
        assert_eq!(find_special(input, 0), Some((2, b'\\')));
    }

    #[test]
    fn finds_raw_control() {
        let input = b"he\x01llo";
        assert_eq!(find_special(input, 0), Some((2, 0x01)));
    }

    #[test]
    fn finds_control_past_vector_width() {
        let mut input = vec![b'a'; 32];
        input.push(0x01);
        input.push(b'b');
        assert_eq!(find_special(&input, 0), Some((32, 0x01)));
    }

    #[test]
    fn none_when_clean() {
        let input = b"hello";
        assert_eq!(find_special(input, 0), None);
    }
}
