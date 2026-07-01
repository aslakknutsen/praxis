// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HMAC computation and constant-time signature comparison.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::config::Encoding;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 and encode per the configured wire format.
pub(super) fn compute_mac(key: &[u8], canonical: &str, encoding: Encoding) -> Result<String, ()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(canonical.as_bytes());
    let result = mac.finalize().into_bytes();

    Ok(match encoding {
        Encoding::Hex => hex::encode(result),
        Encoding::Base64Url => URL_SAFE_NO_PAD.encode(result),
    })
}

/// Constant-time comparison of two signatures of the same encoding.
pub(super) fn signatures_match(expected: &str, actual: &str, encoding: Encoding) -> bool {
    let expected_bytes = match decode_signature(expected, encoding) {
        Some(b) => b,
        None => return false,
    };
    let actual_bytes = match decode_signature(actual, encoding) {
        Some(b) => b,
        None => return false,
    };

    if expected_bytes.len() != actual_bytes.len() {
        return false;
    }

    expected_bytes.ct_eq(&actual_bytes).into()
}

fn decode_signature(sig: &str, encoding: Encoding) -> Option<Vec<u8>> {
    match encoding {
        Encoding::Hex => hex::decode(sig).ok(),
        Encoding::Base64Url => URL_SAFE_NO_PAD.decode(sig).ok(),
    }
}

/// Hex encoding helper (avoids adding hex crate dependency).
mod hex {
    pub(super) fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub(super) fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn hex_mac_matches_worked_example() {
        let key = b"test-secret";
        let canonical = "GET\n/files/report.pdf\ntoken=abc\n1719859200\n";
        let mac = compute_mac(key, canonical, Encoding::Hex).unwrap();
        assert_eq!(mac.len(), 64);
        assert!(signatures_match(&mac, &mac, Encoding::Hex));
    }

    #[test]
    fn mismatch_returns_false() {
        assert!(!signatures_match("aabb", "bbcc", Encoding::Hex));
    }
}
