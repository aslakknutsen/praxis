// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HMAC computation and constant-time comparison helpers.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::FilterError;

// -----------------------------------------------------------------------------
// HMAC
// -----------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Compute HMAC-SHA256 over `message`.
///
/// # Errors
///
/// Returns [`FilterError`] if the HMAC key is rejected by the underlying library.
pub(crate) fn hmac_sha256(secret: &[u8], message: &[u8]) -> Result<[u8; 32], FilterError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| -> FilterError { format!("signature: HMAC-SHA256 init failed: {e}").into() })?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Compute HMAC-SHA1 over `message` (GitHub legacy webhook header only).
///
/// # Errors
///
/// Returns [`FilterError`] if the HMAC key is rejected by the underlying library.
pub(crate) fn hmac_sha1(secret: &[u8], message: &[u8]) -> Result<[u8; 20], FilterError> {
    let mut mac = HmacSha1::new_from_slice(secret)
        .map_err(|e| -> FilterError { format!("signature: HMAC-SHA1 init failed: {e}").into() })?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time equality check for two byte slices.
#[must_use]
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

// -----------------------------------------------------------------------------
// Encoding
// -----------------------------------------------------------------------------

/// Decode a lowercase/uppercase hex string into bytes.
#[must_use]
pub(crate) fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(2) {
        return None;
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as lowercase hex.
#[cfg(test)]
#[must_use]
pub(crate) fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode standard base64 into bytes.
#[must_use]
pub(crate) fn decode_base64(input: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(input).ok()
}
