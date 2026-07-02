// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HMAC signature dialect parsing and verification.

use std::sync::Once;

use super::config::{DialectKind, HmacVerifyConfig, SignatureAlgorithm};
use crate::FilterError;

use crate::builtins::http::security::signature::hmac::{
    constant_time_eq, decode_base64, decode_hex, hmac_sha1, hmac_sha256,
};

// -----------------------------------------------------------------------------
// ResolvedDialect
// -----------------------------------------------------------------------------

/// Resolved dialect settings used at runtime.
#[derive(Debug, Clone)]
pub(super) struct ResolvedDialect {
    /// Header name to read.
    pub header_name: String,

    /// Dialect kind.
    pub kind: DialectKind,

    /// When true, GitHub legacy SHA1 HMAC is used.
    pub github_legacy_sha1: bool,
}

// -----------------------------------------------------------------------------
// Dialect Resolution
// -----------------------------------------------------------------------------

static LEGACY_SHA1_WARN: Once = Once::new();

/// Resolve dialect defaults and emit one-time warnings.
pub(super) fn resolve_dialect(cfg: &HmacVerifyConfig) -> Result<ResolvedDialect, FilterError> {
    let (default_header, github_legacy_sha1) = match cfg.dialect {
        DialectKind::Github => {
            let header = cfg.header.as_deref().unwrap_or("X-Hub-Signature-256");
            let legacy = header.eq_ignore_ascii_case("X-Hub-Signature");
            if legacy {
                LEGACY_SHA1_WARN.call_once(|| {
                    tracing::warn!(
                        "hmac_verify: X-Hub-Signature (SHA1) is deprecated; prefer X-Hub-Signature-256"
                    );
                });
            }
            (header.to_owned(), legacy)
        },
        DialectKind::RawHex | DialectKind::RawBase64 => {
            let header = cfg
                .header
                .clone()
                .ok_or_else(|| FilterError::from("hmac_verify: 'header' is required for raw_hex/raw_base64 dialects"))?;
            (header, false)
        },
    };

    Ok(ResolvedDialect {
        header_name: default_header,
        kind: cfg.dialect,
        github_legacy_sha1,
    })
}

// -----------------------------------------------------------------------------
// Signature Parsing
// -----------------------------------------------------------------------------

/// Client-visible signature parse/verify failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignatureError {
    /// Header missing or empty.
    Missing,

    /// Prefix or encoding invalid.
    Malformed,
}

/// Parse and verify an HMAC signature over `body`.
///
/// # Errors
///
/// Returns [`FilterError`] for internal crypto failures. Client auth failures
/// are returned as [`SignatureError`].
pub(super) fn verify_body_signature(
    cfg: &HmacVerifyConfig,
    dialect: &ResolvedDialect,
    header_value: Option<&str>,
    body: &[u8],
    secret: &[u8],
) -> Result<Result<(), SignatureError>, FilterError> {
    let Some(raw_header) = header_value.filter(|s| !s.is_empty()) else {
        return Ok(Err(SignatureError::Missing));
    };

    let provided = match dialect.kind {
        DialectKind::Github => match parse_github_signature(raw_header, dialect.github_legacy_sha1) {
            Ok(bytes) => bytes,
            Err(err) => return Ok(Err(err)),
        },
        DialectKind::RawHex => {
            let Some(bytes) = decode_hex(raw_header) else {
                return Ok(Err(SignatureError::Malformed));
            };
            bytes
        },
        DialectKind::RawBase64 => {
            let Some(bytes) = decode_base64(raw_header) else {
                return Ok(Err(SignatureError::Malformed));
            };
            bytes
        },
    };

    let expected = compute_digest(cfg, dialect, secret, body)?;

    if provided.len() != expected.len() || !constant_time_eq(&provided, &expected) {
        return Ok(Err(SignatureError::Malformed));
    }

    Ok(Ok(()))
}

fn parse_github_signature(value: &str, legacy_sha1: bool) -> Result<Vec<u8>, SignatureError> {
    if legacy_sha1 {
        let Some(digest) = value.strip_prefix("sha1=") else {
            return Err(SignatureError::Malformed);
        };
        return decode_hex(digest).ok_or(SignatureError::Malformed);
    }

    let Some(digest) = value.strip_prefix("sha256=") else {
        return Err(SignatureError::Malformed);
    };
    decode_hex(digest).ok_or(SignatureError::Malformed)
}

fn compute_digest(
    cfg: &HmacVerifyConfig,
    dialect: &ResolvedDialect,
    secret: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, FilterError> {
    if dialect.github_legacy_sha1 {
        return Ok(hmac_sha1(secret, body)?.to_vec());
    }

    if cfg.algorithm != SignatureAlgorithm::Sha256 {
        return Err("hmac_verify: v1 supports sha256 only".into());
    }

    Ok(hmac_sha256(secret, body)?.to_vec())
}

/// Format a GitHub-style signature for tests.
#[cfg(test)]
#[must_use]
pub(super) fn github_signature(secret: &[u8], body: &[u8]) -> String {
    use crate::builtins::http::security::signature::hmac::encode_hex_lower;

    let digest = hmac_sha256(secret, body).expect("hmac");
    format!("sha256={}", encode_hex_lower(&digest))
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
    use crate::builtins::http::security::signature::{
        hmac_verify::config::HmacVerifyConfig,
        secret::SecretFields,
    };

    fn github_cfg() -> HmacVerifyConfig {
        HmacVerifyConfig {
            secret: SecretFields {
                secret: Some("webhook-secret".to_owned()),
                secret_env_var: None,
            },
            dialect: DialectKind::Github,
            header: None,
            algorithm: SignatureAlgorithm::Sha256,
            max_body_bytes: 1024,
            reject_status: 401,
            strip_header: true,
        }
    }

    #[test]
    fn github_valid_signature() {
        let cfg = github_cfg();
        let dialect = resolve_dialect(&cfg).expect("dialect");
        let secret = b"webhook-secret";
        let body = br#"{"action":"opened"}"#;
        let header = github_signature(secret, body);

        let result =
            verify_body_signature(&cfg, &dialect, Some(&header), body, secret).expect("verify");
        assert!(result.is_ok());
    }

    #[test]
    fn github_rejects_wrong_prefix_on_256_header() {
        let cfg = github_cfg();
        let dialect = resolve_dialect(&cfg).expect("dialect");
        let secret = b"webhook-secret";
        let body = b"payload";

        let result = verify_body_signature(&cfg, &dialect, Some("sha1=abcd"), body, secret).expect("verify");
        assert_eq!(result, Err(SignatureError::Malformed));
    }
}
