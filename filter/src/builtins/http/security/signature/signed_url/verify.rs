// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Signed URL verification logic.

use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use http::Uri;

use super::config::{MessagePart, SignedUrlConfig, SignatureAlgorithm, SignatureEncoding, UriSource};
use crate::builtins::http::transformation::normalize_rewritten_path;
use crate::FilterError;

use crate::builtins::http::security::signature::{
    hmac::{constant_time_eq, decode_hex, hmac_sha256},
    signed_url::canonical::{build_signed_url_message, split_path_query},
};

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Successful signed URL verification output.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedUrl {
    /// Rewritten upstream path with signature params stripped, if requested.
    pub stripped_path: Option<String>,
}

/// Client-visible signed URL verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedUrlError {
    /// Required query parameter missing.
    MissingParam,

    /// Timestamp or expiry could not be parsed.
    ParseError,

    /// Link expired (absolute expiry or max age exceeded).
    Expired,

    /// Timestamp is too far in the future.
    FutureTimestamp,

    /// Signature encoding invalid.
    InvalidEncoding,

    /// Signature mismatch.
    InvalidSignature,
}

// -----------------------------------------------------------------------------
// verify_signed_url
// -----------------------------------------------------------------------------

/// Verify a signed URL against the configured secret and URI.
///
/// # Errors
///
/// Returns [`FilterError`] only for internal/crypto failures. Client auth
/// failures are returned as [`SignedUrlError`].
pub(crate) fn verify_signed_url(
    cfg: &SignedUrlConfig,
    secret: &[u8],
    uri: &Uri,
    rewritten_path: Option<&str>,
    now: SystemTime,
) -> Result<Result<VerifiedUrl, SignedUrlError>, FilterError> {
    if cfg.algorithm != SignatureAlgorithm::Sha256 {
        return Err("signed_url: v1 supports sha256 only".into());
    }
    if cfg.message.encoding != SignatureEncoding::Hex {
        return Err("signed_url: v1 supports hex encoding only".into());
    }

    let query = uri.query().unwrap_or("");
    let params = parse_query_pairs(query);

    let Some(signature) = params.get(&cfg.signature_param) else {
        return Ok(Err(SignedUrlError::MissingParam));
    };

    let expiry = match cfg.expiry_param.as_ref().and_then(|name| params.get(name)) {
        Some(value) => {
            let Ok(parsed) = parse_u64(value) else {
                return Ok(Err(SignedUrlError::ParseError));
            };
            Some(parsed)
        },
        None => None,
    };

    let timestamp_required = cfg.expiry_param.is_none();
    let timestamp = if timestamp_required {
        let Some(raw_ts) = params.get(&cfg.timestamp_param) else {
            return Ok(Err(SignedUrlError::MissingParam));
        };
        let Ok(parsed) = raw_ts.parse::<u64>() else {
            return Ok(Err(SignedUrlError::ParseError));
        };
        Some(parsed)
    } else {
        match params.get(&cfg.timestamp_param) {
            Some(raw_ts) => {
                let Ok(parsed) = raw_ts.parse::<u64>() else {
                    return Ok(Err(SignedUrlError::ParseError));
                };
                Some(parsed)
            },
            None => None,
        }
    };

    if cfg.expiry_param.is_some() && expiry.is_none() {
        return Ok(Err(SignedUrlError::MissingParam));
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| -> FilterError { format!("signed_url: system time before Unix epoch: {e}").into() })?
        .as_secs();

    if let Some(exp) = expiry {
        if now_secs > exp.saturating_add(cfg.clock_skew_seconds) {
            return Ok(Err(SignedUrlError::Expired));
        }
    }

    if let Some(ts) = timestamp {
        if now_secs.saturating_add(cfg.clock_skew_seconds) < ts {
            return Ok(Err(SignedUrlError::FutureTimestamp));
        }

        if expiry.is_none() {
            let max_age = cfg.max_age_seconds.ok_or_else(|| {
                FilterError::from("signed_url: max_age_seconds required when expiry_param is absent")
            })?;
            if now_secs.saturating_sub(ts) > max_age.saturating_add(cfg.clock_skew_seconds) {
                return Ok(Err(SignedUrlError::Expired));
            }
        }
    }

    let message = build_signed_url_message(cfg, uri, rewritten_path, timestamp, expiry);
    let expected = hmac_sha256(secret, &message)?;

    let Some(provided) = decode_hex(signature) else {
        return Ok(Err(SignedUrlError::InvalidEncoding));
    };
    if provided.len() != expected.len() || !constant_time_eq(&provided, &expected) {
        return Ok(Err(SignedUrlError::InvalidSignature));
    }

    let stripped_path = if cfg.strip_params {
        Some(strip_signature_params(cfg, uri, rewritten_path)?)
    } else {
        None
    };

    Ok(Ok(VerifiedUrl { stripped_path }))
}

fn parse_u64(value: &str) -> Result<u64, ()> {
    value.parse::<u64>().map_err(|_| ())
}

fn parse_query_pairs(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if query.is_empty() {
        return map;
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(key.to_owned(), value.to_owned());
    }
    map
}

fn strip_signature_params(
    cfg: &SignedUrlConfig,
    uri: &Uri,
    rewritten_path: Option<&str>,
) -> Result<String, FilterError> {
    let path = match cfg.uri_source {
        UriSource::Client => uri.path(),
        UriSource::Rewritten => rewritten_path
            .map(|p| split_path_query(p).0)
            .unwrap_or_else(|| uri.path()),
    };

    let normalized = normalize_rewritten_path(path);
    let path_str = normalized.as_ref();

    let query = uri.query().unwrap_or("");
    if query.is_empty() {
        return Ok(path_str.to_owned());
    }

    let mut remove = HashSet::new();
    remove.insert(cfg.signature_param.clone());
    remove.insert(cfg.timestamp_param.clone());
    if let Some(ref exp) = cfg.expiry_param {
        remove.insert(exp.clone());
    }

    let remaining: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            !remove.contains(key)
        })
        .collect();

    if remaining.is_empty() {
        Ok(path_str.to_owned())
    } else {
        Ok(format!("{path_str}?{}", remaining.join("&")))
    }
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate parsed config beyond serde defaults.
///
/// # Errors
///
/// Returns [`FilterError`] when required fields or message parts are invalid.
pub(super) fn validate_signed_url_config(cfg: &SignedUrlConfig) -> Result<(), FilterError> {
    if cfg.expiry_param.is_none() && cfg.max_age_seconds.is_none() {
        return Err("signed_url: 'max_age_seconds' is required when 'expiry_param' is absent".into());
    }

    if cfg.message.parts.is_empty() {
        return Err("signed_url: message.parts must not be empty".into());
    }

    for part in &cfg.message.parts {
        if *part == MessagePart::Expiry && cfg.expiry_param.is_none() {
            return Err("signed_url: message part 'expiry' requires 'expiry_param'".into());
        }
    }

    Ok(())
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
        hmac::encode_hex_lower,
        secret::SecretFields,
        signed_url::config::{MessageConfig, UriSource},
    };

    fn test_config(secret: &str) -> (SignedUrlConfig, Vec<u8>) {
        let cfg = SignedUrlConfig {
            secret: SecretFields {
                secret: Some(secret.to_owned()),
                secret_env_var: None,
            },
            algorithm: SignatureAlgorithm::Sha256,
            signature_param: "sig".to_owned(),
            timestamp_param: "ts".to_owned(),
            expiry_param: None,
            max_age_seconds: Some(3600),
            clock_skew_seconds: 30,
            message: MessageConfig {
                parts: vec![MessagePart::Path, MessagePart::Timestamp],
                separator: "\n".to_owned(),
                encoding: SignatureEncoding::Hex,
            },
            uri_source: UriSource::Client,
            strip_params: true,
            reject_status: 403,
            reject_status_expired: 410,
        };
        (cfg, secret.as_bytes().to_vec())
    }

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    #[test]
    fn verify_valid_signed_url() {
        let (cfg, secret) = test_config("test-secret");
        let ts = now_ts();
        let path = "/resource";
        let message = format!("{path}\n{ts}");
        let digest = hmac_sha256(&secret, message.as_bytes()).expect("hmac");
        let sig = encode_hex_lower(&digest);
        let uri: Uri = format!("{path}?ts={ts}&sig={sig}").parse().expect("uri");

        let result = verify_signed_url(&cfg, &secret, &uri, None, SystemTime::now()).expect("verify");
        assert!(result.is_ok(), "expected valid signature");
    }

    #[test]
    fn verify_rejects_expired_by_max_age() {
        let (cfg, secret) = test_config("test-secret");
        let ts = now_ts().saturating_sub(7200);
        let path = "/resource";
        let message = format!("{path}\n{ts}");
        let digest = hmac_sha256(&secret, message.as_bytes()).expect("hmac");
        let sig = encode_hex_lower(&digest);
        let uri: Uri = format!("{path}?ts={ts}&sig={sig}").parse().expect("uri");

        let result = verify_signed_url(&cfg, &secret, &uri, None, SystemTime::now()).expect("verify");
        assert_eq!(result, Err(SignedUrlError::Expired));
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let (cfg, secret) = test_config("test-secret");
        let ts = now_ts();
        let uri: Uri = format!("/resource?ts={ts}&sig=deadbeef").parse().expect("uri");

        let result = verify_signed_url(&cfg, &secret, &uri, None, SystemTime::now()).expect("verify");
        assert_eq!(result, Err(SignedUrlError::InvalidSignature));
    }
}
