// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! [`UrlSignFilter`] implementation and `HttpFilter` trait impl.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tracing::{debug, trace};

use super::{
    canonical::{CanonicalInputs, build_canonical_input},
    config::{
        Algorithm, Encoding, ExpiresConfig, KeyedSecretConfig, Placement, SecretSourceConfig, UrlSignConfig,
    },
    extract::{ExtractedSignature, extract_from_request},
    path::sanitize_resource_path,
    verify::{compute_mac, signatures_match},
};
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// ResolvedSecretStore
// -----------------------------------------------------------------------------

struct ResolvedSecretStore {
    default_key: Option<Vec<u8>>,
    keyed: HashMap<String, Vec<u8>>,
}

impl ResolvedSecretStore {
    fn resolve_key(&self, key_id: Option<&str>) -> Option<&[u8]> {
        match key_id {
            Some(id) => self.keyed.get(id).map(Vec::as_slice),
            None => self.default_key.as_deref(),
        }
    }
}

// -----------------------------------------------------------------------------
// UrlSignFilter
// -----------------------------------------------------------------------------

/// Validates HMAC-signed URLs at the edge.
///
/// Rejects missing, malformed, expired, or invalid signatures with
/// HTTP 403. Does not generate signed links.
pub struct UrlSignFilter {
    secrets: ResolvedSecretStore,
    placement: Placement,
    signature_param: String,
    expires_param: String,
    key_id_param: Option<String>,
    path_prefix: Option<String>,
    expires: ExpiresConfig,
    encoding: Encoding,
    strip_signature: bool,
    canonical: super::config::CanonicalConfig,
}

impl UrlSignFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when configuration or secret resolution fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self::try_from_config(config)?))
    }

    fn try_from_config(config: &serde_yaml::Value) -> Result<Self, FilterError> {
        let cfg: UrlSignConfig = parse_filter_config("url_sign", config)?;
        validate_config(&cfg)?;

        let secrets = resolve_secrets(&cfg)?;
        if secrets.default_key.is_none() && secrets.keyed.is_empty() {
            return Err("url_sign: no signing secrets configured".into());
        }

        Ok(Self {
            secrets,
            placement: cfg.placement,
            signature_param: cfg.signature_param,
            expires_param: cfg.expires_param,
            key_id_param: cfg.key_id_param,
            path_prefix: cfg.path_prefix,
            expires: cfg.expires,
            encoding: cfg.encoding,
            strip_signature: cfg.strip_signature,
            canonical: cfg.canonical,
        })
    }

    fn reject(reason: &'static str) -> FilterAction {
        trace!(reason, "url_sign: rejecting request");
        FilterAction::Reject(Rejection::status(403))
    }

    fn verify_request(&self, ctx: &HttpFilterContext<'_>, extracted: &ExtractedSignature<'_>) -> FilterAction {
        let expires_str = extracted.expires.unwrap_or("");
        if self.expires.required && (expires_str.is_empty() || !is_valid_expires(expires_str)) {
            debug!("url_sign: missing or invalid expires");
            return Self::reject("invalid_expires");
        }

        if !expires_str.is_empty()
            && check_expiry(expires_str, self.expires.clock_skew_secs).is_err()
        {
            debug!("url_sign: expired URL");
            return Self::reject("expired");
        }

        let key = match self.secrets.resolve_key(extracted.key_id) {
            Some(k) => k,
            None => {
                debug!("url_sign: unknown key id");
                return Self::reject("unknown_key_id");
            },
        };

        let canonical_inputs = CanonicalInputs {
            method: &ctx.request.method,
            uri: &ctx.request.uri,
            headers: &ctx.request.headers,
            placement: self.placement,
            canonical: &self.canonical,
            signature_param: &self.signature_param,
            expires_param: &self.expires_param,
            key_id_param: self.key_id_param.as_deref(),
            expires: expires_str,
            resource_path_raw: extracted.resource_path_raw,
        };

        let canonical = match build_canonical_input(&canonical_inputs) {
            Ok(c) => c,
            Err(()) => {
                debug!("url_sign: canonical input/path sanitization failed");
                return Self::reject("path_sanitization_failed");
            },
        };

        trace!(canonical, "url_sign: built canonical input");

        let expected = match compute_mac(key, &canonical, self.encoding) {
            Ok(v) => v,
            Err(()) => {
                debug!("url_sign: HMAC computation failed");
                return Self::reject("hmac_failed");
            },
        };

        if !signatures_match(&expected, extracted.signature, self.encoding) {
            debug!("url_sign: signature mismatch");
            return Self::reject("signature_mismatch");
        }

        FilterAction::Continue
    }
}

#[async_trait]
impl HttpFilter for UrlSignFilter {
    fn name(&self) -> &'static str {
        "url_sign"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let extracted = match extract_from_request(
            &ctx.request.uri,
            self.placement,
            self.path_prefix.as_deref(),
            &self.signature_param,
            &self.expires_param,
            self.key_id_param.as_deref(),
            self.encoding,
        ) {
            Some(v) => v,
            None => {
                debug!("url_sign: missing or malformed signature parameters");
                return Ok(Self::reject("missing_or_malformed"));
            },
        };

        let action = self.verify_request(ctx, &extracted);
        if !matches!(action, FilterAction::Continue) {
            return Ok(action);
        }

        if self.placement == Placement::Path
            && self.strip_signature
            && let Some(raw) = extracted.resource_path_raw
        {
            match sanitize_resource_path(raw) {
                Ok(clean) => {
                    trace!(rewritten_path = %clean, "url_sign: stripped signature path");
                    ctx.rewritten_path = Some(clean);
                },
                Err(()) => {
                    debug!("url_sign: rewritten path sanitization failed");
                    return Ok(Self::reject("rewritten_path_failed"));
                },
            }
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Config Validation & Secret Resolution
// -----------------------------------------------------------------------------

fn validate_config(cfg: &UrlSignConfig) -> Result<(), FilterError> {
    if cfg.algorithm != Algorithm::HmacSha256 {
        return Err("url_sign: only algorithm 'hmac-sha256' is supported".into());
    }

    let has_single = cfg.secret.is_some();
    let has_multi = cfg
        .secrets
        .as_ref()
        .is_some_and(|s| !s.is_empty());

    if has_single == has_multi {
        return Err(
            "url_sign: configure exactly one of 'secret' or non-empty 'secrets'".into(),
        );
    }

    if cfg.placement == Placement::Path {
        let Some(prefix) = cfg.path_prefix.as_deref() else {
            return Err("url_sign: 'path_prefix' is required when placement is 'path'".into());
        };
        if !prefix.starts_with('/') {
            return Err("url_sign: 'path_prefix' must start with '/'".into());
        }
    }

    Ok(())
}

fn resolve_secrets(cfg: &UrlSignConfig) -> Result<ResolvedSecretStore, FilterError> {
    if let Some(secret) = &cfg.secret {
        let bytes = resolve_secret_source(secret, "secret")?;
        return Ok(ResolvedSecretStore {
            default_key: Some(bytes),
            keyed: HashMap::new(),
        });
    }

    let mut keyed = HashMap::new();
    for entry in cfg.secrets.as_ref().expect("validated above") {
        let bytes = resolve_keyed_secret(entry)?;
        keyed.insert(entry.id.clone(), bytes);
    }

    Ok(ResolvedSecretStore {
        default_key: None,
        keyed,
    })
}

fn resolve_secret_source(source: &SecretSourceConfig, label: &str) -> Result<Vec<u8>, FilterError> {
    let raw = match (&source.value, &source.env_var) {
        (Some(val), None) => {
            tracing::warn!(
                "url_sign: inline secret value for '{label}' is intended for dev/test only"
            );
            val.clone()
        },
        (None, Some(var)) => std::env::var(var).map_err(|e| -> FilterError {
            format!("url_sign: environment variable '{var}' not set for {label}: {e}").into()
        })?,
        (Some(_), Some(_)) => {
            return Err(format!(
                "url_sign: {label} has both 'value' and 'env_var' (use exactly one)"
            )
            .into());
        },
        (None, None) => {
            return Err(format!("url_sign: {label} must have either 'value' or 'env_var'").into());
        },
    };

    if raw.is_empty() {
        return Err(format!("url_sign: {label} secret must not be empty").into());
    }

    Ok(raw.into_bytes())
}

fn resolve_keyed_secret(entry: &KeyedSecretConfig) -> Result<Vec<u8>, FilterError> {
    let source = SecretSourceConfig {
        value: entry.value.clone(),
        env_var: entry.env_var.clone(),
    };
    resolve_secret_source(&source, &format!("secrets[].id='{}'", entry.id))
}

fn is_valid_expires(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

fn check_expiry(expires_str: &str, clock_skew_secs: u64) -> Result<(), ()> {
    let expires: u64 = expires_str.parse().map_err(|_| ())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();

    if expires + clock_skew_secs < now {
        Err(())
    } else {
        Ok(())
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
    use http::Method;

    use super::*;
    use crate::builtins::http::security::url_sign::verify::compute_mac;
    use crate::test_utils::{make_filter_context, make_request};

    fn make_filter(secret: &str) -> UrlSignFilter {
        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
secret:
  value: "{secret}"
"#
        ))
        .unwrap();
        UrlSignFilter::try_from_config(&yaml).unwrap()
    }

    fn sign_query(secret: &str, path: &str, query: &str, expires: &str) -> String {
        let canonical = format!("GET\n{path}\n{query}\n{expires}\n");
        compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap()
    }

    #[tokio::test]
    async fn valid_query_signature_continues() {
        let secret = "test-secret";
        let expires = "9999999999";
        let sig = sign_query(secret, "/files/report.pdf", "token=abc", expires);
        let path = format!("/files/report.pdf?token=abc&expires={expires}&sig={sig}");
        let filter = make_filter(secret);
        let req = make_request(Method::GET, &path);
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn missing_signature_rejects_403() {
        let filter = make_filter("secret");
        let req = make_request(Method::GET, "/files/report.pdf?expires=99");
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }

    #[tokio::test]
    async fn wrong_mac_rejects_403() {
        let filter = make_filter("secret");
        let req = make_request(
            Method::GET,
            "/files/report.pdf?expires=9999999999&sig=deadbeef",
        );
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }

    #[tokio::test]
    async fn expired_url_rejects_403() {
        let secret = "test-secret";
        let expires = "1";
        let sig = sign_query(secret, "/x", "", expires);
        let filter = make_filter(secret);
        let req = make_request(Method::GET, &format!("/x?expires={expires}&sig={sig}"));
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }

    #[tokio::test]
    async fn path_mode_sets_rewritten_path() {
        let secret = "test-secret";
        let expires = "9999999999";
        let resource = "/files/report.pdf";
        let canonical = format!("GET\n{resource}\n\n{expires}\n");
        let sig = compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap();

        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
secret:
  value: "{secret}"
placement: path
path_prefix: /s
"#
        ))
        .unwrap();
        let filter = UrlSignFilter::try_from_config(&yaml).unwrap();

        let path = format!("/s/{expires}/{sig}{resource}");
        let req = make_request(Method::GET, &path);
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.rewritten_path.as_deref(), Some("/files/report.pdf"));
    }

    #[tokio::test]
    async fn encoded_traversal_rejects_403() {
        let secret = "test-secret";
        let expires = "9999999999";
        let resource = "/public/file";
        let canonical = format!("GET\n{resource}\n\n{expires}\n");
        let sig = compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap();

        let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
            r#"
secret:
  value: "{secret}"
placement: path
path_prefix: /s
"#
        ))
        .unwrap();
        let filter = UrlSignFilter::try_from_config(&yaml).unwrap();

        let path = format!("/s/{expires}/{sig}/public/%2e%2e/admin");
        let req = make_request(Method::GET, &path);
        let mut ctx = make_filter_context(&req);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }
}

#[cfg(test)]
#[path = "adversarial.rs"]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "adversarial tests"
)]
mod adversarial;
