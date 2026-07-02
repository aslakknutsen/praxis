// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Signed URL (secure link) filter implementation.

use std::time::SystemTime;

use async_trait::async_trait;

use super::{
    config::SignedUrlConfig,
    verify::{SignedUrlError, verify_signed_url},
};
use crate::builtins::http::security::signature::secret::resolve_secret;
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// SignedUrlFilter
// -----------------------------------------------------------------------------

/// Verifies HMAC-signed URLs with query-parameter tokens (NGINX secure_link style).
///
/// Runs in the request phase only; no body buffering is required.
///
/// # YAML configuration
///
/// ```yaml
/// filter: signed_url
/// secret_env_var: LINK_HMAC_SECRET
/// signature_param: sig
/// timestamp_param: ts
/// max_age_seconds: 3600
/// message:
///   parts: [path, timestamp]
///   separator: "\n"
/// ```
pub struct SignedUrlFilter {
    cfg: SignedUrlConfig,
    secret: Vec<u8>,
}

impl SignedUrlFilter {
    /// Create a signed URL filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if configuration or secret resolution fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: SignedUrlConfig = parse_filter_config("signed_url", config)?;
        super::verify::validate_signed_url_config(&cfg)?;
        let secret = resolve_secret("signed_url", &cfg.secret)?;
        Ok(Box::new(Self { cfg, secret }))
    }

    fn reject(&self, status: u16) -> FilterAction {
        FilterAction::Reject(Rejection::status(status))
    }
}

#[async_trait]
impl HttpFilter for SignedUrlFilter {
    fn name(&self) -> &'static str {
        "signed_url"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let uri = &ctx.request.uri;
        let rewritten = ctx.rewritten_path.as_deref();

        match verify_signed_url(&self.cfg, &self.secret, uri, rewritten, SystemTime::now())? {
            Ok(verified) => {
                if let Some(stripped) = verified.stripped_path {
                    ctx.rewritten_path = Some(stripped);
                }
                Ok(FilterAction::Continue)
            },
            Err(SignedUrlError::Expired) => Ok(self.reject(self.cfg.reject_status_expired)),
            Err(SignedUrlError::MissingParam)
            | Err(SignedUrlError::ParseError)
            | Err(SignedUrlError::FutureTimestamp)
            | Err(SignedUrlError::InvalidEncoding)
            | Err(SignedUrlError::InvalidSignature) => Ok(self.reject(self.cfg.reject_status)),
        }
    }
}
