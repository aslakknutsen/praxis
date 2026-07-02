// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Header + raw body HMAC verification filter.

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;

use super::{
    config::HmacVerifyConfig,
    dialect::{resolve_dialect, verify_body_signature, ResolvedDialect, SignatureError},
};
use crate::builtins::http::security::signature::secret::resolve_secret;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// HmacVerifyFilter
// -----------------------------------------------------------------------------

/// Verifies HMAC signatures over the raw request body (GitHub webhooks and similar).
///
/// Uses static [`BodyMode::StreamBuffer`] and performs verification in
/// [`on_request_body`] at end-of-stream so the signature header and full body
/// are available together. Do not split verification into `on_request`.
///
/// # YAML configuration
///
/// ```yaml
/// filter: hmac_verify
/// secret_env_var: WEBHOOK_SECRET
/// dialect: github
/// max_body_bytes: 1048576
/// ```
pub struct HmacVerifyFilter {
    cfg: HmacVerifyConfig,
    secret: Vec<u8>,
    dialect: ResolvedDialect,
}

impl HmacVerifyFilter {
    /// Create an HMAC verify filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if configuration or secret resolution fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: HmacVerifyConfig = parse_filter_config("hmac_verify", config)?;
        let dialect = resolve_dialect(&cfg)?;
        let secret = resolve_secret("hmac_verify", &cfg.secret)?;
        Ok(Box::new(Self { cfg, secret, dialect }))
    }

    fn reject(&self) -> FilterAction {
        FilterAction::Reject(Rejection::status(self.cfg.reject_status))
    }
}

#[async_trait]
impl HttpFilter for HmacVerifyFilter {
    fn name(&self) -> &'static str {
        "hmac_verify"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.cfg.max_body_bytes),
        }
    }

    fn needs_request_context(&self) -> bool {
        true
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let header_value = ctx
            .request
            .headers
            .get(self.dialect.header_name.as_str())
            .and_then(|v| v.to_str().ok());

        let chunk = body.as_ref().map(|b| b.as_ref()).unwrap_or(&[]);

        match verify_body_signature(&self.cfg, &self.dialect, header_value, chunk, &self.secret)? {
            Ok(()) => {
                if self.cfg.strip_header {
                    ctx.extra_request_headers
                        .push((Cow::Owned(self.dialect.header_name.clone()), String::new()));
                }
                Ok(FilterAction::Continue)
            },
            Err(SignatureError::Missing | SignatureError::Malformed) => Ok(self.reject()),
        }
    }
}
