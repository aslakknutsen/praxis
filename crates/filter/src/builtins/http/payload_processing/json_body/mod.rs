// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Rewrites JSON request and response bodies using JSON Pointer
//! add/remove/replace, and copies pointer values into request context.
//!
//! Walks the document with a path-stack tokenizer (no JSON DOM). Unused
//! subtrees are copied as byte spans. Values are resolved from static YAML or
//! filter context during the walk. Request `Content-Length` is repaired by
//! `StreamBuffer`; response growth is refused because headers are already on
//! the wire. Extract-only directions use `BodyAccess::ReadOnly` and stop
//! walking once every extract pointer is found.

#[cfg(feature = "bench-internals")]
pub mod bench;

mod config;
mod error;
mod index;
mod pointer;
mod rewrite;
mod skip;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::warn;

use self::{
    config::{CompiledOp, CompiledOpSet, CompiledOps, JsonBodyConfig, build_ops},
    rewrite::{RewriteMode, rewrite_document},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::payload_processing::OnInvalidBehavior,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// JsonBodyFilter
// -----------------------------------------------------------------------------

/// Rewrites JSON request and response bodies using JSON Pointer add, remove, replace, and extract.
///
/// Applies mutating operations in one pass over a `StreamBuffer`-held body.
/// Extract copies a pointer's JSON into `filter_metadata` or structured
/// metadata without changing the body. `filter_metadata` values over 256
/// bytes are dropped; use structured metadata for nested or larger values.
/// Mutating pointers must not overlap (equal or prefix) within a direction.
/// Duplicate extract pointers are rejected; nested extract pointers are allowed.
/// Unused subtrees are copied as byte spans. Missing parents, missing
/// replace/extract targets, and missing context values skip that operation.
/// Invalid JSON follows [`on_invalid`].
///
/// Extract-only directions are `ReadOnly` and stop walking once every
/// configured extract pointer is found. Mixed extract and rewrite uses one
/// walk; metadata-sourced add/replace resolve lazily at each splice site and
/// are skipped when the extract value is not yet available.
///
/// Response `Content-Length` is already committed when body hooks run.
/// Shrinking responses are padded with trailing spaces; growth is refused
/// and the original body is forwarded.
///
/// # YAML configuration
///
/// ```yaml
/// filter: json_body
/// request_extract:
///   - pointer: /model
///     metadata: original.model
/// request_add:
///   - pointer: /tenant
///     value: acme
///   - pointer: /original_model
///     metadata: original.model
/// request_remove:
///   - /password
/// request_replace:
///   - pointer: /model
///     value: forced-model
/// response_remove:
///   - /internal
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::JsonBodyFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// request_replace:
///   - pointer: /model
///     value: forced-model
/// "#,
/// )
/// .unwrap();
/// let filter = JsonBodyFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "json_body");
/// ```
///
/// [`on_invalid`]: JsonBodyFilter::on_invalid
pub struct JsonBodyFilter {
    /// Maximum request/response body size for `StreamBuffer`.
    max_body_bytes: usize,
    /// Behavior when the body is not valid JSON.
    on_invalid: OnInvalidBehavior,
    /// Compiled request-body operations.
    request_ops: CompiledOpSet,
    /// Compiled response-body operations.
    response_ops: CompiledOpSet,
}

impl JsonBodyFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML is invalid, no operations are
    /// configured, pointers overlap, or a value source is missing.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonBodyConfig = parse_filter_config("json_body", config)?;
        let (max_body_bytes, on_invalid, CompiledOps { request, response }) = build_ops(cfg)?;
        Ok(Box::new(Self {
            max_body_bytes,
            on_invalid,
            request_ops: request,
            response_ops: response,
        }))
    }
}

#[async_trait]
impl HttpFilter for JsonBodyFilter {
    fn name(&self) -> &'static str {
        "json_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        direction_access(&self.request_ops.ops)
    }

    fn response_body_access(&self) -> BodyAccess {
        direction_access(&self.response_ops.ops)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
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
        if !extract_only(&self.request_ops.ops) && !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        apply_rewrite(
            &self.request_ops,
            self.on_invalid,
            ctx,
            body,
            FitMode::Request,
            end_of_stream,
        )
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !extract_only(&self.response_ops.ops) && !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        apply_rewrite(
            &self.response_ops,
            self.on_invalid,
            ctx,
            body,
            FitMode::Response,
            end_of_stream,
        )
    }
}

// -----------------------------------------------------------------------------
// Rewrite application
// -----------------------------------------------------------------------------

/// How to fit a rewritten body to HTTP framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FitMode {
    /// Request: length may change; `StreamBuffer` repairs `Content-Length`.
    Request,
    /// Response: pad on shrink, refuse on grow.
    Response,
}

/// Resolve context values, rewrite, and apply framing policy.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "framing policy is part of the rewrite apply path"
)]
fn apply_rewrite(
    op_set: &CompiledOpSet,
    on_invalid: OnInvalidBehavior,
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    fit: FitMode,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError> {
    if op_set.ops.is_empty() {
        return Ok(FilterAction::Continue);
    }

    let Some(original) = body.as_ref() else {
        return handle_invalid(on_invalid, "empty body");
    };

    let mode = if extract_only(&op_set.ops) {
        RewriteMode::ExtractOnly
    } else {
        RewriteMode::Rewrite
    };

    match rewrite_document(original, op_set, mode, Some(ctx)) {
        Ok(_outcome) if mode == RewriteMode::ExtractOnly => Ok(FilterAction::BodyDone),
        Ok(outcome) => {
            let rewritten = outcome.output.unwrap_or_default();
            match fit {
                FitMode::Request => *body = Some(Bytes::from(rewritten)),
                FitMode::Response => match fit_response(original.len(), rewritten) {
                    Some(fitted) => *body = Some(fitted),
                    None => {
                        warn!(
                            original_len = original.len(),
                            "json_body: refusing response rewrite that exceeds committed Content-Length"
                        );
                    },
                },
            }
            Ok(FilterAction::BodyDone)
        },
        Err(_err) if mode == RewriteMode::ExtractOnly && !end_of_stream => Ok(FilterAction::Continue),
        Err(err) => handle_invalid(on_invalid, err.as_str()),
    }
}

/// Body access for one direction.
fn direction_access(ops: &[CompiledOp]) -> BodyAccess {
    if ops.is_empty() {
        BodyAccess::None
    } else if extract_only(ops) {
        BodyAccess::ReadOnly
    } else {
        BodyAccess::ReadWrite
    }
}

/// Whether every op in this direction is extract.
fn extract_only(ops: &[CompiledOp]) -> bool {
    use self::config::OpKind;
    !ops.is_empty() && ops.iter().all(|op| op.kind == OpKind::Extract)
}

/// Map a parse/rewrite failure to `on_invalid`.
fn handle_invalid(on_invalid: OnInvalidBehavior, reason: &str) -> Result<FilterAction, FilterError> {
    match on_invalid {
        OnInvalidBehavior::Continue => {
            warn!(reason, "json_body: leaving body unchanged");
            Ok(FilterAction::Continue)
        },
        OnInvalidBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
        OnInvalidBehavior::Error => Err(format!("json_body: {reason}").into()),
    }
}

/// Pad a shorter response to `original_len`; `None` means grow (caller keeps original).
fn fit_response(original_len: usize, rewritten: Vec<u8>) -> Option<Bytes> {
    match rewritten.len().cmp(&original_len) {
        std::cmp::Ordering::Greater => None,
        std::cmp::Ordering::Equal => Some(Bytes::from(rewritten)),
        std::cmp::Ordering::Less => {
            let mut padded = rewritten;
            padded.resize(original_len, b' ');
            Some(Bytes::from(padded))
        },
    }
}
