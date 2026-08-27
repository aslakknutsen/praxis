// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Rewrites JSON request and response bodies using JSON Pointer
//! add/remove/replace, and copies pointer values into request context.
//!
//! Walks the document with a path-stack tokenizer (no JSON DOM). Values are
//! resolved from static YAML or filter context before the walk. Request
//! `Content-Length` is repaired by `StreamBuffer`; response growth is refused
//! because headers are already on the wire. Extract-only directions use
//! `BodyAccess::ReadOnly` and stop walking once every extract pointer is found.

mod config;
mod pointer;
mod rewrite;

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
    config::{CompiledOp, CompiledOps, JsonBodyConfig, ValueSource, build_ops},
    rewrite::{ExtractDest, ExtractOp, ExtractedValue, OpKind, ResolvedOp, extract, rewrite},
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
/// Missing parents, missing replace/extract targets, and missing context values
/// skip that operation. Invalid JSON follows [`on_invalid`].
///
/// Extract-only directions are `ReadOnly` and stop walking once every
/// configured extract pointer is found. Mixed extract and rewrite waits for
/// end-of-stream, writes extracts into context, then applies mutating ops
/// (so an add can consume a value extracted in the same filter).
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
    request_ops: Vec<CompiledOp>,
    /// Compiled response-body operations.
    response_ops: Vec<CompiledOp>,
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
        direction_access(&self.request_ops)
    }

    fn response_body_access(&self) -> BodyAccess {
        direction_access(&self.response_ops)
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
        if !extract_only(&self.request_ops) && !end_of_stream {
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
        if !extract_only(&self.response_ops) && !end_of_stream {
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
    reason = "extract-then-rewrite is one request-path"
)]
fn apply_rewrite(
    ops: &[CompiledOp],
    on_invalid: OnInvalidBehavior,
    ctx: &mut HttpFilterContext<'_>,
    body: &mut Option<Bytes>,
    fit: FitMode,
    end_of_stream: bool,
) -> Result<FilterAction, FilterError> {
    if ops.is_empty() {
        return Ok(FilterAction::Continue);
    }

    let Some(original) = body.as_ref() else {
        return handle_invalid(on_invalid, "empty body");
    };

    let extract_ops = extract_ops(ops);
    if !extract_ops.is_empty() {
        match extract(original, &extract_ops) {
            Ok(captures) => write_captures(ctx, captures),
            Err(_err) if extract_only(ops) && !end_of_stream => return Ok(FilterAction::Continue),
            Err(err) => return handle_invalid(on_invalid, err.as_str()),
        }
        if extract_only(ops) {
            return Ok(FilterAction::BodyDone);
        }
    }

    let resolved = resolve_ops(ops, ctx);
    match rewrite(original, &resolved) {
        Ok(rewritten) => {
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
    !ops.is_empty() && ops.iter().all(|op| op.kind == OpKind::Extract)
}

/// Compiled extract ops for the tokenizer walk.
fn extract_ops(ops: &[CompiledOp]) -> Vec<ExtractOp> {
    ops.iter()
        .filter(|op| op.kind == OpKind::Extract)
        .filter_map(|op| {
            op.dest.clone().map(|dest| ExtractOp {
                tokens: op.tokens.clone(),
                dest,
            })
        })
        .collect()
}

/// Write captured JSON spans into context.
fn write_captures(ctx: &mut HttpFilterContext<'_>, captures: Vec<ExtractedValue>) {
    for capture in captures {
        match capture.dest {
            ExtractDest::Metadata(key) => {
                if let Some(text) = metadata_text(&capture.json) {
                    ctx.set_metadata(key, text);
                }
            },
            ExtractDest::Structured { namespace, key } => {
                if let Ok(value) = serde_json::from_slice(&capture.json) {
                    ctx.set_structured_metadata(&namespace, &key, value);
                }
            },
        }
    }
}

/// JSON string → decoded text; any other value → exact source span.
fn metadata_text(json: &[u8]) -> Option<String> {
    if json.first() == Some(&b'"') {
        serde_json::from_slice(json).ok()
    } else {
        String::from_utf8(json.to_vec()).ok()
    }
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

/// Resolve static/context values; drop add/replace ops whose context is missing.
fn resolve_ops(ops: &[CompiledOp], ctx: &HttpFilterContext<'_>) -> Vec<ResolvedOp> {
    ops.iter().filter_map(|op| resolve_one(op, ctx)).collect()
}

/// Resolve one compiled mutating op, or `None` when a context value is missing.
fn resolve_one(op: &CompiledOp, ctx: &HttpFilterContext<'_>) -> Option<ResolvedOp> {
    if op.kind == OpKind::Extract {
        return None;
    }
    let payload = match &op.source {
        None => None,
        Some(ValueSource::Static(bytes)) => Some(bytes.clone()),
        Some(ValueSource::Metadata(key)) => {
            let text = ctx.get_metadata(key)?;
            serde_json::to_vec(text).ok().map(Bytes::from)
        },
        Some(ValueSource::Structured { namespace, key }) => {
            let value = ctx.get_structured_metadata(namespace, key)?;
            serde_json::to_vec(value).ok().map(Bytes::from)
        },
    };
    if matches!(op.kind, OpKind::Add | OpKind::Replace) && payload.is_none() {
        return None;
    }
    Some(ResolvedOp {
        tokens: op.tokens.clone(),
        kind: op.kind,
        payload,
    })
}
