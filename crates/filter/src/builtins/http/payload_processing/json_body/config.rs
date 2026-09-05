// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! YAML configuration for the JSON body pointer filter.

use bytes::Bytes;
use serde::Deserialize;

use super::{
    index::OpPathIndex,
    pointer::{compile_pointer, pointers_overlap},
    skip::encode_json_string,
};
use crate::{
    FilterError,
    body::DEFAULT_JSON_BODY_MAX_BYTES,
    builtins::http::payload_processing::{OnInvalidBehavior, config_validation::validate_max_body_bytes},
};

// -----------------------------------------------------------------------------
// YAML types
// -----------------------------------------------------------------------------

/// YAML configuration for [`super::JsonBodyFilter`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonBodyConfig {
    /// Pointers to insert (or overwrite, for existing object keys) on the request body.
    #[serde(default)]
    pub request_add: Vec<PointerOpConfig>,

    /// Pointers to omit from the request body.
    #[serde(default)]
    pub request_remove: Vec<String>,

    /// Pointers to overwrite on the request body when present.
    #[serde(default)]
    pub request_replace: Vec<PointerOpConfig>,

    /// Pointers whose JSON is copied into request-scoped context.
    ///
    /// `filter_metadata` values are capped at 256 bytes by the context.
    /// Use `structured_metadata` for nested or larger values.
    #[serde(default)]
    pub request_extract: Vec<ExtractOpConfig>,

    /// Pointers to insert (or overwrite) on the response body.
    #[serde(default)]
    pub response_add: Vec<PointerOpConfig>,

    /// Pointers to omit from the response body.
    #[serde(default)]
    pub response_remove: Vec<String>,

    /// Pointers to overwrite on the response body when present.
    #[serde(default)]
    pub response_replace: Vec<PointerOpConfig>,

    /// Pointers whose JSON is copied into request-scoped context from the response body.
    #[serde(default)]
    pub response_extract: Vec<ExtractOpConfig>,

    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Behavior when the body is not valid JSON.
    #[serde(default = "OnInvalidBehavior::default_continue")]
    pub on_invalid: OnInvalidBehavior,
}

/// A pointer plus exactly one of `value`, `metadata`, or `structured_metadata`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PointerOpConfig {
    /// JSON Pointer (RFC 6901) identifying the target.
    pub pointer: String,

    /// Static JSON value (YAML maps to JSON). Mutually exclusive with the other sources.
    pub value: Option<serde_json::Value>,

    /// `filter_metadata` key; injected as a JSON string. Mutually exclusive with the other sources.
    pub metadata: Option<String>,

    /// Namespaced structured metadata; injected as JSON as-is. Mutually exclusive with the other sources.
    pub structured_metadata: Option<StructuredMetadataRef>,
}

/// A pointer plus exactly one of `metadata` or `structured_metadata` as the extract destination.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExtractOpConfig {
    /// JSON Pointer (RFC 6901) identifying the value to copy.
    pub pointer: String,

    /// `filter_metadata` key to write. Mutually exclusive with `structured_metadata`.
    ///
    /// JSON strings are stored decoded; other values are stored as their source JSON
    /// text. Values over 256 bytes are dropped by the context.
    pub metadata: Option<String>,

    /// Namespaced structured metadata to write. Mutually exclusive with `metadata`.
    pub structured_metadata: Option<StructuredMetadataRef>,
}

/// Namespace + key addressing [`HttpFilterContext::get_structured_metadata`].
///
/// [`HttpFilterContext::get_structured_metadata`]: crate::HttpFilterContext::get_structured_metadata
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredMetadataRef {
    /// Structured-metadata namespace.
    pub namespace: String,

    /// Field within the namespace object.
    pub key: String,
}

/// Default maximum body size (10 MiB).
fn default_max_body_bytes() -> usize {
    DEFAULT_JSON_BODY_MAX_BYTES
}

// -----------------------------------------------------------------------------
// Operation kinds
// -----------------------------------------------------------------------------

/// Kind of pointer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpKind {
    /// Insert last token (overwrite existing object keys; insert/append on arrays).
    Add,
    /// Overwrite if the pointer exists; skip if missing.
    Replace,
    /// Omit if present; skip if missing.
    Remove,
    /// Copy the pointer's JSON into context; body is unchanged.
    Extract,
}

impl OpKind {
    /// Whether this op mutates the serialized body.
    pub(super) const fn is_mutating(self) -> bool {
        matches!(self, Self::Add | Self::Replace | Self::Remove)
    }
}

/// Where an extracted JSON span is written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExtractDest {
    /// `filter_metadata` key.
    Metadata(String),
    /// Structured-metadata namespace and key.
    Structured {
        /// Structured-metadata namespace.
        namespace: String,
        /// Field within the namespace object.
        key: String,
    },
}

// -----------------------------------------------------------------------------
// Compiled ops
// -----------------------------------------------------------------------------

/// Where an add/replace value comes from at rewrite time.
#[derive(Clone, Debug)]
pub(super) enum ValueSource {
    /// Pre-serialized JSON bytes from a static YAML value.
    Static(Bytes),
    /// `filter_metadata` key.
    Metadata(String),
    /// Structured metadata namespace and key.
    Structured {
        /// Structured-metadata namespace.
        namespace: String,
        /// Field within the namespace object.
        key: String,
    },
}

/// One compiled pointer operation.
#[derive(Clone, Debug)]
pub(super) struct CompiledOp {
    /// Original pointer string, for logs and overlap errors.
    pub pointer: String,
    /// Decoded RFC 6901 tokens (empty = document root).
    pub tokens: Vec<String>,
    /// Operation kind.
    pub kind: OpKind,
    /// Value to inject; `None` for remove and extract.
    pub source: Option<ValueSource>,
    /// Extract destination; `None` unless [`OpKind::Extract`].
    pub dest: Option<ExtractDest>,
    /// Pre-serialized static payload from YAML `value`.
    pub static_payload: Option<Bytes>,
    /// JSON-quoted last pointer token for object keys (`"tenant"`).
    pub encoded_last_token: Option<Bytes>,
}

/// Compiled operations plus lookup index for one direction.
#[derive(Clone, Debug)]
pub(super) struct CompiledOpSet {
    /// Operations in config order (extract, add, replace, remove).
    pub ops: Vec<CompiledOp>,
    /// Trie index for pointer lookups.
    pub index: OpPathIndex,
    /// Sum of static payload and encoded key sizes for output capacity.
    pub growth_hint: usize,
}

/// Request-side and response-side compiled operations.
pub(super) struct CompiledOps {
    /// Request-body operations.
    pub request: CompiledOpSet,
    /// Response-body operations.
    pub response: CompiledOpSet,
}

// -----------------------------------------------------------------------------
// Build
// -----------------------------------------------------------------------------

/// Validate config and compile pointers.
///
/// # Errors
///
/// Returns [`FilterError`] when no operations are configured, a pointer is
/// invalid, value sources are missing or duplicated, pointers overlap within
/// a direction, or `max_body_bytes` is out of range.
pub(super) fn build_ops(cfg: JsonBodyConfig) -> Result<(usize, OnInvalidBehavior, CompiledOps), FilterError> {
    validate_max_body_bytes("json_body", cfg.max_body_bytes)?;

    let request = compile_direction(
        "request",
        cfg.request_add,
        cfg.request_replace,
        cfg.request_remove,
        cfg.request_extract,
    )?;
    let response = compile_direction(
        "response",
        cfg.response_add,
        cfg.response_replace,
        cfg.response_remove,
        cfg.response_extract,
    )?;

    if request.ops.is_empty() && response.ops.is_empty() {
        return Err("json_body: at least one add, remove, replace, or extract operation is required".into());
    }

    if response
        .ops
        .iter()
        .any(|op| matches!(op.kind, OpKind::Add | OpKind::Replace))
    {
        tracing::warn!(
            "json_body: response_add/response_replace can grow the body; \
             response Content-Length is already committed and growth is refused at runtime"
        );
    }

    Ok((cfg.max_body_bytes, cfg.on_invalid, CompiledOps { request, response }))
}

/// Wrap compiled ops with trie index and growth hint.
fn finalize_op_set(ops: Vec<CompiledOp>) -> CompiledOpSet {
    let growth_hint = ops.iter().map(op_growth_bytes).sum();
    let index = OpPathIndex::build(&ops);
    CompiledOpSet {
        ops,
        index,
        growth_hint,
    }
}

/// Bytes contributed by one op to rewritten output size.
fn op_growth_bytes(op: &CompiledOp) -> usize {
    let payload = op.static_payload.as_ref().map(|b| b.len()).unwrap_or(0);
    let key = op.encoded_last_token.as_ref().map(|b| b.len()).unwrap_or(0);
    match op.kind {
        OpKind::Add | OpKind::Replace => payload + key,
        OpKind::Remove | OpKind::Extract => 0,
    }
}

/// JSON-quoted last pointer token, used when injecting a missing object member.
fn encoded_last_object_token(tokens: &[String]) -> Option<Bytes> {
    tokens.last().map(|last| encode_json_string(last))
}

/// Compile one direction's extract/add/replace/remove lists.
fn compile_direction(
    direction: &str,
    add: Vec<PointerOpConfig>,
    replace: Vec<PointerOpConfig>,
    remove: Vec<String>,
    extract: Vec<ExtractOpConfig>,
) -> Result<CompiledOpSet, FilterError> {
    let mut ops = Vec::with_capacity(extract.len() + add.len() + replace.len() + remove.len());
    for cfg in extract {
        ops.push(compile_extract_op(direction, cfg)?);
    }
    for cfg in add {
        ops.push(compile_valued_op(direction, "add", OpKind::Add, cfg)?);
    }
    for cfg in replace {
        ops.push(compile_valued_op(direction, "replace", OpKind::Replace, cfg)?);
    }
    for pointer in remove {
        ops.push(compile_remove_op(direction, pointer)?);
    }
    reject_overlaps(direction, &ops)?;
    Ok(finalize_op_set(ops))
}

/// Compile an add or replace entry.
fn compile_valued_op(
    direction: &str,
    section: &str,
    kind: OpKind,
    cfg: PointerOpConfig,
) -> Result<CompiledOp, FilterError> {
    let tokens = compile_pointer(&cfg.pointer)?;
    if tokens.is_empty() && kind == OpKind::Add {
        return Err(format!("json_body: {direction}_{section} cannot target the document root (pointer \"\")").into());
    }
    let source = value_source(direction, section, &cfg)?;
    let static_payload = static_payload_from_source(&source);
    let encoded_last_token = encoded_last_object_token(&tokens);
    Ok(CompiledOp {
        pointer: cfg.pointer,
        tokens,
        kind,
        source: source_without_static(static_payload.as_ref(), source),
        dest: None,
        static_payload,
        encoded_last_token,
    })
}

/// Compile a remove pointer.
fn compile_remove_op(direction: &str, pointer: String) -> Result<CompiledOp, FilterError> {
    let tokens = compile_pointer(&pointer)?;
    if tokens.is_empty() {
        return Err(format!("json_body: {direction}_remove cannot target the document root (pointer \"\")").into());
    }
    let encoded_last_token = encoded_last_object_token(&tokens);
    Ok(CompiledOp {
        pointer,
        tokens,
        kind: OpKind::Remove,
        source: None,
        dest: None,
        static_payload: None,
        encoded_last_token,
    })
}

/// Compile an extract entry.
fn compile_extract_op(direction: &str, cfg: ExtractOpConfig) -> Result<CompiledOp, FilterError> {
    let tokens = compile_pointer(&cfg.pointer)?;
    let dest = extract_dest(direction, &cfg)?;
    Ok(CompiledOp {
        pointer: cfg.pointer,
        tokens,
        kind: OpKind::Extract,
        source: None,
        dest: Some(dest),
        static_payload: None,
        encoded_last_token: None,
    })
}

/// Require exactly one of `metadata` or `structured_metadata`.
fn extract_dest(direction: &str, cfg: &ExtractOpConfig) -> Result<ExtractDest, FilterError> {
    match (&cfg.metadata, &cfg.structured_metadata) {
        (Some(key), None) => {
            if key.is_empty() {
                return Err(format!("json_body: {direction}_extract 'metadata' must not be empty").into());
            }
            Ok(ExtractDest::Metadata(key.clone()))
        },
        (None, Some(meta)) if !meta.namespace.is_empty() && !meta.key.is_empty() => Ok(ExtractDest::Structured {
            namespace: meta.namespace.clone(),
            key: meta.key.clone(),
        }),
        (None, Some(_)) => Err(format!(
            "json_body: {direction}_extract structured_metadata namespace and key must not be empty"
        )
        .into()),
        (None, None) | (Some(_), Some(_)) => Err(format!(
            "json_body: {direction}_extract pointer '{}' must set exactly one of \
             'metadata' or 'structured_metadata'",
            cfg.pointer
        )
        .into()),
    }
}

/// Require exactly one of `value`, `metadata`, `structured_metadata`.
#[expect(clippy::too_many_lines, reason = "one-of validation is a linear match")]
fn value_source(direction: &str, section: &str, cfg: &PointerOpConfig) -> Result<ValueSource, FilterError> {
    let n = usize::from(cfg.value.is_some())
        + usize::from(cfg.metadata.is_some())
        + usize::from(cfg.structured_metadata.is_some());
    if n != 1 {
        return Err(format!(
            "json_body: {direction}_{section} pointer '{}' must set exactly one of \
             'value', 'metadata', or 'structured_metadata'",
            cfg.pointer
        )
        .into());
    }
    if let Some(value) = &cfg.value {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| -> FilterError { format!("json_body: failed to serialize static value: {e}").into() })?;
        return Ok(ValueSource::Static(Bytes::from(bytes)));
    }
    if let Some(key) = &cfg.metadata {
        if key.is_empty() {
            return Err(format!("json_body: {direction}_{section} 'metadata' must not be empty").into());
        }
        return Ok(ValueSource::Metadata(key.clone()));
    }
    match &cfg.structured_metadata {
        Some(meta) if !meta.namespace.is_empty() && !meta.key.is_empty() => Ok(ValueSource::Structured {
            namespace: meta.namespace.clone(),
            key: meta.key.clone(),
        }),
        Some(_) => Err(format!(
            "json_body: {direction}_{section} structured_metadata namespace and key must not be empty"
        )
        .into()),
        None => Err(format!(
            "json_body: {direction}_{section} pointer '{}' must set exactly one of \
             'value', 'metadata', or 'structured_metadata'",
            cfg.pointer
        )
        .into()),
    }
}

/// Reject overlapping mutating pointers; reject equal extract pointers.
fn reject_overlaps(direction: &str, ops: &[CompiledOp]) -> Result<(), FilterError> {
    for (i, a) in ops.iter().enumerate() {
        for b in ops.iter().skip(i + 1) {
            if overlapping_ops(a, b) {
                return Err(format!(
                    "json_body: overlapping JSON Pointers in {direction}: '{}' and '{}'",
                    a.pointer, b.pointer
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Whether two compiled ops conflict under the overlap rules.
fn overlapping_ops(a: &CompiledOp, b: &CompiledOp) -> bool {
    let a_mut = a.kind.is_mutating();
    let b_mut = b.kind.is_mutating();
    match (a_mut, b_mut) {
        (true, true) => pointers_overlap(&a.tokens, &b.tokens),
        (false, false) => a.tokens == b.tokens,
        _ => false,
    }
}

fn static_payload_from_source(source: &ValueSource) -> Option<Bytes> {
    match source {
        ValueSource::Static(bytes) => Some(bytes.clone()),
        ValueSource::Metadata(_) | ValueSource::Structured { .. } => None,
    }
}

fn source_without_static(static_payload: Option<&Bytes>, source: ValueSource) -> Option<ValueSource> {
    if static_payload.is_some() { None } else { Some(source) }
}
