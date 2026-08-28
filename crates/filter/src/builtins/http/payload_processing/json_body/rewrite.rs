// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! One-pass JSON Pointer rewriter: tokenize, copy unmatched spans, splice ops.
//!
//! Does not build a `serde_json::Value` tree. Injected literals are
//! pre-serialized JSON bytes. Extract captures run in the same walk as
//! mutating splices; metadata payloads resolve lazily at each splice site.
//! Subtrees with no remaining op are copied as raw spans (`skip_value` + memcpy).

use std::{borrow::Cow, collections::HashMap};

use bytes::Bytes;

use super::config::{CompiledOp, ValueSource};
use crate::HttpFilterContext;

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Maximum object/array nesting while rewriting.
pub(super) const MAX_JSON_DEPTH: u32 = 128;

/// Kind of pointer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpKind {
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
pub(super) enum ExtractDest {
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

/// An extract pointer with its destination already compiled.
#[derive(Clone, Debug)]
pub(super) struct ExtractOp {
    /// Decoded pointer tokens (empty = root).
    pub tokens: Vec<String>,
    /// Context destination.
    pub dest: ExtractDest,
}

/// An operation with values already resolved from context (unit tests).
#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct ResolvedOp {
    /// Decoded pointer tokens (empty = root).
    pub tokens: Vec<String>,
    /// Operation kind.
    pub kind: OpKind,
    /// Serialized JSON to inject; `None` for remove.
    pub payload: Option<Bytes>,
}

/// Whether the walk emits a rewritten body or only captures extracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RewriteMode {
    /// Capture extracts only; may stop once every extract pointer is found.
    ExtractOnly,
    /// Capture extracts and emit a rewritten body in one walk.
    Rewrite,
}

/// Result of a unified document walk.
#[derive(Clone, Debug)]
pub(super) struct RewriteOutcome {
    /// Rewritten bytes; `None` in extract-only mode.
    pub output: Option<Vec<u8>>,
}

/// Why a rewrite failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RewriteError {
    /// Input is not a single JSON value.
    InvalidJson,
    /// Nesting exceeded [`MAX_JSON_DEPTH`].
    Depth,
}

impl RewriteError {
    /// Human-readable reason for logs and `on_invalid: error`.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid JSON",
            Self::Depth => "JSON nesting exceeds maximum depth",
        }
    }
}

// -----------------------------------------------------------------------------
// Session
// -----------------------------------------------------------------------------

/// Per-request capture and lazy resolution state.
struct RewriteSession {
    /// Extract-only vs emit rewritten bytes.
    mode: RewriteMode,
    /// Extract ops for this direction.
    extract_ops: Vec<ExtractOp>,
    /// Parallel to `extract_ops`; true once that pointer was captured.
    extract_satisfied: Vec<bool>,
    /// Metadata captured this walk or preloaded from context.
    scratch_metadata: HashMap<String, String>,
    /// Structured metadata captured this walk or preloaded from context.
    scratch_structured: HashMap<(String, String), serde_json::Value>,
    /// JSON Pointer tokens for the value currently being walked.
    path: Vec<String>,
}

impl RewriteSession {
    /// Build a session with empty scratch maps and path.
    fn new(mode: RewriteMode, extract_ops: Vec<ExtractOp>) -> Self {
        let satisfied_len = extract_ops.len();
        Self {
            mode,
            extract_ops,
            extract_satisfied: vec![false; satisfied_len],
            scratch_metadata: HashMap::new(),
            scratch_structured: HashMap::new(),
            path: Vec::new(),
        }
    }

    /// Write scratch captures into the request context.
    fn flush_to_ctx(&self, ctx: &mut HttpFilterContext<'_>) {
        for (key, text) in &self.scratch_metadata {
            ctx.set_metadata(key.clone(), text.clone());
        }
        for ((namespace, key), value) in &self.scratch_structured {
            ctx.set_structured_metadata(namespace, key, value.clone());
        }
    }

    /// Whether every extract pointer has been captured (or none were configured).
    fn all_extracts_done(&self) -> bool {
        self.extract_ops.is_empty() || self.extract_satisfied.iter().all(|s| *s)
    }
}

/// Whether the walk should stop early.
enum WalkStep {
    /// Keep walking.
    Continue,
    /// Every extract op is satisfied (extract-only early exit).
    Done,
}

// -----------------------------------------------------------------------------
// Entry
// -----------------------------------------------------------------------------

/// Reserve output bytes: shrink-only ops need at most `input_len`; add/replace may grow.
fn rewrite_output_capacity(input_len: usize, ops: &[CompiledOp]) -> usize {
    let grows = ops.iter().any(|op| matches!(op.kind, OpKind::Add | OpKind::Replace));
    if grows {
        input_len.saturating_add(input_len.saturating_mul(2) / 100)
    } else {
        input_len
    }
}

/// Walk `input` once, capturing extracts and optionally rewriting mutating ops.
///
/// # Errors
///
/// Returns [`RewriteError`] when the input is not valid JSON before the walk
/// completes or nesting exceeds [`MAX_JSON_DEPTH`].
#[expect(clippy::too_many_lines, reason = "root replace, walk, and trailing check")]
pub(super) fn rewrite_document(
    input: &[u8],
    ops: &[CompiledOp],
    mode: RewriteMode,
    ctx: Option<&mut HttpFilterContext<'_>>,
) -> Result<RewriteOutcome, RewriteError> {
    let extract_ops = compiled_extract_ops(ops);
    let mut session = RewriteSession::new(mode, extract_ops);
    if let Some(ctx) = ctx.as_deref() {
        preload_context_sources(ops, ctx, &mut session);
    }

    let mut i = skip_bom(input);
    skip_ws(input, &mut i);
    if i >= input.len() {
        return Err(RewriteError::InvalidJson);
    }

    if let Some(root) = root_replace(ops, &session) {
        skip_value(input, &mut i, 0)?;
        skip_ws(input, &mut i);
        if i != input.len() {
            return Err(RewriteError::InvalidJson);
        }
        return Ok(finish_document(
            &session,
            ctx,
            (mode == RewriteMode::Rewrite).then(|| root.to_vec()),
        ));
    }

    let mut out = (mode == RewriteMode::Rewrite)
        .then(|| Vec::with_capacity(rewrite_output_capacity(input.len(), ops)));

    match rewrite_value(input, &mut i, ops, out.as_mut(), 0, &mut session)? {
        WalkStep::Done => {
            return Ok(finish_document(&session, ctx, None));
        },
        WalkStep::Continue => {},
    }

    if mode == RewriteMode::Rewrite {
        skip_ws(input, &mut i);
        if i != input.len() {
            return Err(RewriteError::InvalidJson);
        }
    }

    Ok(finish_document(&session, ctx, out))
}

/// Flush captures and wrap the optional output buffer.
fn finish_document(
    session: &RewriteSession,
    ctx: Option<&mut HttpFilterContext<'_>>,
    output: Option<Vec<u8>>,
) -> RewriteOutcome {
    if let Some(ctx) = ctx {
        session.flush_to_ctx(ctx);
    }
    RewriteOutcome { output }
}

/// Rewrite `input` using pre-resolved ops (unit tests).
#[cfg(test)]
pub(super) fn rewrite(input: &[u8], ops: &[ResolvedOp]) -> Result<Vec<u8>, RewriteError> {
    let compiled = ops
        .iter()
        .map(|op| CompiledOp {
            pointer: String::new(),
            tokens: op.tokens.clone(),
            kind: op.kind,
            source: op.payload.as_ref().map(|bytes| ValueSource::Static(bytes.clone())),
            dest: None,
        })
        .collect::<Vec<_>>();
    rewrite_document(input, &compiled, RewriteMode::Rewrite, None).map(|outcome| outcome.output.unwrap_or_default())
}

// -----------------------------------------------------------------------------
// Capture + lazy resolve
// -----------------------------------------------------------------------------

/// Extract ops copied from the compiled list.
fn compiled_extract_ops(ops: &[CompiledOp]) -> Vec<ExtractOp> {
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

/// Decode a captured JSON span for `filter_metadata` (strings unescaped).
fn metadata_text(json: &[u8]) -> Option<String> {
    if json.first() == Some(&b'"') {
        serde_json::from_slice(json).ok()
    } else {
        String::from_utf8(json.to_vec()).ok()
    }
}

/// Capture an extract at `session.path` from `input[start..end]`.
fn store_capture(input: &[u8], start: usize, end: usize, session: &mut RewriteSession) -> WalkStep {
    let hit = session.extract_ops.iter().enumerate().find_map(|(idx, op)| {
        let pending = session.extract_satisfied.get(idx).copied() != Some(true);
        (pending && op.tokens == session.path).then_some(idx)
    });
    if let Some(idx) = hit {
        let dest = session.extract_ops.get(idx).map(|op| op.dest.clone());
        if let (Some(json), Some(dest)) = (input.get(start..end), dest) {
            write_capture_dest(json, &dest, session);
        }
        if let Some(flag) = session.extract_satisfied.get_mut(idx) {
            *flag = true;
        }
    }
    if session.all_extracts_done() && session.mode == RewriteMode::ExtractOnly {
        WalkStep::Done
    } else {
        WalkStep::Continue
    }
}

/// Write one captured JSON span into the matching scratch map.
fn write_capture_dest(json: &[u8], dest: &ExtractDest, session: &mut RewriteSession) {
    match dest {
        ExtractDest::Metadata(key) => {
            if let Some(text) = metadata_text(json) {
                session.scratch_metadata.insert(key.clone(), text);
            }
        },
        ExtractDest::Structured { namespace, key } => {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(json) {
                session
                    .scratch_structured
                    .insert((namespace.clone(), key.clone()), value);
            }
        },
    }
}

/// Skip one value and capture it if an extract matches `session.path`.
fn capture_value_at_path(
    input: &[u8],
    i: &mut usize,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    let start = *i;
    skip_value(input, i, depth)?;
    Ok(store_capture(input, start, *i, session))
}

/// Copy one JSON value as a raw span (no per-member tokenize of its interior).
fn copy_span(input: &[u8], i: &mut usize, depth: u32, out: Option<&mut Vec<u8>>) -> Result<(), RewriteError> {
    skip_ws(input, i);
    let start = *i;
    skip_value(input, i, depth)?;
    if let Some(out) = out {
        let span = input.get(start..*i).ok_or(RewriteError::InvalidJson)?;
        out.extend_from_slice(span);
    }
    Ok(())
}

/// Copy context metadata/structured values into scratch before the walk.
fn preload_context_sources(ops: &[CompiledOp], ctx: &HttpFilterContext<'_>, session: &mut RewriteSession) {
    for op in ops {
        if op.kind == OpKind::Extract {
            continue;
        }
        match &op.source {
            Some(ValueSource::Metadata(key)) => {
                if let Some(text) = ctx.get_metadata(key) {
                    session.scratch_metadata.insert(key.clone(), text.to_owned());
                }
            },
            Some(ValueSource::Structured { namespace, key }) => {
                if let Some(value) = ctx.get_structured_metadata(namespace, key) {
                    session
                        .scratch_structured
                        .insert((namespace.clone(), key.clone()), value.clone());
                }
            },
            Some(ValueSource::Static(_)) | None => {},
        }
    }
}

/// Resolve a mutating op's payload from static bytes or session scratch.
fn resolve_payload(source: Option<&ValueSource>, session: &RewriteSession) -> Option<Bytes> {
    match source? {
        ValueSource::Static(bytes) => Some(bytes.clone()),
        ValueSource::Metadata(key) => session
            .scratch_metadata
            .get(key)
            .and_then(|text| serde_json::to_vec(text).ok())
            .map(Bytes::from),
        ValueSource::Structured { namespace, key } => session
            .scratch_structured
            .get(&(namespace.clone(), key.clone()))
            .and_then(|value| serde_json::to_vec(value).ok())
            .map(Bytes::from),
    }
}

/// Root-level replace payload, if configured and resolvable.
fn root_replace(ops: &[CompiledOp], session: &RewriteSession) -> Option<Bytes> {
    ops.iter()
        .find(|op| op.tokens.is_empty() && op.kind == OpKind::Replace)
        .and_then(|op| resolve_payload(op.source.as_ref(), session))
}

// -----------------------------------------------------------------------------
// Value walk
// -----------------------------------------------------------------------------

/// Rewrite one JSON value at `session.path`.
#[expect(clippy::too_many_arguments, reason = "walker state is threaded per recursive call")]
fn rewrite_value(
    input: &[u8],
    i: &mut usize,
    ops: &[CompiledOp],
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    skip_ws(input, i);
    if !has_descendant_ops(ops, &session.path) {
        let start = *i;
        copy_span(input, i, depth, out.as_deref_mut())?;
        return Ok(store_capture(input, start, *i, session));
    }
    let start = *i;
    let kind = next_byte(input, *i)?;
    let step = match kind {
        b'{' => rewrite_object(input, i, ops, out.as_deref_mut(), depth, session)?,
        b'[' => rewrite_array(input, i, ops, out.as_deref_mut(), depth, session)?,
        _ => {
            *i = start;
            copy_span(input, i, depth, out)?;
            return Ok(store_capture(input, start, *i, session));
        },
    };
    if matches!(step, WalkStep::Done) {
        return Ok(WalkStep::Done);
    }
    Ok(store_capture(input, start, *i, session))
}

/// Rewrite an object, splicing member ops and injecting missing adds at close.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "object member walk is a linear tokenizer loop"
)]
fn rewrite_object(
    input: &[u8],
    i: &mut usize,
    ops: &[CompiledOp],
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'{')?;
    if let Some(out) = out.as_mut() {
        out.push(b'{');
    }

    let mut emitted_any = false;
    let mut seen_input_member = false;
    let mut satisfied_add_keys: Vec<&str> = Vec::new();
    let mut seen_op_keys: Vec<&str> = Vec::new();

    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b'}' {
            *i += 1;
            break;
        }
        if seen_input_member {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b'}' {
                return Err(RewriteError::InvalidJson);
            }
        }
        seen_input_member = true;

        let (key_span, key) = parse_string(input, i)?;
        skip_ws(input, i);
        expect_byte(input, i, b':')?;

        let first_for_key = !seen_op_keys.iter().any(|k| *k == key.as_ref());
        if first_for_key && let Some(op) = mutate_for_child(ops, &session.path, key.as_ref()) {
            seen_op_keys.push(op.tokens.last().map_or("", String::as_str));
            session.path.push(key.into_owned());
            let step = apply_object_mutate(input, i, key_span, op, &mut out, &mut emitted_any, depth, session)?;
            if op.kind == OpKind::Add
                && matches!(step, WalkStep::Continue)
                && resolve_payload(op.source.as_ref(), session).is_some()
            {
                satisfied_add_keys.push(op.tokens.last().map_or("", String::as_str));
            }
            session.path.pop();
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
            continue;
        }

        if let Some(out) = out.as_mut() {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(key_span);
            out.push(b':');
        }
        if child_needs_rewrite(ops, &session.path, key.as_ref()) {
            session.path.push(key.into_owned());
            let step = rewrite_value(input, i, ops, out.as_deref_mut(), depth, session)?;
            session.path.pop();
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
        } else {
            copy_span(input, i, depth, out.as_deref_mut())?;
        }
    }

    inject_object_adds(ops, &satisfied_add_keys, out.as_deref_mut(), &mut emitted_any, session);
    if let Some(out) = out.as_mut() {
        out.push(b'}');
    }
    Ok(WalkStep::Continue)
}

/// Apply a mutating op to an existing object member. Path already includes the key.
#[expect(clippy::too_many_arguments, reason = "mutate splice needs walk + emit state")]
fn apply_object_mutate(
    input: &[u8],
    i: &mut usize,
    key_span: &[u8],
    op: &CompiledOp,
    out: &mut Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    match op.kind {
        OpKind::Remove => capture_value_at_path(input, i, depth, session),
        OpKind::Replace | OpKind::Add => {
            let step = capture_value_at_path(input, i, depth, session)?;
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
            if let Some(payload) = resolve_payload(op.source.as_ref(), session)
                && let Some(out) = out.as_mut()
            {
                emit_separator(out, emitted_any);
                out.extend_from_slice(key_span);
                out.push(b':');
                out.extend_from_slice(&payload);
            }
            Ok(step)
        },
        OpKind::Extract => Ok(WalkStep::Continue),
    }
}

/// Emit unsatisfied object `add` ops at `session.path` in config order.
fn inject_object_adds(
    ops: &[CompiledOp],
    satisfied: &[&str],
    out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    session: &RewriteSession,
) {
    let Some(out) = out else {
        return;
    };
    for op in ops {
        if op.kind != OpKind::Add || !parent_is(op, &session.path) {
            continue;
        }
        let Some(last) = op.tokens.last() else {
            continue;
        };
        if satisfied.contains(&last.as_str()) {
            continue;
        }
        let Some(payload) = resolve_payload(op.source.as_ref(), session) else {
            continue;
        };
        emit_separator(out, emitted_any);
        if let Ok(encoded) = serde_json::to_vec(last) {
            out.extend_from_slice(&encoded);
        }
        out.push(b':');
        out.extend_from_slice(&payload);
    }
}

/// Rewrite an array, inserting at original indices and appending at close.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "array element walk is a linear tokenizer loop"
)]
fn rewrite_array(
    input: &[u8],
    i: &mut usize,
    ops: &[CompiledOp],
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'[')?;
    if let Some(out) = out.as_mut() {
        out.push(b'[');
    }

    let mut emitted_any = false;
    let mut orig_idx: usize = 0;

    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b']' {
            *i += 1;
            break;
        }
        if orig_idx > 0 {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b']' {
                return Err(RewriteError::InvalidJson);
            }
        }

        if let Some(op) = add_at_index(ops, &session.path, orig_idx)
            && let Some(payload) = resolve_payload(op.source.as_ref(), session)
            && let Some(out) = out.as_mut()
        {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(&payload);
        }

        if let Some(op) = replace_or_remove_at_index(ops, &session.path, orig_idx) {
            session.path.push(orig_idx.to_string());
            let step = match op.kind {
                OpKind::Remove => capture_value_at_path(input, i, depth, session)?,
                OpKind::Replace => {
                    let cap = capture_value_at_path(input, i, depth, session)?;
                    if matches!(cap, WalkStep::Done) {
                        session.path.pop();
                        return Ok(WalkStep::Done);
                    }
                    if let Some(payload) = resolve_payload(op.source.as_ref(), session)
                        && let Some(out) = out.as_mut()
                    {
                        emit_separator(out, &mut emitted_any);
                        out.extend_from_slice(&payload);
                    }
                    cap
                },
                OpKind::Add | OpKind::Extract => WalkStep::Continue,
            };
            session.path.pop();
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
        } else {
            if let Some(out) = out.as_mut() {
                emit_separator(out, &mut emitted_any);
            }
            if child_index_needs_rewrite(ops, &session.path, orig_idx) {
                session.path.push(orig_idx.to_string());
                let step = rewrite_value(input, i, ops, out.as_deref_mut(), depth, session)?;
                session.path.pop();
                if matches!(step, WalkStep::Done) {
                    return Ok(WalkStep::Done);
                }
            } else {
                copy_span(input, i, depth, out.as_deref_mut())?;
            }
        }
        orig_idx = orig_idx.saturating_add(1);
    }

    if let Some(op) = add_at_index(ops, &session.path, orig_idx)
        && let Some(payload) = resolve_payload(op.source.as_ref(), session)
        && let Some(out) = out.as_mut()
    {
        emit_separator(out, &mut emitted_any);
        out.extend_from_slice(&payload);
    }
    if let Some(op) = add_append(ops, &session.path)
        && let Some(payload) = resolve_payload(op.source.as_ref(), session)
        && let Some(out) = out.as_mut()
    {
        emit_separator(out, &mut emitted_any);
        out.extend_from_slice(&payload);
    }

    if let Some(out) = out.as_mut() {
        out.push(b']');
    }
    Ok(WalkStep::Continue)
}

// -----------------------------------------------------------------------------
// Op lookup
// -----------------------------------------------------------------------------

/// Whether any op is nested strictly under `path`.
fn has_descendant_ops(ops: &[CompiledOp], path: &[String]) -> bool {
    ops.iter()
        .any(|op| op.tokens.len() > path.len() && op.tokens.get(..path.len()) == Some(path))
}

/// Whether `rewrite_value` must run for object child `last` (extract or nested ops).
fn child_needs_rewrite(ops: &[CompiledOp], parent: &[String], last: &str) -> bool {
    ops.iter()
        .any(|op| child_token_needs_rewrite(op, parent, |t| t == last))
}

/// Whether `rewrite_value` must run for array element `idx`.
fn child_index_needs_rewrite(ops: &[CompiledOp], parent: &[String], idx: usize) -> bool {
    ops.iter()
        .any(|op| child_token_needs_rewrite(op, parent, |t| array_index(t) == Some(idx)))
}

/// Whether `op` targets `parent`/`last` as an extract or as a nested pointer.
fn child_token_needs_rewrite(op: &CompiledOp, parent: &[String], last_ok: impl Fn(&str) -> bool) -> bool {
    if op.tokens.get(..parent.len()) != Some(parent) {
        return false;
    }
    let Some(token) = op.tokens.get(parent.len()) else {
        return false;
    };
    if !last_ok(token) {
        return false;
    }
    op.tokens.len() > parent.len() + 1 || op.kind == OpKind::Extract
}

/// First mutating op whose parent path is `path` and last token equals `last`.
fn mutate_for_child<'a>(ops: &'a [CompiledOp], path: &[String], last: &str) -> Option<&'a CompiledOp> {
    ops.iter()
        .find(|op| op.kind.is_mutating() && parent_is(op, path) && op.tokens.last().is_some_and(|t| t == last))
}

/// Remove or replace targeting array index `idx` at `path`.
fn replace_or_remove_at_index<'a>(ops: &'a [CompiledOp], path: &[String], idx: usize) -> Option<&'a CompiledOp> {
    ops.iter().find(|op| {
        matches!(op.kind, OpKind::Remove | OpKind::Replace)
            && parent_is(op, path)
            && op.tokens.last().and_then(|t| array_index(t)) == Some(idx)
    })
}


/// Add targeting array index `idx` at `path`.
fn add_at_index<'a>(ops: &'a [CompiledOp], path: &[String], idx: usize) -> Option<&'a CompiledOp> {
    ops.iter().find(|op| {
        op.kind == OpKind::Add && parent_is(op, path) && op.tokens.last().and_then(|t| array_index(t)) == Some(idx)
    })
}

/// Add targeting `/path/-` (append).
fn add_append<'a>(ops: &'a [CompiledOp], path: &[String]) -> Option<&'a CompiledOp> {
    ops.iter()
        .find(|op| op.kind == OpKind::Add && parent_is(op, path) && op.tokens.last().is_some_and(|t| t == "-"))
}

/// Whether `op.tokens[..len-1]` equals `path`.
fn parent_is(op: &CompiledOp, path: &[String]) -> bool {
    op.tokens.len() == path.len() + 1 && op.tokens.get(..path.len()).is_some_and(|p| p == path)
}

/// RFC 6901 array index: unsigned integer with no leading zeros (`0` allowed).
fn array_index(token: &str) -> Option<usize> {
    if token.is_empty() || (token.starts_with('0') && token.len() > 1) {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Insert a comma before the next emitted member or element.
fn emit_separator(out: &mut Vec<u8>, emitted_any: &mut bool) {
    if *emitted_any {
        out.push(b',');
    }
    *emitted_any = true;
}

/// Increment nesting; fail if [`MAX_JSON_DEPTH`] would be exceeded.
fn bump_depth(depth: u32) -> Result<u32, RewriteError> {
    let next = depth.saturating_add(1);
    if next > MAX_JSON_DEPTH {
        return Err(RewriteError::Depth);
    }
    Ok(next)
}

// -----------------------------------------------------------------------------
// Scanner
// -----------------------------------------------------------------------------

/// Skip a UTF-8 BOM if present. Returns the start index of the JSON payload.
fn skip_bom(input: &[u8]) -> usize {
    match input {
        [0xEF, 0xBB, 0xBF, ..] => 3,
        _ => 0,
    }
}

/// Advance past JSON insignificant whitespace (space, tab, LF, CR).
fn skip_ws(input: &[u8], i: &mut usize) {
    while let Some(&b) = input.get(*i) {
        if !matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            break;
        }
        *i += 1;
    }
}

/// Next byte at `i`, or invalid JSON if past the end.
fn next_byte(input: &[u8], i: usize) -> Result<u8, RewriteError> {
    input.get(i).copied().ok_or(RewriteError::InvalidJson)
}

/// Consume `expected` at `i`, or fail if the next byte differs.
fn expect_byte(input: &[u8], i: &mut usize, expected: u8) -> Result<(), RewriteError> {
    let b = next_byte(input, *i)?;
    if b != expected {
        return Err(RewriteError::InvalidJson);
    }
    *i += 1;
    Ok(())
}

/// Parse a JSON string; returns the original quoted span and the decoded text.
fn parse_string<'a>(input: &'a [u8], i: &mut usize) -> Result<(&'a [u8], Cow<'a, str>), RewriteError> {
    let start = *i;
    skip_string(input, i)?;
    let raw = input.get(start..*i).ok_or(RewriteError::InvalidJson)?;
    let inner = raw
        .get(1..raw.len().saturating_sub(1))
        .ok_or(RewriteError::InvalidJson)?;
    if inner.contains(&b'\\') {
        let decoded = serde_json::from_slice(raw).map_err(|_e| RewriteError::InvalidJson)?;
        Ok((raw, Cow::Owned(decoded)))
    } else {
        let decoded = std::str::from_utf8(inner).map_err(|_e| RewriteError::InvalidJson)?;
        Ok((raw, Cow::Borrowed(decoded)))
    }
}

/// Skip one JSON value without copying it.
fn skip_value(input: &[u8], i: &mut usize, depth: u32) -> Result<(), RewriteError> {
    skip_ws(input, i);
    match next_byte(input, *i)? {
        b'{' => skip_object(input, i, depth),
        b'[' => skip_array(input, i, depth),
        b'"' => skip_string(input, i),
        b't' => skip_literal(input, i, b"true"),
        b'f' => skip_literal(input, i, b"false"),
        b'n' => skip_literal(input, i, b"null"),
        b'-' | b'0'..=b'9' => skip_number(input, i),
        _ => Err(RewriteError::InvalidJson),
    }
}

/// Skip an object `{...}` including nested values.
fn skip_object(input: &[u8], i: &mut usize, depth: u32) -> Result<(), RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'{')?;
    let mut seen_member = false;
    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b'}' {
            *i += 1;
            return Ok(());
        }
        if seen_member {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b'}' {
                return Err(RewriteError::InvalidJson);
            }
        }
        skip_string(input, i)?;
        skip_ws(input, i);
        expect_byte(input, i, b':')?;
        skip_value(input, i, depth)?;
        seen_member = true;
    }
}

/// Skip an array `[...]` including nested values.
fn skip_array(input: &[u8], i: &mut usize, depth: u32) -> Result<(), RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'[')?;
    let mut seen_elem = false;
    loop {
        skip_ws(input, i);
        if next_byte(input, *i)? == b']' {
            *i += 1;
            return Ok(());
        }
        if seen_elem {
            expect_byte(input, i, b',')?;
            skip_ws(input, i);
            if next_byte(input, *i)? == b']' {
                return Err(RewriteError::InvalidJson);
            }
        }
        skip_value(input, i, depth)?;
        seen_elem = true;
    }
}

/// Skip a JSON string, including escapes.
fn skip_string(input: &[u8], i: &mut usize) -> Result<(), RewriteError> {
    expect_byte(input, i, b'"')?;
    loop {
        let b = next_byte(input, *i)?;
        *i += 1;
        match b {
            b'"' => return Ok(()),
            b'\\' => {
                let esc = next_byte(input, *i)?;
                *i += 1;
                if esc == b'u' {
                    for _ in 0..4 {
                        let h = next_byte(input, *i)?;
                        if !h.is_ascii_hexdigit() {
                            return Err(RewriteError::InvalidJson);
                        }
                        *i += 1;
                    }
                }
            },
            0x00..=0x1F => return Err(RewriteError::InvalidJson),
            _ => {},
        }
    }
}

/// Skip a JSON literal (`true`, `false`, or `null`).
fn skip_literal(input: &[u8], i: &mut usize, lit: &[u8]) -> Result<(), RewriteError> {
    let slice = input.get(*i..).ok_or(RewriteError::InvalidJson)?;
    let prefix = slice.get(..lit.len()).ok_or(RewriteError::InvalidJson)?;
    if prefix != lit {
        return Err(RewriteError::InvalidJson);
    }
    *i += lit.len();
    Ok(())
}

/// Advance past consecutive ASCII digits.
fn skip_digits(input: &[u8], i: &mut usize) {
    while input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
        *i += 1;
    }
}

/// Skip a JSON number (integer, fraction, exponent).
fn skip_number(input: &[u8], i: &mut usize) -> Result<(), RewriteError> {
    let start = *i;
    if next_byte(input, *i)? == b'-' {
        *i += 1;
    }
    let first = next_byte(input, *i)?;
    if first == b'0' {
        *i += 1;
    } else if first.is_ascii_digit() {
        skip_digits(input, i);
    } else {
        return Err(RewriteError::InvalidJson);
    }
    skip_number_frac_exp(input, i)?;
    if *i == start {
        return Err(RewriteError::InvalidJson);
    }
    Ok(())
}

/// Skip optional fraction and exponent after the integer part of a number.
fn skip_number_frac_exp(input: &[u8], i: &mut usize) -> Result<(), RewriteError> {
    if input.get(*i).copied() == Some(b'.') {
        *i += 1;
        if !input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
            return Err(RewriteError::InvalidJson);
        }
        skip_digits(input, i);
    }
    if matches!(input.get(*i).copied(), Some(b'e' | b'E')) {
        *i += 1;
        if matches!(input.get(*i).copied(), Some(b'+' | b'-')) {
            *i += 1;
        }
        if !input.get(*i).copied().is_some_and(|b| b.is_ascii_digit()) {
            return Err(RewriteError::InvalidJson);
        }
        skip_digits(input, i);
    }
    Ok(())
}

#[cfg(test)]
mod capacity_tests {
    use super::{
        super::config::CompiledOp,
        ExtractDest, OpKind, rewrite_output_capacity,
    };

    fn op(kind: OpKind) -> CompiledOp {
        CompiledOp {
            pointer: String::new(),
            tokens: Vec::new(),
            kind,
            source: None,
            dest: (kind == OpKind::Extract).then(|| ExtractDest::Metadata("k".into())),
        }
    }

    #[test]
    fn remove_only_uses_input_len() {
        assert_eq!(rewrite_output_capacity(10_485_760, &[op(OpKind::Remove)]), 10_485_760);
    }

    #[test]
    fn extract_only_uses_input_len() {
        assert_eq!(rewrite_output_capacity(10_485_760, &[op(OpKind::Extract)]), 10_485_760);
    }

    #[test]
    fn extract_and_remove_use_input_len() {
        assert_eq!(
            rewrite_output_capacity(10_485_760, &[op(OpKind::Extract), op(OpKind::Remove)]),
            10_485_760
        );
    }

    #[test]
    fn add_or_replace_add_two_percent() {
        let input_len = 10_485_760;
        let expected = input_len + input_len * 2 / 100;
        assert_eq!(rewrite_output_capacity(input_len, &[op(OpKind::Add)]), expected);
        assert_eq!(rewrite_output_capacity(input_len, &[op(OpKind::Replace)]), expected);
        assert_eq!(
            rewrite_output_capacity(input_len, &[op(OpKind::Remove), op(OpKind::Add)]),
            expected
        );
    }

    #[test]
    fn zero_input_len_stays_zero() {
        assert_eq!(rewrite_output_capacity(0, &[op(OpKind::Add)]), 0);
        assert_eq!(rewrite_output_capacity(0, &[op(OpKind::Remove)]), 0);
    }
}
