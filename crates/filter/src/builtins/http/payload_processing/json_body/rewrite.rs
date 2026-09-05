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
use smallvec::SmallVec;

use super::{
    config::{CompiledOp, CompiledOpSet, ValueSource},
    index::{PathToken, path_eq_tokens},
    skip::{expect_byte, next_byte, skip_bom, skip_string_with_meta, skip_value, skip_ws},
};
pub(crate) use super::{
    config::{ExtractDest, OpKind},
    error::{MAX_JSON_DEPTH, RewriteError},
};
use crate::HttpFilterContext;

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

// -----------------------------------------------------------------------------
// Session
// -----------------------------------------------------------------------------

/// Per-request capture and lazy resolution state.
struct RewriteSession {
    /// Metadata captured this walk or preloaded from context.
    scratch_metadata: HashMap<String, String>,
    /// Structured values preloaded from context for injection.
    scratch_structured: HashMap<(String, String), serde_json::Value>,
    /// Raw JSON spans captured for structured metadata extract.
    capture_structured: HashMap<(String, String), Bytes>,
    /// Cached serialized payloads per op index.
    resolved: Vec<Option<Bytes>>,
    /// JSON Pointer tokens for the value currently being walked.
    path: SmallVec<[PathToken; 8]>,
}

impl RewriteSession {
    /// Allocate scratch maps and cache static payloads for this walk.
    fn new(op_set: &CompiledOpSet) -> Self {
        let mut resolved = vec![None; op_set.ops.len()];
        for (idx, op) in op_set.ops.iter().enumerate() {
            if let Some(bytes) = &op.static_payload {
                resolved[idx] = Some(bytes.clone());
            }
        }
        Self {
            scratch_metadata: HashMap::new(),
            scratch_structured: HashMap::new(),
            capture_structured: HashMap::new(),
            resolved,
            path: SmallVec::new(),
        }
    }

    /// Write scratch captures into the request context.
    fn flush_to_ctx(&self, ctx: &mut HttpFilterContext<'_>) {
        for (key, text) in &self.scratch_metadata {
            ctx.set_metadata(key.clone(), text.clone());
        }
        for ((namespace, key), bytes) in &self.capture_structured {
            if let Ok(value) = serde_json::from_slice(bytes) {
                ctx.set_structured_metadata(namespace, key, value);
            }
        }
    }
}

/// Whether the walk should stop early (reserved; extract no longer stops mid-object).
enum WalkStep {
    /// Keep walking.
    Continue,
    /// Stop the walk (unused for extract-last; kept for call-site structure).
    Done,
}

// -----------------------------------------------------------------------------
// Entry
// -----------------------------------------------------------------------------

/// Reserve output bytes from input size and compile-time growth hint.
pub(super) fn rewrite_output_capacity(input_len: usize, growth_hint: usize) -> usize {
    if growth_hint == 0 {
        input_len
    } else {
        input_len + growth_hint + 64
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
    op_set: &CompiledOpSet,
    mode: RewriteMode,
    ctx: Option<&mut HttpFilterContext<'_>>,
) -> Result<RewriteOutcome, RewriteError> {
    let mut session = RewriteSession::new(op_set);
    if let Some(ctx) = ctx.as_deref() {
        preload_context_sources(op_set, ctx, &mut session);
    }

    let mut i = skip_bom(input);
    skip_ws(input, &mut i);
    if i >= input.len() {
        return Err(RewriteError::InvalidJson);
    }

    if let Some(root) = root_replace(op_set, &mut session) {
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
        .then(|| Vec::with_capacity(rewrite_output_capacity(input.len(), op_set.growth_hint)));

    match rewrite_value(input, &mut i, op_set, out.as_mut(), 0, &mut session)? {
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
    use super::index::OpPathIndex;

    let compiled = ops
        .iter()
        .map(|op| {
            let encoded_last_token = op.tokens.last().map(|t| super::skip::encode_json_string(t));
            CompiledOp {
                pointer: String::new(),
                tokens: op.tokens.clone(),
                kind: op.kind,
                source: op.payload.as_ref().map(|bytes| ValueSource::Static(bytes.clone())),
                dest: None,
                static_payload: op.payload.clone(),
                encoded_last_token,
            }
        })
        .collect::<Vec<_>>();
    let growth_hint = compiled
        .iter()
        .map(|op| op.static_payload.as_ref().map(|b| b.len()).unwrap_or(0))
        .sum();
    let index = OpPathIndex::build(&compiled);
    let op_set = CompiledOpSet {
        ops: compiled,
        index,
        growth_hint,
    };
    rewrite_document(input, &op_set, RewriteMode::Rewrite, None).map(|outcome| outcome.output.unwrap_or_default())
}

// -----------------------------------------------------------------------------
// Capture + lazy resolve
// -----------------------------------------------------------------------------

/// Decode a captured JSON span for `filter_metadata` (strings unescaped).
fn metadata_text(json: &[u8]) -> Option<String> {
    if json.first() == Some(&b'"') {
        serde_json::from_slice(json).ok()
    } else {
        String::from_utf8(json.to_vec()).ok()
    }
}

/// Capture an extract at `session.path` from `input[start..end]`.
///
/// Duplicate object keys: extract keeps the last match by overwriting. The walk
/// does not stop early; later siblings in the same object can still win.
fn store_capture(
    input: &[u8],
    start: usize,
    end: usize,
    op_set: &CompiledOpSet,
    session: &mut RewriteSession,
) -> WalkStep {
    if !op_set.index.extract_branch_at(&session.path) {
        return WalkStep::Continue;
    }

    if let Some(op_idx) = op_set.index.extract_at(&session.path) {
        let op = &op_set.ops[op_idx as usize];
        if let (Some(json), Some(dest)) = (input.get(start..end), op.dest.as_ref()) {
            write_capture_dest(json, dest, session);
        }
    }

    WalkStep::Continue
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
            session
                .capture_structured
                .insert((namespace.clone(), key.clone()), Bytes::copy_from_slice(json));
        },
    }
}

/// Skip one value and capture it if an extract matches `session.path`.
fn capture_value_at_path(
    input: &[u8],
    i: &mut usize,
    depth: u32,
    op_set: &CompiledOpSet,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    let start = *i;
    skip_value(input, i, depth)?;
    Ok(store_capture(input, start, *i, op_set, session))
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
fn preload_context_sources(op_set: &CompiledOpSet, ctx: &HttpFilterContext<'_>, session: &mut RewriteSession) {
    for op in &op_set.ops {
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

/// Resolve a mutating op's payload from cache, static bytes, or session scratch.
fn resolve_payload(op_idx: u32, op: &CompiledOp, session: &mut RewriteSession) -> Option<Bytes> {
    let idx = op_idx as usize;
    if let Some(cached) = session.resolved.get(idx).and_then(|slot| slot.as_ref()) {
        return Some(cached.clone());
    }
    if let Some(bytes) = &op.static_payload {
        return Some(bytes.clone());
    }
    let bytes = match op.source.as_ref()? {
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
    };
    if let Some(ref payload) = bytes {
        if let Some(slot) = session.resolved.get_mut(idx) {
            *slot = Some(payload.clone());
        }
    }
    bytes
}

/// Root-level replace payload, if configured and resolvable.
fn root_replace(op_set: &CompiledOpSet, session: &mut RewriteSession) -> Option<Bytes> {
    op_set
        .ops
        .iter()
        .enumerate()
        .find(|(_, op)| op.tokens.is_empty() && op.kind == OpKind::Replace)
        .and_then(|(idx, op)| resolve_payload(u32::try_from(idx).unwrap_or(0), op, session))
}

// -----------------------------------------------------------------------------
// Value walk
// -----------------------------------------------------------------------------

/// Rewrite one JSON value at `session.path`.
#[expect(clippy::too_many_arguments, reason = "walker state is threaded per recursive call")]
fn rewrite_value(
    input: &[u8],
    i: &mut usize,
    op_set: &CompiledOpSet,
    mut out: Option<&mut Vec<u8>>,
    depth: u32,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    skip_ws(input, i);
    if !op_set.index.has_descendant_ops(&session.path) {
        let start = *i;
        copy_span(input, i, depth, out.as_deref_mut())?;
        return Ok(store_capture(input, start, *i, op_set, session));
    }
    let start = *i;
    let kind = next_byte(input, *i)?;
    let step = match kind {
        b'{' => rewrite_object(input, i, op_set, out.as_deref_mut(), depth, session)?,
        b'[' => rewrite_array(input, i, op_set, out.as_deref_mut(), depth, session)?,
        _ => {
            *i = start;
            copy_span(input, i, depth, out)?;
            return Ok(store_capture(input, start, *i, op_set, session));
        },
    };
    if matches!(step, WalkStep::Done) {
        return Ok(WalkStep::Done);
    }
    Ok(store_capture(input, start, *i, op_set, session))
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
    op_set: &CompiledOpSet,
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

        if let Some(op_idx) = op_set.index.mutate_child_key(&session.path, key.as_ref()) {
            let op = &op_set.ops[op_idx as usize];
            if op.kind.is_mutating() {
                session.path.push(PathToken::Key(key.into_owned()));
                let step = apply_object_mutate(
                    input,
                    i,
                    key_span,
                    op_idx,
                    op,
                    &mut out,
                    &mut emitted_any,
                    depth,
                    op_set,
                    session,
                )?;
                if op.kind == OpKind::Add
                    && matches!(step, WalkStep::Continue)
                    && resolve_payload(op_idx, op, session).is_some()
                {
                    satisfied_add_keys.push(op.tokens.last().map_or("", String::as_str));
                }
                session.path.pop();
                if matches!(step, WalkStep::Done) {
                    return Ok(WalkStep::Done);
                }
                continue;
            }
        }

        if let Some(out) = out.as_mut() {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(key_span);
            out.push(b':');
        }
        if op_set.index.child_needs_rewrite(&session.path, key.as_ref()) {
            session.path.push(PathToken::Key(key.into_owned()));
            let step = rewrite_value(input, i, op_set, out.as_deref_mut(), depth, session)?;
            session.path.pop();
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
        } else {
            copy_span(input, i, depth, out.as_deref_mut())?;
        }
    }

    inject_object_adds(
        op_set,
        &satisfied_add_keys,
        out.as_deref_mut(),
        &mut emitted_any,
        session,
    );
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
    op_idx: u32,
    op: &CompiledOp,
    out: &mut Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    depth: u32,
    op_set: &CompiledOpSet,
    session: &mut RewriteSession,
) -> Result<WalkStep, RewriteError> {
    match op.kind {
        OpKind::Remove => capture_value_at_path(input, i, depth, op_set, session),
        OpKind::Replace | OpKind::Add => {
            skip_ws(input, i);
            let value_start = *i;
            let step = capture_value_at_path(input, i, depth, op_set, session)?;
            if matches!(step, WalkStep::Done) {
                return Ok(WalkStep::Done);
            }
            if let Some(out_buf) = out.as_mut() {
                if let Some(payload) = resolve_payload(op_idx, op, session) {
                    emit_separator(out_buf, emitted_any);
                    out_buf.extend_from_slice(key_span);
                    out_buf.push(b':');
                    out_buf.extend_from_slice(&payload);
                } else {
                    emit_original_member(input, value_start, *i, key_span, out_buf, emitted_any)?;
                }
            }
            Ok(step)
        },
        OpKind::Extract => Ok(WalkStep::Continue),
    }
}

/// Emit unsatisfied object `add` ops at `session.path` in config order.
fn inject_object_adds(
    op_set: &CompiledOpSet,
    satisfied: &[&str],
    out: Option<&mut Vec<u8>>,
    emitted_any: &mut bool,
    session: &mut RewriteSession,
) {
    let Some(out) = out else {
        return;
    };
    for (idx, op) in op_set.ops.iter().enumerate() {
        if op.kind != OpKind::Add || !parent_is(op, &session.path) {
            continue;
        }
        let Some(last) = op.tokens.last() else {
            continue;
        };
        if satisfied.contains(&last.as_str()) {
            continue;
        }
        let op_idx = u32::try_from(idx).unwrap_or(0);
        let Some(payload) = resolve_payload(op_idx, op, session) else {
            continue;
        };
        let Some(encoded) = &op.encoded_last_token else {
            continue;
        };
        emit_separator(out, emitted_any);
        out.extend_from_slice(encoded);
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
    op_set: &CompiledOpSet,
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

        if let Some(op_idx) = op_set.index.mutate_at_index(&session.path, orig_idx) {
            let op = &op_set.ops[op_idx as usize];
            if op.kind == OpKind::Add {
                if let Some(payload) = resolve_payload(op_idx, op, session)
                    && let Some(out) = out.as_mut()
                {
                    emit_separator(out, &mut emitted_any);
                    out.extend_from_slice(&payload);
                }
            }
        }

        let replace_remove = op_set
            .index
            .mutate_at_index(&session.path, orig_idx)
            .and_then(|op_idx| {
                let op = &op_set.ops[op_idx as usize];
                matches!(op.kind, OpKind::Remove | OpKind::Replace).then_some(op_idx)
            });

        if let Some(op_idx) = replace_remove {
            let op = &op_set.ops[op_idx as usize];
            session.path.push(PathToken::Index(orig_idx));
            let step = match op.kind {
                OpKind::Remove => capture_value_at_path(input, i, depth, op_set, session)?,
                OpKind::Replace => {
                    skip_ws(input, i);
                    let value_start = *i;
                    let cap = capture_value_at_path(input, i, depth, op_set, session)?;
                    if matches!(cap, WalkStep::Done) {
                        session.path.pop();
                        return Ok(WalkStep::Done);
                    }
                    if let Some(out_buf) = out.as_mut() {
                        emit_separator(out_buf, &mut emitted_any);
                        if let Some(payload) = resolve_payload(op_idx, op, session) {
                            out_buf.extend_from_slice(&payload);
                        } else {
                            copy_input_span(input, value_start, *i, out_buf)?;
                        }
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
            if op_set.index.child_index_needs_rewrite(&session.path, orig_idx) {
                session.path.push(PathToken::Index(orig_idx));
                let step = rewrite_value(input, i, op_set, out.as_deref_mut(), depth, session)?;
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

    if let Some(op_idx) = op_set.index.mutate_at_index(&session.path, orig_idx) {
        let op = &op_set.ops[op_idx as usize];
        if op.kind == OpKind::Add {
            if let Some(payload) = resolve_payload(op_idx, op, session)
                && let Some(out) = out.as_mut()
            {
                emit_separator(out, &mut emitted_any);
                out.extend_from_slice(&payload);
            }
        }
    }
    if let Some(op_idx) = op_set.index.add_append(&session.path) {
        let op = &op_set.ops[op_idx as usize];
        if let Some(payload) = resolve_payload(op_idx, op, session)
            && let Some(out) = out.as_mut()
        {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(&payload);
        }
    }

    if let Some(out) = out.as_mut() {
        out.push(b']');
    }
    Ok(WalkStep::Continue)
}

/// Whether `op.tokens[..len-1]` equals `path`.
fn parent_is(op: &CompiledOp, path: &[PathToken]) -> bool {
    op.tokens.len() == path.len() + 1 && path_eq_tokens(path, &op.tokens[..path.len()])
}

/// Insert a comma before the next emitted member or element.
fn emit_separator(out: &mut Vec<u8>, emitted_any: &mut bool) {
    if *emitted_any {
        out.push(b',');
    }
    *emitted_any = true;
}

/// Re-emit an object member whose mutating op was skipped (missing context).
fn emit_original_member(
    input: &[u8],
    value_start: usize,
    value_end: usize,
    key_span: &[u8],
    out: &mut Vec<u8>,
    emitted_any: &mut bool,
) -> Result<(), RewriteError> {
    emit_separator(out, emitted_any);
    out.extend_from_slice(key_span);
    out.push(b':');
    copy_input_span(input, value_start, value_end, out)
}

/// Copy `input[start..end]` into `out`.
fn copy_input_span(input: &[u8], start: usize, end: usize, out: &mut Vec<u8>) -> Result<(), RewriteError> {
    let span = input.get(start..end).ok_or(RewriteError::InvalidJson)?;
    out.extend_from_slice(span);
    Ok(())
}

/// Increment nesting; fail if [`MAX_JSON_DEPTH`] would be exceeded.
fn bump_depth(depth: u32) -> Result<u32, RewriteError> {
    let next = depth.saturating_add(1);
    if next > MAX_JSON_DEPTH {
        return Err(RewriteError::Depth);
    }
    Ok(next)
}

/// Parse a JSON string; returns the original quoted span and the decoded text.
fn parse_string<'a>(input: &'a [u8], i: &mut usize) -> Result<(&'a [u8], Cow<'a, str>), RewriteError> {
    let start = *i;
    let escaped = skip_string_with_meta(input, i)?;
    let raw = input.get(start..*i).ok_or(RewriteError::InvalidJson)?;
    let inner = raw
        .get(1..raw.len().saturating_sub(1))
        .ok_or(RewriteError::InvalidJson)?;
    if escaped {
        let decoded = serde_json::from_slice(raw).map_err(|_e| RewriteError::InvalidJson)?;
        Ok((raw, Cow::Owned(decoded)))
    } else {
        let decoded = std::str::from_utf8(inner).map_err(|_e| RewriteError::InvalidJson)?;
        Ok((raw, Cow::Borrowed(decoded)))
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::rewrite_output_capacity;

    #[test]
    fn remove_only_uses_input_len() {
        assert_eq!(rewrite_output_capacity(10_485_760, 0), 10_485_760);
    }

    #[test]
    fn growth_hint_adds_slack() {
        let hint = 100;
        assert_eq!(rewrite_output_capacity(1000, hint), 1000 + hint + 64);
    }

    #[test]
    fn zero_input_with_growth() {
        assert_eq!(rewrite_output_capacity(0, 10), 74);
    }
}
