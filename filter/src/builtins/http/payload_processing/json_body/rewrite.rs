// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! One-pass JSON Pointer rewriter: tokenize, copy unmatched spans, splice ops.
//!
//! Does not build a `serde_json::Value` tree. Injected literals are
//! pre-serialized JSON bytes.

use bytes::Bytes;

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

/// A captured JSON span ready to write to context.
#[derive(Clone, Debug)]
pub(super) struct ExtractedValue {
    /// Context destination.
    pub dest: ExtractDest,
    /// Exact source bytes of the JSON value.
    pub json: Bytes,
}

/// An operation with values already resolved from context.
#[derive(Clone, Debug)]
pub(super) struct ResolvedOp {
    /// Decoded pointer tokens (empty = root).
    pub tokens: Vec<String>,
    /// Operation kind.
    pub kind: OpKind,
    /// Serialized JSON to inject; `None` for remove.
    pub payload: Option<Bytes>,
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
// Entry
// -----------------------------------------------------------------------------

/// Rewrite `input` as a single JSON value, applying `ops` in one walk.
///
/// # Errors
///
/// Returns [`RewriteError`] when the input is not valid JSON or is nested
/// deeper than [`MAX_JSON_DEPTH`].
pub(super) fn rewrite(input: &[u8], ops: &[ResolvedOp]) -> Result<Vec<u8>, RewriteError> {
    let mut i = skip_bom(input);
    skip_ws(input, &mut i);
    if i >= input.len() {
        return Err(RewriteError::InvalidJson);
    }

    if let Some(root) = root_replace(ops) {
        skip_value(input, &mut i, 0)?;
        skip_ws(input, &mut i);
        if i != input.len() {
            return Err(RewriteError::InvalidJson);
        }
        return Ok(root.to_vec());
    }

    let mut out = Vec::with_capacity(input.len());
    rewrite_value(input, &mut i, &[], ops, &mut out, 0)?;
    skip_ws(input, &mut i);
    if i != input.len() {
        return Err(RewriteError::InvalidJson);
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// Extract
// -----------------------------------------------------------------------------

/// Walk `input` and capture JSON spans for each extract op.
///
/// Stops once every op has been satisfied. Trailing bytes after that are
/// not validated. Missing pointers simply omit a capture.
///
/// # Errors
///
/// Returns [`RewriteError`] when the input is not valid JSON before all
/// extracts are found, or nesting exceeds [`MAX_JSON_DEPTH`].
pub(super) fn extract(input: &[u8], ops: &[ExtractOp]) -> Result<Vec<ExtractedValue>, RewriteError> {
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    let mut walker = ExtractWalker {
        input,
        i: skip_bom(input),
        ops,
        captures: Vec::with_capacity(ops.len()),
        satisfied: vec![false; ops.len()],
    };
    skip_ws(walker.input, &mut walker.i);
    if walker.i >= walker.input.len() {
        return Err(RewriteError::InvalidJson);
    }
    extract_value(&mut walker, &[], 0)?;
    Ok(walker.captures)
}

/// Whether the extract walk should keep parsing siblings.
enum Step {
    /// Keep walking.
    Continue,
    /// Every extract op is satisfied.
    Done,
}

/// Path-stack extract walker (no output buffer).
struct ExtractWalker<'a> {
    /// Full input.
    input: &'a [u8],
    /// Cursor.
    i: usize,
    /// Configured extracts.
    ops: &'a [ExtractOp],
    /// Captures in the order they were found.
    captures: Vec<ExtractedValue>,
    /// Parallel to `ops`: whether each extract has been captured.
    satisfied: Vec<bool>,
}

impl ExtractWalker<'_> {
    /// Capture `input[start..i]` if an unsatisfied extract matches `path`.
    fn try_capture(&mut self, path: &[String], start: usize) -> Step {
        for (idx, op) in self.ops.iter().enumerate() {
            if self.satisfied.get(idx).copied() == Some(true) || op.tokens != path {
                continue;
            }
            let Some(json) = self.input.get(start..self.i) else {
                continue;
            };
            self.captures.push(ExtractedValue {
                dest: op.dest.clone(),
                json: Bytes::copy_from_slice(json),
            });
            if let Some(flag) = self.satisfied.get_mut(idx) {
                *flag = true;
            }
            break;
        }
        if self.satisfied.iter().all(|s| *s) {
            Step::Done
        } else {
            Step::Continue
        }
    }
}

/// Extract one JSON value at `path`.
fn extract_value(w: &mut ExtractWalker<'_>, path: &[String], depth: u32) -> Result<Step, RewriteError> {
    skip_ws(w.input, &mut w.i);
    let start = w.i;
    let step = match next_byte(w.input, w.i)? {
        b'{' => extract_object(w, path, depth)?,
        b'[' => extract_array(w, path, depth)?,
        _ => {
            skip_value(w.input, &mut w.i, depth)?;
            Step::Continue
        },
    };
    if matches!(step, Step::Done) {
        return Ok(Step::Done);
    }
    Ok(w.try_capture(path, start))
}

/// Walk an object, extracting matching members; stop when all extracts are found.
#[expect(clippy::too_many_lines, reason = "object member walk is a linear tokenizer loop")]
fn extract_object(w: &mut ExtractWalker<'_>, path: &[String], depth: u32) -> Result<Step, RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(w.input, &mut w.i, b'{')?;
    let mut seen_member = false;
    let mut seen_op_keys: Vec<String> = Vec::new();
    loop {
        skip_ws(w.input, &mut w.i);
        if next_byte(w.input, w.i)? == b'}' {
            w.i += 1;
            return Ok(Step::Continue);
        }
        if seen_member {
            expect_byte(w.input, &mut w.i, b',')?;
            skip_ws(w.input, &mut w.i);
            if next_byte(w.input, w.i)? == b'}' {
                return Err(RewriteError::InvalidJson);
            }
        }
        seen_member = true;
        let (_, key) = parse_string(w.input, &mut w.i)?;
        skip_ws(w.input, &mut w.i);
        expect_byte(w.input, &mut w.i, b':')?;
        let first_for_key = !seen_op_keys.iter().any(|k| k == &key);
        if first_for_key {
            seen_op_keys.push(key.clone());
            let mut child_path = path.to_vec();
            child_path.push(key);
            if matches!(extract_value(w, &child_path, depth)?, Step::Done) {
                return Ok(Step::Done);
            }
        } else {
            skip_value(w.input, &mut w.i, depth)?;
        }
    }
}

/// Walk an array, extracting matching indices; stop when all extracts are found.
fn extract_array(w: &mut ExtractWalker<'_>, path: &[String], depth: u32) -> Result<Step, RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(w.input, &mut w.i, b'[')?;
    let mut orig_idx: usize = 0;
    loop {
        skip_ws(w.input, &mut w.i);
        if next_byte(w.input, w.i)? == b']' {
            w.i += 1;
            return Ok(Step::Continue);
        }
        if orig_idx > 0 {
            expect_byte(w.input, &mut w.i, b',')?;
            skip_ws(w.input, &mut w.i);
            if next_byte(w.input, w.i)? == b']' {
                return Err(RewriteError::InvalidJson);
            }
        }
        let mut child_path = path.to_vec();
        child_path.push(orig_idx.to_string());
        if matches!(extract_value(w, &child_path, depth)?, Step::Done) {
            return Ok(Step::Done);
        }
        orig_idx = orig_idx.saturating_add(1);
    }
}

/// Root `replace` payload, if configured.
fn root_replace(ops: &[ResolvedOp]) -> Option<&Bytes> {
    ops.iter()
        .find(|op| op.tokens.is_empty() && op.kind == OpKind::Replace)
        .and_then(|op| op.payload.as_ref())
}

// -----------------------------------------------------------------------------
// Value walk
// -----------------------------------------------------------------------------

/// Rewrite one JSON value at `path`.
#[expect(clippy::too_many_arguments, reason = "walker state is threaded per recursive call")]
fn rewrite_value(
    input: &[u8],
    i: &mut usize,
    path: &[String],
    ops: &[ResolvedOp],
    out: &mut Vec<u8>,
    depth: u32,
) -> Result<(), RewriteError> {
    skip_ws(input, i);
    let c = next_byte(input, *i)?;
    match c {
        b'{' => rewrite_object(input, i, path, ops, out, depth),
        b'[' => rewrite_array(input, i, path, ops, out, depth),
        _ => copy_scalar(input, i, out, depth),
    }
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
    path: &[String],
    ops: &[ResolvedOp],
    out: &mut Vec<u8>,
    depth: u32,
) -> Result<(), RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'{')?;
    out.push(b'{');

    let mut emitted_any = false;
    let mut seen_input_member = false;
    let mut satisfied_add_keys: Vec<&str> = Vec::new();
    let mut seen_op_keys: Vec<String> = Vec::new();

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

        let first_for_key = !seen_op_keys.iter().any(|k| k == &key);
        if first_for_key {
            seen_op_keys.push(key.clone());
        }

        if first_for_key && let Some(op) = mutate_for_child(ops, path, &key) {
            match op.kind {
                OpKind::Remove => skip_value(input, i, depth)?,
                OpKind::Replace | OpKind::Add => {
                    let Some(payload) = op.payload.as_ref() else {
                        skip_value(input, i, depth)?;
                        continue;
                    };
                    emit_separator(out, &mut emitted_any);
                    out.extend_from_slice(key_span);
                    out.push(b':');
                    out.extend_from_slice(payload);
                    skip_value(input, i, depth)?;
                    if op.kind == OpKind::Add {
                        satisfied_add_keys.push(op.tokens.last().map_or("", String::as_str));
                    }
                },
                OpKind::Extract => {},
            }
            continue;
        }

        emit_separator(out, &mut emitted_any);
        out.extend_from_slice(key_span);
        out.push(b':');
        let mut child_path = path.to_vec();
        child_path.push(key);
        rewrite_value(input, i, &child_path, ops, out, depth)?;
    }

    inject_object_adds(ops, path, &satisfied_add_keys, out, &mut emitted_any);
    out.push(b'}');
    Ok(())
}

/// Emit unsatisfied object `add` ops at `path` in config order.
fn inject_object_adds(
    ops: &[ResolvedOp],
    path: &[String],
    satisfied: &[&str],
    out: &mut Vec<u8>,
    emitted_any: &mut bool,
) {
    for op in ops {
        if op.kind != OpKind::Add || !parent_is(op, path) {
            continue;
        }
        let Some(last) = op.tokens.last() else {
            continue;
        };
        if satisfied.contains(&last.as_str()) {
            continue;
        }
        let Some(payload) = op.payload.as_ref() else {
            continue;
        };
        emit_separator(out, emitted_any);
        if let Ok(encoded) = serde_json::to_vec(last) {
            out.extend_from_slice(&encoded);
        }
        out.push(b':');
        out.extend_from_slice(payload);
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
    path: &[String],
    ops: &[ResolvedOp],
    out: &mut Vec<u8>,
    depth: u32,
) -> Result<(), RewriteError> {
    let depth = bump_depth(depth)?;
    expect_byte(input, i, b'[')?;
    out.push(b'[');

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

        let idx_token = orig_idx.to_string();
        if let Some(op) = add_at_index(ops, path, orig_idx)
            && let Some(payload) = op.payload.as_ref()
        {
            emit_separator(out, &mut emitted_any);
            out.extend_from_slice(payload);
        }

        if let Some(op) = mutate_for_child(ops, path, &idx_token) {
            match op.kind {
                OpKind::Remove => skip_value(input, i, depth)?,
                OpKind::Replace => {
                    if let Some(payload) = op.payload.as_ref() {
                        emit_separator(out, &mut emitted_any);
                        out.extend_from_slice(payload);
                    }
                    skip_value(input, i, depth)?;
                },
                OpKind::Add => {
                    // Insert is handled above; overlapping add+replace at the
                    // same index is a config error, so the original element is copied.
                    emit_separator(out, &mut emitted_any);
                    let mut child_path = path.to_vec();
                    child_path.push(idx_token);
                    rewrite_value(input, i, &child_path, ops, out, depth)?;
                },
                OpKind::Extract => {},
            }
        } else {
            emit_separator(out, &mut emitted_any);
            let mut child_path = path.to_vec();
            child_path.push(idx_token);
            rewrite_value(input, i, &child_path, ops, out, depth)?;
        }
        orig_idx = orig_idx.saturating_add(1);
    }

    if let Some(op) = add_at_index(ops, path, orig_idx)
        && let Some(payload) = op.payload.as_ref()
    {
        emit_separator(out, &mut emitted_any);
        out.extend_from_slice(payload);
    }
    if let Some(op) = add_append(ops, path)
        && let Some(payload) = op.payload.as_ref()
    {
        emit_separator(out, &mut emitted_any);
        out.extend_from_slice(payload);
    }

    out.push(b']');
    Ok(())
}

/// Copy a scalar (string, number, literal) verbatim.
fn copy_scalar(input: &[u8], i: &mut usize, out: &mut Vec<u8>, depth: u32) -> Result<(), RewriteError> {
    let start = *i;
    skip_value(input, i, depth)?;
    let span = input.get(start..*i).ok_or(RewriteError::InvalidJson)?;
    out.extend_from_slice(span);
    Ok(())
}

// -----------------------------------------------------------------------------
// Op lookup
// -----------------------------------------------------------------------------

/// First mutating op whose parent path is `path` and last token equals `last`.
fn mutate_for_child<'a>(ops: &'a [ResolvedOp], path: &[String], last: &str) -> Option<&'a ResolvedOp> {
    ops.iter()
        .find(|op| op.kind.is_mutating() && parent_is(op, path) && op.tokens.last().is_some_and(|t| t == last))
}

/// Add targeting array index `idx` at `path`.
fn add_at_index<'a>(ops: &'a [ResolvedOp], path: &[String], idx: usize) -> Option<&'a ResolvedOp> {
    ops.iter().find(|op| {
        op.kind == OpKind::Add && parent_is(op, path) && op.tokens.last().and_then(|t| array_index(t)) == Some(idx)
    })
}

/// Add targeting `/path/-` (append).
fn add_append<'a>(ops: &'a [ResolvedOp], path: &[String]) -> Option<&'a ResolvedOp> {
    ops.iter()
        .find(|op| op.kind == OpKind::Add && parent_is(op, path) && op.tokens.last().is_some_and(|t| t == "-"))
}

/// Whether `op.tokens[..len-1]` equals `path`.
fn parent_is(op: &ResolvedOp, path: &[String]) -> bool {
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
fn parse_string<'a>(input: &'a [u8], i: &mut usize) -> Result<(&'a [u8], String), RewriteError> {
    let start = *i;
    skip_string(input, i)?;
    let raw = input.get(start..*i).ok_or(RewriteError::InvalidJson)?;
    let decoded = serde_json::from_slice(raw).map_err(|_e| RewriteError::InvalidJson)?;
    Ok((raw, decoded))
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
