// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared workload, fixtures, and DOM reference for `json_body` benchmarks.
//!
//! Fixtures mimic an OpenAI-style chat completion request body: `model`,
//! `messages`, `temperature`, `max_tokens`, and `stream`.

#![expect(
    clippy::min_ident_chars,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "benchmarks"
)]

use std::sync::LazyLock;

use praxis_filter::builtins::http::payload_processing::bench::{RequestOps, apply_request};
use serde_json::Value;

/// Default `json_body` max body size (10 MiB).
pub(crate) const TARGET_10_MIB: usize = 10_485_760;

/// YAML matching the json-body example workload (chat completion field paths).
pub(crate) const BENCH_YAML: &str = r"
request_extract:
  - pointer: /model
    metadata: original.model
request_replace:
  - pointer: /model
    value: forced-model
request_add:
  - pointer: /tenant
    value: acme
  - pointer: /original_model
    metadata: original.model
request_remove:
  - /secret
";

/// Benchmark body size labels and targets.
pub(crate) const BODY_SIZES: &[(&str, usize)] = &[
    ("10kiB", 10 * 1024),
    ("256kiB", 256 * 1024),
    ("512kiB", 512 * 1024),
    ("10miB", TARGET_10_MIB),
];

/// Where op-target keys sit in generated chat completion bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyLayout {
    /// `secret` appears before the `messages` array (early in the document).
    Prefix,
    /// `secret` appears after `messages` and sampling params (late in the document).
    Spread,
}

static REQUEST_OPS: LazyLock<RequestOps> =
    LazyLock::new(|| RequestOps::from_yaml(BENCH_YAML).expect("bench YAML must compile"));

static BODIES_PREFIX_10_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Prefix, 10 * 1024));
static BODIES_PREFIX_256_KIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Prefix, 256 * 1024));
static BODIES_PREFIX_512_KIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Prefix, 512 * 1024));
static BODIES_PREFIX_10_MIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Prefix, TARGET_10_MIB));

static BODIES_SPREAD_10_KIB: LazyLock<Vec<u8>> = LazyLock::new(|| make_json_body(BodyLayout::Spread, 10 * 1024));
static BODIES_SPREAD_256_KIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Spread, 256 * 1024));
static BODIES_SPREAD_512_KIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Spread, 512 * 1024));
static BODIES_SPREAD_10_MIB: LazyLock<Vec<u8>> =
    LazyLock::new(|| make_json_body(BodyLayout::Spread, TARGET_10_MIB));

/// Compiled tokenizer ops for the example workload.
pub(crate) fn request_ops() -> &'static RequestOps {
    &REQUEST_OPS
}

/// Pre-generated body for a layout and size label.
pub(crate) fn body_for_layout(layout: BodyLayout, label: &str) -> &'static [u8] {
    match (layout, label) {
        (BodyLayout::Prefix, "10kiB") => BODIES_PREFIX_10_KIB.as_slice(),
        (BodyLayout::Prefix, "256kiB") => BODIES_PREFIX_256_KIB.as_slice(),
        (BodyLayout::Prefix, "512kiB") => BODIES_PREFIX_512_KIB.as_slice(),
        (BodyLayout::Prefix, "10miB") => BODIES_PREFIX_10_MIB.as_slice(),
        (BodyLayout::Spread, "10kiB") => BODIES_SPREAD_10_KIB.as_slice(),
        (BodyLayout::Spread, "256kiB") => BODIES_SPREAD_256_KIB.as_slice(),
        (BodyLayout::Spread, "512kiB") => BODIES_SPREAD_512_KIB.as_slice(),
        (BodyLayout::Spread, "10miB") => BODIES_SPREAD_10_MIB.as_slice(),
        (_, other) => panic!("unknown body size label: {other}"),
    }
}

/// Tokenizer path used by Criterion and heap benches.
pub(crate) fn tokenizer_apply(body: &[u8]) -> Vec<u8> {
    apply_request(body, request_ops()).expect("tokenizer apply must succeed on fixtures")
}

/// DOM reference: parse → pointer mutations → serialize.
pub(crate) fn dom_apply_request(body: &[u8]) -> Vec<u8> {
    let mut root: Value = serde_json::from_slice(body).expect("fixture must be valid JSON");

    let extracted_model = pointer_get(&root, &["model".to_owned()])
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .expect("/model must exist on fixtures");

    pointer_replace(&mut root, &["model".to_owned()], Value::String("forced-model".into()));
    pointer_add(&mut root, &["tenant".to_owned()], Value::String("acme".into()));
    pointer_add(
        &mut root,
        &["original_model".to_owned()],
        Value::String(extracted_model),
    );
    pointer_remove(&mut root, &["secret".to_owned()]);

    serde_json::to_vec(&root).expect("serialize DOM result")
}

/// Assert tokenizer and DOM paths produce equivalent JSON values.
pub(crate) fn assert_output_equivalent(body: &[u8]) {
    let tok = tokenizer_apply(body);
    let dom = dom_apply_request(body);
    let tok_val: Value = serde_json::from_slice(&tok).expect("tokenizer output must be JSON");
    let dom_val: Value = serde_json::from_slice(&dom).expect("DOM output must be JSON");
    assert_eq!(tok_val, dom_val, "tokenizer and DOM paths must match semantically");
}

/// Assert equivalence for every registered layout at 256 KiB.
pub(crate) fn assert_all_layouts_equivalent() {
    for layout in [BodyLayout::Prefix, BodyLayout::Spread] {
        assert_output_equivalent(body_for_layout(layout, "256kiB"));
    }
}

/// Build a chat completion request body of at least `target_bytes`.
pub(crate) fn make_json_body(layout: BodyLayout, target_bytes: usize) -> Vec<u8> {
    let mut body = String::with_capacity(target_bytes + 256);
    body.push('{');
    let mut first = true;

    emit_member(&mut body, &mut first, r#""model":"old""#);
    if layout == BodyLayout::Prefix {
        emit_member(&mut body, &mut first, r#""secret":"s3cret""#);
    }

    emit_member(&mut body, &mut first, r#""messages":["#);
    let mut first_msg = true;
    let mut turn = 0usize;
    let trailer_len = chat_trailer_len(layout);
    while body.len() + trailer_len + 1 < target_bytes {
        append_message_turn(&mut body, turn, &mut first_msg);
        turn += 1;
    }
    pad_messages_to_target(&mut body, &mut first_msg, target_bytes, trailer_len);
    body.push(']');

    emit_chat_trailer(&mut body, &mut first);
    if layout == BodyLayout::Spread {
        emit_member(&mut body, &mut first, r#""secret":"s3cret""#);
    }
    body.push('}');

    assert!(
        body.len() >= target_bytes,
        "chat fixture must reach target size: got {} want {target_bytes}",
        body.len()
    );
    assert!(
        body.contains(r#""messages":["#) && body.contains(r#""role":"#),
        "fixture must look like chat completion JSON"
    );
    body.into_bytes()
}

/// Bytes for sampling params, optional late `secret`, and closing `}`.
fn chat_trailer_len(layout: BodyLayout) -> usize {
    let mut len = 1 + r#","temperature":0.7,"max_tokens":4096,"stream":false"#.len();
    if layout == BodyLayout::Spread {
        len += r#","secret":"s3cret""#.len();
    }
    len + 1
}

fn pad_messages_to_target(body: &mut String, first_msg: &mut bool, target_bytes: usize, trailer_len: usize) {
    let closing = 1;
    let deficit = target_bytes.saturating_sub(body.len() + trailer_len + closing);
    if deficit <= 2 {
        return;
    }
    // {"role":"user","content":"..."} with ASCII padding (no JSON escapes needed).
    const OVERHEAD: usize = r#"{"role":"user","content":""}"#.len();
    if deficit <= OVERHEAD {
        return;
    }
    let pad_len = deficit - OVERHEAD;
    if !*first_msg {
        body.push(',');
    }
    *first_msg = false;
    body.push_str(r#"{"role":"user","content":""#);
    body.push_str(&"x".repeat(pad_len));
    body.push_str(r#""}"#);
}

fn emit_chat_trailer(body: &mut String, first: &mut bool) {
    emit_member(body, first, r#""temperature":0.7"#);
    emit_member(body, first, r#""max_tokens":4096"#);
    emit_member(body, first, r#""stream":false"#);
}

fn append_message_turn(body: &mut String, turn: usize, first_msg: &mut bool) {
    if !*first_msg {
        body.push(',');
    }
    *first_msg = false;

    let role = match turn % 3 {
        0 => "system",
        1 => "user",
        _ => "assistant",
    };
    let content = if turn == 0 {
        "You are a helpful assistant.".to_owned()
    } else {
        format!("bench-turn-{turn}: {}", "x".repeat(48 + (turn % 16)))
    };
    let _ = std::fmt::Write::write_fmt(
        body,
        format_args!(r#"{{"role":"{role}","content":"{content}"}}"#),
    );
}

fn emit_member(body: &mut String, first: &mut bool, member: &str) {
    if !*first {
        body.push(',');
    }
    *first = false;
    body.push_str(member);
}

fn pointer_get<'a>(value: &'a Value, tokens: &[String]) -> Option<&'a Value> {
    tokens.iter().try_fold(value, |current, token| match current {
        Value::Object(map) => map.get(token),
        _ => None,
    })
}

fn pointer_get_mut<'a>(value: &'a mut Value, tokens: &[String]) -> Option<&'a mut Value> {
    if tokens.is_empty() {
        return Some(value);
    }
    let (head, tail) = tokens.split_first()?;
    match value {
        Value::Object(map) => {
            let child = map.get_mut(head)?;
            pointer_get_mut(child, tail)
        },
        _ => None,
    }
}

fn pointer_add(root: &mut Value, tokens: &[String], new_value: Value) {
    if tokens.is_empty() {
        *root = new_value;
        return;
    }
    if tokens.len() == 1 {
        if let Value::Object(map) = root {
            map.insert(tokens[0].clone(), new_value);
        }
        return;
    }
    if let Some(parent) = pointer_get_mut(root, &tokens[..tokens.len() - 1]) {
        if let Value::Object(map) = parent {
            map.insert(tokens[tokens.len() - 1].clone(), new_value);
        }
    }
}

fn pointer_replace(root: &mut Value, tokens: &[String], new_value: Value) {
    if let Some(target) = pointer_get_mut(root, tokens) {
        *target = new_value;
    }
}

fn pointer_remove(root: &mut Value, tokens: &[String]) {
    if tokens.is_empty() {
        return;
    }
    if tokens.len() == 1 {
        if let Value::Object(map) = root {
            map.remove(&tokens[0]);
        }
        return;
    }
    if let Some(parent) = pointer_get_mut(root, &tokens[..tokens.len() - 1]) {
        if let Value::Object(map) = parent {
            map.remove(&tokens[tokens.len() - 1]);
        }
    }
}
