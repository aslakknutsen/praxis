// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the JSON body pointer filter.

use bytes::Bytes;
use serde_json::json;

use super::{
    JsonBodyFilter,
    pointer::compile_pointer,
    rewrite::{OpKind, ResolvedOp, RewriteError, rewrite},
};
use crate::FilterAction;

// -----------------------------------------------------------------------------
// Rewrite helpers
// -----------------------------------------------------------------------------

fn resolved(kind: OpKind, pointer: &str, payload: Option<&str>) -> ResolvedOp {
    ResolvedOp {
        tokens: compile_pointer(pointer).unwrap(),
        kind,
        payload: payload.map(|s| Bytes::from(s.to_owned())),
    }
}

fn rewrite_str(input: &str, ops: &[ResolvedOp]) -> Result<String, RewriteError> {
    rewrite(input.as_bytes(), ops).map(|b| String::from_utf8(b).unwrap())
}

fn parse_filter(yaml: &str) -> Box<dyn crate::HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    JsonBodyFilter::from_config(&value).unwrap()
}

fn parse_err(yaml: &str) -> String {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    JsonBodyFilter::from_config(&value).err().unwrap().to_string()
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

#[test]
fn parses_header_like_config() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /tenant
            value: acme
        request_remove:
          - /password
        request_replace:
          - pointer: /model
            value: forced-model
        "#,
    );
    assert_eq!(filter.name(), "json_body", "filter type name");
}

#[test]
fn rejects_empty_ops() {
    let err = parse_err("{}");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn rejects_response_add() {
    let err = parse_err(
        r#"
        response_add:
          - pointer: /x
            value: 1
        "#,
    );
    assert!(err.contains("response_add"), "got: {err}");
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn rejects_response_replace() {
    let err = parse_err(
        r#"
        response_replace:
          - pointer: /x
            value: 1
        "#,
    );
    assert!(err.contains("response_replace"), "got: {err}");
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn rejects_overlapping_pointers() {
    let err = parse_err(
        r#"
        request_remove:
          - /a
          - /a/b
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn rejects_same_pointer_twice() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
            value: 1
        request_remove:
          - /a
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn rejects_root_remove() {
    let err = parse_err("request_remove:\n  - \"\"");
    assert!(err.contains("document root"), "got: {err}");
}

#[test]
fn rejects_missing_value_source() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn rejects_both_value_and_metadata() {
    let err = parse_err(
        r#"
        request_add:
          - pointer: /a
            value: 1
            metadata: foo
        "#,
    );
    assert!(
        err.contains("exactly one") || err.contains("unknown field") || err.contains("data did not match"),
        "got: {err}"
    );
}

// -----------------------------------------------------------------------------
// Tokenizer: objects
// -----------------------------------------------------------------------------

#[test]
fn replace_object_field() {
    let out = rewrite_str(
        r#"{"model":"old","n":1}"#,
        &[resolved(OpKind::Replace, "/model", Some(r#""forced""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"model":"forced","n":1}"#);
}

#[test]
fn replace_missing_is_noop() {
    let out = rewrite_str(r#"{"n":1}"#, &[resolved(OpKind::Replace, "/model", Some(r#""x""#))]).unwrap();
    assert_eq!(out, r#"{"n":1}"#);
}

#[test]
fn remove_first_middle_last_only() {
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap(),
        r#"{"b":2,"c":3}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/b", None)]).unwrap(),
        r#"{"a":1,"c":3}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1,"b":2,"c":3}"#, &[resolved(OpKind::Remove, "/c", None)]).unwrap(),
        r#"{"a":1,"b":2}"#
    );
    assert_eq!(
        rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap(),
        "{}"
    );
}

#[test]
fn remove_missing_is_noop() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Remove, "/nope", None)]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

#[test]
fn add_missing_object_field() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/b", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a":1,"b":2}"#);
}

#[test]
fn add_to_empty_object() {
    let out = rewrite_str("{}", &[resolved(OpKind::Add, "/k", Some(r#""v""#))]).unwrap();
    assert_eq!(out, r#"{"k":"v"}"#);
}

#[test]
fn add_existing_object_key_overwrites() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9}"#);
}

#[test]
fn missing_parent_skips_add() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/x/y", Some("1"))]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

#[test]
fn duplicate_keys_remove_all_matches() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Remove, "/a", None)]).unwrap();
    assert_eq!(out, "{}");
}

#[test]
fn duplicate_keys_replace_all_matches() {
    let out = rewrite_str(r#"{"a":1,"a":2,"b":3}"#, &[resolved(OpKind::Replace, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9,"a":9,"b":3}"#);
}

#[test]
fn duplicate_keys_add_replaces_all_existing() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Add, "/a", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"a":9,"a":9}"#);
}

#[test]
fn untargeted_duplicate_keys_are_preserved() {
    let out = rewrite_str(r#"{"a":1,"a":2}"#, &[resolved(OpKind::Add, "/b", Some("3"))]).unwrap();
    assert_eq!(out, r#"{"a":1,"a":2,"b":3}"#);
}

#[test]
fn remove_object_valued_field() {
    let out = rewrite_str(
        r#"{"keep":1,"drop":{"x":2}}"#,
        &[resolved(OpKind::Remove, "/drop", None)],
    )
    .unwrap();
    assert_eq!(out, r#"{"keep":1}"#);
}

#[test]
fn nested_replace() {
    let out = rewrite_str(
        r#"{"user":{"id":"old","n":1}}"#,
        &[resolved(OpKind::Replace, "/user/id", Some(r#""new""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"user":{"id":"new","n":1}}"#);
}

#[test]
fn unused_nested_object_and_array_are_copied() {
    let out = rewrite_str(
        r#"{"model":"old","obj":{"id":1,"tag":"bench"},"arr":["a","b","0"]}"#,
        &[
            resolved(OpKind::Replace, "/model", Some(r#""forced""#)),
            resolved(OpKind::Add, "/tenant", Some(r#""acme""#)),
        ],
    )
    .unwrap();
    let got: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        got,
        json!({"model":"forced","obj":{"id":1,"tag":"bench"},"arr":["a","b","0"],"tenant":"acme"})
    );
}

#[test]
fn escaped_pointer_key() {
    let out = rewrite_str(r#"{"a/b":1}"#, &[resolved(OpKind::Replace, "/a~1b", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a/b":2}"#);
}

#[test]
fn escaped_key_extract_and_replace() {
    let out = rewrite_str(
        r#"{"a/b":{"x":1},"keep":true}"#,
        &[resolved(OpKind::Replace, "/a~1b/x", Some("2"))],
    )
    .unwrap();
    assert_eq!(out, r#"{"a/b":{"x":2},"keep":true}"#);
}

#[test]
fn root_replace() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Replace, "", Some("[1,2]"))]).unwrap();
    assert_eq!(out, "[1,2]");
}

// -----------------------------------------------------------------------------
// Tokenizer: arrays
// -----------------------------------------------------------------------------

#[test]
fn array_replace_index() {
    let out = rewrite_str("[1,2,3]", &[resolved(OpKind::Replace, "/1", Some("9"))]).unwrap();
    assert_eq!(out, "[1,9,3]");
}

#[test]
fn array_remove_index() {
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/0", None)]).unwrap(),
        "[2,3]"
    );
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/1", None)]).unwrap(),
        "[1,3]"
    );
    assert_eq!(
        rewrite_str("[1,2,3]", &[resolved(OpKind::Remove, "/2", None)]).unwrap(),
        "[1,2]"
    );
}

#[test]
fn array_insert_at_index() {
    let out = rewrite_str("[1,3]", &[resolved(OpKind::Add, "/1", Some("2"))]).unwrap();
    assert_eq!(out, "[1,2,3]");
}

#[test]
fn array_append() {
    let out = rewrite_str("[1]", &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, "[1,2]");
}

#[test]
fn array_append_empty() {
    let out = rewrite_str("[]", &[resolved(OpKind::Add, "/-", Some("1"))]).unwrap();
    assert_eq!(out, "[1]");
}

#[test]
fn array_insert_at_length() {
    let out = rewrite_str("[1,2]", &[resolved(OpKind::Add, "/2", Some("3"))]).unwrap();
    assert_eq!(out, "[1,2,3]");
}

#[test]
fn array_out_of_range_add_skipped() {
    let out = rewrite_str("[1]", &[resolved(OpKind::Add, "/3", Some("9"))]).unwrap();
    assert_eq!(out, "[1]");
}

#[test]
fn array_append_on_object_is_skipped() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"a":1}"#, "add / - is array-only; objects are left unchanged");
}

#[test]
fn array_append_does_not_replace_object_dash_key() {
    let out = rewrite_str(r#"{"-":1}"#, &[resolved(OpKind::Add, "/-", Some("2"))]).unwrap();
    assert_eq!(out, r#"{"-":1}"#, "array append must not rewrite object key '-'");
}

#[test]
fn numeric_pointer_replace_on_object_key() {
    let out = rewrite_str(r#"{"0":1,"a":2}"#, &[resolved(OpKind::Replace, "/0", Some("9"))]).unwrap();
    assert_eq!(out, r#"{"0":9,"a":2}"#);
}

#[test]
fn numeric_pointer_add_on_object_emits_key() {
    let out = rewrite_str(r#"{"a":1}"#, &[resolved(OpKind::Add, "/0", Some("9"))]).unwrap();
    let got: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("rewrite must emit valid JSON, got {out:?}: {e}"));
    assert_eq!(got, json!({"a": 1, "0": 9}));
}

// -----------------------------------------------------------------------------
// Invalid JSON
// -----------------------------------------------------------------------------

#[test]
fn invalid_json_errors() {
    assert_eq!(rewrite_str("{", &[]).unwrap_err(), RewriteError::InvalidJson);
    assert_eq!(rewrite_str(r#"{"a":1,}"#, &[]).unwrap_err(), RewriteError::InvalidJson);
    assert_eq!(rewrite_str("true extra", &[]).unwrap_err(), RewriteError::InvalidJson);
}

#[test]
fn depth_exceeded_errors() {
    let mut nested = String::from("1");
    for _ in 0..130 {
        nested = format!("[{nested}]");
    }
    assert_eq!(rewrite_str(&nested, &[]).unwrap_err(), RewriteError::Depth);
}

#[test]
fn pretty_printed_object_rewrites() {
    let input = "{\n  \"a\": 1,\n  \"b\": 2\n}";
    let out = rewrite_str(input, &[resolved(OpKind::Remove, "/b", None)]).unwrap();
    assert_eq!(out, r#"{"a":1}"#);
}

// -----------------------------------------------------------------------------
// Filter hooks
// -----------------------------------------------------------------------------

#[tokio::test]
async fn request_rewrite_at_eos() {
    let filter = parse_filter(
        r#"
        request_replace:
          - pointer: /model
            value: forced-model
        request_remove:
          - /secret
        request_add:
          - pointer: /tenant
            value: acme
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","secret":"x"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone), "EOS rewrite returns BodyDone");
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model":"forced-model","tenant":"acme"}));
}

#[tokio::test]
async fn request_continues_before_eos() {
    let filter = parse_filter(
        r#"
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "partial chunks pass through");
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"a":1}"#);
}

#[tokio::test]
async fn metadata_value_is_injected_as_json_string() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /method
            metadata: json_rpc.method
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("json_rpc.method", "eth_blockNumber");
    let mut body = Some(Bytes::from_static(br#"{"jsonrpc":"2.0"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got["method"], "eth_blockNumber");
}

#[tokio::test]
async fn missing_metadata_skips_op() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /rpc/method
            metadata: json_rpc.method
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"jsonrpc":"2.0"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"jsonrpc":"2.0"}));
}

#[tokio::test]
async fn structured_metadata_injected_as_json() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /ext
            structured_metadata:
              namespace: ext
              key: payload
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_structured_metadata("ext", "payload", json!({"k": 1}));
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"a":1,"ext":{"k":1}}));
}

#[tokio::test]
async fn invalid_json_continue_leaves_body() {
    let filter = parse_filter(
        r#"
        on_invalid: continue
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"not-json"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert_eq!(body.as_ref().unwrap().as_ref(), b"not-json");
}

#[tokio::test]
async fn invalid_json_reject() {
    let filter = parse_filter(
        r#"
        on_invalid: reject
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{"));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "invalid JSON with on_invalid reject"
    );
}

#[tokio::test]
async fn invalid_json_error() {
    let filter = parse_filter(
        r#"
        on_invalid: error
        request_remove:
          - /a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"{"));
    let err = filter
        .on_request_body(&mut ctx, &mut body, true)
        .await
        .expect_err("on_invalid: error should return FilterError");
    assert!(err.to_string().contains("invalid JSON"), "got: {err}");
}

#[test]
fn response_shrink_is_padded() {
    let filter = parse_filter(
        r#"
        response_remove:
          - /secret
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let original = Bytes::from_static(br#"{"keep":1,"secret":"x"}"#);
    let orig_len = original.len();
    let mut body = Some(original);
    let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let out = body.unwrap();
    assert_eq!(out.len(), orig_len, "padded to original Content-Length");
    assert!(out.starts_with(br#"{"keep":1}"#), "secret removed");
    assert!(
        out.iter().rev().take_while(|b| **b == b' ').count() > 0,
        "trailing spaces"
    );
}

#[test]
fn fit_response_refuses_growth() {
    assert!(
        super::fit_response(4, b"12345".to_vec()).is_none(),
        "longer rewrite cannot be framed"
    );
}

#[test]
fn request_body_access_none_when_only_response_ops() {
    let filter = parse_filter(
        r#"
        response_remove:
          - /a
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::None);
    assert_eq!(filter.response_body_access(), crate::BodyAccess::ReadWrite);
}

#[test]
fn add_nested_under_existing_object() {
    let out = rewrite_str(
        r#"{"user":{"id":1}}"#,
        &[resolved(OpKind::Add, "/user/role", Some(r#""admin""#))],
    )
    .unwrap();
    assert_eq!(out, r#"{"user":{"id":1,"role":"admin"}}"#);
}

#[test]
fn scalar_root_without_matching_ops_copied() {
    let out = rewrite_str("42", &[resolved(OpKind::Remove, "/a", None)]).unwrap();
    assert_eq!(out, "42");
}

#[test]
fn string_value_with_escapes_copied() {
    let input = r#"{"a":"x\"y"}"#;
    let out = rewrite_str(input, &[resolved(OpKind::Add, "/b", Some("1"))]).unwrap();
    assert_eq!(out, r#"{"a":"x\"y","b":1}"#);
}

// -----------------------------------------------------------------------------
// Extract
// -----------------------------------------------------------------------------

#[test]
fn rejects_duplicate_extract_pointers() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /a
            metadata: one
          - pointer: /a
            metadata: two
        "#,
    );
    assert!(err.contains("overlapping"), "got: {err}");
}

#[test]
fn allows_nested_extract_pointers() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
          - pointer: /user/id
            metadata: user.id
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadOnly);
}

#[test]
fn rejects_extract_without_dest() {
    let err = parse_err(
        r#"
        request_extract:
          - pointer: /a
        "#,
    );
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn extract_only_is_read_only() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadOnly);
    assert_eq!(filter.response_body_access(), crate::BodyAccess::None);
}

#[test]
fn extract_plus_replace_is_read_write() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        "#,
    );
    assert_eq!(filter.request_body_access(), crate::BodyAccess::ReadWrite);
}

#[tokio::test]
async fn extract_string_to_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"model":"old","n":1}"#);
}

#[tokio::test]
async fn extract_object_to_structured_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1}}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_structured_metadata("ext", "user"), Some(&json!({"id": 1})));
}

#[tokio::test]
async fn nested_extract_walks_parent() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /user
            structured_metadata:
              namespace: ext
              key: user
          - pointer: /user/id
            metadata: user.id
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"user":{"id":1,"n":2}}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(
        ctx.get_structured_metadata("ext", "user"),
        Some(&json!({"id": 1, "n": 2}))
    );
    assert_eq!(ctx.get_metadata("user.id"), Some("1"));
}

#[tokio::test]
async fn extract_missing_pointer_skips() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /missing
            metadata: gone
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(ctx.get_metadata("gone").is_none(), "missing pointer skips");
}

#[tokio::test]
async fn extract_only_early_exit_ignores_trailing_junk() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old","x":1} not-json"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
}

#[tokio::test]
async fn extract_only_incomplete_before_eos_continues() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(ctx.get_metadata("original.model").is_none());
}

#[tokio::test]
async fn extract_only_complete_before_eos_is_body_done() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
}

#[tokio::test]
async fn extract_then_add_from_metadata() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        request_add:
          - pointer: /original_model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model":"forced-model","original_model":"old"}));
}

#[tokio::test]
async fn extract_oversized_metadata_is_skipped() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /v
            metadata: big
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let long = "a".repeat(257);
    let payload = format!(r#"{{"v":"{long}"}}"#);
    let mut body = Some(Bytes::from(payload));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert!(ctx.get_metadata("big").is_none(), "256-byte metadata cap");
}

#[tokio::test]
async fn metadata_add_skipped_when_extract_late_in_wire_order() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_add:
          - pointer: /meta/extra
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"meta":{},"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"meta": {}, "model": "old"}));
}

#[tokio::test]
async fn same_key_extract_before_replace() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /model
            metadata: original.model
        request_replace:
          - pointer: /model
            value: forced-model
        request_add:
          - pointer: /original_model
            metadata: original.model
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"old"}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("original.model"), Some("old"));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"model": "forced-model", "original_model": "old"}));
}

#[tokio::test]
async fn external_metadata_still_works() {
    let filter = parse_filter(
        r#"
        request_add:
          - pointer: /tenant
            metadata: tenant.id
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.set_metadata("tenant.id".to_owned(), "acme".to_owned());
    let mut body = Some(Bytes::from_static(br#"{"n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(got, json!({"n": 1, "tenant": "acme"}));
}

#[tokio::test]
async fn missing_metadata_on_existing_replace_keeps_original() {
    let filter = parse_filter(
        r#"
        request_replace:
          - pointer: /model
            metadata: missing.key
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"keep-me","n":1}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    let got = serde_json::from_slice::<serde_json::Value>(body.as_ref().unwrap()).unwrap();
    assert_eq!(
        got,
        json!({"model": "keep-me", "n": 1}),
        "missing context must skip the replace, not delete the existing member"
    );
}

#[tokio::test]
async fn extract_duplicate_keys_keeps_last() {
    let filter = parse_filter(
        r#"
        request_extract:
          - pointer: /a
            metadata: a
        "#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"a":1,"a":2}"#));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::BodyDone));
    assert_eq!(ctx.get_metadata("a"), Some("2"), "extract last duplicate");
    assert_eq!(body.as_ref().unwrap().as_ref(), br#"{"a":1,"a":2}"#);
}
