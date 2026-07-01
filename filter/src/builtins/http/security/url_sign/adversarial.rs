// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Adversarial tests for URL signing (QA).

use std::time::{SystemTime, UNIX_EPOCH};

use http::Method;
use praxis_core::config::{Condition, ConditionMatch, FailureMode, FilterEntry};

use http::HeaderMap;

use crate::{
    FilterAction, FilterPipeline, FilterRegistry, Request,
    filter::HttpFilter,
    test_utils::{make_filter_context, make_request},
};

use super::UrlSignFilter;
use crate::builtins::http::security::url_sign::{config::Encoding, verify::compute_mac};

fn make_filter_yaml(extra: &str) -> serde_yaml::Value {
    serde_yaml::from_str(&format!(
        r#"
secret:
  value: "qa-adversarial-secret"
{extra}
"#
    ))
    .unwrap()
}

fn sign_query(secret: &str, method: &str, path: &str, query: &str, expires: &str) -> String {
    let canonical = format!("{method}\n{path}\n{query}\n{expires}\n");
    compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap()
}

fn sign_path(secret: &str, resource: &str, expires: &str) -> String {
    let canonical = format!("GET\n{resource}\n\n{expires}\n");
    compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap()
}

fn sign_query_with_host(
    secret: &str,
    method: &str,
    path: &str,
    query: &str,
    expires: &str,
    host: &str,
) -> String {
    let canonical = format!("{method}\n{path}\n{query}\n{expires}\n{host}");
    compute_mac(secret.as_bytes(), &canonical, Encoding::Hex).unwrap()
}

fn make_request_with_host(method: Method, path: &str, host: &str) -> Request {
    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse().expect("invalid host header"));
    Request {
        method,
        uri: path.parse().expect("invalid URI in test"),
        headers,
    }
}

#[tokio::test]
async fn method_swap_on_signed_get_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let sig = sign_query(secret, "GET", "/resource", "", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let req = make_request(
        Method::POST,
        &format!("/resource?expires={expires}&sig={sig}"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "POST with GET-signed URL must reject"
    );
}

#[tokio::test]
async fn query_mode_percent_encoded_path_sets_decoded_rewritten_path() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let decoded_path = "/files/report.pdf";
    let sig = sign_query(secret, "GET", decoded_path, "token=abc", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let encoded_path = format!("/files%2freport.pdf?token=abc&expires={expires}&sig={sig}");
    let req = make_request(Method::GET, &encoded_path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "MAC verifies on decoded path even when request path is percent-encoded"
    );
    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/files/report.pdf"),
        "query mode must set rewritten_path to decoded canonical path"
    );
}

#[tokio::test]
async fn query_mode_encoded_traversal_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let decoded_path = "/public/file";
    let sig = sign_query(secret, "GET", decoded_path, "", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let path = format!("/public/%2e%2e/admin?expires={expires}&sig={sig}");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "query mode encoded traversal must reject"
    );
}

#[tokio::test]
async fn path_mode_semantically_equivalent_encoding_accepted() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let resource = "/files/report.pdf";
    let sig = sign_path(secret, resource, expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "placement: path\npath_prefix: /s\n",
    ))
    .unwrap();

    let path = format!("/s/{expires}/{sig}/files%2freport.pdf");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "encoding equivalent to signed path should verify"
    );
    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/files/report.pdf"),
        "rewritten_path must be decoded canonical path"
    );
}

#[tokio::test]
async fn path_mode_double_encoded_traversal_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let resource = "/public/file";
    let sig = sign_path(secret, resource, expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "placement: path\npath_prefix: /s\n",
    ))
    .unwrap();

    let path = format!("/s/{expires}/{sig}/public/%252e%252e/admin");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "double-encoded traversal must reject"
    );
}

#[tokio::test]
async fn unknown_key_id_rejects_403() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
secrets:
  - id: v1
    value: "key-one"
  - id: v2
    value: "key-two"
"#,
    )
    .unwrap();
    let filter = UrlSignFilter::try_from_config(&yaml).unwrap();
    let expires = "9999999999";
    let sig = sign_query("key-one", "GET", "/x", "", expires);

    let req = make_request(
        Method::GET,
        &format!("/x?expires={expires}&sig={sig}&kid=unknown"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "unknown kid must reject"
    );
}

#[tokio::test]
async fn keyed_secret_matching_kid_succeeds() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
secrets:
  - id: v1
    value: "key-one"
  - id: v2
    value: "key-two"
key_id_param: kid
"#,
    )
    .unwrap();
    let filter = UrlSignFilter::try_from_config(&yaml).unwrap();
    let expires = "9999999999";
    let sig = sign_query("key-two", "GET", "/data", "", expires);

    let req = make_request(
        Method::GET,
        &format!("/data?expires={expires}&sig={sig}&kid=v2"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid kid should select correct secret"
    );
}

#[tokio::test]
async fn expiry_beyond_clock_skew_rejects_403() {
    let secret = "qa-adversarial-secret";
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "expires:\n  clock_skew_secs: 60\n",
    ))
    .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = (now - 120).to_string();
    let sig = sign_query(secret, "GET", "/late", "", &expires);

    let req = make_request(
        Method::GET,
        &format!("/late?expires={expires}&sig={sig}"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "expiry outside clock skew must reject"
    );
}

#[tokio::test]
async fn expiry_within_clock_skew_accepts() {
    let secret = "qa-adversarial-secret";
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "expires:\n  clock_skew_secs: 120\n",
    ))
    .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = (now - 30).to_string();
    let sig = sign_query(secret, "GET", "/skew-ok", "", &expires);

    let req = make_request(
        Method::GET,
        &format!("/skew-ok?expires={expires}&sig={sig}"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "expiry within clock skew should accept"
    );
}

#[tokio::test]
async fn empty_signature_param_rejects_403() {
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();
    let req = make_request(Method::GET, "/x?expires=9999999999&sig=");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "empty signature value must reject"
    );
}

#[tokio::test]
async fn tampered_query_param_after_signing_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let sig = sign_query(secret, "GET", "/x", "token=abc", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let req = make_request(
        Method::GET,
        &format!("/x?token=evil&expires={expires}&sig={sig}"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "tampered query param must reject"
    );
}

#[tokio::test]
async fn path_mode_mixed_case_hex_signature_accepts() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let resource = "/doc";
    let sig = sign_path(secret, resource, expires);
    let mixed_sig = sig
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i.is_multiple_of(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect::<String>();

    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "placement: path\npath_prefix: /s\n",
    ))
    .unwrap();
    let path = format!("/s/{expires}/{mixed_sig}{resource}");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "hex signatures should be case-insensitive"
    );
}

#[test]
fn pipeline_rejects_url_sign_with_failure_mode_open() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        filter_type: "url_sign".into(),
        config: serde_yaml::from_str("secret:\n  value: x\n").unwrap(),
        conditions: vec![],
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
    assert!(
        errors.iter().any(|e| e.contains("failure_mode: open")),
        "pipeline must reject url_sign with failure_mode open: {errors:?}"
    );
}

#[test]
fn pipeline_rejects_conditional_url_sign() {
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        filter_type: "url_sign".into(),
        config: serde_yaml::from_str("secret:\n  value: x\n").unwrap(),
        conditions: vec![Condition::When(ConditionMatch {
            path: None,
            path_prefix: Some("/public".into()),
            methods: None,
            headers: None,
        })],
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
    assert!(
        errors.iter().any(|e| e.contains("security filter 'url_sign'")),
        "pipeline must reject conditional url_sign: {errors:?}"
    );
}

#[tokio::test]
async fn query_mode_double_encoded_traversal_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let decoded_path = "/public/file";
    let sig = sign_query(secret, "GET", decoded_path, "", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let path = format!("/public/%252e%252e/admin?expires={expires}&sig={sig}");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "query mode double-encoded traversal must reject"
    );
}

#[tokio::test]
async fn query_mode_encoded_double_slash_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let decoded_path = "/a/b";
    let sig = sign_query(secret, "GET", decoded_path, "", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let path = format!("/a%2f%2fb?expires={expires}&sig={sig}");
    let req = make_request(Method::GET, &path);
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "query mode encoded double slash must reject"
    );
}

#[tokio::test]
async fn host_header_mismatch_with_include_host_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let path = "/resource";
    let signed_host = "cdn.example.com";
    let sig = sign_query_with_host(secret, "GET", path, "", expires, signed_host);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "canonical:\n  include_host: true\n",
    ))
    .unwrap();

    let req = make_request_with_host(
        Method::GET,
        &format!("{path}?expires={expires}&sig={sig}"),
        "evil.example.com",
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "host swap must reject when include_host is enabled"
    );
}

#[tokio::test]
async fn multi_key_missing_kid_rejects_403() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
secrets:
  - id: v1
    value: "key-one"
  - id: v2
    value: "key-two"
key_id_param: kid
"#,
    )
    .unwrap();
    let filter = UrlSignFilter::try_from_config(&yaml).unwrap();
    let expires = "9999999999";
    let sig = sign_query("key-one", "GET", "/x", "", expires);

    let req = make_request(Method::GET, &format!("/x?expires={expires}&sig={sig}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "multi-key config without kid must reject"
    );
}

#[tokio::test]
async fn base64url_signature_encoding_accepts_valid_mac() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let path = "/doc";
    let canonical = format!("GET\n{path}\n\n{expires}\n");
    let sig = compute_mac(secret.as_bytes(), &canonical, Encoding::Base64Url).unwrap();
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("encoding: base64url\n")).unwrap();

    let req = make_request(Method::GET, &format!("{path}?expires={expires}&sig={sig}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid base64url signature must verify"
    );
}

#[tokio::test]
async fn duplicate_query_key_last_value_in_canonical_rejects_tamper() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let sig = sign_query(secret, "GET", "/x", "token=abc", expires);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();

    let req = make_request(
        Method::GET,
        &format!("/x?token=abc&token=evil&expires={expires}&sig={sig}"),
    );
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "duplicate query key with tampered trailing value must reject"
    );
}

#[tokio::test]
async fn host_required_but_header_absent_rejects_403() {
    let secret = "qa-adversarial-secret";
    let expires = "9999999999";
    let path = "/resource";
    let signed_host = "cdn.example.com";
    let sig = sign_query_with_host(secret, "GET", path, "", expires, signed_host);
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml(
        "canonical:\n  include_host: true\n",
    ))
    .unwrap();

    let req = make_request(Method::GET, &format!("{path}?expires={expires}&sig={sig}"));
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "signed host must be present on request when include_host is enabled"
    );
}

#[tokio::test]
async fn bad_mac_returns_reject_not_filter_error() {
    let filter = UrlSignFilter::try_from_config(&make_filter_yaml("")).unwrap();
    let req = make_request(
        Method::GET,
        "/x?expires=9999999999&sig=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let mut ctx = make_filter_context(&req);
    let result = filter.on_request(&mut ctx).await;
    assert!(result.is_ok(), "bad MAC must not surface as FilterError");
    assert!(
        matches!(result.unwrap(), FilterAction::Reject(r) if r.status == 403),
        "bad MAC must reject with 403"
    );
}
