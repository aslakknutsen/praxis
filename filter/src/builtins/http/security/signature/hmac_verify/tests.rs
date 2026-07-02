// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for the HMAC verify filter.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};

use super::HmacVerifyFilter;
use crate::{
    FilterAction,
    builtins::http::security::signature::hmac_verify::dialect::github_signature,
    filter::HttpFilter,
};

#[tokio::test]
async fn accepts_valid_github_signature() {
    let secret = b"webhook-secret";
    let body = br#"{"zen":"Design for failure."}"#;
    let header = github_signature(secret, body);

    let filter = from_yaml(
        r#"
secret: "webhook-secret"
dialect: github
"#,
    );

    let mut headers = HeaderMap::new();
    headers.insert("X-Hub-Signature-256", HeaderValue::from_str(&header).expect("header"));
    let req = make_request(headers);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut chunk = Some(Bytes::from_static(body));
    let action = filter
        .on_request_body(&mut ctx, &mut chunk, true)
        .await
        .expect("on_request_body");

    assert!(matches!(action, FilterAction::Continue));
    assert!(
        ctx.extra_request_headers
            .iter()
            .any(|(k, v)| k == "X-Hub-Signature-256" && v.is_empty()),
        "signature header should be stripped"
    );
}

#[tokio::test]
async fn rejects_missing_signature_header() {
    let filter = from_yaml(
        r#"
secret: "webhook-secret"
dialect: github
"#,
    );

    let req = make_request(HeaderMap::new());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut chunk = Some(Bytes::from_static(b"payload"));

    let action = filter
        .on_request_body(&mut ctx, &mut chunk, true)
        .await
        .expect("on_request_body");

    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 401),
        "missing signature should reject with 401"
    );
}

#[tokio::test]
async fn waits_for_end_of_stream() {
    let filter = from_yaml(
        r#"
secret: "webhook-secret"
dialect: github
"#,
    );

    let req = make_request(HeaderMap::new());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut chunk = Some(Bytes::from_static(b"part"));

    let action = filter
        .on_request_body(&mut ctx, &mut chunk, false)
        .await
        .expect("on_request_body");

    assert!(matches!(action, FilterAction::Continue));
}

fn from_yaml(yaml: &str) -> Box<dyn HttpFilter> {
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).expect("yaml");
    HmacVerifyFilter::from_config(&config).expect("config")
}

fn make_request(headers: HeaderMap) -> crate::Request {
    crate::Request {
        method: Method::POST,
        uri: Uri::from_static("/webhook"),
        headers,
    }
}
