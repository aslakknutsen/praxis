// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for the signed URL filter.

use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderMap, Method, Uri};

use super::SignedUrlFilter;
use crate::{
    FilterAction,
    builtins::http::security::signature::hmac::{encode_hex_lower, hmac_sha256},
    filter::HttpFilter,
};

#[tokio::test]
async fn accepts_valid_signature_and_strips_params() {
    let secret = "link-secret";
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let path = "/files/report.pdf";
    let message = format!("{path}\n{ts}");
    let sig = encode_hex_lower(&hmac_sha256(secret.as_bytes(), message.as_bytes()).expect("hmac"));

    let filter = from_yaml(&format!(
        r#"
secret: "{secret}"
max_age_seconds: 3600
message:
  parts: [path, timestamp]
"#
    ));

    let uri: Uri = format!("{path}?ts={ts}&sig={sig}&token=keep").parse().expect("uri");
    let req = make_request(Method::GET, uri);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("on_request");
    assert!(matches!(action, FilterAction::Continue));
    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some(format!("{path}?token=keep").as_str()),
        "signature params should be stripped"
    );
}

#[tokio::test]
async fn rejects_missing_signature() {
    let filter = from_yaml(
        r#"
secret: "link-secret"
max_age_seconds: 3600
message:
  parts: [path, timestamp]
"#,
    );
    let req = make_request(Method::GET, "/path?ts=123".parse().expect("uri"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("on_request");
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "missing signature should reject with 403"
    );
}

#[tokio::test]
async fn rejects_expired_link_with_410() {
    let secret = "link-secret";
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        .saturating_sub(7200);
    let path = "/old";
    let message = format!("{path}\n{ts}");
    let sig = encode_hex_lower(&hmac_sha256(secret.as_bytes(), message.as_bytes()).expect("hmac"));

    let filter = from_yaml(
        r#"
secret: "link-secret"
max_age_seconds: 3600
message:
  parts: [path, timestamp]
"#,
    );

    let uri: Uri = format!("{path}?ts={ts}&sig={sig}").parse().expect("uri");
    let req = make_request(Method::GET, uri);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("on_request");
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 410),
        "expired link should reject with 410"
    );
}

fn from_yaml(yaml: &str) -> Box<dyn HttpFilter> {
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).expect("yaml");
    SignedUrlFilter::from_config(&config).expect("config")
}

fn make_request(method: Method, uri: Uri) -> crate::Request {
    crate::Request {
        method,
        uri,
        headers: HeaderMap::new(),
    }
}
