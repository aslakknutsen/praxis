// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for the `url_sign` filter.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, start_backend_with_shutdown, start_proxy, wait_for_http,
};

// -----------------------------------------------------------------------------
// Signing Helper
// -----------------------------------------------------------------------------

fn sign_query(secret: &[u8], path: &str, query: &str, expires: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let canonical = format!("GET\n{path}\n{query}\n{expires}\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("valid key length");
    mac.update(canonical.as_bytes());
    hex_encode(mac.finalize().into_bytes().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn valid_signed_query_reaches_backend() {
    let backend_guard = start_backend_with_shutdown("signed-ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let secret = b"integration-test-secret";
    let expires = "9999999999";
    let sig = sign_query(secret, "/files/report.pdf", "token=abc", expires);

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: url_sign
        secret:
          value: "integration-test-secret"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http(proxy.addr());

    let path = format!("/files/report.pdf?token=abc&expires={expires}&sig={sig}");
    let (status, body) = http_get(proxy.addr(), &path, None);
    assert_eq!(status, 200, "valid signature should reach backend");
    assert_eq!(body, "signed-ok");
}

#[test]
fn unsigned_request_rejected_with_403() {
    let backend_guard = start_backend_with_shutdown("should-not-see");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: url_sign
        secret:
          value: "secret"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http(proxy.addr());

    let (status, body) = http_get(proxy.addr(), "/public", None);
    assert_eq!(status, 403, "unsigned request should be rejected");
    assert!(body.is_empty(), "403 response should have empty body");
}

#[test]
fn path_mode_strips_signature_and_routes() {
    let backend_guard = start_backend_with_shutdown("path-mode");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let secret = b"path-secret";
    let expires = "9999999999";
    let resource = "/files/report.pdf";
    let canonical = format!("GET\n{resource}\n\n{expires}\n");
    let sig = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(canonical.as_bytes());
        hex_encode(mac.finalize().into_bytes().as_slice())
    };

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: url_sign
        secret:
          value: "path-secret"
        placement: path
        path_prefix: /s
      - filter: router
        routes:
          - path_prefix: "/files/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http(proxy.addr());

    let path = format!("/s/{expires}/{sig}{resource}");
    let (status, body) = http_get(proxy.addr(), &path, None);
    assert_eq!(status, 200, "path-mode signed URL should route after strip");
    assert_eq!(body, "path-mode");
}

#[test]
fn query_mode_encoded_path_routes_on_decoded_path_with_valid_mac() {
    let backend_guard = start_backend_with_shutdown("encoded-path-backend");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let secret = b"qa-encoding-secret";
    let expires = "9999999999";
    let decoded_path = "/files/report.pdf";
    let sig = sign_query(secret, decoded_path, "token=abc", expires);

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: url_sign
        secret:
          value: "qa-encoding-secret"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    wait_for_http(proxy.addr());

    let encoded_path = format!("/files%2freport.pdf?token=abc&expires={expires}&sig={sig}");
    let (status, body) = http_get(proxy.addr(), &encoded_path, None);
    assert_eq!(
        status, 200,
        "query mode must route on decoded path after percent-encoded wire path verifies"
    );
    assert_eq!(body, "encoded-path-backend");
}

#[test]
fn config_rejects_url_sign_with_failure_mode_open() {
    use praxis_core::config::{FailureMode, FilterEntry};
    use praxis_filter::{FilterPipeline, FilterRegistry};

    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![FilterEntry {
        branch_chains: None,
        filter_type: "url_sign".into(),
        config: serde_yaml::from_str("secret:\n  value: secret\n").unwrap(),
        conditions: vec![],
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::Open,
    }];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    let errors = pipeline.ordering_errors(&entries);
    assert!(
        errors.iter().any(|e| e.contains("failure_mode: open")),
        "pipeline validation must reject url_sign with failure_mode: open: {errors:?}"
    );
}
