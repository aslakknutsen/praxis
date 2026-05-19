// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shorthand routing rules.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Route
// -----------------------------------------------------------------------------

/// A routing rule mapping requests to a cluster.
///
/// Exactly one of `path_prefix`, `path_exact`, or `path_regex` should be set.
/// When none of the exact/regex fields are set, `path_prefix` is used (the
/// longest matching prefix wins). Prefix matching follows Gateway API segment
/// rules: `/api` matches `/api` and `/api/v1` but not `/apikeys`; a trailing
/// slash on the configured prefix is ignored (`/api` and `/api/` are the
/// same). When `path_exact` is set, `path_prefix` is ignored for path matching.
/// When `path_regex` is set, it is matched against the full request path.
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path_prefix: "/api"
/// cluster: backend
/// "#,
/// )
/// .unwrap();
/// assert_eq!(route.path_prefix, "/api");
/// assert_eq!(&*route.cluster, "backend");
/// assert!(route.host.is_none());
/// assert!(route.headers.is_none());
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Path prefix to match. The longest matching prefix wins.
    ///
    /// Used when neither `path_exact` nor `path_regex` are set. Defaults to
    /// `"/"` (match all paths) when constructing routes programmatically where
    /// `path_exact` or `path_regex` provides the real path constraint.
    pub path_prefix: String,

    /// Exact path to match. When set, takes precedence over `path_prefix`.
    #[serde(default)]
    pub path_exact: Option<String>,

    /// Regex pattern to match against the full request path.
    /// When set, takes precedence over `path_prefix` (but not `path_exact`).
    #[serde(default)]
    pub path_regex: Option<String>,

    /// HTTP methods to match (e.g. `["GET", "POST"]`). When set, the route
    /// only matches requests using one of the listed methods.
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// Host to match. If set, the route only applies to this host.
    #[serde(default)]
    pub host: Option<String>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Query parameters to match. All specified params must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    pub query_params: Option<HashMap<String, String>>,

    /// When set, respond with this redirect instead of forwarding to [`cluster`].
    #[serde(default)]
    pub redirect: Option<RedirectAction>,

    /// Request header changes after this route matches (Gateway RequestHeaderModifier).
    #[serde(default)]
    pub request_header_modifier: Option<RequestHeaderModifier>,

    /// Response header changes after this route matches (GRPCRoute ResponseHeaderModifier).
    #[serde(default)]
    pub response_header_modifier: Option<RequestHeaderModifier>,

    /// URL rewrite: replace hostname (Host header) on upstream request.
    #[serde(default)]
    pub url_rewrite_hostname: Option<String>,

    /// URL rewrite: replace the entire path.
    #[serde(default)]
    pub url_rewrite_path_full: Option<String>,

    /// URL rewrite: replace the matched prefix portion of the path.
    #[serde(default)]
    pub url_rewrite_path_prefix: Option<String>,

    /// Request-level timeout in milliseconds (0 = disabled).
    #[serde(default)]
    pub request_timeout_ms: u64,

    /// Backend request timeout in milliseconds (0 = disabled).
    #[serde(default)]
    pub backend_timeout_ms: u64,

    /// When true, backend refs did not resolve — reject with HTTP 500 (Gateway conformance).
    #[serde(default)]
    pub invalid_backend_ref: bool,

    /// True when this rule came from a GRPCRoute (enables gRPC-specific behaviour).
    #[serde(default)]
    pub grpc_route: bool,

    /// Per-route CORS policy (Gateway API CORSFilter). When set, the router
    /// handles preflight and injects CORS response headers for this route.
    #[serde(default)]
    pub cors: Option<RouteCorsPolicy>,

    /// Name of the cluster to route matched requests to.
    pub cluster: Arc<str>,
}

/// Per-route CORS policy from Gateway API.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCorsPolicy {
    /// Allowed origins (exact strings or `*.suffix` wildcards; `"*"` = any).
    #[serde(default)]
    pub allow_origins: Vec<String>,

    /// Allowed HTTP methods. Empty = `["GET", "HEAD", "POST"]`.
    #[serde(default)]
    pub allow_methods: Vec<String>,

    /// Allowed request headers.
    #[serde(default)]
    pub allow_headers: Vec<String>,

    /// Response headers exposed to the client.
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Preflight cache duration in seconds.
    #[serde(default)]
    pub max_age: u32,

    /// Whether to include `Access-Control-Allow-Credentials: true`.
    #[serde(default)]
    pub allow_credentials: bool,
}

/// Gateway API RequestRedirect rendered as status + Location template (`${path}`, `${query}`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectAction {
    /// HTTP redirect status (301, 302, 307, or 308).
    pub status: u16,

    /// `Location` header template (same placeholders as the `redirect` filter).
    pub location: String,
}

/// One set/add header entry (Gateway `HTTPHeader`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderNameValue {
    /// Case-insensitive header field name.
    pub name: String,
    /// Field value(s); RFC 7230 formatting when multiple comma-separated values are required.
    pub value: String,
}

/// Gateway `HTTPHeaderFilter` for the request (set / add / remove).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderModifier {
    /// Headers to overwrite if present (Gateway `set`).
    #[serde(default)]
    pub set: Vec<HeaderNameValue>,

    /// Headers to append (Gateway `add`).
    #[serde(default)]
    pub add: Vec<HeaderNameValue>,

    /// Header names to strip (Gateway `remove`).
    #[serde(default)]
    pub remove: Vec<String>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_without_host() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.path_prefix, "/api", "path_prefix mismatch");
        assert_eq!(&*route.cluster, "backend", "cluster mismatch");
        assert!(route.host.is_none(), "host should be None when omitted");
    }

    #[test]
    fn parse_route_with_headers() {
        let yaml = r#"
path_prefix: "/"
cluster: "backend"
headers:
  x-model: "claude-sonnet-4-5"
  x-version: "v1"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let headers = route.headers.unwrap();
        assert_eq!(headers.len(), 2, "should have 2 header constraints");
        assert_eq!(
            headers.get("x-model").unwrap(),
            "claude-sonnet-4-5",
            "x-model header mismatch"
        );
        assert_eq!(headers.get("x-version").unwrap(), "v1", "x-version header mismatch");
    }

    #[test]
    fn parse_route_with_host() {
        let yaml = r#"
path_prefix: "/"
host: "api.example.com"
cluster: "api"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.host.as_deref(), Some("api.example.com"), "host should be parsed");
    }
}
