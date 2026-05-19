// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path-prefix and host-header routing filter.

mod config;
mod matching;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "tests"
)]
mod tests;

use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderMap;
use praxis_core::config::{RequestHeaderModifier, Route, RouteCorsPolicy};
use tracing::{debug, trace};

use self::{
    config::RouterConfig,
    matching::{path_specificity, route_matches_request, should_stop_early, update_best_match},
};
use super::redirect::expand_redirect_location;
use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    filter::{HttpFilter, HttpFilterContext},
    PendingRequestHeaderOp,
};

// -----------------------------------------------------------------------------
// RouterFilter
// -----------------------------------------------------------------------------

/// Routes requests to clusters based on path prefix and host header.
///
/// If a preceding filter (such as `path_rewrite` or `url_rewrite`) has
/// set [`rewritten_path`], the router matches against the rewritten
/// path. Otherwise, it uses the original request path.
///
/// # YAML configuration
///
/// ```yaml
/// filter: router
/// routes:
///   - path_prefix: "/"
///     cluster: default
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::RouterFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// routes:
///   - path_prefix: "/"
///     cluster: default
/// "#,
/// )
/// .unwrap();
/// let filter = RouterFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "router");
/// ```
///
/// [`rewritten_path`]: crate::HttpFilterContext::rewritten_path
#[derive(Debug)]
pub struct RouterFilter {
    /// Ordered route table with pre-computed wildcard suffixes.
    routes: Vec<ResolvedRoute>,
}

/// A route paired with its pre-lowercased wildcard suffix (if any).
#[derive(Debug)]
struct ResolvedRoute {
    /// The original route configuration.
    route: Route,

    /// For wildcard hosts (e.g. `*.example.com`), the pre-lowercased
    /// suffix with leading dot: `.example.com`. `None` for exact hosts
    /// or routes without a host constraint.
    wildcard_suffix: Option<String>,
}

fn validate_request_header_modifier(m: &RequestHeaderModifier) -> Result<(), FilterError> {
    for pairs in [&m.set[..], &m.add[..]] {
        for h in pairs {
            http::header::HeaderName::from_bytes(h.name.as_bytes()).map_err(|_| {
                let msg: FilterError =
                    format!("router: invalid request_header_modifier header name '{}'", h.name).into();
                msg
            })?;
            http::header::HeaderValue::from_str(&h.value).map_err(|_| {
                let msg: FilterError = format!(
                    "router: invalid request_header_modifier value for '{}'",
                    h.name
                )
                .into();
                msg
            })?;
        }
    }
    for name in &m.remove {
        http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            let msg: FilterError =
                format!("router: invalid request_header_modifier remove name '{name}'").into();
            msg
        })?;
    }
    Ok(())
}

fn enqueue_route_request_header_ops(ctx: &mut HttpFilterContext<'_>, m: &RequestHeaderModifier) {
    for name in &m.remove {
        ctx.pending_request_header_ops
            .push(PendingRequestHeaderOp::Remove(name.clone()));
    }
    for h in &m.set {
        ctx.pending_request_header_ops
            .push(PendingRequestHeaderOp::Set(h.name.clone(), h.value.clone()));
    }
    for h in &m.add {
        ctx.pending_request_header_ops
            .push(PendingRequestHeaderOp::Add(h.name.clone(), h.value.clone()));
    }
}

impl RouterFilter {
    /// Create a router from a list of routes.
    ///
    /// Prefix routes use Gateway API–aligned matching: a `path_prefix` of `/api`
    /// matches `/api`, `/api/`, and `/api/v1` but not `/apikeys`. A trailing slash
    /// on the configured prefix is ignored (`/api` and `/api/` are equivalent).
    ///
    /// ```
    /// use praxis_core::config::Route;
    /// use praxis_filter::RouterFilter;
    ///
    /// let router = RouterFilter::new(vec![
    ///     Route {
    ///         path_prefix: "/".into(),
    ///         cluster: "default".into(),
    ///         ..Default::default()
    ///     },
    ///     Route {
    ///         path_prefix: "/api".into(),
    ///         cluster: "api".into(),
    ///         ..Default::default()
    ///     },
    /// ])
    /// .unwrap();
    /// ```
    pub fn new(routes: Vec<Route>) -> Result<Self, FilterError> {
        for route in &routes {
            if let Some(ref m) = route.request_header_modifier {
                validate_request_header_modifier(m)?;
            }
        }
        let mut routes = routes;
        routes.sort_by_key(|b| std::cmp::Reverse(path_specificity(b)));
        let resolved: Vec<ResolvedRoute> = routes
            .into_iter()
            .map(|route| {
                let wildcard_suffix = route.host.as_ref().and_then(|h| h.strip_prefix("*.")).map(|suffix| {
                    let lower = suffix.to_ascii_lowercase();
                    format!(".{lower}")
                });
                ResolvedRoute { route, wildcard_suffix }
            })
            .collect();
        debug!(routes = resolved.len(), "router initialized");
        Ok(Self { routes: resolved })
    }

    /// Create a router from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if route YAML is invalid or routes fail validation.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RouterConfig = crate::parse_filter_config("router", config)?;
        Ok(Box::new(Self::new(cfg.routes)?))
    }

    /// Find the best matching route for the given path, host, headers, and method.
    ///
    /// When multiple routes have the same specificity, the route with more
    /// constraints (host presence + header count + method constraint) wins.
    fn match_route(
        &self,
        path: &str,
        host: Option<&str>,
        req_headers: &HeaderMap,
        method: Option<&str>,
        query: Option<&str>,
    ) -> Option<&Route> {
        let mut best: Option<(usize, usize, &Route)> = None;

        for resolved in &self.routes {
            let route = &resolved.route;
            if !route_matches_request(resolved, path, host, req_headers, method, query) {
                continue;
            }
            best = update_best_match(best, route);
            if should_stop_early(best, route) {
                break;
            }
        }

        best.map(|(_, _, r)| r)
    }
}

#[async_trait]
impl HttpFilter for RouterFilter {
    fn name(&self) -> &'static str {
        "router"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let path = ctx.rewritten_path.as_deref().unwrap_or_else(|| ctx.request.uri.path()).to_owned();
        let host = ctx
            .request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| ctx.request.uri.authority().map(http::uri::Authority::as_str))
            .map(str::to_owned);
        let method = ctx.request.method.as_str().to_owned();

        let origin = ctx
            .request
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let is_preflight = method == "OPTIONS"
            && origin.is_some()
            && ctx
                .request
                .headers
                .contains_key("access-control-request-method");

        // For preflight, match without method constraint so OPTIONS can find the target route.
        let match_method = if is_preflight { None } else { Some(method.as_str()) };

        let query = ctx.request.uri.query().map(str::to_owned);
        trace!(path = %path, host = host.as_deref().unwrap_or(""), method = %method, "matching route");
        if let Some(route) = self.match_route(&path, host.as_deref(), &ctx.request.headers, match_method, query.as_deref()) {
            // Handle CORS preflight: respond immediately with CORS headers.
            if is_preflight {
                if let Some(ref cors) = route.cors {
                    let origin_str = origin.as_deref().unwrap_or("");
                    if is_cors_origin_allowed(origin_str, cors) {
                        debug!(origin = %origin_str, "CORS preflight allowed");
                        return Ok(FilterAction::Reject(
                            build_cors_preflight_rejection(origin_str, cors, &ctx.request.headers),
                        ));
                    }
                    debug!(origin = %origin_str, "CORS preflight origin disallowed");
                    return Ok(FilterAction::Reject(
                        Rejection::status(204).with_header(
                            "Vary",
                            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
                        ),
                    ));
                }
                // No CORS policy on route — fall through to normal routing (returns 404 for OPTIONS
                // or routes to upstream if OPTIONS is allowed).
            }

            if route.invalid_backend_ref {
                if route.grpc_route {
                    return Ok(FilterAction::Reject(grpc_unimplemented()));
                }
                return Ok(FilterAction::Reject(Rejection::status(500)));
            }
            if let Some(redir) = &route.redirect {
                let uri = &ctx.request.uri;
                let req_scheme = uri.scheme_str().unwrap_or("http");
                let req_host = ctx.request.headers.get("host")
                    .and_then(|v| v.to_str().ok())
                    .or_else(|| uri.authority().map(http::uri::Authority::as_str))
                    .unwrap_or("");
                let raw_location = redir.location
                    .replace("${scheme}", req_scheme)
                    .replace("${host}", req_host);
                let req_path = uri.path();
                let path_suffix = req_path.strip_prefix(route.path_prefix.as_str())
                    .unwrap_or("");
                let raw_location = raw_location.replace("${path_suffix}", path_suffix);
                let location = expand_redirect_location(&raw_location, req_path, uri.query());
                let rejection = Rejection::status(redir.status).with_header("Location", &location);
                return Ok(FilterAction::Reject(rejection));
            }
            debug!(
                path = %path,
                cluster = %route.cluster,
                "route matched"
            );
            ctx.cluster = Some(Arc::clone(&route.cluster));
            if let Some(ref m) = route.request_header_modifier {
                enqueue_route_request_header_ops(ctx, m);
            }
            // Merge per-route response header modifier with CORS response headers.
            let cors_modifier = if let (Some(cors), Some(origin_str)) = (&route.cors, &origin) {
                if is_cors_origin_allowed(origin_str, cors) {
                    Some(build_cors_response_modifier(origin_str, cors))
                } else {
                    None
                }
            } else {
                None
            };
            match (&route.response_header_modifier, cors_modifier) {
                (Some(m), Some(cors_m)) => {
                    let mut merged = m.clone();
                    merged.set.extend(cors_m.set);
                    merged.add.extend(cors_m.add);
                    ctx.response_header_modifier = Some(merged);
                }
                (Some(m), None) => ctx.response_header_modifier = Some(m.clone()),
                (None, Some(cors_m)) => ctx.response_header_modifier = Some(cors_m),
                (None, None) => {}
            }
            if let Some(ref host) = route.url_rewrite_hostname {
                ctx.rewritten_host = Some(host.clone());
            }
            if let Some(ref full_path) = route.url_rewrite_path_full {
                ctx.rewritten_path = Some(full_path.clone());
            } else if let Some(ref prefix) = route.url_rewrite_path_prefix {
                let original = ctx.rewritten_path.as_deref().unwrap_or(&path);
                let matched_prefix = &route.path_prefix;
                if let Some(suffix) = original.strip_prefix(matched_prefix.as_str()) {
                    let joined = if prefix.ends_with('/') && suffix.starts_with('/') {
                        format!("{}{}", prefix.trim_end_matches('/'), suffix)
                    } else if !prefix.ends_with('/') && !suffix.starts_with('/') && !suffix.is_empty() {
                        format!("{prefix}/{suffix}")
                    } else {
                        format!("{prefix}{suffix}")
                    };
                    ctx.rewritten_path = Some(if joined.is_empty() { "/".to_owned() } else { joined });
                } else if original == matched_prefix.trim_end_matches('/') {
                    ctx.rewritten_path = Some(if prefix.is_empty() { "/".to_owned() } else { prefix.clone() });
                }
            }
            if route.request_timeout_ms > 0 {
                ctx.request_deadline = Some(
                    std::time::Instant::now()
                        + std::time::Duration::from_millis(route.request_timeout_ms),
                );
            }
            if route.backend_timeout_ms > 0 {
                ctx.backend_timeout_ms = route.backend_timeout_ms;
            }
            Ok(FilterAction::Continue)
        } else {
            debug!(path = %path, "no route matched");
            if is_grpc_request(&ctx.request.headers) {
                return Ok(FilterAction::Reject(grpc_unimplemented()));
            }
            Ok(FilterAction::Reject(Rejection::status(404)))
        }
    }
}

fn is_grpc_request(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}

fn grpc_unimplemented() -> Rejection {
    Rejection::status(200)
        .with_header("content-type", "application/grpc")
        .with_header("grpc-status", "12")
        .with_header("grpc-message", "unimplemented")
}

// ---------------------------------------------------------------------------
// Per-route CORS handling
// ---------------------------------------------------------------------------

fn is_cors_origin_allowed(origin: &str, policy: &RouteCorsPolicy) -> bool {
    for allowed in &policy.allow_origins {
        if allowed == "*" {
            return true;
        }
        if allowed == origin {
            return true;
        }
        if let Some((scheme, host)) = allowed.split_once("://") {
            if host.starts_with("*.") {
                let suffix = &host[1..]; // e.g. ".bar.com"
                if let Some((o_scheme, o_rest)) = origin.split_once("://") {
                    let o_host = o_rest.split(':').next().unwrap_or(o_rest);
                    if o_scheme == scheme
                        && o_host.ends_with(suffix)
                        && o_host.len() > suffix.len()
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn build_cors_preflight_rejection(
    origin: &str,
    policy: &RouteCorsPolicy,
    request_headers: &HeaderMap,
) -> Rejection {
    // Always echo the specific origin (never return literal "*"). This is
    // required for credentialed requests per the Fetch Standard, and the
    // Gateway API conformance suite expects echoed origins throughout.
    let acao = origin;

    // CORS spec (Fetch Standard): when allowCredentials is true, wildcard
    // values are forbidden. Echo the preflight request's specific method
    // and headers instead.
    let has_wildcard_methods = policy.allow_methods.iter().any(|m| m == "*");
    let methods = if policy.allow_methods.is_empty() {
        "GET, HEAD, POST".to_owned()
    } else if has_wildcard_methods && policy.allow_credentials {
        request_headers
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("GET, HEAD, POST")
            .to_owned()
    } else {
        policy.allow_methods.join(", ")
    };

    let has_wildcard_headers = policy.allow_headers.iter().any(|h| h == "*");
    let allow_headers = if has_wildcard_headers && policy.allow_credentials {
        request_headers
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
    } else if !policy.allow_headers.is_empty() {
        Some(policy.allow_headers.join(", "))
    } else {
        None
    };

    let mut r = Rejection::status(204)
        .with_header("Access-Control-Allow-Origin", acao)
        .with_header("Access-Control-Allow-Methods", &methods)
        .with_header("Access-Control-Max-Age", &policy.max_age.to_string())
        .with_header(
            "Vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        );

    if let Some(ref hdrs) = allow_headers {
        r = r.with_header("Access-Control-Allow-Headers", hdrs);
    }
    if !policy.expose_headers.is_empty() {
        r = r.with_header("Access-Control-Expose-Headers", &policy.expose_headers.join(", "));
    }
    if policy.allow_credentials {
        r = r.with_header("Access-Control-Allow-Credentials", "true");
    }
    r
}

fn build_cors_response_modifier(origin: &str, policy: &RouteCorsPolicy) -> RequestHeaderModifier {
    // Always echo the specific origin rather than returning literal "*".
    // Returning "*" breaks credentialed requests per the Fetch Standard, and
    // the Gateway API conformance suite expects the echoed origin.
    let acao = origin.to_owned();

    let mut set = vec![
        praxis_core::config::HeaderNameValue {
            name: "Access-Control-Allow-Origin".to_owned(),
            value: acao,
        },
    ];
    if !policy.expose_headers.is_empty() {
        set.push(praxis_core::config::HeaderNameValue {
            name: "Access-Control-Expose-Headers".to_owned(),
            value: policy.expose_headers.join(", "),
        });
    }
    if policy.allow_credentials {
        set.push(praxis_core::config::HeaderNameValue {
            name: "Access-Control-Allow-Credentials".to_owned(),
            value: "true".to_owned(),
        });
    }
    let add = vec![praxis_core::config::HeaderNameValue {
        name: "Vary".to_owned(),
        value: "Origin".to_owned(),
    }];
    RequestHeaderModifier {
        set,
        add,
        remove: vec![],
    }
}
