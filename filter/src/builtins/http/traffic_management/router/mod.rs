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
use praxis_core::config::Route;
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
    ///         path_exact: None,
    ///         path_regex: None,
    ///         methods: None,
    ///         host: None,
    ///         headers: None,
    ///         redirect: None,
    ///         cluster: "default".into(),
    ///     },
    ///     Route {
    ///         path_prefix: "/api".into(),
    ///         path_exact: None,
    ///         path_regex: None,
    ///         methods: None,
    ///         host: None,
    ///         headers: None,
    ///         redirect: None,
    ///         cluster: "api".into(),
    ///     },
    /// ])
    /// .unwrap();
    /// ```
    pub fn new(routes: Vec<Route>) -> Result<Self, FilterError> {
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
    ) -> Option<&Route> {
        let mut best: Option<(usize, usize, &Route)> = None;

        for resolved in &self.routes {
            let route = &resolved.route;
            if !route_matches_request(resolved, path, host, req_headers, method) {
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
        let path = ctx.rewritten_path.as_deref().unwrap_or_else(|| ctx.request.uri.path());
        let host = ctx
            .request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| ctx.request.uri.authority().map(http::uri::Authority::as_str));
        let method = ctx.request.method.as_str();

        trace!(path = %path, host = host.unwrap_or(""), method = %method, "matching route");
        if let Some(route) = self.match_route(path, host, &ctx.request.headers, Some(method)) {
            if let Some(redir) = &route.redirect {
                let uri = &ctx.request.uri;
                let location = expand_redirect_location(&redir.location, uri.path(), uri.query());
                let rejection = Rejection::status(redir.status).with_header("Location", &location);
                return Ok(FilterAction::Reject(rejection));
            }
            debug!(
                path = %path,
                cluster = %route.cluster,
                "route matched"
            );
            ctx.cluster = Some(Arc::clone(&route.cluster));
            Ok(FilterAction::Continue)
        } else {
            debug!(path = %path, "no route matched");
            Ok(FilterAction::Reject(Rejection::status(404)))
        }
    }
}
