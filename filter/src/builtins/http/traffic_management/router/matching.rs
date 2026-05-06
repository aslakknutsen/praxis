// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path, host, header, and method matching logic for the router filter.

use std::collections::HashMap;

use http::HeaderMap;
use praxis_core::config::Route;
use regex::Regex;

use super::ResolvedRoute;

// -----------------------------------------------------------------------------
// Path Specificity
// -----------------------------------------------------------------------------

/// Effective path specificity used for sorting and best-match selection.
///
/// Exact matches are maximally specific; regex matches rank above any prefix;
/// prefix matches use their byte length.
pub(super) fn path_specificity(route: &Route) -> usize {
    if route.path_exact.is_some() {
        usize::MAX
    } else if route.path_regex.is_some() {
        usize::MAX - 1
    } else {
        route.path_prefix.len()
    }
}

// -----------------------------------------------------------------------------
// Route Matching
// -----------------------------------------------------------------------------

/// Check whether a resolved route matches the request path, host, headers, and method.
pub(super) fn route_matches_request(
    resolved: &ResolvedRoute,
    path: &str,
    host: Option<&str>,
    req_headers: &HeaderMap,
    method: Option<&str>,
) -> bool {
    let route = &resolved.route;

    let path_ok = if let Some(exact) = &route.path_exact {
        path == exact
    } else if let Some(pattern) = &route.path_regex {
        Regex::new(pattern).is_ok_and(|re| re.is_match(path))
    } else {
        path.starts_with(&route.path_prefix)
    };

    if !path_ok {
        return false;
    }

    if let Some(methods) = &route.methods {
        if !methods.is_empty() {
            let m = method.unwrap_or("");
            if !methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(m)) {
                return false;
            }
        }
    }

    let host_ok = match &route.host {
        Some(h) => host.is_some_and(|req_host| {
            let req_host = strip_port(req_host);
            host_matches(h, resolved.wildcard_suffix.as_deref(), req_host)
        }),
        None => true,
    };
    host_ok && headers_match(&route.headers, req_headers)
}

/// Update the best match if the current route has more constraints.
pub(super) fn update_best_match<'a>(
    best: Option<(usize, usize, &'a Route)>,
    route: &'a Route,
) -> Option<(usize, usize, &'a Route)> {
    let specificity = path_specificity(route);
    let constraints = usize::from(route.host.is_some())
        + route.headers.as_ref().map_or(0, HashMap::len)
        + usize::from(route.methods.as_ref().is_some_and(|m| !m.is_empty()));
    let dominated = best.is_some_and(|(bp, bc, _)| (specificity, constraints) <= (bp, bc));
    if dominated {
        best
    } else {
        Some((specificity, constraints, route))
    }
}

/// Return `true` if shorter prefixes cannot improve on the current best.
///
/// Exact and regex routes are never stopped early since they may appear
/// anywhere in the sorted list.
pub(super) fn should_stop_early(best: Option<(usize, usize, &Route)>, route: &Route) -> bool {
    if route.path_exact.is_some() || route.path_regex.is_some() {
        return false;
    }
    best.is_some_and(|(bp, ..)| route.path_prefix.len() < bp)
}

// -----------------------------------------------------------------------------
// Wildcard Host Matching
// -----------------------------------------------------------------------------

/// Check whether a request host matches a route host pattern.
///
/// When `wildcard_suffix` is `Some`, the pattern is a wildcard
/// (e.g. `*.example.com`) and `wildcard_suffix` holds the
/// pre-lowercased suffix (`.example.com`). Zero allocations.
fn host_matches(pattern: &str, wildcard_suffix: Option<&str>, host: &str) -> bool {
    if let Some(suffix) = wildcard_suffix {
        if host.len() <= suffix.len() {
            return false;
        }
        let host_suffix = &host[host.len() - suffix.len()..];
        if !host_suffix.eq_ignore_ascii_case(suffix) {
            return false;
        }
        let subdomain = &host[..host.len() - suffix.len()];
        !subdomain.is_empty() && !subdomain.contains('.')
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

// -----------------------------------------------------------------------------
// Header Matching
// -----------------------------------------------------------------------------

/// Returns `true` if the request headers satisfy all route header constraints.
fn headers_match(required: &Option<HashMap<String, String>>, actual: &HeaderMap) -> bool {
    let Some(required) = required else {
        return true;
    };
    required.iter().all(|(key, val)| {
        actual
            .get_all(key.as_str())
            .iter()
            .any(|v| v.to_str().ok().is_some_and(|v| v == val))
    })
}

// -----------------------------------------------------------------------------
// Host Utilities
// -----------------------------------------------------------------------------

/// Strip the port from a host string, handling both IPv4 and bracketed IPv6.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            Some(i) => &host[..=i],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}
