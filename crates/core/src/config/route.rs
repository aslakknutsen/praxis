// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shorthand routing rules.
//!
//! [`PathMatch`] and [`Route`] provide the YAML-level routing model
//! consumed by the router filter. Routes match requests by path
//! (exact or prefix), optional host, and optional header predicates,
//! then select a target cluster. These types are config-only; runtime
//! matching logic lives in the router filter's `matching` module.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::{HedgePolicy, RetryPolicy};

// -----------------------------------------------------------------------------
// PathMatch
// -----------------------------------------------------------------------------

/// How a route matches request paths.
///
/// Deserializes from YAML as an untagged enum: a `path` key produces
/// [`Exact`], a `path_prefix` key produces [`Prefix`].
///
/// ```
/// use praxis_core::config::PathMatch;
///
/// let exact: PathMatch = serde_yaml::from_str("path: /one\n").unwrap();
/// assert!(matches!(exact, PathMatch::Exact { .. }));
/// assert_eq!(exact.value(), "/one");
///
/// let prefix: PathMatch = serde_yaml::from_str("path_prefix: /api/\n").unwrap();
/// assert!(matches!(prefix, PathMatch::Prefix { .. }));
/// assert_eq!(prefix.value(), "/api/");
/// ```
///
/// [`Exact`]: PathMatch::Exact
/// [`Prefix`]: PathMatch::Prefix
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PathMatch {
    /// Exact path match.
    Exact {
        /// The exact path to match.
        path: String,
    },

    /// Segment-boundary prefix match (Gateway API semantics).
    /// `/api` matches `/api`, `/api/`, `/api/v1` but NOT `/apikeys`.
    Prefix {
        /// Path prefix. The longest matching prefix wins.
        path_prefix: String,
    },
}

impl PathMatch {
    /// Build a [`PathMatch`] from optional `path` / `path_prefix` keys,
    /// enforcing that exactly one is set.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let exact = PathMatch::from_parts(Some("/one".to_owned()), None).unwrap();
    /// assert!(exact.is_exact());
    ///
    /// let both = PathMatch::from_parts(Some("/one".to_owned()), Some("/api".to_owned()));
    /// assert!(both.is_err());
    ///
    /// let neither = PathMatch::from_parts(None, None);
    /// assert!(neither.is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when both or neither of `path` and
    /// `path_prefix` are set.
    pub fn from_parts(path: Option<String>, path_prefix: Option<String>) -> Result<Self, String> {
        match (path, path_prefix) {
            (Some(path), None) => {
                if path.is_empty() {
                    return Err("route 'path' must not be empty (request paths always begin with '/')".to_owned());
                }
                if !path.starts_with('/') {
                    return Err(format!(
                        "route 'path' must start with '/' (got '{path}'); request paths always begin with '/', \
                         so this route can never match"
                    ));
                }
                Ok(Self::Exact { path })
            },
            (None, Some(path_prefix)) => {
                // An empty prefix is the documented match-all; any other
                // non-'/'-prefixed value can never match a request path.
                if !path_prefix.is_empty() && !path_prefix.starts_with('/') {
                    return Err(format!(
                        "route 'path_prefix' must start with '/' or be empty (got '{path_prefix}'); \
                         request paths always begin with '/', so this prefix can never match"
                    ));
                }
                Ok(Self::Prefix { path_prefix })
            },
            (Some(_), Some(_)) => Err("route cannot set both 'path' and 'path_prefix' (use exactly one)".to_owned()),
            (None, None) => Err("route requires either 'path' or 'path_prefix'".to_owned()),
        }
    }

    /// Returns `true` when this is an exact-path match.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let exact = PathMatch::Exact {
    ///     path: "/one".to_owned(),
    /// };
    /// assert!(exact.is_exact());
    ///
    /// let prefix = PathMatch::Prefix {
    ///     path_prefix: "/".to_owned(),
    /// };
    /// assert!(!prefix.is_exact());
    /// ```
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }

    /// Byte length of the matched path or prefix.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Prefix {
    ///     path_prefix: "/api/".to_owned(),
    /// };
    /// assert_eq!(m.len(), 5);
    /// ```
    pub fn len(&self) -> usize {
        self.value().len()
    }

    /// Returns `true` when the path or prefix string is empty.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Prefix {
    ///     path_prefix: "/".to_owned(),
    /// };
    /// assert!(!m.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.value().is_empty()
    }

    /// The path or prefix string.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Exact {
    ///     path: "/health".to_owned(),
    /// };
    /// assert_eq!(m.value(), "/health");
    /// ```
    pub fn value(&self) -> &str {
        match self {
            Self::Exact { path } => path,
            Self::Prefix { path_prefix } => path_prefix,
        }
    }
}

// -----------------------------------------------------------------------------
// Route
// -----------------------------------------------------------------------------

/// A route's cluster destination.
///
/// Both YAML forms normalize to this one type: `cluster: name` deserializes to
/// [`Single`] and `weighted_clusters: { targets: [...] }` to [`Weighted`].
/// Serialization emits the form that was configured.
///
/// [`Single`]: RouteTarget::Single
/// [`Weighted`]: RouteTarget::Weighted
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RouteTarget {
    /// Single-target shorthand: route every request to one cluster.
    Single {
        /// Name of the cluster to route matched requests to.
        cluster: Arc<str>,
    },

    /// Weighted and priority-tiered cluster selection.
    Weighted {
        /// Weighted cluster targets.
        weighted_clusters: WeightedClusters,
    },
}

impl RouteTarget {
    /// Build a target from the two mutually exclusive YAML keys.
    ///
    /// `route_label` names the route in the error message.
    ///
    /// # Errors
    ///
    /// Returns an error when both `cluster` and `weighted_clusters` are set,
    /// or when neither is.
    pub fn from_parts(
        cluster: Option<Arc<str>>,
        weighted_clusters: Option<WeightedClusters>,
        route_label: &str,
    ) -> Result<Self, String> {
        match (cluster, weighted_clusters) {
            (Some(cluster), None) => Ok(Self::Single { cluster }),
            (None, Some(weighted_clusters)) => Ok(Self::Weighted { weighted_clusters }),
            (Some(_), Some(_)) => Err(format!(
                "route '{route_label}' cannot set both 'cluster' and 'weighted_clusters' (use exactly one)"
            )),
            (None, None) => Err(format!(
                "route '{route_label}' requires either 'cluster' or 'weighted_clusters'"
            )),
        }
    }

    /// Returns `true` when this target uses the weighted form.
    pub fn is_weighted(&self) -> bool {
        matches!(self, Self::Weighted { .. })
    }

    /// The cluster name for the single-target shorthand.
    pub fn single_cluster(&self) -> Option<&str> {
        match self {
            Self::Single { cluster } => Some(cluster),
            Self::Weighted { .. } => None,
        }
    }

    /// Every target name, in configuration order.
    pub fn target_names(&self) -> Box<dyn Iterator<Item = &Arc<str>> + '_> {
        match self {
            Self::Single { cluster } => Box::new(std::iter::once(cluster)),
            Self::Weighted { weighted_clusters } => {
                Box::new(weighted_clusters.targets.iter().map(|target| &target.name))
            },
        }
    }

    /// Every target in canonical weighted form.
    ///
    /// The single-target shorthand expands to one target with weight `1` and
    /// priority `0`. This is a configuration-time conversion; the router builds
    /// its selector once per route, never per request.
    pub fn targets(&self) -> Vec<WeightedTarget> {
        match self {
            Self::Single { cluster } => vec![WeightedTarget {
                name: Arc::clone(cluster),
                weight: DEFAULT_TARGET_WEIGHT,
                priority: 0,
            }],
            Self::Weighted { weighted_clusters } => weighted_clusters.targets.clone(),
        }
    }

    /// Validate the weighted form; the shorthand cannot be invalid.
    fn validate(&self, route_label: &str) -> Result<(), String> {
        let Self::Weighted { weighted_clusters } = self else {
            return Ok(());
        };
        let targets = &weighted_clusters.targets;
        if targets.is_empty() {
            return Err(format!(
                "{route_label}: 'weighted_clusters.targets' must not be empty \
                 (use 'cluster' for a single target)"
            ));
        }
        Self::validate_targets(route_label, targets)?;
        Self::validate_total_weight(route_label, targets)
    }

    /// Validate each target's name and weight, and reject duplicates.
    fn validate_targets(route_label: &str, targets: &[WeightedTarget]) -> Result<(), String> {
        let mut seen = HashSet::new();
        for (index, target) in targets.iter().enumerate() {
            if target.name.is_empty() {
                return Err(format!(
                    "{route_label}: 'weighted_clusters.targets[{index}].name' must not be empty"
                ));
            }
            if !seen.insert(target.name.as_ref()) {
                return Err(format!(
                    "{route_label}: 'weighted_clusters.targets' has duplicate name '{}'; \
                     each cluster may appear at most once",
                    target.name
                ));
            }
            if target.weight == 0 || target.weight > MAX_TARGET_WEIGHT {
                return Err(format!(
                    "{route_label}: 'weighted_clusters.targets[{index}].weight' must be between 1 and \
                     {MAX_TARGET_WEIGHT} (got {})",
                    target.weight
                ));
            }
        }
        Ok(())
    }

    /// Reject a total weight the smooth-WRR scores cannot represent.
    fn validate_total_weight(route_label: &str, targets: &[WeightedTarget]) -> Result<(), String> {
        let mut total: u64 = 0;
        for target in targets {
            total = total
                .checked_add(u64::from(target.weight))
                .ok_or_else(|| format!("{route_label}: 'weighted_clusters' total weight overflows"))?;
        }
        let max_total = u64::try_from(i64::MAX).map_or(u64::MAX, |max| max);
        if total > max_total {
            return Err(format!(
                "{route_label}: 'weighted_clusters' total weight is too large to track"
            ));
        }
        Ok(())
    }
}

impl From<&str> for RouteTarget {
    fn from(cluster: &str) -> Self {
        Self::Single {
            cluster: Arc::from(cluster),
        }
    }
}

/// Default weight for a weighted-cluster target.
pub const DEFAULT_TARGET_WEIGHT: u32 = 1; // equal share unless configured

/// Maximum accepted weight for a weighted-cluster target.
pub const MAX_TARGET_WEIGHT: u32 = 1000;

/// Serde default for [`WeightedTarget::weight`].
fn default_target_weight() -> u32 {
    DEFAULT_TARGET_WEIGHT
}

/// An ordered set of weighted cluster targets.
///
/// Targets sharing a `priority` form one tier. Selection uses the lowest
/// priority number with a healthy target, then smooth weighted round-robin
/// within that tier.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WeightedClusters {
    /// Cluster targets. Must not be empty.
    pub targets: Vec<WeightedTarget>,
}

/// One cluster in a weighted route target set.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WeightedTarget {
    /// Name of the cluster to route matched requests to.
    pub name: Arc<str>,

    /// Relative weight within the target's priority tier.
    ///
    /// Must be in `1..=1000`. The effective share is this weight's fraction of
    /// its tier, multiplied by the selected endpoint's share within its cluster.
    #[serde(default = "default_target_weight")]
    pub weight: u32,

    /// Priority tier; lower numbers are preferred. Defaults to `0`.
    #[serde(default)]
    pub priority: u32,
}

/// A routing rule mapping requests to a cluster.
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path_prefix: "/api/"
/// cluster: backend
/// "#,
/// )
/// .unwrap();
/// assert_eq!(route.path_match.value(), "/api/");
/// assert_eq!(route.single_cluster(), Some("backend"));
/// assert!(!route.path_match.is_exact());
/// assert!(route.host.is_none());
/// assert!(route.headers.is_none());
/// ```
///
/// Exact path matching:
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path: "/one"
/// cluster: backend
/// "#,
/// )
/// .unwrap();
/// assert!(route.path_match.is_exact());
/// assert_eq!(route.path_match.value(), "/one");
/// ```
///
/// Weighted targets with a priority-tier fallback:
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path_prefix: "/"
/// weighted_clusters:
///   targets:
///     - name: stable
///       weight: 90
///     - name: canary
///       weight: 10
///     - name: dr
///       priority: 1
/// "#,
/// )
/// .unwrap();
/// assert!(route.target.is_weighted());
/// assert_eq!(route.target.targets().len(), 3);
/// assert_eq!(route.target.targets()[2].priority, 1);
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "RouteRaw")]
pub struct Route {
    /// Path matching strategy (exact or prefix).
    #[serde(flatten)]
    pub path_match: PathMatch,

    /// Cluster destination: the `cluster` shorthand or `weighted_clusters`.
    ///
    /// Exactly one of the two YAML keys must be set. `cluster: x` is
    /// equivalent to one target `{ name: x, weight: 1, priority: 0 }`.
    #[serde(flatten)]
    pub target: RouteTarget,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    pub headers: Option<HashMap<String, String>>,

    /// Host to match. If set, the route only applies to this host.
    pub host: Option<String>,

    /// Optional per-route retry policy override.
    ///
    /// Merged onto the cluster `retry_policy`: route fields replace
    /// cluster fields where present. List fields replace entirely.
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,

    /// Optional per-route hedged-request policy.
    ///
    /// When `max_attempts` is greater than 1, the route buffers the request,
    /// races it across healthy endpoints in the selected cluster, and returns
    /// the first 2xx, 3xx, or 4xx response, cancelling the other attempts.
    /// `max_attempts` of 1, `CONNECT`, and `Upgrade` keep a single upstream
    /// attempt. Absent means one upstream attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hedge_policy: Option<HedgePolicy>,
}

/// Raw deserialization target for [`Route`].
///
/// Spells out `path` / `path_prefix` as plain optional fields so
/// `deny_unknown_fields` works (it is incompatible with the
/// `#[serde(flatten)]` + untagged-enum shape that [`Route`] uses for
/// serialization); [`TryFrom`] enforces exactly-one-of.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteRaw {
    /// Exact path to match. Exactly one of `path` or `path_prefix`
    /// must be set.
    #[serde(default)]
    path: Option<String>,

    /// Path prefix to match; the longest matching prefix wins. Exactly
    /// one of `path` or `path_prefix` must be set.
    #[serde(default)]
    path_prefix: Option<String>,

    /// Name of the cluster to route matched requests to. Exactly one of
    /// `cluster` or `weighted_clusters` must be set.
    #[serde(default)]
    cluster: Option<Arc<str>>,

    /// Weighted cluster targets with optional priority tiers. Exactly one of
    /// `cluster` or `weighted_clusters` must be set.
    #[serde(default)]
    weighted_clusters: Option<WeightedClusters>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    headers: Option<HashMap<String, String>>,

    /// Host to match. If set, the route only applies to this host.
    #[serde(default)]
    host: Option<String>,

    /// Optional per-route retry policy override.
    #[serde(default)]
    retry_policy: Option<RetryPolicy>,

    /// Optional per-route hedged-request policy.
    ///
    /// When `max_attempts` is greater than 1, the route buffers the request,
    /// races it across healthy endpoints in the selected cluster, and returns
    /// the first 2xx, 3xx, or 4xx response, cancelling the other attempts.
    /// `max_attempts` of 1, `CONNECT`, and `Upgrade` keep a single upstream
    /// attempt. Absent means one upstream attempt.
    #[serde(default)]
    hedge_policy: Option<HedgePolicy>,
}

impl Route {
    /// The cluster name when this route uses the single-target shorthand.
    ///
    /// Returns `None` for a weighted route, which may select any of its
    /// [`targets`](Route::targets).
    pub fn single_cluster(&self) -> Option<&str> {
        self.target.single_cluster()
    }

    /// Every cluster name this route may select, in configuration order.
    pub fn target_names(&self) -> impl Iterator<Item = &Arc<str>> {
        self.target.target_names()
    }

    /// Every target in canonical weighted form (config-time only).
    pub fn targets(&self) -> Vec<WeightedTarget> {
        self.target.targets()
    }

    /// Validate cross-field route semantics that the type system does
    /// not enforce: retry-policy timeout bounds and header-match keys.
    ///
    /// Called from every construction path (the [`Route`] deserializer
    /// and the router filter's own route config) so a route can never
    /// reach the runtime with an out-of-bounds retry timeout or an empty
    /// header-match key (which can never match a request).
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending field.
    pub fn validate_semantics(&self) -> Result<(), String> {
        let label = self.error_label();
        self.target.validate(&label)?;
        if let Some(policy) = &self.retry_policy {
            policy.validate_timeout_bounds(&label)?;
        }
        if let Some(headers) = &self.headers
            && headers.keys().any(String::is_empty)
        {
            return Err(format!(
                "{label}: header match key must not be empty (an empty header name can never match)"
            ));
        }
        if self.host.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "{label}: host must not be empty (an empty host can never match; \
                 omit 'host' to match any host)"
            ));
        }
        Ok(())
    }

    /// Label naming the constraints that distinguish this route in errors.
    ///
    /// Routes that share a path are still distinct when they match different
    /// hosts or headers, so those constraints are part of the label. Header
    /// match values are omitted: they may hold credentials, and the name alone
    /// separates the routes.
    fn error_label(&self) -> String {
        let path = self.path_match.value();
        let mut details = Vec::new();
        if let Some(host) = &self.host {
            details.push(format!("host '{host}'"));
        }
        if let Some(headers) = &self.headers {
            let mut names: Vec<&str> = headers.keys().map(String::as_str).collect();
            names.sort_unstable();
            details.push(format!("headers [{}]", names.join(", ")));
        }
        if details.is_empty() {
            return format!("route '{path}'");
        }
        format!("route '{path}' ({})", details.join("; "))
    }
}

impl TryFrom<RouteRaw> for Route {
    type Error = String;

    fn try_from(raw: RouteRaw) -> Result<Self, Self::Error> {
        let path_match = PathMatch::from_parts(raw.path, raw.path_prefix)?;
        let target = RouteTarget::from_parts(raw.cluster, raw.weighted_clusters, path_match.value())?;
        let route = Self {
            path_match,
            target,
            headers: raw.headers,
            host: raw.host,
            retry_policy: raw.retry_policy,
            hedge_policy: raw.hedge_policy,
        };
        route.validate_semantics()?;
        Ok(route)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
        assert_eq!(route.path_match.value(), "/api", "path value mismatch");
        assert!(!route.path_match.is_exact(), "should be prefix match");
        assert_eq!(route.single_cluster(), Some("backend"), "cluster mismatch");
        assert!(route.host.is_none(), "host should be None when omitted");
    }

    #[test]
    fn parse_route_with_headers() {
        let yaml = r#"
path_prefix: "/"
cluster: "backend"
headers:
  x-model: "model-alpha-1"
  x-version: "v1"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let headers = route.headers.unwrap();
        assert_eq!(headers.len(), 2, "should have 2 header constraints");
        assert_eq!(
            headers.get("x-model").unwrap(),
            "model-alpha-1",
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

    #[test]
    fn parse_exact_path() {
        let yaml = r#"
path: "/exact"
cluster: "backend"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert!(route.path_match.is_exact(), "should be exact match");
        assert_eq!(route.path_match.value(), "/exact", "exact path mismatch");
    }

    #[test]
    fn reject_unknown_route_keys() {
        let yaml = r#"
path_prfix: "/api"
path_prefix: "/api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("path_prfix") || err.to_string().contains("unknown field"),
            "typoed keys must be rejected, not silently absorbed: {err}"
        );
    }

    #[test]
    fn reject_both_path_and_prefix() {
        let yaml = r#"
path: "/one"
path_prefix: "/api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("both 'path' and 'path_prefix'"),
            "setting both path keys must be rejected: {err}"
        );
    }

    #[test]
    fn reject_missing_path_keys() {
        let yaml = r#"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("either 'path' or 'path_prefix'"),
            "a route without a path key must be rejected: {err}"
        );
    }

    #[test]
    fn reject_prefix_without_leading_slash() {
        let yaml = r#"
path_prefix: "api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must start with '/'"),
            "a prefix that can never match a request path must be rejected: {err}"
        );
    }

    #[test]
    fn reject_exact_path_without_leading_slash() {
        let yaml = r#"
path: "health"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(err.to_string().contains("must start with '/'"), "got: {err}");
    }

    #[test]
    fn reject_empty_exact_path() {
        let yaml = r#"
path: ""
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn empty_prefix_is_match_all() {
        let route: Route = serde_yaml::from_str("path_prefix: \"\"\ncluster: backend\n").unwrap();
        assert_eq!(
            route.path_match.value(),
            "",
            "the documented empty match-all prefix must stay valid"
        );
    }

    #[test]
    fn reject_empty_header_match_key() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
headers:
  "": "value"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("header match key must not be empty"),
            "an empty header name can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_host_match() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
host: ""
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("host must not be empty"),
            "an empty host can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_route_retry_policy_zero_timeout() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
retry_policy:
  per_try_timeout_ms: 0
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("per_try_timeout_ms is 0"),
            "route-level retry overrides get the same timeout bounds as clusters: {err}"
        );
    }

    #[test]
    fn route_serializes_with_flattened_path() {
        let route = Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/api".to_owned(),
            },
            target: RouteTarget::Single {
                cluster: Arc::from("backend"),
            },
            headers: None,
            host: None,
            retry_policy: None,
            hedge_policy: None,
        };
        let yaml = serde_yaml::to_string(&route).unwrap();
        assert!(
            yaml.contains("path_prefix: /api"),
            "serialization keeps the flattened path key: {yaml}"
        );
    }

    #[test]
    fn route_parses_hedge_policy() {
        let route: Route = serde_yaml::from_str(
            r#"
path_prefix: "/"
cluster: backend
hedge_policy:
  initial_requests: 1
  max_attempts: 2
  per_try_timeout_ms: 25
  budget_percent: 10
"#,
        )
        .unwrap();
        let policy = route.hedge_policy.expect("hedge policy is set");
        assert_eq!(policy.initial_requests(), 1, "initial attempts include the primary");
        assert_eq!(policy.max_attempts(), 2, "one hedge copy is allowed");
        assert_eq!(policy.per_try_timeout_ms(), Some(25), "the trigger delay is kept");
    }

    #[test]
    fn path_match_len() {
        let prefix = PathMatch::Prefix {
            path_prefix: "/api/".to_owned(),
        };
        assert_eq!(prefix.len(), 5, "prefix length mismatch");

        let exact = PathMatch::Exact {
            path: "/one".to_owned(),
        };
        assert_eq!(exact.len(), 4, "exact length mismatch");
    }

    fn weighted_route_yaml(targets: &str) -> String {
        format!("path_prefix: \"/\"\nweighted_clusters:\n  targets:\n{targets}")
    }

    #[test]
    fn parses_weighted_clusters() {
        let yaml = weighted_route_yaml(
            "    - name: stable\n      weight: 90\n    - name: canary\n      weight: 10\n    - name: dr\n      priority: 1\n",
        );
        let route: Route = serde_yaml::from_str(&yaml).unwrap();
        assert!(route.target.is_weighted(), "weighted form should be recognized");
        assert_eq!(route.single_cluster(), None, "weighted routes have no single cluster");

        let targets = route.targets();
        assert_eq!(targets.len(), 3, "all targets should be preserved");
        assert_eq!(&*targets[0].name, "stable", "first target name");
        assert_eq!(targets[0].weight, 90, "first target weight");
        assert_eq!(targets[0].priority, 0, "priority defaults to zero");
        assert_eq!(targets[2].weight, DEFAULT_TARGET_WEIGHT, "weight defaults to one");
        assert_eq!(targets[2].priority, 1, "explicit priority is kept");
    }

    #[test]
    fn weighted_clusters_rejects_both_forms() {
        let yaml = r#"
path_prefix: "/"
cluster: stable
weighted_clusters:
  targets:
    - name: canary
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("both 'cluster' and 'weighted_clusters'"),
            "setting both target forms must be rejected: {err}"
        );
    }

    #[test]
    fn weighted_clusters_rejects_neither_form() {
        let err = serde_yaml::from_str::<Route>("path_prefix: \"/\"\n").unwrap_err();
        assert!(
            err.to_string().contains("either 'cluster' or 'weighted_clusters'"),
            "a route without a target must be rejected: {err}"
        );
    }

    #[test]
    fn weighted_clusters_rejects_empty_targets() {
        let yaml = weighted_route_yaml("    []\n");
        let err = serde_yaml::from_str::<Route>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "an empty weighted target list must be rejected: {err}"
        );
    }

    #[test]
    fn weighted_clusters_rejects_duplicate_names() {
        let yaml = weighted_route_yaml("    - name: stable\n    - name: stable\n");
        let err = serde_yaml::from_str::<Route>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate name 'stable'"),
            "duplicate target names must be rejected: {err}"
        );
    }

    #[test]
    fn weighted_errors_name_the_route_host_and_header_names() {
        let yaml = r#"
path_prefix: "/api"
host: "api.example.com"
headers:
  x-tenant: "acme"
  x-api-key: "secret"
weighted_clusters:
  targets:
    - name: stable
    - name: stable
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err().to_string();
        assert!(
            err.contains("route '/api' (host 'api.example.com'; headers [x-api-key, x-tenant])"),
            "the error must identify the route by its match constraints: {err}"
        );
        assert!(
            !err.contains("secret"),
            "header match values must not leak into errors: {err}"
        );
    }

    #[test]
    fn weighted_clusters_rejects_out_of_range_weights() {
        for weight in ["0", "1001"] {
            let yaml = weighted_route_yaml(&format!("    - name: stable\n      weight: {weight}\n"));
            let err = serde_yaml::from_str::<Route>(&yaml).unwrap_err();
            assert!(
                err.to_string().contains("weight' must be between 1 and 1000"),
                "weight {weight} must be rejected: {err}"
            );
        }
    }

    #[test]
    fn weighted_clusters_rejects_empty_name() {
        let yaml = weighted_route_yaml("    - name: \"\"\n");
        let err = serde_yaml::from_str::<Route>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("name' must not be empty"),
            "an empty target name can never match a cluster: {err}"
        );
    }

    #[test]
    fn weighted_clusters_rejects_unknown_fields() {
        let yaml = weighted_route_yaml("    - name: stable\n      wieght: 2\n");
        let err = serde_yaml::from_str::<Route>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("wieght") || err.to_string().contains("unknown field"),
            "typoed target keys must be rejected: {err}"
        );
    }

    #[test]
    fn cluster_shorthand_round_trips_as_shorthand() {
        let yaml = "path_prefix: /api\ncluster: backend\n";
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let out = serde_yaml::to_string(&route).unwrap();
        assert!(out.contains("cluster: backend"), "shorthand stays shorthand: {out}");
        assert!(
            !out.contains("weighted_clusters"),
            "shorthand must not serialize the general form: {out}"
        );
    }

    #[test]
    fn weighted_clusters_round_trips_as_object() {
        let yaml = weighted_route_yaml(
            "    - name: stable\n      weight: 90\n    - name: canary\n      weight: 10\n      priority: 2\n",
        );
        let route: Route = serde_yaml::from_str(&yaml).unwrap();
        let out = serde_yaml::to_string(&route).unwrap();
        assert!(
            out.contains("weighted_clusters:"),
            "weighted form keeps its object shape: {out}"
        );
        let reparsed: Route = serde_yaml::from_str(&out).unwrap();
        assert_eq!(
            reparsed.targets(),
            route.targets(),
            "serialization must round-trip every target"
        );
    }

    #[test]
    fn weighted_single_target_behaves_like_cluster() {
        let yaml = weighted_route_yaml("    - name: only\n");
        let route: Route = serde_yaml::from_str(&yaml).unwrap();
        let targets = route.targets();
        assert_eq!(targets.len(), 1, "one configured target");
        assert_eq!(&*targets[0].name, "only");
        assert_eq!(targets[0].weight, DEFAULT_TARGET_WEIGHT);
        assert_eq!(targets[0].priority, 0);
    }
}
