// SPDX-License-Identifier: MIT

//! Translate a slice of [`Resource`] objects (from istiod's gwxds xDS stream)
//! into a praxis [`Config`].
//!
//! # Translation model (v1)
//!
//! Each incoming [`Resource`] carries one Gateway listener and its attached routes.
//! Resources whose listeners share the same bind identity `(port, protocol, TLS
//! material)` are **merged** into one praxis [`Listener`] and one filter chain so
//! all virtual-host routes share a single router (Gateway API hostname semantics).
//!
//! Per merged group (or a lone resource), translation emits:
//! - One [`Listener`] bound on `0.0.0.0:{port}`
//! - One [`FilterChainConfig`] named `{listener-name}-chain` containing:
//!   - A `router` filter with route entries derived from all merged [`Route`]s
//!   - A `load_balancer` filter with one cluster per unique backend `host:port`
//! - N [`Cluster`] objects, deduped across all routes
//!
//! # Listener topology
//!
//! Listener topology changes require a proxy restart because Pingora binds
//! sockets at startup. Subsequent gwxds pushes can only hot-reload route
//! tables and cluster endpoints via `reload_pipelines`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use praxis_tls::{CaConfig, CertKeyPair, ClusterTls, ListenerTls};
use serde_yaml::Value as YamlValue;
use tracing::warn;

use crate::config::{
    AdminConfig, BodyLimitsConfig, Cluster, Config, Endpoint, FailureMode, FilterChainConfig,
    FilterEntry, HeaderNameValue, InsecureOptions, Listener, ProtocolKind, RedirectAction,
    RequestHeaderModifier, Route, RuntimeConfig,
};

use super::proto::{
    Backend, BackendTls, Listener as GwListener, Protocol, RequestRedirect as ProtoRequestRedirect,
    RequestHeaderModifier as ProtoRequestHeaderModifier, Resource, Route as GwRoute, TlsConfig,
};

#[inline]
fn backend_socket_port(b: &Backend) -> u32 {
    if b.dial_port != 0 {
        b.dial_port
    } else {
        b.port
    }
}

fn route_namespace_from_key(route_key: &str) -> &str {
    route_key.split('/').next().unwrap_or("")
}

/// Turn a bare Kubernetes Service `metadata.name` into a cluster DNS name.
///
/// Istio may send `host` as a single DNS label for same-namespace `Service`
/// backends. The proxy often runs in another namespace; `getaddrinfo` on
/// `headless:8080` then fails or resolves incorrectly because the pod search
/// path does not apply the HTTPRoute's namespace. We use the route key prefix
/// (`namespace/route/rule-index`) as the service namespace.
///
/// Cross-namespace backends must arrive as a multi-label FQDN (or IP); we do not
/// rewrite hosts that already contain `.`.
fn qualify_k8s_service_host(host: &str, route_key: &str) -> String {
    if host.eq_ignore_ascii_case("localhost") {
        return host.to_owned();
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_owned();
    }
    if host.contains('.') {
        return host.to_owned();
    }
    let ns = route_namespace_from_key(route_key);
    if ns.is_empty() {
        return host.to_owned();
    }
    format!("{host}.{ns}.svc.cluster.local")
}

#[inline]
fn backend_upstream_host(b: &Backend, route_key: &str) -> String {
    qualify_k8s_service_host(&b.host, route_key)
}

/// Groups listeners that share the same bind parameters so their routes are merged into one router.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct MergeKey {
    port: u32,
    protocol: i32,
    tls_fp: u64,
}

impl MergeKey {
    fn from_listener(l: &GwListener) -> Self {
        Self {
            port: l.port,
            protocol: l.protocol,
            tls_fp: l.tls.as_ref().map(tls_fingerprint).unwrap_or(0),
        }
    }
}

fn tls_fingerprint(t: &TlsConfig) -> u64 {
    let mut h = DefaultHasher::new();
    t.cert_pem.hash(&mut h);
    t.key_pem.hash(&mut h);
    t.ca_pem.hash(&mut h);
    t.min_version.hash(&mut h);
    h.finish()
}

/// Stable listener name: original key when unmerged, synthetic when several Gateway listeners share a port.
fn merged_listener_name(group: &[&Resource]) -> String {
    if group.len() == 1 {
        return group[0].key.clone();
    }
    let mut h = DefaultHasher::new();
    for r in group {
        r.key.hash(&mut h);
    }
    let port = group
        .first()
        .and_then(|r| r.listener.as_ref())
        .map(|l| l.port)
        .unwrap_or(0);
    format!("gwxds-merge-{port}-{:016x}", h.finish())
}

/// Convert a slice of [`Resource`] objects into a praxis [`Config`].
pub fn translate(resources: &[Resource]) -> Config {
    let mut listeners: Vec<Listener> = Vec::new();
    let mut filter_chains: Vec<FilterChainConfig> = Vec::new();
    let mut clusters: HashMap<String, Cluster> = HashMap::new();

    let mut groups: HashMap<MergeKey, Vec<&Resource>> = HashMap::new();
    for resource in resources {
        let Some(gw_listener) = resource.listener.as_ref() else {
            warn!(key = %resource.key, "gwxds resource has no listener; skipping");
            continue;
        };
        let key = MergeKey::from_listener(gw_listener);
        groups.entry(key).or_default().push(resource);
    }

    let mut group_entries: Vec<(MergeKey, Vec<&Resource>)> = groups.into_iter().collect();
    group_entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (_key, mut group) in group_entries {
        group.sort_by_key(|r| r.key.as_str());
        let Some(first) = group.first().copied() else {
            continue;
        };
        let gw_listener = first.listener.as_ref().expect("grouped resource has listener");

        let merge_label = merged_listener_name(&group);
        let chain_name = format!("{merge_label}-chain");

        let listener = build_listener(gw_listener, &chain_name, Some(&merge_label));

        let is_tls_passthrough = gw_listener.protocol() == Protocol::Tls;

        if is_tls_passthrough {
            let filter_chain = build_sni_filter_chain(chain_name, &group);
            listeners.push(listener);
            filter_chains.push(filter_chain);
            continue;
        }

        let mut routes: Vec<Route> = Vec::new();
        let mut resource_clusters: Vec<Cluster> = Vec::new();

        for resource in &group {
            let gl = resource.listener.as_ref().expect("listener");
            let (mut rs, mut cs) = build_routes_and_clusters(gl, resource);
            routes.append(&mut rs);
            resource_clusters.append(&mut cs);
        }

        for cluster in resource_clusters {
            clusters.entry(cluster.name.to_string()).or_insert(cluster);
        }

        let merged_routes: Vec<GwRoute> = group.iter().flat_map(|r| r.routes.iter().cloned()).collect();
        let filter_chain = build_filter_chain(chain_name, routes, &merged_routes);

        listeners.push(listener);
        filter_chains.push(filter_chain);
    }

    Config {
        admin: AdminConfig::default(),
        body_limits: BodyLimitsConfig::default(),
        clusters: clusters.into_values().collect(),
        filter_chains,
        insecure_options: InsecureOptions::default(),
        listeners,
        runtime: RuntimeConfig::default(),
        shutdown_timeout_secs: 30,
    }
}

// -----------------------------------------------------------------------------
// Listener
// -----------------------------------------------------------------------------

fn build_listener(gw_listener: &GwListener, chain_name: &str, name_override: Option<&str>) -> Listener {
    let protocol = match gw_listener.protocol() {
        Protocol::Tcp | Protocol::Tls | Protocol::Udp => ProtocolKind::Tcp,
        Protocol::Http | Protocol::Https | Protocol::Unknown => ProtocolKind::Http,
    };

    let tls = gw_listener.tls.as_ref().and_then(|t| {
        if t.cert_pem.is_empty() || t.key_pem.is_empty() {
            return None;
        }
        let pair = CertKeyPair::from_pem(t.cert_pem.clone(), t.key_pem.clone());
        match ListenerTls::from_inline(pair) {
            Ok(listener_tls) => Some(listener_tls),
            Err(e) => {
                warn!(key = %gw_listener.key, error = %e, "failed to build listener TLS from inline PEM");
                None
            }
        }
    });

    Listener {
        name: name_override.unwrap_or(gw_listener.key.as_str()).to_owned(),
        address: format!("0.0.0.0:{}", gw_listener.port),
        downstream_read_timeout_ms: None,
        filter_chains: vec![chain_name.to_owned()],
        max_connections: None,
        protocol,
        tcp_idle_timeout_ms: None,
        tcp_max_duration_secs: None,
        tls,
        upstream: None,
        cluster: None,
    }
}

// -----------------------------------------------------------------------------
// Route + cluster building
// -----------------------------------------------------------------------------

fn build_routes_and_clusters(listener: &GwListener, resource: &Resource) -> (Vec<Route>, Vec<Cluster>) {
    let mut routes: Vec<Route> = Vec::new();
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut seen_clusters: HashMap<String, ()> = HashMap::new();

    for gw_route in &resource.routes {
        let redirect_cfg = gw_route.request_redirect.as_ref().and_then(proto_redirect_to_action);
        let hdr_modifier = gw_route
            .request_header_modifier
            .as_ref()
            .and_then(proto_http_request_header_modifier);
        let resp_hdr_modifier = gw_route
            .response_header_modifier
            .as_ref()
            .and_then(proto_http_request_header_modifier);

        let invalid_backend_ref = gw_route.invalid_backend_ref;
        let is_grpc_route = gw_route.grpc_route;

        if gw_route.backends.is_empty() && redirect_cfg.is_none() && !invalid_backend_ref {
            continue;
        }

        // InferencePool backends require EPP support that is not yet implemented.
        if !gw_route.backends.is_empty() && gw_route.backends.iter().any(|b| b.inference_pool.is_some()) {
            warn!(
                route = %gw_route.key,
                "route has InferencePool backends which are not yet supported; skipping route"
            );
            continue;
        }

        let Some(hostnames) = effective_route_hostnames(listener, gw_route) else {
            continue;
        };

        if !gw_route.backends.is_empty()
            && !invalid_backend_ref
            && redirect_cfg.is_none()
            && gw_route.backends.iter().all(|b| b.weight == 0)
        {
            warn!(
                route = %gw_route.key,
                "all backends have weight 0; skipping route"
            );
            continue;
        }

        let cluster_name = if redirect_cfg.is_some() && gw_route.backends.is_empty() {
            "__redirect__".to_owned()
        } else if invalid_backend_ref {
            "__invalid_backend__".to_owned()
        } else if gw_route.backends.len() == 1 {
            backend_cluster_name(&gw_route.backends[0], &gw_route.key)
        } else {
            format!("{}-backends", gw_route.key)
        };

        if !gw_route.backends.is_empty() && !seen_clusters.contains_key(&cluster_name) {
            let endpoints: Vec<Endpoint> = gw_route
                .backends
                .iter()
                .filter(|b| b.weight > 0)
                .flat_map(|b| {
                    let addr = format!(
                        "{}:{}",
                        backend_upstream_host(b, &gw_route.key),
                        backend_socket_port(b)
                    );
                    let weight = b.weight as usize;
                    std::iter::repeat_with(move || Endpoint::Simple(addr.clone())).take(weight)
                })
                .collect();

            let tls = gw_route.backends.first().and_then(|b| b.tls.as_ref()).and_then(build_cluster_tls);

            clusters.push(Cluster {
                name: Arc::from(cluster_name.as_str()),
                connection_timeout_ms: None,
                endpoints,
                health_check: None,
                idle_timeout_ms: None,
                load_balancer_strategy: Default::default(),
                read_timeout_ms: None,
                tls,
                total_connection_timeout_ms: None,
                write_timeout_ms: None,
            });
            seen_clusters.insert(cluster_name.clone(), ());
        }
        let match_routes: Vec<Route> = if gw_route.matches.is_empty() {
            hostnames
                .iter()
                .map(|host| Route {
                    path_prefix: "/".to_owned(),
                    path_exact: None,
                    path_regex: None,
                    methods: if is_grpc_route { Some(vec!["POST".to_owned()]) } else { None },
                    host: host.clone(),
                    headers: None,
                    redirect: redirect_cfg.clone(),
                    request_header_modifier: hdr_modifier.clone(),
                    response_header_modifier: resp_hdr_modifier.clone(),
                    invalid_backend_ref,
                    grpc_route: is_grpc_route,
                    cluster: Arc::from(cluster_name.as_str()),
                })
                .collect()
        } else {
            gw_route
                .matches
                .iter()
                .flat_map(|m| {
                    expand_route_match(
                        m,
                        &cluster_name,
                        &hostnames,
                        redirect_cfg.clone(),
                        hdr_modifier.clone(),
                        resp_hdr_modifier.clone(),
                        invalid_backend_ref,
                        is_grpc_route,
                    )
                })
                .collect()
        };

        routes.extend(match_routes);
    }

    (routes, clusters)
}

fn proto_http_request_header_modifier(p: &ProtoRequestHeaderModifier) -> Option<RequestHeaderModifier> {
    let set: Vec<HeaderNameValue> = p
        .set
        .iter()
        .map(|h| HeaderNameValue {
            name: h.name.clone(),
            value: h.value.clone(),
        })
        .collect();
    let add: Vec<HeaderNameValue> = p
        .add
        .iter()
        .map(|h| HeaderNameValue {
            name: h.name.clone(),
            value: h.value.clone(),
        })
        .collect();
    let remove = p.remove.clone();
    if set.is_empty() && add.is_empty() && remove.is_empty() {
        None
    } else {
        Some(RequestHeaderModifier { set, add, remove })
    }
}

fn proto_redirect_to_action(r: &ProtoRequestRedirect) -> Option<RedirectAction> {
    if r.hostname.is_empty() {
        return None;
    }
    let scheme = if r.scheme.is_empty() { "http" } else { r.scheme.as_str() };
    let mut location = format!("{scheme}://{}", r.hostname);
    if r.port != 0 {
        location.push(':');
        location.push_str(&r.port.to_string());
    }
    location.push_str("${path}${query}");
    let status = if r.status_code == 0 {
        302
    } else {
        u16::try_from(r.status_code).ok()?
    };
    Some(RedirectAction { status, location })
}

/// Effective virtual-host hostnames for this route on its Gateway listener (Gateway API intersection).
///
/// Each emitted hostname is **narrowed** to the set of hosts that match both the listener hostname
/// and the route hostname. Without this, merging multiple HTTP listeners on the same port would let
/// a route pattern (`*.specific.com`) match requests that never belonged on an exact listener
/// (`very.specific.com`).
fn effective_route_hostnames(listener: &GwListener, gw_route: &GwRoute) -> Option<Vec<Option<String>>> {
    let lh = listener.hostname.trim();
    if gw_route.hostnames.is_empty() {
        return Some(if lh.is_empty() {
            vec![None]
        } else {
            vec![Some(lh.to_string())]
        });
    }

    let mut out = Vec::new();
    for rh in &gw_route.hostnames {
        if lh.is_empty() {
            out.push(Some(rh.clone()));
            continue;
        }
        if let Some(narrowed) = intersect_listener_route_hostname(lh, rh) {
            out.push(Some(narrowed));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[derive(Debug, Clone)]
enum HostPattern {
    /// Lowercased exact hostname.
    Exact(String),
    /// Lowercased suffix after `*.` (no `*.` prefix stored).
    Wildcard(String),
}

fn parse_host_pattern(raw: &str) -> HostPattern {
    let h = raw.trim();
    if let Some(suf) = h.strip_prefix("*.") {
        HostPattern::Wildcard(suf.to_ascii_lowercase())
    } else {
        HostPattern::Exact(h.to_ascii_lowercase())
    }
}

fn pattern_to_host_header(p: &HostPattern) -> String {
    match p {
        HostPattern::Exact(e) => e.clone(),
        HostPattern::Wildcard(s) => format!("*.{s}"),
    }
}

fn patterns_intersect(a: HostPattern, b: HostPattern) -> Option<HostPattern> {
    use HostPattern::{Exact, Wildcard};
    match (a, b) {
        (Exact(e), Wildcard(s)) | (Wildcard(s), Exact(e)) => {
            if host_matches_wildcard_suffix_multi(&e, &s) {
                Some(Exact(e))
            } else {
                None
            }
        }
        (Exact(e1), Exact(e2)) => {
            if e1 == e2 {
                Some(Exact(e1))
            } else {
                None
            }
        }
        (Wildcard(s1), Wildcard(s2)) => {
            if s1 == s2 {
                return Some(Wildcard(s1));
            }
            let (long, short) = if s1.len() >= s2.len() {
                (s1, s2)
            } else {
                (s2, s1)
            };
            if long.len() > short.len() && long.ends_with(&format!(".{short}")) {
                return Some(Wildcard(long));
            }
            None
        }
    }
}

/// Intersection of Gateway listener hostname with HTTPRoute hostname (Gateway API).
fn intersect_listener_route_hostname(listener_raw: &str, route_raw: &str) -> Option<String> {
    let l = parse_host_pattern(listener_raw);
    let r = parse_host_pattern(route_raw);
    patterns_intersect(l, r).map(|p| pattern_to_host_header(&p))
}

/// `*.suffix` pattern: host must end with `.suffix` with a non-empty prefix (any number of labels).
fn host_matches_wildcard_suffix_multi(host: &str, suffix_after_star_dot: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let suffix = format!(".{}", suffix_after_star_dot.to_ascii_lowercase());
    if h.len() <= suffix.len() || !h.ends_with(&suffix) {
        return false;
    }
    let prefix = &h[..h.len() - suffix.len()];
    !prefix.is_empty()
}

fn backend_cluster_name(backend: &Backend, route_key: &str) -> String {
    format!("{}:{}", backend_upstream_host(backend, route_key), backend_socket_port(backend))
}

fn expand_route_match(
    m: &super::proto::RouteMatch,
    cluster_name: &str,
    hostnames: &[Option<String>],
    redirect: Option<RedirectAction>,
    request_header_modifier: Option<RequestHeaderModifier>,
    response_header_modifier: Option<RequestHeaderModifier>,
    invalid_backend_ref: bool,
    grpc_route: bool,
) -> Vec<Route> {
    let (path_prefix, path_exact, path_regex, methods) = resolve_grpc_or_http_match(m, grpc_route);
    let headers = if m.headers.is_empty() { None } else { Some(m.headers.clone()) };

    hostnames
        .iter()
        .map(|host| Route {
            path_prefix: path_prefix.clone(),
            path_exact: path_exact.clone(),
            path_regex: path_regex.clone(),
            methods: methods.clone(),
            host: host.clone(),
            headers: headers.clone(),
            redirect: redirect.clone(),
            request_header_modifier: request_header_modifier.clone(),
            response_header_modifier: response_header_modifier.clone(),
            invalid_backend_ref,
            grpc_route,
            cluster: Arc::from(cluster_name),
        })
        .collect()
}

/// Convert a gRPC service/method match (or plain HTTP match) into path + method constraints.
///
/// gRPC over HTTP/2 uses `POST /{service}/{method}`, so:
/// - Both service + method set -> exact path `/{service}/{method}`, method POST
/// - Only service set -> prefix path `/{service}/`, method POST
/// - Neither (wildcard gRPC) -> prefix `/`, method POST
/// - Not a gRPC route -> fall through to normal HTTP path matching
fn resolve_grpc_or_http_match(
    m: &super::proto::RouteMatch,
    grpc_route: bool,
) -> (String, Option<String>, Option<String>, Option<Vec<String>>) {
    if grpc_route && (!m.grpc_service.is_empty() || !m.grpc_method.is_empty()) {
        let methods = Some(vec!["POST".to_owned()]);
        if !m.grpc_service.is_empty() && !m.grpc_method.is_empty() {
            let path = format!("/{}/{}", m.grpc_service, m.grpc_method);
            ("/".to_owned(), Some(path), None, methods)
        } else if !m.grpc_service.is_empty() {
            let prefix = format!("/{}", m.grpc_service);
            (prefix, None, None, methods)
        } else {
            ("/".to_owned(), None, None, methods)
        }
    } else {
        let methods = if grpc_route {
            Some(vec!["POST".to_owned()])
        } else if m.methods.is_empty() {
            None
        } else {
            Some(m.methods.clone())
        };
        let (pp, pe, pr) = if !m.path_exact.is_empty() {
            ("/".to_owned(), Some(m.path_exact.clone()), None)
        } else if !m.path_regex.is_empty() {
            ("/".to_owned(), None, Some(m.path_regex.clone()))
        } else if !m.path_prefix.is_empty() {
            (normalize_prefix(&m.path_prefix), None, None)
        } else {
            ("/".to_owned(), None, None)
        };
        (pp, pe, pr, methods)
    }
}

/// Normalize a Gateway `PathPrefix` value for the router.
///
/// Gateway API treats `/abc` and `/abc/` as the same match; we store the
/// canonical form without a trailing slash (except root `/`).
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

// -----------------------------------------------------------------------------
// Filter chain
// -----------------------------------------------------------------------------

fn build_filter_chain(name: String, routes: Vec<Route>, gw_routes: &[GwRoute]) -> FilterChainConfig {
    let router_entry = build_router_entry(routes);
    let lb_entry = build_lb_entry(gw_routes);
    FilterChainConfig { name, filters: vec![router_entry, lb_entry] }
}

/// Build an `sni_router` filter chain for TLS passthrough listeners.
///
/// Each TLSRoute maps to an SNI route entry where `server_names` are the route
/// hostnames (intersected with the listener hostname) and `upstream` is the
/// backend address. The proxy forwards raw TLS bytes without termination.
///
/// When a route has no specific hostnames (match-any), it becomes the
/// `default_upstream` for the sni_router (handles connections whose SNI
/// doesn't match any explicit route).
fn build_sni_filter_chain(name: String, group: &[&Resource]) -> FilterChainConfig {
    let mut sni_routes: Vec<YamlValue> = Vec::new();
    let mut default_upstream: Option<String> = None;
    let mut seen_names: HashMap<String, ()> = HashMap::new();

    for resource in group {
        let Some(listener) = resource.listener.as_ref() else { continue };
        for gw_route in &resource.routes {
            if gw_route.backends.is_empty() {
                continue;
            }

            let Some(hostnames) = effective_route_hostnames(listener, gw_route) else {
                continue;
            };

            let first_backend = &gw_route.backends[0];
            let upstream = format!(
                "{}:{}",
                backend_upstream_host(first_backend, &gw_route.key),
                backend_socket_port(first_backend)
            );

            let new_names: Vec<String> = hostnames
                .into_iter()
                .flatten()
                .filter(|h| !seen_names.contains_key(h))
                .collect();
            for n in &new_names {
                seen_names.insert(n.clone(), ());
            }
            let server_names: Vec<YamlValue> = new_names
                .into_iter()
                .map(YamlValue::String)
                .collect();

            if server_names.is_empty() {
                if default_upstream.is_none() {
                    default_upstream = Some(upstream);
                }
                continue;
            }

            let mut entry = serde_yaml::Mapping::new();
            entry.insert(k("server_names"), YamlValue::Sequence(server_names));
            entry.insert(k("upstream"), YamlValue::String(upstream));
            sni_routes.push(YamlValue::Mapping(entry));
        }
    }

    let mut config_map: Vec<(&str, YamlValue)> = Vec::new();
    config_map.push(("routes", YamlValue::Sequence(sni_routes)));
    if let Some(default) = default_upstream {
        config_map.push(("default_upstream", YamlValue::String(default)));
    }

    FilterChainConfig {
        name,
        filters: vec![FilterEntry {
            filter_type: "sni_router".to_owned(),
            config: yaml_map(config_map),
            branch_chains: None,
            conditions: Vec::new(),
            response_conditions: Vec::new(),
            failure_mode: FailureMode::Closed,
            name: None,
        }],
    }
}

fn build_router_entry(routes: Vec<Route>) -> FilterEntry {
    let route_values: Vec<YamlValue> = routes
        .into_iter()
        .filter_map(|r| {
            serde_yaml::to_value(r)
                .map_err(|e| warn!(error = %e, "failed to serialize route"))
                .ok()
        })
        .collect();

    FilterEntry {
        filter_type: "router".to_owned(),
        config: yaml_map([("routes", YamlValue::Sequence(route_values))]),
        branch_chains: None,
        conditions: Vec::new(),
        response_conditions: Vec::new(),
        failure_mode: FailureMode::Closed,
        name: None,
    }
}

fn build_lb_entry(gw_routes: &[GwRoute]) -> FilterEntry {
    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut lb_clusters: Vec<YamlValue> = Vec::new();

    for gw_route in gw_routes {
        if gw_route.backends.is_empty() {
            continue;
        }

        // Skip InferencePool routes (already warned in build_routes_and_clusters).
        if gw_route.backends.iter().any(|b| b.inference_pool.is_some()) {
            continue;
        }

        let cluster_name = if gw_route.backends.len() == 1 {
            backend_cluster_name(&gw_route.backends[0], &gw_route.key)
        } else {
            format!("{}-backends", gw_route.key)
        };

        if seen.contains_key(&cluster_name) {
            continue;
        }
        seen.insert(cluster_name.clone(), ());

        let route_key = gw_route.key.as_str();
        let endpoints: Vec<YamlValue> = gw_route
            .backends
            .iter()
            .filter(|b| b.weight > 0)
            .map(|b| lb_endpoint_yaml(b, route_key))
            .collect();

        let mut cluster_map = serde_yaml::Mapping::new();
        cluster_map.insert(k("name"), YamlValue::String(cluster_name));
        cluster_map.insert(k("endpoints"), YamlValue::Sequence(endpoints));

        if let Some(b) = gw_route.backends.first() {
            if let Some(tls_yaml) = b.tls.as_ref().and_then(backend_tls_to_yaml) {
                cluster_map.insert(k("tls"), tls_yaml);
            }
        }

        lb_clusters.push(YamlValue::Mapping(cluster_map));
    }

    FilterEntry {
        filter_type: "load_balancer".to_owned(),
        config: yaml_map([("clusters", YamlValue::Sequence(lb_clusters))]),
        branch_chains: None,
        conditions: Vec::new(),
        response_conditions: Vec::new(),
        failure_mode: FailureMode::Closed,
        name: None,
    }
}

// -----------------------------------------------------------------------------
// TLS helpers
// -----------------------------------------------------------------------------

fn build_cluster_tls(backend_tls: &BackendTls) -> Option<ClusterTls> {
    if backend_tls.invalid {
        return None;
    }

    let ca = if backend_tls.ca_cert.is_empty() {
        None
    } else {
        Some(CaConfig::from_pem(backend_tls.ca_cert.clone()))
    };

    let has_ca = ca.is_some();

    let client_cert = if !backend_tls.client_cert.is_empty() && !backend_tls.client_key.is_empty() {
        Some(CertKeyPair::from_pem(backend_tls.client_cert.clone(), backend_tls.client_key.clone()))
    } else {
        None
    };

    let sni = if backend_tls.hostname.is_empty() { None } else { Some(backend_tls.hostname.clone()) };

    Some(ClusterTls {
        ca,
        client_cert,
        sni,
        verify: has_ca,
    })
}

fn backend_tls_to_yaml(tls: &BackendTls) -> Option<YamlValue> {
    if tls.invalid {
        return None;
    }
    let cluster_tls = build_cluster_tls(tls)?;
    serde_yaml::to_value(cluster_tls).ok()
}

// -----------------------------------------------------------------------------
// YAML helpers
// -----------------------------------------------------------------------------

fn yaml_map<K, I>(pairs: I) -> YamlValue
where
    K: Into<String>,
    I: IntoIterator<Item = (K, YamlValue)>,
{
    let mut map = serde_yaml::Mapping::new();
    for (key, v) in pairs {
        map.insert(YamlValue::String(key.into()), v);
    }
    YamlValue::Mapping(map)
}

fn k(s: &str) -> YamlValue {
    YamlValue::String(s.to_owned())
}

/// YAML for one load_balancer cluster endpoint, preserving Gateway backend weights.
///
/// Matches [`Endpoint`](crate::config::Endpoint) untagged serde: plain string (implicit weight 1)
/// or `{ address, weight }`.
fn lb_endpoint_yaml(b: &Backend, route_key: &str) -> YamlValue {
    let address = format!("{}:{}", backend_upstream_host(b, route_key), backend_socket_port(b));
    let weight = b.weight;
    debug_assert!(weight > 0, "lb_endpoint_yaml expects callers to filter weight > 0");
    if weight == 1 {
        YamlValue::String(address)
    } else {
        let mut m = serde_yaml::Mapping::new();
        m.insert(k("address"), YamlValue::String(address));
        m.insert(k("weight"), YamlValue::Number(weight.into()));
        YamlValue::Mapping(m)
    }
}

#[cfg(test)]
mod lb_yaml_tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct LoadBalancerYaml {
        clusters: Vec<Cluster>,
    }

    #[test]
    fn lb_entry_preserves_multi_backend_weights() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(super::super::proto::Listener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: 1,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/rule".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![
                    Backend {
                        host: "a.ns.svc.cluster.local".into(),
                        port: 80,
                        dial_port: 0,
                        weight: 70,
                        inference_pool: None,
                        tls: None,
                    },
                    Backend {
                        host: "b.ns.svc.cluster.local".into(),
                        port: 80,
                        dial_port: 0,
                        weight: 30,
                        inference_pool: None,
                        tls: None,
                    },
                ],
                ..Default::default()
            }],
        };

        let entry = build_lb_entry(&resource.routes);
        let parsed: LoadBalancerYaml =
            serde_yaml::from_value(entry.config.clone()).expect("load_balancer filter config should deserialize");

        assert_eq!(parsed.clusters.len(), 1);
        let c = &parsed.clusters[0];
        assert_eq!(c.endpoints.len(), 2);
        assert_eq!(c.endpoints[0].address(), "a.ns.svc.cluster.local:80");
        assert_eq!(c.endpoints[0].weight(), 70);
        assert_eq!(c.endpoints[1].address(), "b.ns.svc.cluster.local:80");
        assert_eq!(c.endpoints[1].weight(), 30);
    }

    #[test]
    fn lb_entry_omits_zero_weight_backends() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(super::super::proto::Listener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: 1,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/rule".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![
                    Backend {
                        host: "a.ns.svc.cluster.local".into(),
                        port: 80,
                        dial_port: 0,
                        weight: 70,
                        inference_pool: None,
                        tls: None,
                    },
                    Backend {
                        host: "b.ns.svc.cluster.local".into(),
                        port: 80,
                        dial_port: 0,
                        weight: 30,
                        inference_pool: None,
                        tls: None,
                    },
                    Backend {
                        host: "c.ns.svc.cluster.local".into(),
                        port: 80,
                        dial_port: 0,
                        weight: 0,
                        inference_pool: None,
                        tls: None,
                    },
                ],
                ..Default::default()
            }],
        };

        let entry = build_lb_entry(&resource.routes);
        let parsed: LoadBalancerYaml =
            serde_yaml::from_value(entry.config.clone()).expect("load_balancer filter config should deserialize");

        assert_eq!(parsed.clusters.len(), 1);
        assert_eq!(parsed.clusters[0].endpoints.len(), 2);
    }

    #[test]
    fn lb_entry_uses_dial_port_in_addresses() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(super::super::proto::Listener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: 1,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/rule".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![Backend {
                    host: "svc.ns.svc.cluster.local".into(),
                    port: 8080,
                    dial_port: 3000,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let entry = build_lb_entry(&resource.routes);
        let parsed: LoadBalancerYaml =
            serde_yaml::from_value(entry.config.clone()).expect("load_balancer filter config should deserialize");

        assert_eq!(parsed.clusters.len(), 1);
        assert_eq!(
            parsed.clusters[0].endpoints[0].address(),
            "svc.ns.svc.cluster.local:3000"
        );
    }

    #[test]
    fn lb_entry_qualifies_short_same_namespace_service_host() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(super::super::proto::Listener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: 1,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "gateway-conformance-infra/service-types/0".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![Backend {
                    host: "headless".into(),
                    port: 8080,
                    dial_port: 3000,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let entry = build_lb_entry(&resource.routes);
        let parsed: LoadBalancerYaml =
            serde_yaml::from_value(entry.config.clone()).expect("load_balancer filter config should deserialize");

        assert_eq!(parsed.clusters.len(), 1);
        assert_eq!(
            parsed.clusters[0].endpoints[0].address(),
            "headless.gateway-conformance-infra.svc.cluster.local:3000"
        );
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    #[test]
    fn hostname_overlap_wildcard_and_exact() {
        assert!(intersect_listener_route_hostname("*.wildcard.io", "foo.wildcard.io").is_some());
        assert!(intersect_listener_route_hostname("*.wildcard.io", "foo.bar.wildcard.io").is_some());
        assert!(!intersect_listener_route_hostname("*.wildcard.io", "wildcard.io").is_some());
        assert!(intersect_listener_route_hostname("very.specific.com", "very.specific.com").is_some());
    }

    #[test]
    fn hostname_intersection_narrows_wildcard_route_to_exact_listener() {
        assert_eq!(
            intersect_listener_route_hostname("very.specific.com", "*.specific.com"),
            Some("very.specific.com".into())
        );
        assert_eq!(intersect_listener_route_hostname("very.specific.com", "foo.specific.com"), None);
    }

    #[test]
    fn hostname_intersection_multi_prefix_under_listener_wildcard() {
        assert_eq!(
            intersect_listener_route_hostname("*.bar.com", "multiple.prefixes.bar.com"),
            Some("multiple.prefixes.bar.com".into())
        );
        assert_eq!(
            intersect_listener_route_hostname("*.foo.com", "multiple.prefixes.foo.com"),
            Some("multiple.prefixes.foo.com".into())
        );
    }

    #[test]
    fn merge_two_http_listeners_same_port() {
        let backend = Backend {
            host: "svc.ns.svc.cluster.local".into(),
            port: 80,
            dial_port: 0,
            weight: 1,
            inference_pool: None,
            tls: None,
        };

        let r1 = Resource {
            key: "ns/gw/l1".into(),
            listener: Some(GwListener {
                key: "ns/gw/l1".into(),
                hostname: "a.example.com".into(),
                port: 8080,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/1".into(),
                listener_key: "ns/gw/l1".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![backend.clone()],
                ..Default::default()
            }],
        };

        let r2 = Resource {
            key: "ns/gw/l2".into(),
            listener: Some(GwListener {
                key: "ns/gw/l2".into(),
                hostname: "b.example.com".into(),
                port: 8080,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/2".into(),
                listener_key: "ns/gw/l2".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                backends: vec![backend],
                ..Default::default()
            }],
        };

        let cfg = translate(&[r1, r2]);
        assert_eq!(cfg.listeners.len(), 1);
        assert!(cfg.listeners[0].name.starts_with("gwxds-merge-8080-"));
        assert_eq!(cfg.filter_chains.len(), 1);

        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let n = router
            .config
            .get("routes")
            .and_then(|v| v.as_sequence())
            .expect("routes")
            .len();
        assert_eq!(n, 2, "expected one route row per merged listener hostname");
    }

    #[test]
    fn invalid_backend_ref_emits_router_row_without_cluster() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(GwListener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/route/bad".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: true,
                backends: vec![],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        assert!(cfg.clusters.is_empty(), "invalid backend route should not create clusters");

        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let row = &router.config["routes"].as_sequence().expect("routes seq")[0];
        assert_eq!(row.get("invalid_backend_ref").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn partial_invalid_backend_ref_produces_valid_config() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(GwListener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![
                GwRoute {
                    key: "ns/route/denied".into(),
                    listener_key: "ns/gw/http".into(),
                    hostnames: vec![],
                    matches: vec![super::super::proto::RouteMatch {
                        path_prefix: "/v2".into(),
                        ..Default::default()
                    }],
                    invalid_backend_ref: true,
                    backends: vec![],
                    ..Default::default()
                },
                GwRoute {
                    key: "ns/route/allowed".into(),
                    listener_key: "ns/gw/http".into(),
                    hostnames: vec![],
                    matches: vec![super::super::proto::RouteMatch {
                        path_prefix: "/".into(),
                        ..Default::default()
                    }],
                    invalid_backend_ref: false,
                    backends: vec![Backend {
                        host: "app-v1.other.svc.cluster.local".into(),
                        port: 8080,
                        dial_port: 0,
                        weight: 1,
                        inference_pool: None,
                        tls: None,
                    }],
                    ..Default::default()
                },
            ],
        };

        let cfg = translate(&[resource]);

        assert_eq!(cfg.clusters.len(), 1, "only the valid backend should produce a cluster");
        assert_eq!(cfg.clusters[0].name.as_ref(), "app-v1.other.svc.cluster.local:8080");

        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let routes = router.config["routes"].as_sequence().expect("routes seq");
        assert_eq!(routes.len(), 2, "both routes should appear in router config");

        let denied_route = routes
            .iter()
            .find(|r| r.get("path_prefix").and_then(|v| v.as_str()) == Some("/v2"))
            .expect("denied /v2 route");
        assert_eq!(
            denied_route.get("cluster").and_then(|v| v.as_str()),
            Some("__invalid_backend__"),
        );
        assert_eq!(
            denied_route.get("invalid_backend_ref").and_then(|v| v.as_bool()),
            Some(true),
        );

        let lb = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "load_balancer")
            .expect("load_balancer filter");
        let lb_clusters = lb.config["clusters"].as_sequence().expect("clusters seq");
        assert_eq!(lb_clusters.len(), 1, "LB should have only the valid cluster");
        let lb_cluster_names: Vec<&str> = lb_clusters
            .iter()
            .filter_map(|c| c.get("name").and_then(|v| v.as_str()))
            .collect();
        assert!(
            !lb_cluster_names.contains(&"__invalid_backend__"),
            "__invalid_backend__ should NOT appear in LB clusters"
        );
    }

    #[test]
    fn grpc_route_service_method_becomes_exact_path() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(GwListener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/grpc-route/0".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                grpc_route: true,
                matches: vec![super::super::proto::RouteMatch {
                    grpc_service: "helloworld.Greeter".into(),
                    grpc_method: "SayHello".into(),
                    ..Default::default()
                }],
                backends: vec![Backend {
                    host: "grpc-svc.ns.svc.cluster.local".into(),
                    port: 50051,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let routes = router.config["routes"].as_sequence().expect("routes seq");
        assert_eq!(routes.len(), 1);
        let row: Route = serde_yaml::from_value(routes[0].clone()).expect("deserialise route");
        assert_eq!(row.path_exact.as_deref(), Some("/helloworld.Greeter/SayHello"));
        assert_eq!(row.methods.as_deref(), Some(&["POST".to_owned()][..]));
        assert!(row.grpc_route);
    }

    #[test]
    fn grpc_route_service_only_becomes_prefix_path() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(GwListener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/grpc-route/0".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                grpc_route: true,
                matches: vec![super::super::proto::RouteMatch {
                    grpc_service: "helloworld.Greeter".into(),
                    ..Default::default()
                }],
                backends: vec![Backend {
                    host: "grpc-svc.ns.svc.cluster.local".into(),
                    port: 50051,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let routes = router.config["routes"].as_sequence().expect("routes seq");
        let row: Route = serde_yaml::from_value(routes[0].clone()).expect("deserialise route");
        assert_eq!(row.path_prefix, "/helloworld.Greeter");
        assert!(row.path_exact.is_none());
        assert_eq!(row.methods.as_deref(), Some(&["POST".to_owned()][..]));
        assert!(row.grpc_route);
    }

    #[test]
    fn grpc_route_wildcard_becomes_root_prefix() {
        let resource = Resource {
            key: "ns/gw/http".into(),
            listener: Some(GwListener {
                key: "ns/gw/http".into(),
                hostname: "".into(),
                port: 80,
                protocol: Protocol::Http as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/grpc-route/0".into(),
                listener_key: "ns/gw/http".into(),
                hostnames: vec![],
                grpc_route: true,
                matches: vec![],
                backends: vec![Backend {
                    host: "grpc-svc.ns.svc.cluster.local".into(),
                    port: 50051,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        let router = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "router")
            .expect("router filter");
        let routes = router.config["routes"].as_sequence().expect("routes seq");
        let row: Route = serde_yaml::from_value(routes[0].clone()).expect("deserialise route");
        assert_eq!(row.path_prefix, "/");
        assert!(row.path_exact.is_none());
        assert_eq!(row.methods.as_deref(), Some(&["POST".to_owned()][..]));
        assert!(row.grpc_route);
    }

    #[test]
    fn tls_passthrough_produces_sni_router_filter() {
        let resource = Resource {
            key: "ns/gw/tls".into(),
            listener: Some(GwListener {
                key: "ns/gw/tls".into(),
                hostname: "*.example.com".into(),
                port: 443,
                protocol: Protocol::Tls as i32,
                tls: None,
                allowed_routes: vec!["gateway.networking.k8s.io/TLSRoute".into()],
            }),
            routes: vec![GwRoute {
                key: "ns/tls-route/0".into(),
                listener_key: "ns/gw/tls".into(),
                hostnames: vec!["svc.example.com".into()],
                matches: vec![],
                request_redirect: None,
                request_header_modifier: None,
                invalid_backend_ref: false,
                tls_route: true,
                backends: vec![Backend {
                    host: "svc.ns.svc.cluster.local".into(),
                    port: 8443,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].protocol, ProtocolKind::Tcp);
        assert_eq!(cfg.filter_chains.len(), 1);

        let sni_filter = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "sni_router")
            .expect("sni_router filter should be present for TLS passthrough");

        let routes = sni_filter.config["routes"]
            .as_sequence()
            .expect("sni_router should have routes");
        assert_eq!(routes.len(), 1);

        let entry = &routes[0];
        let names = entry["server_names"].as_sequence().expect("server_names");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), Some("svc.example.com"));

        let upstream = entry["upstream"].as_str().expect("upstream");
        assert_eq!(upstream, "svc.ns.svc.cluster.local:8443");

        assert!(
            cfg.filter_chains[0].filters.iter().all(|f| f.filter_type != "router"),
            "TLS passthrough should not have an HTTP router filter"
        );
    }

    #[test]
    fn tls_passthrough_multiple_routes_merged() {
        let backend1 = Backend {
            host: "svc1.ns.svc.cluster.local".into(),
            port: 8443,
            dial_port: 0,
            weight: 1,
            inference_pool: None,
            tls: None,
        };
        let backend2 = Backend {
            host: "svc2.ns.svc.cluster.local".into(),
            port: 9443,
            dial_port: 0,
            weight: 1,
            inference_pool: None,
            tls: None,
        };

        let r1 = Resource {
            key: "ns/gw/tls-1".into(),
            listener: Some(GwListener {
                key: "ns/gw/tls-1".into(),
                hostname: "*.example.com".into(),
                port: 443,
                protocol: Protocol::Tls as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/tls-route-a/0".into(),
                listener_key: "ns/gw/tls-1".into(),
                hostnames: vec!["a.example.com".into()],
                tls_route: true,
                backends: vec![backend1],
                ..Default::default()
            }],
        };

        let r2 = Resource {
            key: "ns/gw/tls-2".into(),
            listener: Some(GwListener {
                key: "ns/gw/tls-2".into(),
                hostname: "*.example.com".into(),
                port: 443,
                protocol: Protocol::Tls as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/tls-route-b/0".into(),
                listener_key: "ns/gw/tls-2".into(),
                hostnames: vec!["b.example.com".into()],
                tls_route: true,
                backends: vec![backend2],
                ..Default::default()
            }],
        };

        let cfg = translate(&[r1, r2]);
        assert_eq!(cfg.listeners.len(), 1, "TLS passthrough listeners on same port should merge");
        assert_eq!(cfg.filter_chains.len(), 1);

        let sni_filter = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "sni_router")
            .expect("sni_router filter");
        let routes = sni_filter.config["routes"]
            .as_sequence()
            .expect("routes");
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn tls_passthrough_empty_hostname_uses_route_hostnames() {
        let resource = Resource {
            key: "ns/gw/tls".into(),
            listener: Some(GwListener {
                key: "ns/gw/tls".into(),
                hostname: "".into(),
                port: 443,
                protocol: Protocol::Tls as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/tls-route/0".into(),
                listener_key: "ns/gw/tls".into(),
                hostnames: vec!["foo.test.com".into(), "bar.test.com".into()],
                tls_route: true,
                backends: vec![Backend {
                    host: "backend.ns.svc.cluster.local".into(),
                    port: 443,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        let sni_filter = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "sni_router")
            .expect("sni_router filter");
        let routes = sni_filter.config["routes"]
            .as_sequence()
            .expect("routes");
        assert_eq!(routes.len(), 1);
        let names = routes[0]["server_names"].as_sequence().expect("server_names");
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].as_str(), Some("foo.test.com"));
        assert_eq!(names[1].as_str(), Some("bar.test.com"));
    }

    #[test]
    fn tls_passthrough_no_hostnames_becomes_default_upstream() {
        let resource = Resource {
            key: "ns/gw/tls".into(),
            listener: Some(GwListener {
                key: "ns/gw/tls".into(),
                hostname: "".into(),
                port: 443,
                protocol: Protocol::Tls as i32,
                tls: None,
                allowed_routes: vec![],
            }),
            routes: vec![GwRoute {
                key: "ns/tls-route/0".into(),
                listener_key: "ns/gw/tls".into(),
                hostnames: vec![],
                tls_route: true,
                backends: vec![Backend {
                    host: "backend.ns.svc.cluster.local".into(),
                    port: 443,
                    dial_port: 0,
                    weight: 1,
                    inference_pool: None,
                    tls: None,
                }],
                ..Default::default()
            }],
        };

        let cfg = translate(&[resource]);
        let sni_filter = cfg.filter_chains[0]
            .filters
            .iter()
            .find(|f| f.filter_type == "sni_router")
            .expect("sni_router filter");

        assert!(
            sni_filter.config.get("routes").is_none()
                || sni_filter.config["routes"].as_sequence().map_or(true, |r| r.is_empty()),
            "no explicit routes when both listener and route have no hostname"
        );

        let default = sni_filter.config["default_upstream"]
            .as_str()
            .expect("default_upstream should be set");
        assert_eq!(default, "backend.ns.svc.cluster.local:443");
    }
}
