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
    FilterEntry, InsecureOptions, Listener, ProtocolKind, RedirectAction, Route, RuntimeConfig,
};

use super::proto::{
    Backend, BackendTls, Listener as GwListener, Protocol, RequestRedirect as ProtoRequestRedirect, Resource,
    Route as GwRoute, TlsConfig,
};

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
        Protocol::Tcp | Protocol::Tls => ProtocolKind::Tcp,
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

        if gw_route.backends.is_empty() && redirect_cfg.is_none() {
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

        let cluster_name = if redirect_cfg.is_some() && gw_route.backends.is_empty() {
            "__redirect__".to_owned()
        } else if gw_route.backends.len() == 1 {
            backend_cluster_name(&gw_route.backends[0])
        } else {
            format!("{}-backends", gw_route.key)
        };

        if !gw_route.backends.is_empty() && !seen_clusters.contains_key(&cluster_name) {
            let endpoints: Vec<Endpoint> = gw_route
                .backends
                .iter()
                .flat_map(|b| {
                    let addr = format!("{}:{}", b.host, b.port);
                    let weight = b.weight.max(1) as usize;
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
                    methods: None,
                    host: host.clone(),
                    headers: None,
                    redirect: redirect_cfg.clone(),
                    cluster: Arc::from(cluster_name.as_str()),
                })
                .collect()
        } else {
            gw_route
                .matches
                .iter()
                .flat_map(|m| expand_route_match(m, &cluster_name, &hostnames, redirect_cfg.clone()))
                .collect()
        };

        routes.extend(match_routes);
    }

    (routes, clusters)
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
        if lh.is_empty() || hostname_patterns_overlap(lh, rh) {
            out.push(Some(rh.clone()));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Whether `route_host` hostname pattern overlaps `listener_host` (listener hostname from Gateway).
fn hostname_patterns_overlap(listener_host: &str, route_host: &str) -> bool {
    let l = listener_host.trim();
    let r = route_host.trim();
    if l.eq_ignore_ascii_case(r) {
        return true;
    }

    let l_wild = l.strip_prefix("*.");
    let r_wild = r.strip_prefix("*.");

    match (l_wild, r_wild) {
        (Some(lsuffix), Some(rsuffix)) => {
            lsuffix.eq_ignore_ascii_case(rsuffix)
                || lsuffix.ends_with(&format!(".{rsuffix}"))
                || rsuffix.ends_with(&format!(".{lsuffix}"))
        }
        (Some(lsuffix), None) => host_matches_wildcard_suffix(r, lsuffix),
        (None, Some(rsuffix)) => host_matches_wildcard_suffix(l, rsuffix),
        (None, None) => false,
    }
}

/// `*.suffix` Gateway pattern: one DNS label + suffix domain (matches router wildcard semantics).
fn host_matches_wildcard_suffix(host: &str, suffix_after_star_dot: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let suffix = format!(".{}", suffix_after_star_dot.to_ascii_lowercase());
    if h.len() <= suffix.len() || !h.ends_with(&suffix) {
        return false;
    }
    let prefix = &h[..h.len() - suffix.len()];
    !prefix.is_empty() && !prefix.contains('.')
}

fn backend_cluster_name(backend: &Backend) -> String {
    format!("{}:{}", backend.host, backend.port)
}

fn expand_route_match(
    m: &super::proto::RouteMatch,
    cluster_name: &str,
    hostnames: &[Option<String>],
    redirect: Option<RedirectAction>,
) -> Vec<Route> {
    let (path_prefix, path_exact, path_regex) = resolve_path_match(m);
    let headers = if m.headers.is_empty() { None } else { Some(m.headers.clone()) };
    let methods = if m.methods.is_empty() { None } else { Some(m.methods.clone()) };

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
            cluster: Arc::from(cluster_name),
        })
        .collect()
}

fn resolve_path_match(
    m: &super::proto::RouteMatch,
) -> (String, Option<String>, Option<String>) {
    if !m.path_exact.is_empty() {
        ("/".to_owned(), Some(m.path_exact.clone()), None)
    } else if !m.path_regex.is_empty() {
        ("/".to_owned(), None, Some(m.path_regex.clone()))
    } else if !m.path_prefix.is_empty() {
        let prefix = normalize_prefix(&m.path_prefix);
        (prefix, None, None)
    } else {
        ("/".to_owned(), None, None)
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
            backend_cluster_name(&gw_route.backends[0])
        } else {
            format!("{}-backends", gw_route.key)
        };

        if seen.contains_key(&cluster_name) {
            continue;
        }
        seen.insert(cluster_name.clone(), ());

        let endpoints: Vec<YamlValue> = gw_route.backends.iter().map(lb_endpoint_yaml).collect();

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
fn lb_endpoint_yaml(b: &Backend) -> YamlValue {
    let address = format!("{}:{}", b.host, b.port);
    let weight = b.weight.max(1);
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
                backends: vec![
                    Backend {
                        host: "a.ns.svc.cluster.local".into(),
                        port: 80,
                        weight: 70,
                        inference_pool: None,
                        tls: None,
                    },
                    Backend {
                        host: "b.ns.svc.cluster.local".into(),
                        port: 80,
                        weight: 30,
                        inference_pool: None,
                        tls: None,
                    },
                ],
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
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    #[test]
    fn hostname_overlap_wildcard_and_exact() {
        assert!(hostname_patterns_overlap("*.wildcard.io", "foo.wildcard.io"));
        assert!(!hostname_patterns_overlap("*.wildcard.io", "wildcard.io"));
        assert!(hostname_patterns_overlap("very.specific.com", "very.specific.com"));
    }

    #[test]
    fn merge_two_http_listeners_same_port() {
        let backend = Backend {
            host: "svc.ns.svc.cluster.local".into(),
            port: 80,
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
                backends: vec![backend.clone()],
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
                backends: vec![backend],
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
}
