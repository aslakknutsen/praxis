// SPDX-License-Identifier: MIT

//! Translate a slice of [`Resource`] objects (from istiod's gwxds xDS stream)
//! into a praxis [`Config`].
//!
//! # Translation model (v1)
//!
//! One `Resource` (= one gateway listener) produces:
//! - One praxis [`Listener`] bound on `0.0.0.0:{port}`
//! - One synthetic [`FilterChainConfig`] named `{resource-key}-chain` containing:
//!   - A `router` filter with route entries derived from all `Route`s
//!   - A `load_balancer` filter with one cluster per unique backend `host:port`
//! - N [`Cluster`] objects, one per unique backend, deduped across all routes
//!
//! # Listener topology
//!
//! Listener topology changes require a proxy restart because Pingora binds
//! sockets at startup. Subsequent gwxds pushes can only hot-reload route
//! tables and cluster endpoints via `reload_pipelines`.

use std::collections::HashMap;
use std::sync::Arc;

use praxis_tls::{CaConfig, CertKeyPair, ClusterTls, ListenerTls};
use serde_yaml::Value as YamlValue;
use tracing::warn;

use crate::config::{
    AdminConfig, BodyLimitsConfig, Cluster, Config, Endpoint, FailureMode, FilterChainConfig,
    FilterEntry, InsecureOptions, Listener, ProtocolKind, Route, RuntimeConfig,
};

use super::proto::{Backend, BackendTls, Listener as GwListener, Protocol, Resource, Route as GwRoute};

/// Convert a slice of [`Resource`] objects into a praxis [`Config`].
pub fn translate(resources: &[Resource]) -> Config {
    let mut listeners: Vec<Listener> = Vec::new();
    let mut filter_chains: Vec<FilterChainConfig> = Vec::new();
    let mut clusters: HashMap<String, Cluster> = HashMap::new();

    for resource in resources {
        let chain_name = format!("{}-chain", resource.key);
        let Some(gw_listener) = resource.listener.as_ref() else {
            warn!(key = %resource.key, "gwxds resource has no listener; skipping");
            continue;
        };
        let listener = build_listener(gw_listener, &chain_name);

        let (routes, resource_clusters) = build_routes_and_clusters(resource);

        for cluster in resource_clusters {
            clusters.entry(cluster.name.to_string()).or_insert(cluster);
        }

        let filter_chain = build_filter_chain(chain_name, routes, resource);
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

fn build_listener(gw_listener: &GwListener, chain_name: &str) -> Listener {
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
        name: gw_listener.key.clone(),
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

fn build_routes_and_clusters(resource: &Resource) -> (Vec<Route>, Vec<Cluster>) {
    let mut routes: Vec<Route> = Vec::new();
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut seen_clusters: HashMap<String, ()> = HashMap::new();

    for gw_route in &resource.routes {
        if gw_route.backends.is_empty() {
            continue;
        }

        // InferencePool backends require EPP support that is not yet implemented.
        if gw_route.backends.iter().any(|b| b.inference_pool.is_some()) {
            warn!(
                route = %gw_route.key,
                "route has InferencePool backends which are not yet supported; skipping route"
            );
            continue;
        }

        let cluster_name = if gw_route.backends.len() == 1 {
            backend_cluster_name(&gw_route.backends[0])
        } else {
            format!("{}-backends", gw_route.key)
        };

        if !seen_clusters.contains_key(&cluster_name) {
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
        let match_routes = if gw_route.matches.is_empty() {
            vec![Route {
                path_prefix: "/".to_owned(),
                path_exact: None,
                path_regex: None,
                methods: None,
                host: gw_route.hostnames.first().cloned(),
                headers: None,
                cluster: Arc::from(cluster_name.as_str()),
            }]
        } else {
            gw_route
                .matches
                .iter()
                .flat_map(|m| expand_route_match(m, &cluster_name, gw_route))
                .collect()
        };

        routes.extend(match_routes);
    }

    (routes, clusters)
}

fn backend_cluster_name(backend: &Backend) -> String {
    format!("{}:{}", backend.host, backend.port)
}

fn expand_route_match(
    m: &super::proto::RouteMatch,
    cluster_name: &str,
    gw_route: &GwRoute,
) -> Vec<Route> {
    let (path_prefix, path_exact, path_regex) = resolve_path_match(m);
    let headers = if m.headers.is_empty() { None } else { Some(m.headers.clone()) };
    let methods = if m.methods.is_empty() { None } else { Some(m.methods.clone()) };

    let hostnames: Vec<Option<String>> = if gw_route.hostnames.is_empty() {
        vec![None]
    } else {
        gw_route.hostnames.iter().map(|h| Some(h.clone())).collect()
    };

    hostnames
        .into_iter()
        .map(|host| Route {
            path_prefix: path_prefix.clone(),
            path_exact: path_exact.clone(),
            path_regex: path_regex.clone(),
            methods: methods.clone(),
            host,
            headers: headers.clone(),
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

fn build_filter_chain(name: String, routes: Vec<Route>, resource: &Resource) -> FilterChainConfig {
    let router_entry = build_router_entry(routes);
    let lb_entry = build_lb_entry(resource);
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

fn build_lb_entry(resource: &Resource) -> FilterEntry {
    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut lb_clusters: Vec<YamlValue> = Vec::new();

    for gw_route in &resource.routes {
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

        let endpoints: Vec<YamlValue> = gw_route
            .backends
            .iter()
            .map(|b| YamlValue::String(format!("{}:{}", b.host, b.port)))
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
