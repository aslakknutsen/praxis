// SPDX-License-Identifier: MIT

//! Node identity construction for gateway proxies.
//!
//! istiod parses `node.id` via `ParseServiceNodeWithMetadata` (Istio pilot): it must be four
//! segments separated by `~`: `{nodeType}~{ip}~{workload}.{namespace}~{namespace}.svc.{trustDomain}`.
//! A short id like `{gateway}.{namespace}` is rejected and ADS never completes.
//!
//! Labels that scope PerGatewayCollection live under metadata key `LABELS` (Istio
//! `NodeMetadata.Labels`), not at the top level of the metadata struct.

use std::collections::BTreeMap;

use prost_types::{Struct, Value, value::Kind};
use tracing::info;

use crate::proto::Node;

/// Default trust domain when `TRUST_DOMAIN` is unset (matches typical Istio installs).
const DEFAULT_TRUST_DOMAIN: &str = "cluster.local";

/// Read gateway identity from environment and build an xDS [`Node`].
///
/// Environment variables:
/// - `GATEWAY_NAME` (required): name of the Kubernetes Gateway resource
/// - `GATEWAY_NAMESPACE` (required): namespace of the Gateway resource
/// - `POD_NAME` (optional): pod name for the Istio service-node id (`status.podIP`-style workloads)
/// - `POD_NAMESPACE` (optional): falls back to `GATEWAY_NAMESPACE`
/// - `INSTANCE_IP` or `POD_IP` (optional): pod IP; defaults to `127.0.0.1` for local/dev without refs
/// - `TRUST_DOMAIN` (optional): defaults to `cluster.local`
/// - `SERVICE_ACCOUNT_NAME` (optional): sets metadata `SERVICE_ACCOUNT` for istiod identity checks
/// - `ISTIO_VERSION` or `ISTIO_META_ISTIO_VERSION` (optional): istiod expects JSON key `ISTIO_VERSION`
///   (same as Envoy bootstrap); omitting it logs `Istio Version is not found in metadata`. Set to the
///   control plane / mesh version your gateway targets (e.g. Helm `global.tag`).
///
/// # Errors
///
/// Returns an error string if either gateway env var is missing.
pub(crate) fn node_from_env() -> Result<Node, String> {
    let gateway_name = std::env::var("GATEWAY_NAME")
        .map_err(|_| "GATEWAY_NAME env var not set".to_owned())?;
    let gateway_namespace = std::env::var("GATEWAY_NAMESPACE")
        .map_err(|_| "GATEWAY_NAMESPACE env var not set".to_owned())?;

    let pod_name = std::env::var("POD_NAME").ok();
    let pod_namespace =
        std::env::var("POD_NAMESPACE").unwrap_or_else(|_| gateway_namespace.clone());

    let instance_ip = std::env::var("INSTANCE_IP")
        .ok()
        .or_else(|| std::env::var("POD_IP").ok())
        .filter(|s| !s.is_empty());

    let trust_domain =
        std::env::var("TRUST_DOMAIN").unwrap_or_else(|_| DEFAULT_TRUST_DOMAIN.to_owned());

    let node = build_node(
        &gateway_name,
        &gateway_namespace,
        pod_name.as_deref(),
        &pod_namespace,
        instance_ip.as_deref(),
        &trust_domain,
    );

    info!(
        node_id = %node.id,
        cluster = %node.cluster,
        gateway_name = %gateway_name,
        gateway_namespace = %gateway_namespace,
        pod_name = pod_name.as_deref(),
        pod_namespace = %pod_namespace,
        trust_domain = %trust_domain,
        instance_ip_env = instance_ip.is_some(),
        "xDS node identity (istiod expects node.id = type~ip~workload.ns~ns.svc.trustDomain)"
    );

    Ok(node)
}

fn build_node(
    gateway_name: &str,
    gateway_namespace: &str,
    pod_name: Option<&str>,
    pod_namespace: &str,
    instance_ip: Option<&str>,
    trust_domain: &str,
) -> Node {
    let ip = instance_ip.unwrap_or("127.0.0.1");

    let workload_segment = match pod_name {
        Some(pn) => format!("{pn}.{pod_namespace}"),
        None => format!("{gateway_name}.{gateway_namespace}"),
    };

    let dns_domain = format!("{pod_namespace}.svc.{trust_domain}");

    // Istio `GwXds` node type is registered for gwxds-capable proxies (see pkg/model/proxy.go).
    let id = format!("gwxds~{ip}~{workload_segment}~{dns_domain}");

    let mut label_fields: BTreeMap<String, Value> = BTreeMap::new();
    label_fields.insert(
        "gateway.networking.k8s.io/gateway-name".to_owned(),
        Value { kind: Some(Kind::StringValue(gateway_name.to_owned())) },
    );
    label_fields.insert(
        "gateway.networking.k8s.io/gateway-namespace".to_owned(),
        Value { kind: Some(Kind::StringValue(gateway_namespace.to_owned())) },
    );

    let labels_struct = Value {
        kind: Some(Kind::StructValue(Struct { fields: label_fields })),
    };

    let mut meta_fields: BTreeMap<String, Value> = BTreeMap::new();
    meta_fields.insert("LABELS".to_owned(), labels_struct);
    meta_fields.insert(
        "NAMESPACE".to_owned(),
        Value { kind: Some(Kind::StringValue(pod_namespace.to_owned())) },
    );
    // StringList in Istio metadata JSON is a comma-separated string.
    meta_fields.insert(
        "INSTANCE_IPS".to_owned(),
        Value { kind: Some(Kind::StringValue(ip.to_owned())) },
    );

    // Istio `NodeMetadata.SERVICE_ACCOUNT` — optional; helps if PILOT_ENABLE_XDS_IDENTITY_CHECK
    // matching is enabled. Inject via downward API: fieldPath `spec.serviceAccountName`.
    if let Ok(sa) = std::env::var("SERVICE_ACCOUNT_NAME") {
        if !sa.is_empty() {
            meta_fields.insert(
                "SERVICE_ACCOUNT".to_owned(),
                Value { kind: Some(Kind::StringValue(sa)) },
            );
        }
    }

    let istio_version = std::env::var("ISTIO_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("ISTIO_META_ISTIO_VERSION")
                .ok()
                .filter(|s| !s.is_empty())
        });
    if let Some(v) = istio_version {
        meta_fields.insert(
            "ISTIO_VERSION".to_owned(),
            Value { kind: Some(Kind::StringValue(v)) },
        );
    }

    let metadata = Struct { fields: meta_fields };

    Node {
        id,
        cluster: gateway_namespace.to_owned(),
        metadata: Some(metadata),
    }
}
