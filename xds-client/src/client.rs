// SPDX-License-Identifier: MIT

//! High-level xDS client that subscribes to gwxds resources and decodes them
//! into [`Resource`] objects.
//!
//! # Wire format
//!
//! istiod encodes each `Resource` as:
//!   1. A `gwxdsapi.Resource` serialized to binary protobuf.
//!   2. Wrapped in `google.protobuf.Any` with
//!      `type_url = "type.googleapis.com/istio.gwxds.Resource"`.
//!   3. The `Any` is placed inside a `DiscoveryResponse.resources` list.
//!
//! We decode it by calling `Resource::decode` directly on `Any.value`.
//!
//! # Authentication
//!
//! When `istiod_address` begins with `https://`, credentials are loaded from
//! well-known paths (overridable via `CA_CERT_PATH` / `XDS_TOKEN_PATH` env
//! vars) and passed to the underlying ADS client. The token is re-read from
//! disk on every reconnect to handle Kubernetes projected token rotation.

use prost::Message as _;
use tonic::Streaming;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use praxis_core::gwxds::Resource;

use crate::{
    ads::{XdsCredentials, XdsError, connect, open_ads_stream},
    node::node_from_env,
    proto::{DiscoveryRequest, DiscoveryResponse},
};

/// TypeURL for gwxds resources (`istio.gwxds.Resource`).
pub const GW_TYPE_URL: &str = "type.googleapis.com/istio.gwxds.Resource";

/// Default path to the istiod CA certificate (from the `istiod-ca-cert` ConfigMap).
const DEFAULT_CA_CERT_PATH: &str = "/var/run/secrets/xds/root-cert.pem";

/// Default path to the projected service account token used for JWT auth.
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/xds-tokens/xds-token";

/// Run the xDS client loop.
///
/// Connects to `istiod_address`, subscribes to `GW_TYPE_URL`, decodes incoming
/// resources, and sends them as `Vec<Resource>` batches to `tx`.
///
/// When `istiod_address` starts with `https://`, TLS + JWT authentication is
/// enabled automatically. Credentials are loaded from `CA_CERT_PATH` /
/// `XDS_TOKEN_PATH` env vars, falling back to the well-known in-cluster paths.
///
/// The client reconnects on transient errors and re-reads the JWT token from
/// disk on every reconnect (handles Kubernetes token rotation transparently).
///
/// # Errors
///
/// Returns [`XdsError`] if the node identity is unavailable.
pub async fn run(istiod_address: String, tx: mpsc::Sender<Vec<Resource>>) -> Result<(), XdsError> {
    let node = node_from_env().map_err(XdsError::Transport)?;
    let secure = istiod_address.starts_with("https://");

    loop {
        info!(istiod = %istiod_address, secure, "connecting to istiod ADS");

        let creds = if secure {
            match load_credentials() {
                Ok(c) => Some(c),
                Err(e) => {
                    error!(error = %e, "failed to load xDS credentials, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        } else {
            None
        };

        let token = creds.as_ref().map(|c| c.token.as_str());
        let channel = match connect(&istiod_address, creds.as_ref()).await {
            Ok(ch) => ch,
            Err(e) => {
                error!(error = %e, "ADS channel setup failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let subscribe = DiscoveryRequest {
            version_info: String::new(),
            node: Some(node.clone()),
            resource_names: Vec::new(),
            type_url: GW_TYPE_URL.to_owned(),
            response_nonce: String::new(),
            error_detail: None,
        };

        let (req_tx, mut resp_rx) = match open_ads_stream(channel, token, subscribe).await {
            Ok(pair) => pair,
            Err(e) => {
                error!(error = %e, "ADS stream open failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        info!(
            type_url = %GW_TYPE_URL,
            "initial ADS subscribe queued before streaming handshake completed"
        );

        let result = drive_stream(&mut resp_rx, &req_tx, &node, &tx).await;
        if let Err(e) = result {
            error!(error = %e, "ADS stream error, reconnecting");
        }
    }
}

/// Load TLS + JWT credentials from environment-overridable well-known paths.
///
/// Reads:
/// - CA cert from `CA_CERT_PATH` env var, or `/var/run/secrets/xds/root-cert.pem`
/// - JWT token from `XDS_TOKEN_PATH` env var, or `/var/run/secrets/xds-tokens/xds-token`
///
/// # Errors
///
/// Returns [`XdsError::Tls`] if either file cannot be read.
fn load_credentials() -> Result<XdsCredentials, XdsError> {
    let ca_path = std::env::var("CA_CERT_PATH")
        .unwrap_or_else(|_| DEFAULT_CA_CERT_PATH.to_owned());
    let token_path = std::env::var("XDS_TOKEN_PATH")
        .unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_owned());

    let ca_cert_pem = std::fs::read(&ca_path)
        .map_err(|e| XdsError::Tls(format!("cannot read CA cert {ca_path}: {e}")))?;

    let token = std::fs::read_to_string(&token_path)
        .map_err(|e| XdsError::Tls(format!("cannot read xDS token {token_path}: {e}")))?;
    let token = token.trim().to_owned();

    Ok(XdsCredentials { ca_cert_pem, token })
}

/// Drive the response stream, decode resources, send to the consumer, and ACK.
async fn drive_stream(
    resp_rx: &mut Streaming<DiscoveryResponse>,
    req_tx: &mpsc::Sender<DiscoveryRequest>,
    node: &crate::proto::Node,
    consumer_tx: &mpsc::Sender<Vec<Resource>>,
) -> Result<(), XdsError> {
    info!("waiting for first DiscoveryResponse from istiod");
    loop {
        let Some(response) = resp_rx.message().await? else {
            info!("ADS stream closed by server");
            return Ok(());
        };

        let version = response.version_info.clone();
        let nonce = response.nonce.clone();
        let raw_resource_count = response.resources.len();

        match decode_response(response) {
            Ok(resources) => {
                info!(
                    count = resources.len(),
                    raw_resources = raw_resource_count,
                    version = %version,
                    nonce = %nonce,
                    "received DiscoveryResponse from istiod"
                );

                if consumer_tx.send(resources).await.is_err() {
                    info!("consumer channel closed, stopping xDS client");
                    return Ok(());
                }

                let ack = DiscoveryRequest {
                    version_info: version,
                    node: Some(node.clone()),
                    resource_names: Vec::new(),
                    type_url: GW_TYPE_URL.to_owned(),
                    response_nonce: nonce,
                    error_detail: None,
                };
                if req_tx.send(ack).await.is_err() {
                    return Ok(());
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to decode gwxds response; sending NACK");

                let nack = DiscoveryRequest {
                    version_info: String::new(),
                    node: Some(node.clone()),
                    resource_names: Vec::new(),
                    type_url: GW_TYPE_URL.to_owned(),
                    response_nonce: nonce,
                    error_detail: Some(crate::proto::Status {
                        code: 3, // INVALID_ARGUMENT
                        message: e.to_string(),
                    }),
                };
                req_tx.send(nack).await.ok();
            }
        }
    }
}

/// Decode a `DiscoveryResponse` into a list of `Resource` objects.
fn decode_response(response: DiscoveryResponse) -> Result<Vec<Resource>, XdsError> {
    let mut resources = Vec::new();

    for any in response.resources {
        if any.type_url != GW_TYPE_URL {
            warn!(type_url = %any.type_url, "unexpected TypeURL in ADS response; skipping");
            continue;
        }

        let resource = Resource::decode(any.value.as_slice()).map_err(XdsError::Decode)?;
        resources.push(resource);
    }

    Ok(resources)
}
