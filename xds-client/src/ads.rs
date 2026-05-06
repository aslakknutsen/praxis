// SPDX-License-Identifier: MIT

//! ADS (Aggregated Discovery Service) gRPC client.
//!
//! Implements the raw tonic streaming call against istiod's ADS endpoint
//! without a generated service stub. We use `tonic::client::Grpc` directly
//! so that we can avoid a `build.rs` / `protoc` dependency.
//!
//! # Authentication
//!
//! When connecting to istiod's authenticated port (15012, TLS), the caller
//! supplies [`XdsCredentials`] containing the mesh CA certificate (for server
//! verification) and a JWT bearer token (for client identity). The token is
//! sent as an `authorization: Bearer <token>` gRPC metadata header, which
//! istiod validates via Kubernetes token review.
//!
//! For the unauthenticated plaintext port (15010), pass `creds: None`.

use tonic::{
    Request, Status,
    codec::ProstCodec,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Uri},
};
use tracing::{debug, info};

use crate::proto::{DiscoveryRequest, DiscoveryResponse};

/// The gRPC full method path for the ADS streaming RPC.
const ADS_METHOD: &str = "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";

/// Credentials for connecting to istiod on the authenticated TLS port (15012).
pub(crate) struct XdsCredentials {
    /// PEM-encoded CA certificate used to verify istiod's TLS certificate.
    pub ca_cert_pem: Vec<u8>,
    /// JWT bearer token sent as `authorization: Bearer <token>` gRPC metadata.
    /// Re-read from disk on every reconnect to handle Kubernetes token rotation.
    pub token: String,
}

/// Open a bidirectional streaming ADS session.
///
/// If `token` is `Some`, inserts `authorization: Bearer <token>` into the
/// outgoing request metadata (required for port 15012).
///
/// `initial` is queued on the outbound stream before awaiting `Grpc::streaming`.
/// Istiod's ADS handler blocks until the first client `DiscoveryRequest` is
/// received; priming avoids a handshake stall when the client would otherwise
/// send only after `streaming` returns.
///
/// # Errors
///
/// Returns an error if the initial RPC handshake fails.
pub(crate) async fn open_ads_stream(
    channel: Channel,
    token: Option<&str>,
    initial: DiscoveryRequest,
) -> Result<
    (
        tokio::sync::mpsc::Sender<DiscoveryRequest>,
        tonic::Streaming<DiscoveryResponse>,
    ),
    XdsError,
> {
    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryRequest>(16);
    tx.try_send(initial).map_err(|e| {
        XdsError::Transport(format!("queue initial ADS DiscoveryRequest: {e}"))
    })?;

    let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    let mut req = Request::new(request_stream);
    if let Some(jwt) = token {
        let value = MetadataValue::try_from(format!("Bearer {jwt}"))
            .map_err(|e| XdsError::Tls(format!("invalid token for metadata: {e}")))?;
        req.metadata_mut().insert("authorization", value);
    }

    let mut client = tonic::client::Grpc::new(channel);
    let path = http::uri::PathAndQuery::from_static(ADS_METHOD);

    debug!("ADS: waiting for gRPC channel ready");
    client.ready().await.map_err(|e| XdsError::Transport(e.to_string()))?;

    debug!("ADS: invoking StreamAggregatedResources");
    let response = client
        .streaming(req, path, ProstCodec::<DiscoveryRequest, DiscoveryResponse>::default())
        .await
        .map_err(XdsError::Rpc)?;

    info!("ADS: bidirectional stream open with istiod (initial DiscoveryRequest was queued pre-handshake)");
    Ok((tx, response.into_inner()))
}

/// Build a tonic gRPC channel to istiod.
///
/// When `creds` is `Some`, configures TLS using the provided CA certificate
/// for server verification (targeting port 15012). When `None`, creates a
/// plaintext channel (port 15010).
///
/// # Errors
///
/// Returns [`XdsError::Tls`] if TLS configuration fails, or
/// [`XdsError::Transport`] if the URI is invalid.
pub(crate) async fn connect(
    istiod_address: &str,
    creds: Option<&XdsCredentials>,
) -> Result<Channel, XdsError> {
    let uri = istiod_address
        .parse::<Uri>()
        .map_err(|e| XdsError::Transport(e.to_string()))?;

    let mut endpoint = Channel::builder(uri);

    if let Some(c) = creds {
        let ca = Certificate::from_pem(&c.ca_cert_pem);
        // domain_name must match the SAN in istiod's serving cert.
        // Kubernetes in-cluster DNS name is the standard match.
        let tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name("istiod.istio-system.svc");
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| XdsError::Tls(e.to_string()))?;
    }

    Ok(endpoint.connect_lazy())
}

/// Errors produced by the ADS client.
#[derive(Debug, thiserror::Error)]
pub enum XdsError {
    /// A network or URI-level failure.
    #[error("transport error: {0}")]
    Transport(String),

    /// TLS configuration or certificate error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// A gRPC status error returned by istiod.
    #[error("rpc error: {0}")]
    Rpc(#[from] Status),

    /// Failed to decode a protobuf message.
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
}
