// SPDX-License-Identifier: MIT

//! Minimal hand-written prost message types for the envoy xDS protocol.
//!
//! We only define the fields we actually use. Additional fields are silently
//! ignored by prost's protobuf decoding (unknown field handling is built in).

use prost::Message;

// -----------------------------------------------------------------------------
// google.rpc.Status (minimal, for DiscoveryRequest.error_detail)
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Status {
    #[prost(int32, tag = "1")]
    pub(crate) code: i32,
    #[prost(string, tag = "2")]
    pub(crate) message: String,
}

// -----------------------------------------------------------------------------
// envoy.config.core.v3.Node
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Node {
    /// Opaque node identifier (e.g. "gateway-name.namespace").
    #[prost(string, tag = "1")]
    pub(crate) id: String,

    /// Node cluster (namespace in Istio's usage).
    #[prost(string, tag = "2")]
    pub(crate) cluster: String,

    /// Arbitrary metadata sent with each request.
    ///
    /// istiod uses this to scope pushes via `PerGatewayCollection`.
    /// We embed the `gateway.networking.k8s.io/gateway-name` label here.
    #[prost(message, optional, tag = "3")]
    pub(crate) metadata: Option<prost_types::Struct>,
}

// -----------------------------------------------------------------------------
// google.protobuf.Any
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Any {
    #[prost(string, tag = "1")]
    pub(crate) type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) value: Vec<u8>,
}

// -----------------------------------------------------------------------------
// envoy.service.discovery.v3.DiscoveryRequest
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DiscoveryRequest {
    /// Version from the last accepted DiscoveryResponse.
    #[prost(string, tag = "1")]
    pub(crate) version_info: String,

    /// Node identity of this proxy.
    #[prost(message, optional, tag = "2")]
    pub(crate) node: Option<Node>,

    /// Resource names to subscribe to. Empty subscribes to all.
    #[prost(string, repeated, tag = "3")]
    pub(crate) resource_names: Vec<String>,

    /// TypeURL of the resource (e.g. `type.googleapis.com/istio.gwxds.Resource`).
    #[prost(string, tag = "4")]
    pub(crate) type_url: String,

    /// Nonce from the last DiscoveryResponse being ACKed/NACKed.
    #[prost(string, tag = "5")]
    pub(crate) response_nonce: String,

    /// Set when NACKing a response.
    #[prost(message, optional, tag = "7")]
    pub(crate) error_detail: Option<Status>,
}

// -----------------------------------------------------------------------------
// envoy.service.discovery.v3.DiscoveryResponse
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DiscoveryResponse {
    #[prost(string, tag = "1")]
    pub(crate) version_info: String,

    /// Opaque resources, each wrapped in `google.protobuf.Any`.
    #[prost(message, repeated, tag = "2")]
    pub(crate) resources: Vec<Any>,

    #[prost(string, tag = "4")]
    pub(crate) type_url: String,

    /// Nonce to echo in the next ACK/NACK request.
    #[prost(string, tag = "5")]
    pub(crate) nonce: String,
}
