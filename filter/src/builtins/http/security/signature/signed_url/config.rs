// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration for the signed URL filter.

use serde::Deserialize;

use super::super::secret::SecretFields;

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

/// Default signature query parameter name.
pub(super) fn default_signature_param() -> String {
    "sig".to_owned()
}

/// Default timestamp query parameter name.
pub(super) fn default_timestamp_param() -> String {
    "ts".to_owned()
}

/// Default clock skew tolerance in seconds.
pub(super) fn default_clock_skew_seconds() -> u64 {
    30
}

/// Default canonical message separator.
pub(super) fn default_message_separator() -> String {
    "\n".to_owned()
}

/// Default HTTP status for auth failures.
pub(super) fn default_reject_status() -> u16 {
    403
}

/// Default HTTP status for expired links.
pub(super) fn default_reject_status_expired() -> u16 {
    410
}

fn default_strip_params() -> bool {
    true
}

fn default_message_parts() -> Vec<MessagePart> {
    vec![MessagePart::Path, MessagePart::Timestamp, MessagePart::Expiry]
}

// -----------------------------------------------------------------------------
// SignedUrlConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the signed URL filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedUrlConfig {
    #[serde(flatten)]
    pub secret: SecretFields,

    /// HMAC algorithm (v1 supports `sha256` only).
    #[serde(default = "default_algorithm")]
    pub algorithm: SignatureAlgorithm,

    /// Query parameter holding the HMAC digest.
    #[serde(default = "default_signature_param")]
    pub signature_param: String,

    /// Query parameter holding the Unix timestamp in seconds.
    #[serde(default = "default_timestamp_param")]
    pub timestamp_param: String,

    /// Optional query parameter holding absolute expiry (Unix seconds).
    pub expiry_param: Option<String>,

    /// Maximum link age when `expiry_param` is not configured.
    pub max_age_seconds: Option<u64>,

    /// Allowed clock skew in seconds.
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: u64,

    /// Canonical message template.
    #[serde(default = "default_message")]
    pub message: MessageConfig,

    /// Which URI path participates in the canonical message.
    #[serde(default)]
    pub uri_source: UriSource,

    /// Remove signature-related query params before upstream forwarding.
    #[serde(default = "default_strip_params")]
    pub strip_params: bool,

    /// HTTP status for invalid or missing signatures.
    #[serde(default = "default_reject_status")]
    pub reject_status: u16,

    /// HTTP status when the link has expired.
    #[serde(default = "default_reject_status_expired")]
    pub reject_status_expired: u16,
}

fn default_algorithm() -> SignatureAlgorithm {
    SignatureAlgorithm::Sha256
}

fn default_message() -> MessageConfig {
    MessageConfig {
        parts: default_message_parts(),
        separator: default_message_separator(),
        encoding: SignatureEncoding::Hex,
    }
}

// -----------------------------------------------------------------------------
// MessageConfig
// -----------------------------------------------------------------------------

/// Canonical message template configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MessageConfig {
    /// Ordered message components.
    #[serde(default = "default_message_parts")]
    pub parts: Vec<MessagePart>,

    /// Separator between message parts.
    #[serde(default = "default_message_separator")]
    pub separator: String,

    /// HMAC digest encoding in the query parameter (v1: hex only).
    #[serde(default)]
    pub encoding: SignatureEncoding,
}

// -----------------------------------------------------------------------------
// Enums
// -----------------------------------------------------------------------------

/// Supported HMAC algorithms (v1: SHA-256 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SignatureAlgorithm {
    /// HMAC-SHA256.
    Sha256,
}

/// HMAC digest encoding in query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SignatureEncoding {
    /// Lowercase hexadecimal (default).
    #[default]
    Hex,
}

/// Which request path is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum UriSource {
    /// Incoming client URI path (default).
    #[default]
    Client,

    /// Path from `ctx.rewritten_path` when set by an earlier rewrite filter.
    Rewritten,
}

/// Canonical message component identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum MessagePart {
    /// URL path component.
    Path,

    /// Timestamp query parameter value.
    Timestamp,

    /// Expiry query parameter value (when configured and present).
    Expiry,
}
