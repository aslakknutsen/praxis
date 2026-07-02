// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration for the HMAC verify filter.

use serde::Deserialize;

use super::super::secret::SecretFields;

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

/// Default maximum request body size (1 MiB).
pub(super) const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

fn default_reject_status() -> u16 {
    401
}

fn default_strip_header() -> bool {
    true
}

fn default_algorithm() -> SignatureAlgorithm {
    SignatureAlgorithm::Sha256
}

// -----------------------------------------------------------------------------
// HmacVerifyConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the HMAC verify filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HmacVerifyConfig {
    #[serde(flatten)]
    pub secret: SecretFields,

    /// Signature dialect preset.
    pub dialect: DialectKind,

    /// Header containing the signature (defaults per dialect).
    pub header: Option<String>,

    /// HMAC algorithm (v1 supports `sha256` only, except GitHub legacy SHA1).
    #[serde(default = "default_algorithm")]
    pub algorithm: SignatureAlgorithm,

    /// Maximum request body bytes to buffer for verification.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// HTTP status for missing or invalid signatures.
    #[serde(default = "default_reject_status")]
    pub reject_status: u16,

    /// Strip the signature header before upstream forwarding.
    #[serde(default = "default_strip_header")]
    pub strip_header: bool,
}

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Enums
// -----------------------------------------------------------------------------

/// Supported HMAC signature dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DialectKind {
    /// GitHub webhooks (`sha256=<hex>` on `X-Hub-Signature-256`).
    Github,

    /// Raw lowercase hex digest in a configurable header.
    RawHex,

    /// Raw standard base64 digest in a configurable header.
    RawBase64,
}

/// Supported HMAC algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SignatureAlgorithm {
    /// HMAC-SHA256 (default).
    Sha256,
}
