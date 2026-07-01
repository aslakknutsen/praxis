// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the URL signing filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// UrlSignConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the URL signing filter.
///
/// ```yaml
/// filter: url_sign
/// secret:
///   env_var: URL_SIGN_SECRET
/// placement: query
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UrlSignConfig {
    /// Single signing secret (mutually exclusive with `secrets`).
    pub secret: Option<SecretSourceConfig>,

    /// Key-rotation secret list (mutually exclusive with `secret`).
    pub secrets: Option<Vec<KeyedSecretConfig>>,

    /// HMAC algorithm. Only `hmac-sha256` is supported in v1.
    #[serde(default)]
    pub algorithm: Algorithm,

    /// Where signature and expiry are carried in the request URL.
    #[serde(default)]
    pub placement: Placement,

    /// Query parameter name for the signature (query placement).
    #[serde(default = "default_signature_param")]
    pub signature_param: String,

    /// Query parameter name for expiry (query placement).
    #[serde(default = "default_expires_param")]
    pub expires_param: String,

    /// Optional query parameter for key id. Omit field to disable.
    pub key_id_param: Option<String>,

    /// Path prefix for path-segment placement (required when `placement: path`).
    pub path_prefix: Option<String>,

    /// Expiration validation settings.
    #[serde(default)]
    pub expires: ExpiresConfig,

    /// Signature encoding on the wire.
    #[serde(default)]
    pub encoding: Encoding,

    /// Strip signature segments into `rewritten_path` after verify (path mode).
    #[serde(default = "default_strip_signature")]
    pub strip_signature: bool,

    /// Canonical signing input composition.
    #[serde(default)]
    pub canonical: CanonicalConfig,
}

// -----------------------------------------------------------------------------
// Nested Config Types
// -----------------------------------------------------------------------------

/// Inline value or environment variable for a signing secret.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretSourceConfig {
    /// Literal secret bytes (dev/test only).
    pub value: Option<String>,

    /// Environment variable containing the secret.
    pub env_var: Option<String>,
}

/// A named signing key for rotation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyedSecretConfig {
    /// Key identifier matched against the optional `kid` parameter.
    pub id: String,

    /// Literal secret bytes (dev/test only).
    pub value: Option<String>,

    /// Environment variable containing the secret.
    pub env_var: Option<String>,
}

/// Supported HMAC algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Algorithm {
    HmacSha256,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::HmacSha256
    }
}

/// Signature placement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Placement {
    Query,
    Path,
}

impl Default for Placement {
    fn default() -> Self {
        Self::Query
    }
}

/// Signature wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Encoding {
    Hex,
    Base64Url,
}

impl Default for Encoding {
    fn default() -> Self {
        Self::Hex
    }
}

/// Expiration validation settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExpiresConfig {
    /// Whether the expiry parameter must be present.
    #[serde(default = "default_expires_required")]
    pub required: bool,

    /// Clock skew tolerance in seconds (±).
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
}

impl Default for ExpiresConfig {
    fn default() -> Self {
        Self {
            required: default_expires_required(),
            clock_skew_secs: default_clock_skew_secs(),
        }
    }
}

/// Canonical signing input field toggles.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CanonicalConfig {
    /// Include uppercase HTTP method as the first field.
    #[serde(default = "default_true")]
    pub include_method: bool,

    /// Include lowercase host without port.
    #[serde(default)]
    pub include_host: bool,

    /// Include canonicalized query string (excluding sig params).
    #[serde(default = "default_true")]
    pub include_query: bool,
}

impl Default for CanonicalConfig {
    fn default() -> Self {
        Self {
            include_method: default_true(),
            include_host: false,
            include_query: default_true(),
        }
    }
}

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

fn default_signature_param() -> String {
    "sig".to_owned()
}

fn default_expires_param() -> String {
    "expires".to_owned()
}

fn default_expires_required() -> bool {
    true
}

fn default_clock_skew_secs() -> u64 {
    60
}

fn default_strip_signature() -> bool {
    true
}

fn default_true() -> bool {
    true
}
