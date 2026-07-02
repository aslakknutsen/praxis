// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Secret resolution for signature filters.

use crate::FilterError;

// -----------------------------------------------------------------------------
// SecretConfig
// -----------------------------------------------------------------------------

/// Raw secret source from YAML (exactly one of `secret` or `secret_env_var`).
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretFields {
    /// Inline secret value (dev/test only).
    pub secret: Option<String>,

    /// Environment variable containing the secret (resolved at construction).
    pub secret_env_var: Option<String>,
}

// -----------------------------------------------------------------------------
// Secret Resolution
// -----------------------------------------------------------------------------

/// Resolve a secret from inline value or environment variable.
///
/// # Errors
///
/// Returns [`FilterError`] when both or neither source is set, or when an
/// environment variable is missing.
pub(super) fn resolve_secret(filter_name: &str, fields: &SecretFields) -> Result<Vec<u8>, FilterError> {
    match (&fields.secret, &fields.secret_env_var) {
        (Some(val), None) => Ok(val.as_bytes().to_vec()),
        (None, Some(var)) => std::env::var(var)
            .map(|v| v.into_bytes())
            .map_err(|e| -> FilterError { format!("{filter_name}: environment variable '{var}' not set: {e}").into() }),
        (Some(_), Some(_)) => Err(format!(
            "{filter_name}: must set exactly one of 'secret' or 'secret_env_var'"
        )
        .into()),
        (None, None) => Err(format!("{filter_name}: must set either 'secret' or 'secret_env_var'").into()),
    }
}
