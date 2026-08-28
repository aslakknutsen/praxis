// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Benchmark entrypoint for the JSON body tokenizer path.
//!
//! Compiled only with the `bench-internals` feature on `praxis-filter`.

use super::{
    config::{CompiledOp, JsonBodyConfig, build_ops},
    rewrite::{RewriteMode, rewrite_document},
};
use crate::{FilterError, factory::parse_filter_config};

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Compiled request-body operations for benchmarks.
#[derive(Clone, Debug)]
pub struct RequestOps {
    ops: Vec<CompiledOp>,
}

impl RequestOps {
    /// Build request ops from a YAML config fragment (same shape as filter config).
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the config is invalid.
    pub fn from_yaml(yaml: &str) -> Result<Self, FilterError> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml)
            .map_err(|e| -> FilterError { format!("json_body bench: invalid YAML: {e}").into() })?;
        Self::from_config(&value)
    }

    /// Build request ops from parsed YAML.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Self, FilterError> {
        let cfg: JsonBodyConfig = parse_filter_config("json_body", config)?;
        let (_max_body_bytes, _on_invalid, compiled) = build_ops(cfg)?;
        Ok(Self { ops: compiled.request })
    }
}

/// Apply extract and rewrite on `body` in one tokenizer walk.
///
/// # Errors
///
/// Returns an error when JSON is invalid or rewrite fails.
pub fn apply_request(body: &[u8], ops: &RequestOps) -> Result<Vec<u8>, String> {
    rewrite_document(body, &ops.ops, RewriteMode::Rewrite, None)
        .map(|outcome| outcome.output.unwrap_or_default())
        .map_err(|e| e.as_str().to_owned())
}
