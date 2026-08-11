// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Built-in proxy configuration for Agentgateway.

use std::path::PathBuf;

use super::ProxyConfig;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default Docker image for Agentgateway comparison runs.
const DEFAULT_IMAGE: &str = "cr.agentgateway.dev/agentgateway:v1.4.1";

// -----------------------------------------------------------------------------
// AgentgatewayConfig
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for Agentgateway via Docker.
///
/// Starts an Agentgateway container with resource limits matching the
/// comparison benchmark constraints.
#[derive(Debug)]
pub struct AgentgatewayConfig {
    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Path to the Agentgateway YAML config file.
    pub config: PathBuf,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for AgentgatewayConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:18094".into(),
            config: PathBuf::from("benchmarks/comparison/configs/agentgateway.yaml"),
            container_name: "praxis-bench-agentgateway".into(),
            image: None,
        }
    }
}

impl ProxyConfig for AgentgatewayConfig {
    fn name(&self) -> &str {
        "agentgateway"
    }

    fn listen_address(&self) -> &str {
        &self.address
    }

    fn start_command(&self) -> (String, Vec<String>) {
        let config_abs = std::fs::canonicalize(&self.config).unwrap_or_else(|_| self.config.clone());

        (
            "docker".into(),
            vec![
                "run".into(),
                "--rm".into(),
                "--name".into(),
                self.container_name.clone(),
                "--network".into(),
                "host".into(),
                // Agentgateway images run as non-root by default; force root so
                // the mounted comparison config is readable in the harness.
                "--user".into(),
                "0:0".into(),
                "--cpus=4.0".into(),
                "--memory=2g".into(),
                "-v".into(),
                format!("{}:/config.yaml:ro,z", config_abs.display()),
                self.image.as_deref().unwrap_or(DEFAULT_IMAGE).to_owned(),
                "-f".into(),
                "/config.yaml".into(),
            ],
        )
    }

    fn config_path(&self) -> &std::path::Path {
        &self.config
    }

    fn container_name(&self) -> Option<&str> {
        Some(&self.container_name)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn agentgateway_config_defaults() {
        let config = AgentgatewayConfig::default();

        assert_eq!(config.name(), "agentgateway");
        assert_eq!(config.listen_address(), "127.0.0.1:18094");
        assert_eq!(config.container_name(), Some("praxis-bench-agentgateway"));
        assert_eq!(config.health_url(), None, "agentgateway has no built-in health URL");
    }

    #[test]
    fn agentgateway_start_command_uses_docker() {
        let config = AgentgatewayConfig {
            image: Some("cr.agentgateway.dev/agentgateway:v1.4.1".into()),
            ..Default::default()
        };
        let (cmd, args) = config.start_command();

        assert_eq!(cmd, "docker");
        assert!(args.contains(&"run".into()));
        assert!(args.contains(&"--network".into()));
        assert!(args.contains(&"host".into()));
        assert!(args.contains(&"--cpus=4.0".into()));
        assert!(args.contains(&"--memory=2g".into()));
        assert!(args.contains(&"--user".into()));
        assert!(args.contains(&"0:0".into()));
        assert!(args.contains(&"-f".into()));
        assert!(args.contains(&"/config.yaml".into()));
        assert!(args.iter().any(|a| a.contains("agentgateway")));
    }
}
