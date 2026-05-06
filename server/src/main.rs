#![deny(unsafe_code)]

//! Praxis proxy server binary.
//!
//! Starts in gwxds mode (Kubernetes Gateway API via istiod) when `GATEWAY_NAME`
//! is set; otherwise loads configuration from a YAML file.

/// Jemalloc global allocator is used by default on unix platforms.
///
/// Reduces allocator contention under concurrent load.
#[cfg(unix)]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use tracing::info;

/// Cloud and AI-native proxy server.
#[derive(Parser)]
#[command(name = "praxis")]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short = 'c', long = "config")]
    config: Option<String>,
}

/// Entry point.
///
/// When `GATEWAY_NAME` is set, Praxis enters gwxds mode: it connects to
/// istiod, waits for the first gwxds push, builds its initial configuration
/// from it, and then runs. Subsequent pushes are applied as hot-reloads.
///
/// Otherwise, Praxis loads configuration from a YAML file (the `--config`
/// flag, `PRAXIS_CONFIG` env var, or `praxis.yaml` in the working directory).
#[allow(clippy::print_stderr, reason = "fatal error output")]
fn main() {
    // Install the ring CryptoProvider as the process-wide default before any
    // TLS code runs. Both tonic (xDS client) and pingora-rustls use ring;
    // installing it explicitly avoids the rustls 0.23 panic that fires when
    // the provider cannot be auto-detected from compiled features.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring CryptoProvider");

    if std::env::var("GATEWAY_NAME").is_ok() {
        main_gwxds();
    } else {
        main_yaml();
    }
}

fn main_gwxds() {
    // Initialize tracing from the built-in default config (no file needed).
    let default_config = praxis::load_config(None).unwrap_or_else(|e| praxis::fatal(&e));
    praxis::init_tracing(&default_config).unwrap_or_else(|e| praxis::fatal(&e));

    info!(
        gateway_name = %std::env::var("GATEWAY_NAME").unwrap_or_default(),
        gateway_namespace = %std::env::var("GATEWAY_NAMESPACE").unwrap_or_default(),
        "starting in gwxds mode"
    );

    // Resolve the admin address early so both the pre-flight server and the
    // real Pingora admin server bind the same address.
    let admin_addr = std::env::var("PRAXIS_ADMIN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:15021".to_owned());

    // Start the pre-flight health server immediately so Kubernetes startup
    // probes succeed while we wait for the first xDS push from istiod.
    // /healthy → 200, /ready → 503 until the real server takes over.
    //
    // TODO: when Praxis supports dynamic listener reloading, replace this
    // pre-flight shim with Option C: start the full server with an admin-only
    // config and apply the first xDS push via reload_pipelines, eliminating
    // the startup race entirely.
    let preflight = praxis::preflight::start(&admin_addr);

    let istiod_addr = praxis::gwxds::istiod_address();
    let (mut config, xds_rx) = praxis::gwxds::await_first_config(&istiod_addr)
        .unwrap_or_else(|e| praxis::fatal(&e));

    // Stop the pre-flight server and wait for it to release the port before
    // Pingora binds the same address.
    preflight.stop();

    config.admin.address = Some(admin_addr);
    praxis::run_server_gwxds(config, xds_rx)
}

fn main_yaml() {
    let cli = Cli::parse();
    let explicit = cli.config.or_else(|| std::env::var("PRAXIS_CONFIG").ok());
    let config_path = praxis::resolve_config_path(explicit.as_deref());
    let config = praxis::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis::fatal(&e));
    praxis::init_tracing(&config).unwrap_or_else(|e| praxis::fatal(&e));
    info!("starting server");
    praxis::run_server(config, config_path)
}
