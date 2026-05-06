// SPDX-License-Identifier: MIT

//! gwxds mode startup and hot-reload loop.
//!
//! When `GATEWAY_NAME` is set, Praxis operates in gwxds mode:
//! 1. Blocks until the first `Vec<Resource>` arrives from istiod.
//! 2. Translates it into a praxis [`Config`] and returns it to the caller.
//! 3. Runs the server normally from that Config.
//! 4. Forwards subsequent pushes to `reload_pipelines` via a background watcher thread.

use std::sync::{Arc, Mutex};

use praxis_core::{
    config::Config,
    gwxds::{Resource, translate},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::reload::reload_pipelines;

// In-cluster default: TLS-authenticated port. Override with ISTIOD_ADDR=http://... for local dev.
const DEFAULT_ISTIOD: &str = "https://istiod.istio-system.svc:15012";

/// Return the istiod ADS address from `ISTIOD_ADDR` or the default.
pub fn istiod_address() -> String {
    std::env::var("ISTIOD_ADDR").unwrap_or_else(|_| DEFAULT_ISTIOD.to_owned())
}

/// Block until the first gwxds push arrives and translate it to a [`Config`].
///
/// Spawns the xDS client on a background tokio runtime thread. Returns as
/// soon as the first batch of resources is received, translating them into
/// the initial server configuration.
///
/// # Errors
///
/// Returns an error if the node identity is unavailable or the first push
/// never arrives (channel dropped).
#[allow(clippy::expect_used, reason = "fatal startup path")]
pub fn await_first_config(istiod_addr: &str) -> Result<(Config, mpsc::Receiver<Vec<Resource>>), String> {
    // channel: xDS client → server (unbounded in terms of resource batches)
    let (xds_tx, xds_rx) = mpsc::channel::<Vec<Resource>>(8);

    // One-shot channel to get the first batch back to this synchronous context
    let (first_tx, first_rx) = std::sync::mpsc::channel::<Vec<Resource>>();

    let addr = istiod_addr.to_owned();
    let xds_tx_clone = xds_tx.clone();

    // Spawn a dedicated thread for the async xDS client runtime
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("xDS client tokio runtime");

        rt.block_on(async move {
            let (relay_tx, mut relay_rx) = mpsc::channel::<Vec<Resource>>(8);

            // Start the xDS client (runs forever, reconnects on error)
            tokio::spawn(async move {
                if let Err(e) = praxis_xds_client::run(addr, relay_tx).await {
                    tracing::error!(error = %e, "xDS client stopped unexpectedly");
                }
            });

            // Forward the first batch via std mpsc, then forward the rest via xds_tx
            let mut first_sent = false;
            while let Some(resources) = relay_rx.recv().await {
                if !first_sent {
                    first_sent = true;
                    first_tx.send(resources.clone()).ok();
                }
                if xds_tx_clone.send(resources).await.is_err() {
                    break;
                }
            }
        });
    });

    // Block the startup thread until the first push arrives
    info!("waiting for first gwxds push from istiod");
    let first_resources = first_rx
        .recv()
        .map_err(|_| "xDS channel closed before first push was received".to_owned())?;

    info!(count = first_resources.len(), "received first gwxds push");
    let config = translate(&first_resources);

    Ok((config, xds_rx))
}

/// Spawn a background watcher thread that applies gwxds config updates.
///
/// Receives `Vec<Resource>` batches from `xds_rx` and calls
/// `reload_pipelines` for each one. The watcher stops when `xds_rx` is
/// closed.
#[allow(clippy::expect_used, reason = "fatal if tokio runtime cannot start")]
pub fn spawn_gwxds_watcher(
    initial_config: Config,
    registry: Arc<FilterRegistry>,
    pipelines: Arc<ListenerPipelines>,
    health_shutdown: Arc<Mutex<CancellationToken>>,
    mut xds_rx: mpsc::Receiver<Vec<Resource>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("gwxds watcher tokio runtime");

        rt.block_on(async move {
            let mut current_config = initial_config;

            while let Some(resources) = xds_rx.recv().await {
                let new_config = translate(&resources);
                info!(listeners = new_config.listeners.len(), "applying gwxds config update");

                if let Err(e) =
                    reload_pipelines(&new_config, &current_config, &registry, &pipelines, &health_shutdown)
                {
                    error!(error = %e, "gwxds config reload failed");
                } else {
                    current_config = new_config;
                }
            }

            warn!("gwxds xDS channel closed; config updates paused");
        });
    })
}
