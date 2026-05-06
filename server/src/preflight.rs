// SPDX-License-Identifier: MIT

//! Pre-flight health server for gwxds mode.
//!
//! In gwxds mode the main Pingora server cannot start until the first xDS push
//! arrives from istiod (listener topology is fixed at bind time). This means
//! the admin health endpoint on port 15021 is dark during the connection and
//! initial-push window, causing Kubernetes startup probes to fail.
//!
//! This module starts a minimal TCP/HTTP server on the admin address *before*
//! blocking on the first xDS push. It answers:
//!   - `GET /healthy` → 200 OK (process is alive)
//!   - `GET /ready`   → 503 Service Unavailable (not yet configured)
//!
//! Once `await_first_config` returns and the real Pingora admin server is about
//! to bind the same address, the pre-flight server is stopped via
//! [`PreflightGuard::stop`], which signals the background thread and joins it
//! to ensure the OS has released the port before Pingora tries to bind it.
//!
//! # Future work
//!
//! When Praxis gains dynamic listener reloading (i.e. Pingora can add new
//! listeners after startup), the preferred approach (Option C) would be to
//! start the full server immediately with an admin-only config, then apply the
//! first xDS push as a hot `reload_pipelines` call — eliminating the need for
//! this pre-flight shim entirely.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tracing::{debug, info, warn};

const HTTP_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
const HTTP_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"status\":\"starting\"}";

/// A guard that keeps the pre-flight health server alive until dropped or stopped.
pub struct PreflightGuard {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PreflightGuard {
    /// Signal the pre-flight server to stop and block until it has exited and
    /// released the port.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            h.join().ok();
        }
    }
}

impl Drop for PreflightGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            h.join().ok();
        }
    }
}

/// Start a pre-flight health server on `addr`.
///
/// Returns a [`PreflightGuard`]; call [`PreflightGuard::stop`] (or drop it)
/// to shut the server down and release the port before handing it to Pingora.
///
/// # Panics
///
/// Panics if the address cannot be bound (port already in use, invalid address,
/// insufficient privileges).
#[must_use]
pub fn start(addr: &str) -> PreflightGuard {
    let listener = TcpListener::bind(addr)
        .unwrap_or_else(|e| panic!("pre-flight health server: cannot bind {addr}: {e}"));
    listener
        .set_nonblocking(true)
        .expect("pre-flight health server: set_nonblocking failed");

    info!(address = %addr, "pre-flight health server started");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = std::thread::Builder::new()
        .name("preflight-health".into())
        .spawn(move || run_loop(listener, stop_clone))
        .expect("pre-flight health thread spawn failed");

    PreflightGuard { stop, handle: Some(handle) }
}

fn run_loop(listener: TcpListener, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                debug!(%peer, "pre-flight: accepted connection");
                if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(200))) {
                    warn!("pre-flight: set_read_timeout: {e}");
                }
                handle_connection(&mut stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                warn!("pre-flight: accept error: {e}");
                break;
            }
        }
    }
    info!("pre-flight health server stopped");
}

fn handle_connection(stream: &mut std::net::TcpStream) {
    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };

    let path = extract_path(&buf[..n]);
    let response = match path {
        "/ready" => HTTP_503,
        // /healthy and everything else → alive
        _ => HTTP_200,
    };

    stream.write_all(response).ok();
}

/// Extract the request path from the first line of an HTTP/1.x request.
fn extract_path(buf: &[u8]) -> &str {
    // "GET /path HTTP/1.1\r\n..."
    let line = buf.split(|&b| b == b'\n').next().unwrap_or(b"");
    let line = std::str::from_utf8(line).unwrap_or("").trim();
    let mut parts = line.splitn(3, ' ');
    let _method = parts.next();
    parts.next().unwrap_or("/")
}
