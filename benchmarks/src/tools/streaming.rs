// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Streaming passthrough load tool with TTFB measurement.
//!
//! Starts a paced chunked HTTP backend and drives concurrent clients
//! that record time-to-first-byte and total response time.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tracing::info;

use crate::{
    error::BenchmarkError,
    result::{BenchmarkResult, ErrorMetrics, LatencyMetrics, ThroughputMetrics},
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Configuration for a streaming-passthrough measurement.
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Concurrent client workers.
    pub concurrency: u32,

    /// Number of body chunks per response.
    pub chunks: u32,

    /// Delay between chunks on the backend.
    pub chunk_delay: Duration,

    /// Size of each chunk in bytes.
    pub chunk_size: usize,

    /// Wall-clock duration to keep issuing requests.
    pub duration: Duration,
}

// -----------------------------------------------------------------------------
// Backend
// -----------------------------------------------------------------------------

/// Handle for a paced chunk backend running in-process.
#[derive(Debug)]
pub struct PacedBackend {
    /// Bound listen port.
    pub port: u16,

    /// Task serving connections.
    handle: tokio::task::JoinHandle<()>,

    /// Signal to stop accepting new connections.
    shutdown: watch::Sender<bool>,
}

impl PacedBackend {
    /// Stop the backend task.
    pub async fn stop(self) {
        let _send = self.shutdown.send(true);
        self.handle.abort();
        let _join = self.handle.await;
    }
}

/// Start a paced chunked HTTP backend on `port`.
///
/// Pass `0` to bind an ephemeral port; the chosen port is available on
/// [`PacedBackend::port`].
///
/// # Errors
///
/// Returns [`BenchmarkError::Io`] if the listener cannot bind.
pub async fn start_paced_backend(
    port: u16,
    chunks: u32,
    chunk_delay: Duration,
    chunk_size: usize,
) -> Result<PacedBackend, BenchmarkError> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(BenchmarkError::Io)?;
    let port = listener.local_addr().map_err(BenchmarkError::Io)?.port();
    let (shutdown, rx) = watch::channel(false);
    info!(port, chunks, chunk_size, ?chunk_delay, "starting paced chunk backend");

    let handle = tokio::spawn(async move {
        accept_loop(listener, rx, chunks, chunk_delay, chunk_size).await;
    });

    Ok(PacedBackend {
        port,
        handle,
        shutdown,
    })
}

async fn accept_loop(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    chunks: u32,
    chunk_delay: Duration,
    chunk_size: usize,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        tokio::spawn(serve_paced(stream, chunks, chunk_delay, chunk_size));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn serve_paced(mut stream: TcpStream, chunks: u32, chunk_delay: Duration, chunk_size: usize) {
    let mut buf = vec![0_u8; 4096];
    let mut req = Vec::new();
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if req.len() > 65_536 {
                    return;
                }
            },
            Err(_) => return,
        }
    }

    let header = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Type: text/event-stream\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: close\r\n",
        "\r\n"
    );
    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    if stream.flush().await.is_err() {
        return;
    }

    let payload = vec![b'x'; chunk_size];
    for _ in 0..chunks {
        if chunk_delay > Duration::ZERO {
            tokio::time::sleep(chunk_delay).await;
        }
        let hex = format!("{:x}\r\n", payload.len());
        if stream.write_all(hex.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(&payload).await.is_err() {
            return;
        }
        if stream.write_all(b"\r\n").await.is_err() {
            return;
        }
        if stream.flush().await.is_err() {
            return;
        }
    }

    let _write_end = stream.write_all(b"0\r\n\r\n").await;
    let _flush_end = stream.flush().await;
}

// -----------------------------------------------------------------------------
// Load generation
// -----------------------------------------------------------------------------

/// Run concurrent streaming clients and return a JSON report string.
///
/// # Errors
///
/// Returns [`BenchmarkError`] if no successful samples are collected.
pub async fn run(url: &str, config: &StreamingConfig) -> Result<String, BenchmarkError> {
    let (host, port, path) = parse_http_url(url)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let duration = config.duration;

    let timer = tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        stop_flag.store(true, Ordering::Relaxed);
    });

    let samples = Arc::new(tokio::sync::Mutex::new(Vec::<Sample>::new()));
    let errors = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(config.concurrency as usize);

    for _ in 0..config.concurrency {
        let host = host.clone();
        let path = path.clone();
        let stop = Arc::clone(&stop);
        let samples = Arc::clone(&samples);
        let errors = Arc::clone(&errors);
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                match one_request(&host, port, &path).await {
                    Ok(sample) => samples.lock().await.push(sample),
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    },
                }
            }
        }));
    }

    for worker in workers {
        let _join = worker.await;
    }
    let _timer = timer.await;

    let samples = samples.lock().await.clone();
    if samples.is_empty() {
        return Err(BenchmarkError::ParseError {
            tool: "streaming".into(),
            reason: format!(
                "no successful samples (errors={})",
                errors.load(Ordering::Relaxed)
            ),
        });
    }

    let report = StreamingReport::from_samples(&samples, errors.load(Ordering::Relaxed), duration);
    serde_json::to_string(&report).map_err(BenchmarkError::Json)
}

#[derive(Debug, Clone)]
struct Sample {
    ttfb: Duration,
    total: Duration,
    bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamingReport {
    samples: u64,
    errors: u64,
    duration_secs: f64,
    bytes_total: u64,
    ttfb_secs: Percentiles,
    total_secs: Percentiles,
}

#[derive(Debug, Serialize, Deserialize)]
struct Percentiles {
    min: f64,
    max: f64,
    mean: f64,
    p50: f64,
    p90: f64,
    p95: f64,
    p99: f64,
    p99_9: f64,
}

impl StreamingReport {
    fn from_samples(samples: &[Sample], errors: u64, duration: Duration) -> Self {
        let mut ttfb: Vec<f64> = samples.iter().map(|s| s.ttfb.as_secs_f64()).collect();
        let mut total: Vec<f64> = samples.iter().map(|s| s.total.as_secs_f64()).collect();
        let bytes_total: u64 = samples.iter().map(|s| s.bytes).sum();
        Self {
            samples: samples.len() as u64,
            errors,
            duration_secs: duration.as_secs_f64(),
            bytes_total,
            ttfb_secs: percentiles(&mut ttfb),
            total_secs: percentiles(&mut total),
        }
    }
}

fn percentiles(values: &mut [f64]) -> Percentiles {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    };
    Percentiles {
        min: values.first().copied().unwrap_or(0.0),
        max: values.last().copied().unwrap_or(0.0),
        mean,
        p50: percentile(values, 0.50),
        p90: percentile(values, 0.90),
        p95: percentile(values, 0.95),
        p99: percentile(values, 0.99),
        p99_9: percentile(values, 0.999),
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted.get(idx).copied().unwrap_or(0.0)
}

async fn one_request(host: &str, port: u16, path: &str) -> Result<Sample, BenchmarkError> {
    let start = Instant::now();
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(BenchmarkError::Io)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.map_err(BenchmarkError::Io)?;
    stream.flush().await.map_err(BenchmarkError::Io)?;

    let mut buf = vec![0_u8; 8192];
    let mut collected = Vec::new();
    let mut ttfb = None;
    let mut header_done = false;

    loop {
        let n = stream.read(&mut buf).await.map_err(BenchmarkError::Io)?;
        if n == 0 {
            break;
        }
        collected.extend_from_slice(&buf[..n]);
        if !header_done {
            if let Some(pos) = find_header_end(&collected) {
                header_done = true;
                if collected.len() > pos {
                    ttfb = Some(start.elapsed());
                }
            }
        } else if ttfb.is_none() {
            ttfb = Some(start.elapsed());
        }
    }

    let ttfb = ttfb.unwrap_or_else(|| start.elapsed());
    let total = start.elapsed();
    let body_start = find_header_end(&collected).unwrap_or(collected.len());
    let bytes = (collected.len() - body_start) as u64;

    if !collected.starts_with(b"HTTP/1.1 200") && !collected.starts_with(b"HTTP/1.0 200") {
        return Err(BenchmarkError::ParseError {
            tool: "streaming".into(),
            reason: "non-200 response".into(),
        });
    }

    Ok(Sample { ttfb, total, bytes })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), BenchmarkError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| BenchmarkError::ParseError {
            tool: "streaming".into(),
            reason: format!("unsupported url: {url}"),
        })?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".into()),
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (
            h.to_owned(),
            p.parse::<u16>().map_err(|_| BenchmarkError::ParseError {
                tool: "streaming".into(),
                reason: format!("bad port in url: {url}"),
            })?,
        ),
        None => (authority.to_owned(), 80),
    };
    Ok((host, port, path))
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse a streaming JSON report into a [`BenchmarkResult`].
///
/// Latency fields are populated from **TTFB** (the primary metric for
/// this workload). Total response latency is retained in `raw_report`
/// when requested.
///
/// # Errors
///
/// Returns [`BenchmarkError::ParseError`] if the JSON is invalid.
pub fn parse(
    json: &str,
    scenario: &str,
    proxy: &str,
    commit: &str,
    include_raw: bool,
) -> Result<BenchmarkResult, BenchmarkError> {
    let report: StreamingReport = serde_json::from_str(json).map_err(|e| BenchmarkError::ParseError {
        tool: "streaming".into(),
        reason: e.to_string(),
    })?;

    let duration_secs = report.duration_secs.max(f64::EPSILON);
    #[expect(clippy::cast_precision_loss, reason = "throughput from counters")]
    let requests_per_sec = report.samples as f64 / duration_secs;
    #[expect(clippy::cast_precision_loss, reason = "throughput from counters")]
    let bytes_per_sec = report.bytes_total as f64 / duration_secs;

    let raw_report = if include_raw {
        serde_json::from_str(json).ok()
    } else {
        None
    };

    Ok(BenchmarkResult {
        commit: commit.into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        scenario: scenario.into(),
        proxy: proxy.into(),
        tool: "streaming".into(),
        environment: crate::result::current_environment(),
        latency: LatencyMetrics {
            min: report.ttfb_secs.min,
            max: report.ttfb_secs.max,
            mean: report.ttfb_secs.mean,
            p50: report.ttfb_secs.p50,
            p90: report.ttfb_secs.p90,
            p95: report.ttfb_secs.p95,
            p99: report.ttfb_secs.p99,
            p99_9: report.ttfb_secs.p99_9,
        },
        throughput: ThroughputMetrics {
            requests_per_sec,
            bytes_per_sec,
        },
        resource: None,
        errors: ErrorMetrics {
            non_2xx: Some(report.errors),
            timeouts: 0,
            connect_failures: 0,
        },
        raw_report,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_http_url_with_port_and_path() {
        let (host, port, path) = parse_http_url("http://127.0.0.1:18094/").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 18094);
        assert_eq!(path, "/");
    }

    #[test]
    fn percentiles_basic() {
        let mut values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let p = percentiles(&mut values);
        assert!((p.min - 1.0).abs() < 1e-9);
        assert!((p.max - 5.0).abs() < 1e-9);
        assert!((p.mean - 3.0).abs() < 1e-9);
        assert!((p.p50 - 3.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn paced_backend_and_client_measure_ttfb() {
        let backend = start_paced_backend(0, 3, Duration::from_millis(5), 16)
            .await
            .unwrap();
        let url = format!("http://127.0.0.1:{}/", backend.port);
        let json = run(
            &url,
            &StreamingConfig {
                concurrency: 2,
                chunks: 3,
                chunk_delay: Duration::from_millis(5),
                chunk_size: 16,
                duration: Duration::from_millis(200),
            },
        )
        .await
        .unwrap();
        let result = parse(&json, "streaming-passthrough", "direct", "test", true).unwrap();
        assert!(result.latency.mean > 0.0, "ttfb mean should be positive");
        assert!(result.throughput.requests_per_sec > 0.0);
        backend.stop().await;
    }
}
