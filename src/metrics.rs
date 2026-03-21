// ============================================================================
// Rudras — Metrics System (Prometheus-compatible)
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

// ── Direction (used by record_bytes) ─────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}
use anyhow::Result;

// ── Stats Snapshot ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub packets_total: u64,
    pub packets_allowed: u64,
    pub packets_blocked: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connections_tcp: u64,
    pub connections_udp: u64,
    pub threats_detected: u64,
    pub uptime_seconds: u64,
    pub protocol_counts: HashMap<String, u64>,
}

// ── Metrics ───────────────────────────────────────────────────────────────────

pub struct Metrics {
    packets_total: AtomicU64,
    packets_allowed: AtomicU64,
    packets_blocked: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    connections_tcp: AtomicU64,
    connections_udp: AtomicU64,
    threats_detected: AtomicU64,
    start_time: u64,
    protocol_counts: RwLock<HashMap<String, u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            packets_total: AtomicU64::new(0),
            packets_allowed: AtomicU64::new(0),
            packets_blocked: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            connections_tcp: AtomicU64::new(0),
            connections_udp: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            start_time: unix_now(),
            protocol_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Called once per raw packet (before any filtering)
    pub fn record_processed(&self) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Called with byte count + direction for bandwidth accounting
    pub fn record_bytes(&self, bytes: u64, _direction: Direction) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_packet(&self, bytes: usize) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_allowed(&self) {
        self.packets_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.packets_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_threat(&self) {
        self.threats_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection(&self, proto: &str) {
        match proto {
            "tcp" => {
                self.connections_tcp.fetch_add(1, Ordering::Relaxed);
            }
            "udp" => {
                self.connections_udp.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_protocol(&self, proto: &str) {
        let mut map = self.protocol_counts.write();
        *map.entry(proto.to_string()).or_insert(0) += 1;
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_total: self.packets_total.load(Ordering::Relaxed),
            packets_allowed: self.packets_allowed.load(Ordering::Relaxed),
            packets_blocked: self.packets_blocked.load(Ordering::Relaxed),
            bytes_received: self.bytes_rx.load(Ordering::Relaxed),
            bytes_sent: self.bytes_tx.load(Ordering::Relaxed),
            connections_tcp: self.connections_tcp.load(Ordering::Relaxed),
            connections_udp: self.connections_udp.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            uptime_seconds: unix_now().saturating_sub(self.start_time),
            protocol_counts: self.protocol_counts.read().clone(),
        }
    }
}

// ── Prometheus HTTP Metrics Server ───────────────────────────────────────────
//
// SECURITY:
//   - Binds to 127.0.0.1 only — metrics are NOT accessible from the network.
//   - Requires an `X-Rudras-Auth` bearer token in HTTP requests.
//     Set RUDRAS_METRICS_TOKEN environment variable or the token defaults
//     to a per-run ephemeral value logged at startup.
//   - Requests without a valid token receive HTTP 401.
//   - The open `0.0.0.0` binding in previous versions was a SECURITY BUG
//     that exposed internal counters (threat counts, blocked IPs, etc.)
//     to any host that could reach this machine on the metrics port.

pub async fn start_metrics_server(port: u16, metrics: Arc<Metrics>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Derive the auth token: env-var override or ephemeral per-run UUID
    let auth_token = std::env::var("RUDRAS_METRICS_TOKEN").unwrap_or_else(|_| {
        let t = uuid::Uuid::new_v4().to_string();
        info!(
            "📊 Metrics auth token (set RUDRAS_METRICS_TOKEN to pin it): {}",
            t
        );
        t
    });

    // ── CRITICAL: bind to loopback only ──────────────────────────────────────
    let bind_addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(
        "📊 Metrics server listening on http://{}/metrics  (loopback-only)",
        bind_addr
    );

    loop {
        if let Ok((mut stream, peer)) = listener.accept().await {
            let m = metrics.get_stats();
            let token = auth_token.clone();

            tokio::spawn(async move {
                // Read the HTTP request (up to 4 KB)
                let mut buf = vec![0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);

                // Check for the auth header: "X-Rudras-Auth: <token>"
                let authorized = req.lines().any(|line| {
                    line.to_lowercase().starts_with("x-rudras-auth:")
                        && line.split_once(':').map(|x| x.1)
                            .map(|v| v.trim() == token.as_str())
                            .unwrap_or(false)
                });

                let (status, content_type, body) = if authorized {
                    let body = format!(
                        "# HELP rudras_packets_total Total packets processed\n\
                         # TYPE rudras_packets_total counter\n\
                         rudras_packets_total {}\n\
                         rudras_packets_allowed {}\n\
                         rudras_packets_blocked {}\n\
                         rudras_threats_detected {}\n\
                         rudras_uptime_seconds {}\n\
                         rudras_connections_tcp {}\n\
                         rudras_connections_udp {}\n",
                        m.packets_total,
                        m.packets_allowed,
                        m.packets_blocked,
                        m.threats_detected,
                        m.uptime_seconds,
                        m.connections_tcp,
                        m.connections_udp,
                    );
                    ("200 OK", "text/plain; version=0.0.4", body)
                } else {
                    debug!("📊 Metrics: unauthorized request from {}", peer);
                    (
                        "401 Unauthorized",
                        "text/plain",
                        "Unauthorized. Set X-Rudras-Auth header.\n".to_string(),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    content_type,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
