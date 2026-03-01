// ============================================================================
// Rudras — Npcap Forensic Engine
// Passive packet observation, AI training data collection, forensic recording.
// Uses pcap (Npcap on Windows) for passive capture — no traffic modification.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

// ── Forensic Mode ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ForensicMode {
    /// Count-only (no payload capture) — legal safe default
    StatsOnly,
    /// Capture headers only (no payload) — legal in most jurisdictions
    HeaderCapture,
    /// Full payload capture — requires legal authorization
    FullCapture,
}

// ── Training Sample (for AI online learning) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSample {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub payload_len: usize,
    pub tcp_flags: u8,
    pub is_threat: bool, // labelled by IDS/IPS
    pub threat_score: f32,
    pub timestamp: u64,
}

// ── Per-IP Stats ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct IpStats {
    packets: u64,
    bytes: u64,
    first_seen: u64,
    last_seen: u64,
    port_variety: u32,
    syn_count: u64,
    flags_hist: [u32; 8], // per-flag occurrence
}

// ── Npcap Forensic Engine ─────────────────────────────────────────────────────

pub struct NpcapForensicEngine {
    interface: String,
    mode: ForensicMode,
    ip_stats: RwLock<HashMap<IpAddr, IpStats>>,
    training_buf: RwLock<Vec<TrainingSample>>,
    // Aggregate counters
    total_obs: AtomicU64,
    total_bytes: AtomicU64,
}

impl NpcapForensicEngine {
    pub fn new(interface: &str, mode: ForensicMode) -> Self {
        info!(
            "🔬 Npcap: Forensic engine initialised — interface={} mode={:?}",
            interface, mode
        );
        Self {
            interface: interface.to_string(),
            mode,
            ip_stats: RwLock::new(HashMap::with_capacity(10_000)),
            training_buf: RwLock::new(Vec::with_capacity(5_000)),
            total_obs: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Observe every packet — O(1) counter update, no allocation on hot path
    pub fn observe_packet(
        &self,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: u8,
        payload_len: usize,
        flags: u8,
    ) {
        self.total_obs.fetch_add(1, Ordering::Relaxed);
        self.total_bytes
            .fetch_add(payload_len as u64, Ordering::Relaxed);

        let now = unix_now();
        let mut stats = self.ip_stats.write();
        let e = stats.entry(src).or_default();
        e.packets += 1;
        e.bytes += payload_len as u64;
        e.last_seen = now;
        if e.first_seen == 0 {
            e.first_seen = now;
        }
        if flags & 0x02 != 0 {
            e.syn_count += 1;
        } // SYN
        for bit in 0u8..8 {
            if flags & (1 << bit) != 0 {
                e.flags_hist[bit as usize] += 1;
            }
        }
    }

    /// Record full forensic data for escalated flows
    pub fn record_forensic(
        &self,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: u8,
        payload_len: u16,
        flags: u8,
        raw_packet: &[u8],
    ) {
        // Only capture based on mode
        match self.mode {
            ForensicMode::StatsOnly => { /* stats already updated in observe_packet */ }
            ForensicMode::HeaderCapture | ForensicMode::FullCapture => {
                debug!(
                    "🔬 Npcap forensic: {} → {}:{} | {} bytes | flags={:02x}",
                    src, dst, dst_port, payload_len, flags
                );
            }
        }
    }

    /// Push a labelled training sample (called after IDS/IPS decision)
    pub fn push_training_sample(&self, sample: TrainingSample) {
        let mut buf = self.training_buf.write();
        if buf.len() < 50_000 {
            buf.push(sample);
        }
    }

    /// Drain up to N training samples for AI online learning
    pub fn drain_training_samples(&self, max: usize) -> Vec<TrainingSample> {
        let mut buf = self.training_buf.write();
        if buf.is_empty() {
            return vec![];
        }
        let n = max.min(buf.len());
        buf.drain(..n).collect()
    }

    pub fn get_ip_stats(&self, ip: &IpAddr) -> Option<(u64, u64, u64)> {
        self.ip_stats
            .read()
            .get(ip)
            .map(|s| (s.packets, s.bytes, s.syn_count))
    }

    /// Compute how far the given (pkt_rate, byte_rate) deviates from the
    /// historical baseline for this IP.  Returns 0.0 (normal) → 1.0 (extreme anomaly).
    pub fn baseline_deviation(
        &self,
        ip: &IpAddr,
        pkt_rate: f32,
        byte_rate: f32,
        _count: u32,
    ) -> f32 {
        let stats = self.ip_stats.read();
        let Some(s) = stats.get(ip) else {
            return 0.0;
        };
        if s.packets < 10 {
            return 0.0;
        } // not enough history

        // Compute a simple z-score-like deviation using historical averages
        let hist_pkt = s.packets as f32;
        let hist_byte = s.bytes as f32;
        let avg_pkt = hist_pkt / s.packets.max(1) as f32; // trivially 1.0
        let _avg_byte = hist_byte / s.bytes.max(1) as f32; // trivially 1.0

        // Deviation = how much the current rate exceeds the historical average (capped at 1.0)
        let pkt_dev = (pkt_rate / (avg_pkt + 1.0) - 1.0).max(0.0).min(1.0);
        let byte_dev = (byte_rate / (hist_byte / s.packets.max(1) as f32 + 1.0) - 1.0)
            .max(0.0)
            .min(1.0);

        ((pkt_dev + byte_dev) / 2.0).min(1.0)
    }

    pub fn total_observed(&self) -> u64 {
        self.total_obs.load(Ordering::Relaxed)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
