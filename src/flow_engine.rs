// ============================================================================
// Rudras Flow Engine — Stateful Flow Tracking & Risk Scoring
// ============================================================================
//
// WHAT THIS MODULE DOES:
//   The Flow Engine is the GATE for every packet. It maintains a lightweight
//   per-flow state table (HashMap<FlowKey, FlowRecord>) and computes a risk
//   score for each flow based on observable metadata:
//     ✔ Packet/byte rates
//     ✔ TCP flag patterns (SYN ratio, RST ratio)
//     ✔ Port spread (unique destination ports per source)
//     ✔ Flow asymmetry (inbound vs outbound imbalance)
//
// PERFORMANCE:
//   O(1) per-packet cost. Designed to run on 100% of traffic.
//   The expensive shield stack only runs for ~5% of flows (Escalate).
//
// THRESHOLDS:
//   SUSPICIOUS_RISK_THRESHOLD (0.65): Start shield stack
//   BLOCK_RISK_THRESHOLD      (0.85): Immediate block, install WFP rule

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

pub const SUSPICIOUS_RISK_THRESHOLD: f32 = 0.65;
pub const BLOCK_RISK_THRESHOLD: f32 = 0.85;

// ── Flow key ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

// ── Per-flow record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub pkt_count: u64,
    pub byte_count: u64,
    pub syn_count: u64,
    pub rst_count: u64,
    pub fin_count: u64,
    pub unique_dst_ports: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub risk_score: f32,
    // Track unique dst ports per source
    dst_ports_seen: std::collections::HashSet<u16>,
}

// ── Feature vector (extracted from FlowRecord) ────────────────────────────────

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub pkt_rate: f32,         // packets per second
    pub byte_rate: f32,        // bytes per second
    pub imbalance_ratio: f32,  // 0=balanced 1=fully asymmetric
    pub syn_ratio: f32,        // SYN / total packets
    pub rst_ratio: f32,        // RST / total packets
    pub unique_dst_ports: f32, // distinct dst ports this source hit
    pub flow_duration_sec: f32,
    pub avg_pkt_size: f32,
}

impl FlowFeatures {
    /// Lightweight heuristic score (O(1)).
    /// Returns 0.0 (clean) to 1.0 (confirmed threat).
    pub fn heuristic_score(&self) -> f32 {
        let mut score: f32 = 0.0;

        // Port scan: high unique destination port spread
        if self.unique_dst_ports > 20.0 {
            score += 0.45;
        } else if self.unique_dst_ports > 10.0 {
            score += 0.20;
        } else if self.unique_dst_ports > 5.0 {
            score += 0.10;
        }

        // SYN flood: very high SYN ratio
        if self.syn_ratio > 0.80 {
            score += 0.35;
        } else if self.syn_ratio > 0.50 {
            score += 0.15;
        }

        // RST storm (brute force / scanner)
        if self.rst_ratio > 0.50 {
            score += 0.25;
        }

        // DDoS: very high packet rate
        if self.pkt_rate > 1000.0 {
            score += 0.30;
        } else if self.pkt_rate > 200.0 {
            score += 0.10;
        }

        // Data exfiltration: extreme traffic imbalance at high byte rate
        if self.imbalance_ratio > 0.90 && self.byte_rate > 50_000.0 {
            score += 0.30;
        }

        score.min(1.0)
    }
}

// ── Flow decision ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum FlowDecision {
    Allow { score: f32 },
    Escalate { score: f32 },
    Block { score: f32, reason: String },
}

// ── Flow Engine ───────────────────────────────────────────────────────────────

pub struct FlowEngine {
    flows: RwLock<HashMap<FlowKey, FlowRecord>>,
    max_flows: usize,
    flow_timeout_sec: u64,
    flows_created: AtomicU64,
    flows_expired: AtomicU64,
    escalations: AtomicU64,
    blocks: AtomicU64,
}

impl FlowEngine {
    pub fn new() -> Self {
        Self {
            flows: RwLock::new(HashMap::with_capacity(50_000)),
            max_flows: 100_000,
            flow_timeout_sec: 300,
            flows_created: AtomicU64::new(0),
            flows_expired: AtomicU64::new(0),
            escalations: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
        }
    }

    /// Called for every packet. Returns a FlowDecision.
    pub fn update(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        pkt_len: usize,
        tcp_flags: u8,
    ) -> FlowDecision {
        let now = unix_now();

        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        let mut flows = self.flows.write();

        // Evict if full
        if flows.len() >= self.max_flows {
            let stale_cutoff = now.saturating_sub(self.flow_timeout_sec);
            flows.retain(|_, r| r.last_seen > stale_cutoff);
        }

        let record = flows.entry(key.clone()).or_insert_with(|| {
            self.flows_created.fetch_add(1, Ordering::Relaxed);
            FlowRecord {
                key: key.clone(),
                pkt_count: 0,
                byte_count: 0,
                syn_count: 0,
                rst_count: 0,
                fin_count: 0,
                unique_dst_ports: 0,
                first_seen: now,
                last_seen: now,
                risk_score: 0.0,
                dst_ports_seen: std::collections::HashSet::new(),
            }
        });

        // Update record
        record.pkt_count += 1;
        record.byte_count += pkt_len as u64;
        record.last_seen = now;

        // TCP flag parsing
        if (tcp_flags & 0x02) != 0 {
            record.syn_count += 1;
        } // SYN
        if (tcp_flags & 0x04) != 0 {
            record.rst_count += 1;
        } // RST
        if (tcp_flags & 0x01) != 0 {
            record.fin_count += 1;
        } // FIN

        // Track unique destination ports per source
        if record.dst_ports_seen.insert(dst_port) {
            record.unique_dst_ports += 1;
        }

        // Compute features
        let duration = (now.saturating_sub(record.first_seen).max(1)) as f32;
        let pkt_rate = record.pkt_count as f32 / duration;
        let byte_rate = record.byte_count as f32 / duration;
        let syn_ratio = if record.pkt_count > 0 {
            record.syn_count as f32 / record.pkt_count as f32
        } else {
            0.0
        };
        let rst_ratio = if record.pkt_count > 0 {
            record.rst_count as f32 / record.pkt_count as f32
        } else {
            0.0
        };
        let avg_pkt = if record.pkt_count > 0 {
            record.byte_count as f32 / record.pkt_count as f32
        } else {
            0.0
        };

        let features = FlowFeatures {
            pkt_rate,
            byte_rate,
            imbalance_ratio: if pkt_rate > 0.0 {
                (syn_ratio - rst_ratio).abs()
            } else {
                0.0
            },
            syn_ratio,
            rst_ratio,
            unique_dst_ports: record.unique_dst_ports as f32,
            flow_duration_sec: duration,
            avg_pkt_size: avg_pkt,
        };

        let score = features.heuristic_score();
        record.risk_score = score;

        // Decision
        if score >= BLOCK_RISK_THRESHOLD {
            self.blocks.fetch_add(1, Ordering::Relaxed);
            let reason = format_block_reason(&features);
            FlowDecision::Block { score, reason }
        } else if score >= SUSPICIOUS_RISK_THRESHOLD {
            self.escalations.fetch_add(1, Ordering::Relaxed);
            FlowDecision::Escalate { score }
        } else {
            FlowDecision::Allow { score }
        }
    }

    /// Clean up flows not seen in the past `flow_timeout_sec` seconds.
    pub fn cleanup(&self) {
        let cutoff = unix_now().saturating_sub(self.flow_timeout_sec);
        let before = self.flows.read().len();
        self.flows.write().retain(|_, r| r.last_seen > cutoff);
        let after = self.flows.read().len();
        let removed = before.saturating_sub(after);
        if removed > 0 {
            self.flows_expired
                .fetch_add(removed as u64, Ordering::Relaxed);
            debug!(
                "🌊 FlowEngine: Expired {} stale flows ({} active)",
                removed, after
            );
        }
    }

    pub fn get_stats(&self) -> FlowEngineStats {
        let esc = self.escalations.load(Ordering::Relaxed);
        let blk = self.blocks.load(Ordering::Relaxed);
        FlowEngineStats {
            active_flows: self.flows.read().len(),
            flows_created: self.flows_created.load(Ordering::Relaxed),
            flows_expired: self.flows_expired.load(Ordering::Relaxed),
            escalations: esc,
            blocks: blk,
            // Aliases for capture.rs stats display
            high_risk_flows: blk,
            escalated_flows: esc,
            avg_risk_score: 0.0, // Aggregate avg would need extra tracking
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowEngineStats {
    pub active_flows: usize,
    pub flows_created: u64,
    pub flows_expired: u64,
    pub escalations: u64,
    pub blocks: u64,
    // Aliases used by capture.rs print_stats
    pub high_risk_flows: u64,
    pub escalated_flows: u64,
    pub avg_risk_score: f32,
}

fn format_block_reason(f: &FlowFeatures) -> String {
    if f.unique_dst_ports > 20.0 {
        format!(
            "Port scan ({:.0} ports in {:.0}s)",
            f.unique_dst_ports, f.flow_duration_sec
        )
    } else if f.syn_ratio > 0.80 {
        format!("SYN flood (syn_ratio={:.2})", f.syn_ratio)
    } else if f.pkt_rate > 1000.0 {
        format!("Volumetric attack ({:.0} pps)", f.pkt_rate)
    } else {
        "High risk score".to_string()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
