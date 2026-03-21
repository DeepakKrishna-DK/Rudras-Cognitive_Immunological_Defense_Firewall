// ============================================================================
// Rudras — Single-Pass Packet Processing Engine
//
// Processes each captured packet through ALL security zones in a single
// traversal, eliminating redundant parsing and enabling a unified drop
// decision. The architecture:
//
//   1. Parse packet ONCE (extract all headers upfront)
//   2. Run all engine checks against the parsed header struct
//   3. Collect verdicts from each zone in parallel scoring
//   4. Apply a unified DROP/ALLOW/LOG decision
//
// Engines in priority order:
//   Zone 1: Stateful (TCP state) → InvalidState = immediate drop
//   Zone 1: Threat Intel (known-bad IP) → immediate drop
//   Zone 1: Bogon/RFC-1918 spoofing check
//   Zone 2: Comprehensive Blocker (malware sigs, domain block)
//   Zone 3: IDS signature match
//   Zone 3: WAF / DPI (application-layer)
//   Zone 4: UEBA / behavioral anomaly
//   Zone 5: AI risk score fusion
//   Final: Verdict aggregation → single WFP/WinDivert drop call
// ============================================================================

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

// ── Parsed Packet Header (parsed once, shared across all zones) ────────────────

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    // L3
    pub src_ip:      IpAddr,
    pub dst_ip:      IpAddr,
    pub proto:       u8,       // 6=TCP, 17=UDP, 1=ICMP
    pub ttl:         u8,
    pub ip_len:      u16,

    // L4 (TCP/UDP)
    pub src_port:    u16,
    pub dst_port:    u16,
    pub tcp_flags:   u8,
    pub seq_num:     u32,
    pub ack_num:     u32,

    // L7 raw payload (first 512 bytes max for DPI without full copy)
    pub payload:     Vec<u8>,
    pub payload_len: usize,

    // Metadata
    pub is_inbound:  bool,
    pub interface:   String,
}

impl ParsedPacket {
    pub fn is_tcp(&self)  -> bool { self.proto == 6  }
    pub fn is_udp(&self)  -> bool { self.proto == 17 }
    pub fn is_icmp(&self) -> bool { self.proto == 1  }

    /// Returns true if src_ip is a private/bogon address (for spoofing detection)
    pub fn is_src_bogon(&self) -> bool {
        is_bogon(self.src_ip)
    }
}

fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC-1918, loopback, link-local, CGNAT, documentation, broadcast
            matches!(o,
                [10, ..] |
                [172, 16..=31, ..] |
                [192, 168, ..] |
                [127, ..] |
                [169, 254, ..] |
                [100, 64..=127, ..] |
                [192, 0, 2, _] |
                [198, 51, 100, _] |
                [203, 0, 113, _] |
                [0, ..] |
                [255, 255, 255, 255]
            )
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // Loopback ::1, link-local fe80::/10, ULA fc/fd
            v6.is_loopback()
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

// ── Per-Zone Verdict ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneVerdict {
    /// Zone says: this packet is clean, continue.
    Pass,
    /// Zone says: drop immediately, reason given.
    Drop(DropReason),
    /// Zone says: suspicious but not conclusive — add to risk score.
    Suspicious(f32),
    /// Zone says: already handled (e.g. IPS sent RST) — don't re-process.
    Handled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DropReason {
    StatefulViolation,
    ThreatIntelHit(String),   // matched IOC / malicious IP
    BogonSpoof,
    MalwareSig(String),       // sig name
    IDSAlert(String),         // rule name / SID
    WAFBlock(String),         // WAF rule
    RateLimit,
    IPSBlock,
    AiHighRisk(f32),          // AI score exceeded threshold
    PolicyDeny(String),       // Identity policy
}

// ── Final Packet Decision ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PacketDecision {
    Allow,
    Drop(DropReason),
    /// Allow but alert (IDS logged, not blocked)
    AllowWithAlert(String),
}

// ── Single-Pass Configuration ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SinglePassConfig {
    /// AI risk score above this → BLOCK
    pub ai_block_threshold:     f32,
    /// AI risk score above this → ALERT
    pub ai_suspicious_threshold: f32,
    /// Enable stateful check (Zone 1 fast-path deny on invalid state)
    pub stateful_enabled:       bool,
    /// Enable bogon check for inbound packets
    pub bogon_check_inbound:    bool,
    /// Enable bogon check for outbound packets (catches internal spoofing)
    pub bogon_check_outbound:   bool,
}

impl Default for SinglePassConfig {
    fn default() -> Self {
        SinglePassConfig {
            ai_block_threshold:      0.75,
            ai_suspicious_threshold: 0.45,
            stateful_enabled:        true,
            bogon_check_inbound:     false, // inbound bogon src is normal (NAT'd)
            bogon_check_outbound:    true,  // outbound bogon src = IP spoofing
        }
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SinglePassStats {
    pub total_processed:    AtomicU64,
    pub dropped_stateful:   AtomicU64,
    pub dropped_threat_intel: AtomicU64,
    pub dropped_malware_sig: AtomicU64,
    pub dropped_ids:        AtomicU64,
    pub dropped_waf:        AtomicU64,
    pub dropped_ai:         AtomicU64,
    pub dropped_policy:     AtomicU64,
    pub allowed:            AtomicU64,
    pub alerted:            AtomicU64,
}

// ── Single-Pass Engine ────────────────────────────────────────────────────────

pub struct SinglePassEngine {
    pub config: SinglePassConfig,
    pub stats:  SinglePassStats,
}

impl SinglePassEngine {
    pub fn new() -> Self {
        info!("⚡ Single-Pass Engine initialized — unified packet verdict pipeline");
        info!("   Zone order: Stateful → ThreatIntel → Bogon → Blocker → IDS → WAF → AI → Policy");
        SinglePassEngine {
            config: SinglePassConfig::default(),
            stats:  SinglePassStats::default(),
        }
    }

    pub fn with_config(config: SinglePassConfig) -> Self {
        info!("⚡ Single-Pass Engine initialized with custom config");
        SinglePassEngine {
            config,
            stats: SinglePassStats::default(),
        }
    }

    // ── Main Entry ────────────────────────────────────────────────────────────

    /// Process all zone verdicts and return a single unified packet decision.
    /// Each zone returns a ZoneVerdict; we collect them and apply priority rules.
    pub fn decide(&self, pkt: &ParsedPacket, zone_verdicts: &[ZoneVerdict]) -> PacketDecision {
        self.stats.total_processed.fetch_add(1, Ordering::Relaxed);

        let mut cumulative_risk: f32 = 0.0;
        let mut alert_reasons: Vec<String> = Vec::new();

        for verdict in zone_verdicts {
            match verdict {
                ZoneVerdict::Drop(reason) => {
                    // First DROP wins — immediate decision
                    self.record_drop(reason);
                    debug!("⚡ SINGLE-PASS DROP: {:?} src={} dst={}:{}",
                        reason, pkt.src_ip, pkt.dst_ip, pkt.dst_port);
                    return PacketDecision::Drop(reason.clone());
                }
                ZoneVerdict::Suspicious(score) => {
                    cumulative_risk += score;
                    alert_reasons.push(format!("risk+{:.2}", score));
                }
                ZoneVerdict::Pass | ZoneVerdict::Handled => {}
            }
        }

        // AI risk fusion — if cumulative risk exceeds block threshold → drop
        if cumulative_risk >= self.config.ai_block_threshold {
            let reason = DropReason::AiHighRisk(cumulative_risk);
            self.stats.dropped_ai.fetch_add(1, Ordering::Relaxed);
            warn!("⚡ SINGLE-PASS AI-DROP: risk={:.3} src={} dst={}:{}",
                cumulative_risk, pkt.src_ip, pkt.dst_ip, pkt.dst_port);
            return PacketDecision::Drop(reason);
        }

        // Suspicious but below block — allow with alert
        if cumulative_risk >= self.config.ai_suspicious_threshold {
            self.stats.alerted.fetch_add(1, Ordering::Relaxed);
            let msg = format!("risk={:.3} flags=[{}]", cumulative_risk, alert_reasons.join(","));
            return PacketDecision::AllowWithAlert(msg);
        }

        // Clean
        self.stats.allowed.fetch_add(1, Ordering::Relaxed);
        PacketDecision::Allow
    }

    fn record_drop(&self, reason: &DropReason) {
        match reason {
            DropReason::StatefulViolation       => { self.stats.dropped_stateful.fetch_add(1, Ordering::Relaxed); }
            DropReason::ThreatIntelHit(_)       => { self.stats.dropped_threat_intel.fetch_add(1, Ordering::Relaxed); }
            DropReason::MalwareSig(_)           => { self.stats.dropped_malware_sig.fetch_add(1, Ordering::Relaxed); }
            DropReason::IDSAlert(_)             => { self.stats.dropped_ids.fetch_add(1, Ordering::Relaxed); }
            DropReason::WAFBlock(_)             => { self.stats.dropped_waf.fetch_add(1, Ordering::Relaxed); }
            DropReason::AiHighRisk(_)           => { self.stats.dropped_ai.fetch_add(1, Ordering::Relaxed); }
            DropReason::PolicyDeny(_)           => { self.stats.dropped_policy.fetch_add(1, Ordering::Relaxed); }
            DropReason::BogonSpoof              => { self.stats.dropped_stateful.fetch_add(1, Ordering::Relaxed); }
            DropReason::RateLimit | DropReason::IPSBlock => {}
        }
    }

    // ── Zone-specific helper checkers (called by the packet loop) ─────────────

    /// Zone 1: Bogon source IP check (outbound only).
    pub fn check_bogon(&self, pkt: &ParsedPacket) -> ZoneVerdict {
        let should_check = if pkt.is_inbound {
            self.config.bogon_check_inbound
        } else {
            self.config.bogon_check_outbound
        };

        if should_check && pkt.is_src_bogon() && !pkt.is_inbound {
            warn!("⚡ BOGON spoof attempt: src={} dst={}:{}", pkt.src_ip, pkt.dst_ip, pkt.dst_port);
            return ZoneVerdict::Drop(DropReason::BogonSpoof);
        }
        ZoneVerdict::Pass
    }

    /// Convert a StatefulVerdict into a ZoneVerdict.
    pub fn from_stateful_verdict(
        &self,
        sv: &crate::stateful::StatefulVerdict,
    ) -> ZoneVerdict {
        use crate::stateful::StatefulVerdict as SV;
        match sv {
            SV::NewSession | SV::Established => ZoneVerdict::Pass,
            SV::InvalidState   => ZoneVerdict::Drop(DropReason::StatefulViolation),
            SV::SynFlooded     => ZoneVerdict::Drop(DropReason::StatefulViolation),
            SV::ConnLimitExceeded => ZoneVerdict::Drop(DropReason::StatefulViolation),
        }
    }

    pub fn print_stats(&self) {
        let s = &self.stats;
        info!("⚡ SINGLE-PASS: total={} allowed={} alerted={} drop[stateful={} ti={} mal={} ids={} waf={} ai={} pol={}]",
            s.total_processed.load(Ordering::Relaxed),
            s.allowed.load(Ordering::Relaxed),
            s.alerted.load(Ordering::Relaxed),
            s.dropped_stateful.load(Ordering::Relaxed),
            s.dropped_threat_intel.load(Ordering::Relaxed),
            s.dropped_malware_sig.load(Ordering::Relaxed),
            s.dropped_ids.load(Ordering::Relaxed),
            s.dropped_waf.load(Ordering::Relaxed),
            s.dropped_ai.load(Ordering::Relaxed),
            s.dropped_policy.load(Ordering::Relaxed),
        );
    }
}
