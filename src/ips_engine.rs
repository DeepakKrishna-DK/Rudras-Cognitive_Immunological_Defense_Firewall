// ============================================================================
// Rudras IPS Engine — Intrusion Prevention System
// ============================================================================
//
// ARCHITECTURE (Industry Standard — like McAfee IPS / Cisco FirePOWER / Palo Alto):
//
//  IDS Alerts ──► IPS Decision Engine ──► Response Executor
//                       │                       │
//               Penalty Scoring           ┌─────┴──────────────────────┐
//               Reputation DB             │  Rate Limiter (token bucket)│
//               Whitelist check           │  TCP RST Injector           │
//               Threshold eval            │  WFP Block Rule             │
//                                         │  Connection Teardown        │
//                                         │  Honeypot Redirect          │
//                                         │  Quarantine Zone            │
//                                         └─────────────────────────────┘
//
// RESPONSE LEVELS (graduated — like McAfee IPS policy modes):
//   Level 0 — Monitor:     Alert only, no action (IDS mode)
//   Level 1 — Rate Limit:  Throttle to N pps (soft action)
//   Level 2 — TCP Reset:   Send RST to both endpoints (stateless block)
//   Level 3 — WFP Block:   Kernel-level drop via WFP (stateful, persistent)
//   Level 4 — Quarantine:  Move source to isolated VLAN/zone + full block
//   Level 5 — Blacklist:   Permanent WFP rule + SIEM critical alert
//
// PREVENTION MODES:
//   Inline (Active):  IPS can block/modify traffic  ← default
//   Passive (IDS):    Alert only, no blocking
//   Learning:         Build baseline, minimal blocking
//
// PENALTY SYSTEM:
//   Each alert from IDS adds penalty points to the source IP.
//   Penalty decays over time. When threshold crossed → escalate response.
//   Critical alert: +50 pts   High: +20   Medium: +10   Low: +2

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use crate::ids_engine::{IdsAlert, IdsCategory, IdsSeverity};
use crate::wfp_engine::{WfpDirection, WfpEngine, WfpRuleOrigin};

// ── IPS Mode ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum IpsMode {
    /// Full inline prevention — block, rate-limit, RST
    Inline,
    /// Alert-only — same as IDS, no active prevention
    Passive,
    /// Learning mode — observe and build baseline, minimal blocking
    Learning,
}

// ── Response Action ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpsAction {
    /// Log and continue — no active prevention
    Monitor,
    /// Throttle this IP to max_pps packets per second
    RateLimit { max_pps: u32 },
    /// Send TCP RST to terminate the connection
    TcpReset,
    /// Install WFP kernel block rule for N seconds
    WfpBlock { duration_secs: u64 },
    /// Full block + alert to SIEM + escalate to security team
    Quarantine { duration_secs: u64 },
    /// Permanent block — never unblock without manual review
    Blacklist,
}

impl IpsAction {
    pub fn level(&self) -> u8 {
        match self {
            Self::Monitor => 0,
            Self::RateLimit { .. } => 1,
            Self::TcpReset => 2,
            Self::WfpBlock { .. } => 3,
            Self::Quarantine { .. } => 4,
            Self::Blacklist => 5,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Monitor => "MONITOR",
            Self::RateLimit { .. } => "RATE_LIMIT",
            Self::TcpReset => "TCP_RESET",
            Self::WfpBlock { .. } => "WFP_BLOCK",
            Self::Quarantine { .. } => "QUARANTINE",
            Self::Blacklist => "BLACKLIST",
        }
    }
}

// ── IPS Decision ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpsDecision {
    pub src_ip: IpAddr,
    pub action: IpsAction,
    pub reason: String,
    pub alert_id: u64,
    pub penalty: f32, // penalty score at decision time
    pub timestamp: u64,
}

// ── IP Penalty Record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PenaltyRecord {
    score: f32,                // Current accumulated penalty
    last_alert: u64,           // Unix timestamp of last alert
    alert_count: u32,          // Total alerts from this IP
    current_action: IpsAction, // Current active response level
    action_until: u64,         // Timestamp when current action expires
    is_whitelisted: bool,
    is_blacklisted: bool,
    // Rate limiter state (token bucket)
    tokens: f32,      // Current token count
    last_refill: u64, // Last token bucket refill time
    pps_limit: u32,   // Packets per second limit (0 = unlimited)
}

impl PenaltyRecord {
    fn new() -> Self {
        Self {
            score: 0.0,
            last_alert: unix_now(),
            alert_count: 0,
            current_action: IpsAction::Monitor,
            action_until: 0,
            is_whitelisted: false,
            is_blacklisted: false,
            tokens: 100.0,
            last_refill: unix_now_ms(), // millisecond precision for rate limiter
            pps_limit: 0,
        }
    }

    /// Decay penalty score based on time since last alert.
    /// Half-life = 1800 seconds (30 minutes).
    fn decay(&mut self) {
        let now = unix_now();
        let elapsed = now.saturating_sub(self.last_alert) as f32;
        let half_life = 1800.0f32;
        // Exponential decay: score * 0.5^(elapsed/half_life)
        self.score *= 0.5_f32.powf(elapsed / half_life);
    }

    /// Add penalty points for a new alert.
    fn add_penalty(&mut self, severity: &IdsSeverity) {
        self.decay();
        let pts = match severity {
            IdsSeverity::Critical => 50.0,
            IdsSeverity::High => 20.0,
            IdsSeverity::Medium => 10.0,
            IdsSeverity::Low => 2.0,
        };
        self.score = (self.score + pts).min(500.0);
        self.alert_count += 1;
        self.last_alert = unix_now();
    }

    /// Token bucket rate check: returns true if packet is allowed within pps_limit.
    /// Uses millisecond precision so bursts within a single second are throttled correctly.
    fn rate_check(&mut self) -> bool {
        if self.pps_limit == 0 {
            return true;
        } // unlimited
        let now_ms = unix_now_ms();
        let elapsed_secs = now_ms.saturating_sub(self.last_refill) as f32 / 1000.0;
        // Refill tokens proportionally to elapsed time
        self.tokens =
            (self.tokens + self.pps_limit as f32 * elapsed_secs).min(self.pps_limit as f32);
        self.last_refill = now_ms;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false // Rate limit exceeded
        }
    }
}

// ── IPS Configuration ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpsConfig {
    pub mode: IpsMode,
    /// Penalty threshold to trigger level-1 rate limiting
    pub rate_limit_threshold: f32,
    /// Penalty threshold to trigger level-2 TCP RST
    pub rst_threshold: f32,
    /// Penalty threshold to trigger level-3 WFP kernel block
    pub block_threshold: f32,
    /// Penalty threshold to trigger level-4 quarantine
    pub quarantine_threshold: f32,
    /// Penalty threshold to trigger level-5 permanent blacklist
    pub blacklist_threshold: f32,
    /// Default WFP block duration (seconds)
    pub block_duration_secs: u64,
    /// Default quarantine duration (seconds)
    pub quarantine_duration_secs: u64,
    /// Rate limit (packets per second) when rate-limiting
    pub rate_limit_pps: u32,
    /// Auto-block HIGH severity alerts immediately
    pub auto_block_high: bool,
    /// Auto-block CRITICAL severity alerts immediately
    pub auto_block_critical: bool,
    /// IP addresses that are never blocked (management IPs)
    pub whitelist: Vec<String>,
}

impl Default for IpsConfig {
    fn default() -> Self {
        Self {
            mode: IpsMode::Inline,
            rate_limit_threshold: 30.0,
            rst_threshold: 60.0,
            block_threshold: 100.0,
            quarantine_threshold: 200.0,
            blacklist_threshold: 350.0,
            block_duration_secs: 3600,       // 1 hour
            quarantine_duration_secs: 86400, // 24 hours
            rate_limit_pps: 10,              // 10 pps throttle
            auto_block_high: false,          // accumulate first
            auto_block_critical: true,       // immediate on critical
            whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

// ── IPS Engine ────────────────────────────────────────────────────────────────

pub struct IpsEngine {
    config: RwLock<IpsConfig>,
    penalties: RwLock<HashMap<IpAddr, PenaltyRecord>>,
    wfp: Arc<WfpEngine>,

    // Whitelist (fast-path O(1) check)
    whitelist: RwLock<std::collections::HashSet<IpAddr>>,

    // Stats
    decisions_total: AtomicU64,
    blocks_issued: AtomicU64,
    resets_injected: AtomicU64,
    rate_limits_applied: AtomicU64,
    quarantines_active: AtomicU64,
    blacklists_total: AtomicU64,
    packets_dropped: AtomicU64,
}

impl IpsEngine {
    pub fn new(config: IpsConfig, wfp: Arc<WfpEngine>) -> Self {
        let mut whitelist_set = std::collections::HashSet::new();
        for ip_str in &config.whitelist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                whitelist_set.insert(ip);
            }
        }

        info!("🛡️  IPS: Initializing in {:?} mode | Thresholds: rate={} rst={} block={} quarantine={}",
              config.mode,
              config.rate_limit_threshold, config.rst_threshold,
              config.block_threshold, config.quarantine_threshold);

        Self {
            config: RwLock::new(config),
            penalties: RwLock::new(HashMap::with_capacity(10_000)),
            wfp,
            whitelist: RwLock::new(whitelist_set),
            decisions_total: AtomicU64::new(0),
            blocks_issued: AtomicU64::new(0),
            resets_injected: AtomicU64::new(0),
            rate_limits_applied: AtomicU64::new(0),
            quarantines_active: AtomicU64::new(0),
            blacklists_total: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
        }
    }

    // ── Main Entry Point ───────────────────────────────────────────────────
    // Called by capture.rs with the alerts produced by IDS.
    // Returns an IpsDecision describing what action to take.

    pub fn respond_to_alerts(&self, alerts: &[IdsAlert]) -> Option<IpsDecision> {
        if alerts.is_empty() {
            return None;
        }

        let config = self.config.read();
        if config.mode == IpsMode::Passive {
            // Passive mode — alert only, no action
            return None;
        }

        // Pick the most severe alert as the primary
        let primary = alerts.iter().max_by_key(|a| &a.severity).unwrap();

        let src_ip = primary.src_ip;

        // Skip whitelisted IPs
        if self.whitelist.read().contains(&src_ip) {
            debug!("🛡️  IPS: Skipping whitelisted IP {}", src_ip);
            return None;
        }

        // Immediate response for CRITICAL alerts if configured
        if primary.severity == IdsSeverity::Critical && config.auto_block_critical {
            let action = IpsAction::WfpBlock {
                duration_secs: config.block_duration_secs,
            };
            self.execute_action(src_ip, &action, primary, &config);
            let decision = IpsDecision {
                src_ip,
                action,
                alert_id: primary.id,
                reason: format!("CRITICAL immediate block: {}", primary.rule_name),
                penalty: 50.0,
                timestamp: unix_now(),
            };
            self.decisions_total.fetch_add(1, Ordering::Relaxed);
            return Some(decision);
        }

        // Immediate response for HIGH alerts if configured
        if primary.severity == IdsSeverity::High && config.auto_block_high {
            let action = IpsAction::TcpReset;
            self.execute_action(src_ip, &action, primary, &config);
            let decision = IpsDecision {
                src_ip,
                action,
                alert_id: primary.id,
                reason: format!("HIGH auto-reset: {}", primary.rule_name),
                penalty: 20.0,
                timestamp: unix_now(),
            };
            self.decisions_total.fetch_add(1, Ordering::Relaxed);
            return Some(decision);
        }

        // Update penalty score
        let penalty_score = {
            let mut penalties = self.penalties.write();
            let rec = penalties.entry(src_ip).or_insert_with(PenaltyRecord::new);

            if rec.is_blacklisted {
                // Already blacklisted — just ensure WFP block is active
                return Some(IpsDecision {
                    src_ip,
                    action: IpsAction::Blacklist,
                    reason: "IP permanently blacklisted".to_string(),
                    alert_id: primary.id,
                    penalty: rec.score,
                    timestamp: unix_now(),
                });
            }

            rec.add_penalty(&primary.severity);
            rec.score
        };

        // Determine response level based on accumulated penalty
        let action = self.select_action(penalty_score, &config);

        // Execute the action
        self.execute_action(src_ip, &action, primary, &config);

        // Update penalty record with applied action
        {
            let mut penalties = self.penalties.write();
            if let Some(rec) = penalties.get_mut(&src_ip) {
                rec.current_action = action.clone();
                rec.action_until = unix_now()
                    + match &action {
                        IpsAction::WfpBlock { duration_secs } => *duration_secs,
                        IpsAction::Quarantine { duration_secs } => *duration_secs,
                        IpsAction::Blacklist => u64::MAX / 2,
                        _ => 300,
                    };
                if action == IpsAction::Blacklist {
                    rec.is_blacklisted = true;
                }
                if matches!(action, IpsAction::RateLimit { .. }) {
                    rec.pps_limit = config.rate_limit_pps;
                }
            }
        }

        self.decisions_total.fetch_add(1, Ordering::Relaxed);

        Some(IpsDecision {
            src_ip,
            action,
            reason: format!("Penalty={:.0} — {}", penalty_score, primary.rule_name),
            alert_id: primary.id,
            penalty: penalty_score,
            timestamp: unix_now(),
        })
    }

    /// Per-packet rate check — called on every packet for rate-limited IPs.
    /// Returns true = allow, false = drop (rate exceeded).
    pub fn rate_check(&self, src_ip: IpAddr) -> bool {
        let mut penalties = self.penalties.write();
        if let Some(rec) = penalties.get_mut(&src_ip) {
            if rec.pps_limit > 0 {
                let allowed = rec.rate_check();
                if !allowed {
                    self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
                return allowed;
            }
        }
        true // No rate limit set for this IP
    }

    /// Check whether this IP is currently under an active block/quarantine.
    pub fn is_actively_blocked(&self, src_ip: IpAddr) -> bool {
        let penalties = self.penalties.read();
        if let Some(rec) = penalties.get(&src_ip) {
            let now = unix_now();
            if rec.is_blacklisted {
                return true;
            }
            if rec.action_until > now
                && matches!(
                    rec.current_action,
                    IpsAction::WfpBlock { .. } | IpsAction::Quarantine { .. }
                )
            {
                return true;
            }
        }
        false
    }

    // ── Response Selector ──────────────────────────────────────────────────

    fn select_action(&self, penalty: f32, config: &IpsConfig) -> IpsAction {
        if penalty >= config.blacklist_threshold {
            IpsAction::Blacklist
        } else if penalty >= config.quarantine_threshold {
            IpsAction::Quarantine {
                duration_secs: config.quarantine_duration_secs,
            }
        } else if penalty >= config.block_threshold {
            IpsAction::WfpBlock {
                duration_secs: config.block_duration_secs,
            }
        } else if penalty >= config.rst_threshold {
            IpsAction::TcpReset
        } else if penalty >= config.rate_limit_threshold {
            IpsAction::RateLimit {
                max_pps: config.rate_limit_pps,
            }
        } else {
            IpsAction::Monitor
        }
    }

    // ── Response Executor ──────────────────────────────────────────────────

    fn execute_action(
        &self,
        src_ip: IpAddr,
        action: &IpsAction,
        alert: &IdsAlert,
        config: &IpsConfig,
    ) {
        match action {
            IpsAction::Monitor => {
                debug!("🛡️  IPS MONITOR: {} — {}", src_ip, alert.rule_name);
            }

            IpsAction::RateLimit { max_pps } => {
                warn!(
                    "🛡️  IPS RATE-LIMIT: {} → {}pps | {} | category={}",
                    src_ip,
                    max_pps,
                    alert.rule_name,
                    alert.category.label()
                );
                self.rate_limits_applied.fetch_add(1, Ordering::Relaxed);
                // Rate limit is enforced in rate_check() per-packet
            }

            IpsAction::TcpReset => {
                warn!(
                    "🛡️  IPS TCP-RST: {} | {} | sev={:?}",
                    src_ip, alert.rule_name, alert.severity
                );
                self.resets_injected.fetch_add(1, Ordering::Relaxed);
                // In production: send RST packet via raw socket
                // Windows: WSASendTo() on a raw IPPROTO_TCP socket
                // Or via WinDivert: WinDivertSend() with RST-flagged packet
                self.inject_tcp_rst(src_ip, alert.dst_ip, alert.src_port, alert.dst_port);
            }

            IpsAction::WfpBlock { duration_secs } => {
                warn!(
                    "🛡️  IPS WFP-BLOCK: {} | {}s | {} | penalty escalation",
                    src_ip, duration_secs, alert.rule_name
                );
                self.blocks_issued.fetch_add(1, Ordering::Relaxed);
                self.wfp.block_ip(
                    src_ip,
                    &format!("IPS: {} (sev={:?})", alert.rule_name, alert.severity),
                    WfpRuleOrigin::CyberImmune,
                );
            }

            IpsAction::Quarantine { duration_secs } => {
                error!(
                    "🛡️  IPS QUARANTINE: {} | {}h | {} | repeat offender",
                    src_ip,
                    duration_secs / 3600,
                    alert.rule_name
                );
                self.quarantines_active.fetch_add(1, Ordering::Relaxed);

                // 1. WFP kernel-level IP block (covers both inbound and outbound at the IP layer)
                self.wfp.block_ip(
                    src_ip,
                    &format!("IPS QUARANTINE: {} ({}s)", alert.rule_name, duration_secs),
                    WfpRuleOrigin::CyberImmune,
                );

                // 2. Block outbound on the offending source port to cut off C2 callbacks
                self.wfp.block_port(
                    alert.src_port,
                    WfpDirection::Outbound,
                    &format!(
                        "IPS QUARANTINE [C2-CUTOFF]: {} | src={}",
                        alert.rule_name, src_ip
                    ),
                );

                // 3. Immediately tear down the active connection via TCP RST
                self.inject_tcp_rst(src_ip, alert.dst_ip, alert.src_port, alert.dst_port);

                // 4. Emit a structured SIEM-compatible critical alert (JSON-parseable by any SIEM ingestor)
                error!(
                    target: "siem",
                    "{{\"event\":\"QUARANTINE\",\"src_ip\":\"{}\",\"dst_ip\":\"{}\",\"src_port\":{},\"dst_port\":{},\"rule\":\"{}\",\"category\":\"{}\",\"severity\":\"CRITICAL\",\"duration_secs\":{},\"ts\":{}}}",
                    src_ip,
                    alert.dst_ip,
                    alert.src_port,
                    alert.dst_port,
                    alert.rule_name,
                    alert.category.label(),
                    duration_secs,
                    unix_now()
                );
            }

            IpsAction::Blacklist => {
                error!(
                    "🚨 IPS BLACKLIST: {} | PERMANENT | {} | multi-offense",
                    src_ip, alert.rule_name
                );
                self.blacklists_total.fetch_add(1, Ordering::Relaxed);
                self.wfp.block_ip(
                    src_ip,
                    &format!("IPS BLACKLIST PERMANENT: {}", alert.rule_name),
                    WfpRuleOrigin::CyberImmune,
                );
                // Broadcast to peer nodes via Distributed Immunity
                // Page SOC on-call
            }
        }
    }

    // ── TCP RST Injection ─────────────────────────────────────────────────────
    // Sends a TCP RST packet to terminate an established connection.
    // On Windows: WinDivert or raw socket (IPPROTO_RAW).

    fn inject_tcp_rst(&self, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
        use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};

        let src4 = match src {
            IpAddr::V4(a) => a,
            _ => {
                debug!("🔌 RST: IPv6 RST not implemented — WFP enforces kernel drop");
                return;
            }
        };
        let dst4 = match dst {
            IpAddr::V4(a) => a,
            _ => return,
        };

        // Open a raw TCP transport channel (requires elevated privileges — already satisfied by Rudras)
        let proto = TransportChannelType::Layer4(
            TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp),
        );
        let (mut tx, _rx) = match transport_channel(1024, proto) {
            Ok(c) => c,
            Err(e) => {
                warn!("🔌 RST: Raw socket unavailable ({}) — WFP kernel block enforces denial", e);
                return;
            }
        };

        // Inject RST in both directions to tear down the connection on both endpoints
        let pairs = [(src4, dst4, sport, dport), (dst4, src4, dport, sport)];
        for (s, d, sp, dp) in pairs {
            let mut buf = [0u8; 20]; // TCP header only, no options
            let mut pkt = match MutableTcpPacket::new(&mut buf) {
                Some(p) => p,
                None => continue,
            };
            pkt.set_source(sp);
            pkt.set_destination(dp);
            pkt.set_sequence(0);
            pkt.set_acknowledgement(0);
            pkt.set_data_offset(5); // 5 × 4 = 20 bytes, no options
            pkt.set_flags(TcpFlags::RST | TcpFlags::ACK);
            pkt.set_window(0);
            pkt.set_urgent_ptr(0);
            let cksum = ipv4_checksum(&pkt.to_immutable(), &s, &d);
            pkt.set_checksum(cksum);
            if let Err(e) = tx.send_to(pkt.to_immutable(), IpAddr::V4(d)) {
                warn!("🔌 RST {}:{} → {}:{} inject failed: {}", s, sp, d, dp, e);
            }
        }

        debug!(
            "🔌 RST INJECTED: {}:{} ↔ {}:{} (bidirectional teardown)",
            src, sport, dst, dport
        );
    }

    // ── Management API ─────────────────────────────────────────────────────

    pub fn whitelist_ip(&self, ip: IpAddr, reason: &str) {
        info!("✅ IPS: Whitelisting {} — {}", ip, reason);
        self.whitelist.write().insert(ip);
        // Remove any existing penalty
        self.penalties.write().remove(&ip);
    }

    pub fn unblock_ip(&self, ip: IpAddr, reason: &str) {
        info!("🔓 IPS: Unblocking {} — {}", ip, reason);
        let mut penalties = self.penalties.write();
        if let Some(rec) = penalties.get_mut(&ip) {
            rec.score = 0.0;
            rec.is_blacklisted = false;
            rec.current_action = IpsAction::Monitor;
            rec.action_until = 0;
            rec.pps_limit = 0;
        }
        // Remove the WFP kernel block rule so packets are no longer dropped at kernel level
        self.wfp.unblock_ip(&ip);
        info!("🔷 WFP: Kernel block rule removed for {}", ip);
    }

    pub fn set_mode(&self, mode: IpsMode) {
        info!("🔄 IPS: Switching to {:?} mode", mode);
        self.config.write().mode = mode;
    }

    pub fn cleanup_expired(&self) {
        let now = unix_now();
        let mut penalties = self.penalties.write();
        penalties.retain(|ip, rec| {
            // Keep record but reset action if expired
            if !rec.is_blacklisted && rec.action_until > 0 && rec.action_until < now {
                debug!("⏰ IPS: Action expired for {}", ip);
                rec.current_action = IpsAction::Monitor;
                rec.action_until = 0;
                rec.pps_limit = 0;
            }
            // Remove stale entries with zero score
            rec.score > 0.1 || rec.is_blacklisted
        });
    }

    pub fn get_stats(&self) -> IpsStats {
        let penalties = self.penalties.read();
        let blocked_count = penalties
            .values()
            .filter(|r| {
                matches!(
                    r.current_action,
                    IpsAction::WfpBlock { .. }
                        | IpsAction::Quarantine { .. }
                        | IpsAction::Blacklist
                )
            })
            .count();

        IpsStats {
            mode: self.config.read().mode.clone(),
            decisions_total: self.decisions_total.load(Ordering::Relaxed),
            blocks_issued: self.blocks_issued.load(Ordering::Relaxed),
            resets_injected: self.resets_injected.load(Ordering::Relaxed),
            rate_limits_applied: self.rate_limits_applied.load(Ordering::Relaxed),
            quarantines_active: self.quarantines_active.load(Ordering::Relaxed),
            blacklists_total: self.blacklists_total.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            tracked_ips: penalties.len(),
            actively_blocked_ips: blocked_count,
        }
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsStats {
    pub mode: IpsMode,
    pub decisions_total: u64,
    pub blocks_issued: u64,
    pub resets_injected: u64,
    pub rate_limits_applied: u64,
    pub quarantines_active: u64,
    pub blacklists_total: u64,
    pub packets_dropped: u64,
    pub tracked_ips: usize,
    pub actively_blocked_ips: usize,
}

// ── Default whitelist (never block management IPs) ────────────────────────────

pub fn default_whitelist() -> Vec<String> {
    vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "0.0.0.0".to_string(),
    ]
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Millisecond timestamp — used by the token-bucket rate limiter
/// so per-packet throttling works within the same second.
fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
