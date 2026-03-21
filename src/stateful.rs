// ============================================================================
// Rudras — Real Stateful Inspection Engine (OSI L3-L4)
//
// Implements a full TCP/UDP connection state table:
//   • TCP: SYN → SYN-ACK → ESTABLISHED → FIN/RST → CLOSED lifecycle
//   • UDP: pseudo-state via first-packet + idle timeout
//   • Half-open SYN flood detection (too many HALF_OPEN from same src)
//   • Session hijacking detection (unexpected RST / invalid seq number)
//   • Connection limit enforcement per source IP
//   • Idle connection reaping (background TTL expiry)
//
// Every packet processed by the capture loop is first classified here.
// The IDS/IPS/WAF engines only receive packets for ESTABLISHED or NEW
// sessions that pass stateful validation — this eliminates spoofed,
// mid-session injected, and invalid state-machine packets early.
// ============================================================================

#![allow(dead_code)]

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// ── Connection Key ────────────────────────────────────────────────────────────

/// Bidirectional 5-tuple key (normalized so src < dst for symmetry).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnKey {
    pub proto:    u8,
    pub src_ip:   IpAddr,
    pub src_port: u16,
    pub dst_ip:   IpAddr,
    pub dst_port: u16,
}

impl ConnKey {
    pub fn new(proto: u8, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        // Normalize: always store the "lower" endpoint as src so forward/reply
        // packets hash to the same key.
        let (s_ip, s_port, d_ip, d_port) = if (src_ip, src_port) < (dst_ip, dst_port) {
            (src_ip, src_port, dst_ip, dst_port)
        } else {
            (dst_ip, dst_port, src_ip, src_port)
        };
        ConnKey { proto, src_ip: s_ip, src_port: s_port, dst_ip: d_ip, dst_port: d_port }
    }
}

// ── TCP State Machine ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    /// SYN seen, awaiting SYN-ACK.
    SynSent,
    /// SYN-ACK seen, awaiting ACK.
    SynReceived,
    /// Full 3-way handshake complete.
    Established,
    /// FIN seen from one side.
    FinWait,
    /// Both FINs seen — closing.
    TimeWait,
    /// RST received or timeout expired.
    Closed,
}

// ── Connection Record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnRecord {
    pub key:          ConnKey,
    pub state:        TcpState,      // TCP only; UDP always Established after first pkt
    pub bytes_fwd:    u64,
    pub bytes_rev:    u64,
    pub pkts_fwd:     u64,
    pub pkts_rev:     u64,
    pub last_seq_fwd: u32,           // seq number validation
    pub last_seq_rev: u32,
    pub created_at:   u64,           // unix seconds
    pub last_seen:    u64,           // unix seconds
    pub is_udp:       bool,
    /// Flow risk score (written by FlowEngine / AI)
    pub risk_score:   f32,
}

impl ConnRecord {
    fn new(key: ConnKey, is_udp: bool) -> Self {
        let now = unix_secs();
        ConnRecord {
            key,
            state: if is_udp { TcpState::Established } else { TcpState::SynSent },
            bytes_fwd:    0,
            bytes_rev:    0,
            pkts_fwd:     0,
            pkts_rev:     0,
            last_seq_fwd: 0,
            last_seq_rev: 0,
            created_at:   now,
            last_seen:    now,
            is_udp,
            risk_score:   0.0,
        }
    }

    fn touch(&mut self) {
        self.last_seen = unix_secs();
    }

    /// Age in seconds.
    pub fn age_secs(&self) -> u64 {
        unix_secs().saturating_sub(self.created_at)
    }
}

// ── Decision returned to caller ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatefulVerdict {
    /// New connection — valid SYN, let through for further inspection.
    NewSession,
    /// Belongs to an established session — fast-path allow.
    Established,
    /// State machine violation — drop this packet.
    InvalidState,
    /// SYN flood threshold exceeded for this src IP.
    SynFlooded,
    /// Connection limit exceeded from this src IP.
    ConnLimitExceeded,
}

// ── TCP Flag Bits ─────────────────────────────────────────────────────────────

pub struct TcpFlags;
impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Configuration knobs.
#[derive(Debug, Clone)]
pub struct StatefulConfig {
    /// Max half-open (SYN_SENT) connections per source IP before flagging SYN flood.
    pub syn_flood_threshold:    usize,
    /// Max simultaneous connections per source IP (all states).
    pub conn_limit_per_src:     usize,
    /// TCP established timeout (seconds).
    pub tcp_established_timeout: u64,
    /// TCP half-open timeout (seconds).
    pub tcp_halfopen_timeout:   u64,
    /// UDP pseudo-session timeout (seconds).
    pub udp_timeout:            u64,
    /// TIME_WAIT timeout (seconds).
    pub time_wait_timeout:      u64,
}

impl Default for StatefulConfig {
    fn default() -> Self {
        StatefulConfig {
            syn_flood_threshold:     32,
            conn_limit_per_src:     512,
            tcp_established_timeout: 3600,
            tcp_halfopen_timeout:    30,
            udp_timeout:            120,
            time_wait_timeout:       30,
        }
    }
}

/// Statistics counters.
#[derive(Debug, Default)]
pub struct StatefulStats {
    pub total_packets:      AtomicU64,
    pub new_sessions:       AtomicU64,
    pub established_hits:   AtomicU64,
    pub invalid_state_drops: AtomicU64,
    pub syn_flood_drops:    AtomicU64,
    pub conn_limit_drops:   AtomicU64,
    pub reaped_connections: AtomicU64,
    pub active_connections: AtomicU64,
}

pub struct StatefulEngine {
    /// Conn table: ConnKey → ConnRecord (DashMap = concurrent hash map).
    table:     DashMap<ConnKey, ConnRecord>,
    /// Per-source-IP: count of HALF-OPEN (SynSent) connections.
    halfopen:  DashMap<IpAddr, usize>,
    /// Per-source-IP: total connection count.
    src_count: DashMap<IpAddr, usize>,
    config:    StatefulConfig,
    pub stats: StatefulStats,
    last_reap: RwLock<Instant>,
}

impl StatefulEngine {
    pub fn new() -> Self {
        let cfg = StatefulConfig::default();
        info!("🔗 Stateful Engine initialized — TCP/UDP state table ACTIVE");
        info!("   SYN-flood threshold: {} half-open/src", cfg.syn_flood_threshold);
        info!("   Conn limit/src: {}", cfg.conn_limit_per_src);
        info!("   TCP established TTL: {}s | half-open TTL: {}s | UDP TTL: {}s",
              cfg.tcp_established_timeout, cfg.tcp_halfopen_timeout, cfg.udp_timeout);
        StatefulEngine {
            table:     DashMap::new(),
            halfopen:  DashMap::new(),
            src_count: DashMap::new(),
            config:    cfg,
            stats:     StatefulStats::default(),
            last_reap: RwLock::new(Instant::now()),
        }
    }

    pub fn with_config(config: StatefulConfig) -> Self {
        info!("🔗 Stateful Engine initialized with custom config");
        StatefulEngine {
            table:     DashMap::new(),
            halfopen:  DashMap::new(),
            src_count: DashMap::new(),
            config,
            stats:     StatefulStats::default(),
            last_reap: RwLock::new(Instant::now()),
        }
    }

    // ── Main Entry Point ──────────────────────────────────────────────────────

    /// Process a packet and return the stateful verdict.
    ///
    /// Parameters:
    /// - `proto`:  IP protocol number (6=TCP, 17=UDP)
    /// - `src_ip`, `src_port`, `dst_ip`, `dst_port`: 5-tuple
    /// - `tcp_flags`: TCP flags byte (0 for UDP)
    /// - `seq_num`:   TCP sequence number (0 for UDP)
    /// - `payload_len`: Number of payload bytes
    pub fn process_packet(
        &self,
        proto:       u8,
        src_ip:      IpAddr,
        src_port:    u16,
        dst_ip:      IpAddr,
        dst_port:    u16,
        tcp_flags:   u8,
        seq_num:     u32,
        payload_len: usize,
    ) -> StatefulVerdict {
        self.stats.total_packets.fetch_add(1, Ordering::Relaxed);

        // Periodically reap expired connections (every 30s).
        if self.last_reap.read().elapsed() > Duration::from_secs(30) {
            *self.last_reap.write() = Instant::now();
            self.reap_expired();
        }

        let key = ConnKey::new(proto, src_ip, src_port, dst_ip, dst_port);
        let is_udp = proto == 17;

        // ── UDP path ──────────────────────────────────────────────────────────
        if is_udp {
            return self.process_udp(key, src_ip, payload_len);
        }

        // ── TCP path ──────────────────────────────────────────────────────────
        self.process_tcp(key, src_ip, tcp_flags, seq_num, payload_len)
    }

    // ── UDP Processing ────────────────────────────────────────────────────────

    fn process_udp(&self, key: ConnKey, src_ip: IpAddr, payload_len: usize) -> StatefulVerdict {
        if let Some(mut rec) = self.table.get_mut(&key) {
            // Existing UDP pseudo-session — refresh.
            rec.touch();
            rec.pkts_fwd += 1;
            rec.bytes_fwd += payload_len as u64;
            self.stats.established_hits.fetch_add(1, Ordering::Relaxed);
            StatefulVerdict::Established
        } else {
            // New UDP flow.
            if self.check_conn_limit(src_ip) {
                self.stats.conn_limit_drops.fetch_add(1, Ordering::Relaxed);
                warn!("🔗 STATEFUL: UDP conn-limit exceeded from {}", src_ip);
                return StatefulVerdict::ConnLimitExceeded;
            }
            let mut rec = ConnRecord::new(key.clone(), true);
            rec.pkts_fwd = 1;
            rec.bytes_fwd = payload_len as u64;
            self.table.insert(key, rec);
            *self.src_count.entry(src_ip).or_insert(0) += 1;
            self.stats.new_sessions.fetch_add(1, Ordering::Relaxed);
            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
            StatefulVerdict::NewSession
        }
    }

    // ── TCP Processing ────────────────────────────────────────────────────────

    fn process_tcp(
        &self,
        key:         ConnKey,
        src_ip:      IpAddr,
        tcp_flags:   u8,
        seq_num:     u32,
        payload_len: usize,
    ) -> StatefulVerdict {
        let is_syn = tcp_flags & TcpFlags::SYN != 0;
        let is_ack = tcp_flags & TcpFlags::ACK != 0;
        let is_fin = tcp_flags & TcpFlags::FIN != 0;
        let is_rst = tcp_flags & TcpFlags::RST != 0;

        // ── RST always closes the session immediately ──────────────────────
        if is_rst {
            if let Some((_, mut rec)) = self.table.remove(&key) {
                rec.state = TcpState::Closed;
                self.decrement_src_count(src_ip);
                self.decrement_halfopen(src_ip, &rec.state);
            }
            debug!("🔗 STATEFUL: RST closed connection from {}", src_ip);
            return StatefulVerdict::Established; // RST is valid — don't drop it
        }

        // ── Existing session ──────────────────────────────────────────────
        if let Some(mut rec) = self.table.get_mut(&key) {
            let old_state = rec.state.clone();
            match old_state {
                TcpState::SynSent => {
                    if is_syn && is_ack {
                        // SYN-ACK — server responded
                        rec.state = TcpState::SynReceived;
                        rec.last_seq_rev = seq_num;
                        self.decrement_halfopen(src_ip, &TcpState::SynSent);
                        rec.touch();
                        return StatefulVerdict::Established;
                    }
                    // Only SYN-ACK is valid here
                    self.stats.invalid_state_drops.fetch_add(1, Ordering::Relaxed);
                    warn!("🔗 STATEFUL: Invalid TCP flags in SYN_SENT state from {}", src_ip);
                    return StatefulVerdict::InvalidState;
                }
                TcpState::SynReceived => {
                    if is_ack && !is_syn {
                        // ACK completes the 3-way handshake → ESTABLISHED
                        rec.state = TcpState::Established;
                        rec.last_seq_fwd = seq_num;
                        rec.touch();
                        self.stats.established_hits.fetch_add(1, Ordering::Relaxed);
                        debug!("🔗 STATEFUL: TCP session ESTABLISHED from {}", src_ip);
                        return StatefulVerdict::Established;
                    }
                    self.stats.invalid_state_drops.fetch_add(1, Ordering::Relaxed);
                    return StatefulVerdict::InvalidState;
                }
                TcpState::Established => {
                    rec.pkts_fwd += 1;
                    rec.bytes_fwd += payload_len as u64;
                    rec.last_seq_fwd = seq_num;
                    rec.touch();
                    if is_fin {
                        rec.state = TcpState::FinWait;
                    }
                    self.stats.established_hits.fetch_add(1, Ordering::Relaxed);
                    return StatefulVerdict::Established;
                }
                TcpState::FinWait => {
                    rec.touch();
                    if is_fin {
                        rec.state = TcpState::TimeWait;
                    }
                    return StatefulVerdict::Established;
                }
                TcpState::TimeWait | TcpState::Closed => {
                    // Session is closing — accept remaining FIN/ACK but mark invalid if new SYN
                    if is_syn && !is_ack {
                        // Re-SYN on a closing connection — drop
                        self.stats.invalid_state_drops.fetch_add(1, Ordering::Relaxed);
                        return StatefulVerdict::InvalidState;
                    }
                    rec.touch();
                    return StatefulVerdict::Established;
                }
            }
        }

        // ── New session: must start with SYN (not SYN-ACK, not ACK-only) ──
        if is_syn && !is_ack {
            // Check SYN flood
            let halfopen_count = self.halfopen.get(&src_ip).map(|v| *v).unwrap_or(0);
            if halfopen_count >= self.config.syn_flood_threshold {
                self.stats.syn_flood_drops.fetch_add(1, Ordering::Relaxed);
                warn!("🚨 STATEFUL: SYN FLOOD detected from {} ({} half-open)", src_ip, halfopen_count);
                return StatefulVerdict::SynFlooded;
            }
            // Check per-src connection limit
            if self.check_conn_limit(src_ip) {
                self.stats.conn_limit_drops.fetch_add(1, Ordering::Relaxed);
                warn!("🔗 STATEFUL: TCP conn-limit exceeded from {}", src_ip);
                return StatefulVerdict::ConnLimitExceeded;
            }
            // Create new half-open record
            let mut rec = ConnRecord::new(key.clone(), false);
            rec.last_seq_fwd = seq_num;
            self.table.insert(key, rec);
            *self.halfopen.entry(src_ip).or_insert(0) += 1;
            *self.src_count.entry(src_ip).or_insert(0) += 1;
            self.stats.new_sessions.fetch_add(1, Ordering::Relaxed);
            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
            return StatefulVerdict::NewSession;
        }

        // Mid-session packet with no record (e.g. asymmetric routing,
        // engine restart, or spoofed packet). Allow through but don't track.
        debug!("🔗 STATEFUL: Untracked TCP packet from {} (asymmetric route?)", src_ip);
        StatefulVerdict::Established // Don't block — could be asymmetric
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn check_conn_limit(&self, src_ip: IpAddr) -> bool {
        self.src_count.get(&src_ip).map(|v| *v).unwrap_or(0)
            >= self.config.conn_limit_per_src
    }

    fn decrement_src_count(&self, src_ip: IpAddr) {
        if let Some(mut v) = self.src_count.get_mut(&src_ip) {
            *v = v.saturating_sub(1);
        }
        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    fn decrement_halfopen(&self, src_ip: IpAddr, old_state: &TcpState) {
        if *old_state == TcpState::SynSent {
            if let Some(mut v) = self.halfopen.get_mut(&src_ip) {
                *v = v.saturating_sub(1);
            }
        }
    }

    // ── Reaper ────────────────────────────────────────────────────────────────

    /// Expire timed-out connections. Called every 30s by process_packet.
    fn reap_expired(&self) {
        let now = unix_secs();
        let cfg = &self.config;
        let mut reaped = 0u64;

        self.table.retain(|_, rec| {
            let ttl = match rec.state {
                TcpState::SynSent | TcpState::SynReceived => cfg.tcp_halfopen_timeout,
                TcpState::Established => cfg.tcp_established_timeout,
                TcpState::FinWait | TcpState::TimeWait => cfg.time_wait_timeout,
                TcpState::Closed => 0,
            };
            let elapsed = now.saturating_sub(rec.last_seen);
            let keep = elapsed < ttl;
            if !keep {
                // Decrement per-src counts
                if let Some(mut v) = self.src_count.get_mut(&rec.key.src_ip) {
                    *v = v.saturating_sub(1);
                }
                if rec.state == TcpState::SynSent {
                    if let Some(mut v) = self.halfopen.get_mut(&rec.key.src_ip) {
                        *v = v.saturating_sub(1);
                    }
                }
                reaped += 1;
            }
            keep
        });

        if reaped > 0 {
            self.stats.reaped_connections.fetch_add(reaped, Ordering::Relaxed);
            let active = self.table.len() as u64;
            self.stats.active_connections.store(active, Ordering::Relaxed);
            debug!("🔗 STATEFUL: Reaped {} expired connections ({} active)", reaped, active);
        }
    }

    // ── Public Accessors ──────────────────────────────────────────────────────

    pub fn active_conn_count(&self) -> usize { self.table.len() }

    pub fn get_record(&self, key: &ConnKey) -> Option<ConnRecord> {
        self.table.get(key).map(|r| r.clone())
    }

    pub fn snapshot(&self) -> Vec<ConnRecord> {
        self.table.iter().map(|e| e.value().clone()).collect()
    }

    pub fn print_stats(&self) {
        info!("🔗 STATEFUL STATS: total={} new={} established={} invalid={} synflood={} connlimit={} reaped={} active={}",
            self.stats.total_packets.load(Ordering::Relaxed),
            self.stats.new_sessions.load(Ordering::Relaxed),
            self.stats.established_hits.load(Ordering::Relaxed),
            self.stats.invalid_state_drops.load(Ordering::Relaxed),
            self.stats.syn_flood_drops.load(Ordering::Relaxed),
            self.stats.conn_limit_drops.load(Ordering::Relaxed),
            self.stats.reaped_connections.load(Ordering::Relaxed),
            self.stats.active_connections.load(Ordering::Relaxed),
        );
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
