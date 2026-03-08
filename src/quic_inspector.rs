// ============================================================================
// Rudras — QUIC / HTTP3 Inspector
//
// QUIC (RFC 9000) uses UDP with its own transport-layer encryption (QUIC TLS).
// Traditional network inspection cannot see inside QUIC payloads; however
// the unencrypted long-header Initial packets expose connection metadata
// (DCID, SCID, token) which enables:
//
//   • Version fingerprinting (spec vs. proprietary vs. unknown)
//   • Connection migration detection (potential QUIC-based NAT traversal evasion)
//   • 0-RTT replay attempt detection (Early Data replay risk)
//   • Excessive handshake retry amplification (DoS vector)
//   • Covert channel detection via QUIC PADDING frame abuse
//   • SNI extraction from QUIC Client Hello (crypto stream frame 0)
//
// All analysis is purely observational (passive) — no packet modification.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── QUIC Versions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicVersion {
    /// RFC 9000 — standard QUIC v1
    V1,
    /// QUIC v2 (RFC 9369)
    V2,
    /// QUIC force-negotiation probe packet (version 0x00000000)
    VersionNegotiation,
    /// Facebook MvFST / Google GQUIC / Microsoft MsQuic proprietary draft
    Draft(u32),
    /// Unknown version — potential exploit or new protocol
    Unknown(u32),
}

impl QuicVersion {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x00000001 => Self::V1,
            0x6b3343cf => Self::V2,
            0x00000000 => Self::VersionNegotiation,
            0xff000000..=0xff00001d => Self::Draft((v & 0xFF) as u32),
            _ => Self::Unknown(v),
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::V1 | Self::V2 | Self::Draft(_))
    }
}

// ── Alert Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuicAlertType {
    /// QUIC version not in known-good list — potential exploit or Tor-over-QUIC
    UnknownVersion { version: u32 },
    /// Client changed source IP/port mid-connection (RFC 9000 §9) — evasion risk
    ConnectionMigration { old_ip: IpAddr, new_ip: IpAddr, cid: String },
    /// Client sent Early Data (0-RTT) — possible replay attack
    ZeroRttEarlyData { sni: Option<String> },
    /// More than N INITIAL packets from same IP in short window — retry amplification
    ExcessiveHandshakeRetry { count: u32 },
    /// SNI in QUIC matches known C2/malware host
    MaliciousSni { sni: String, reason: String },
    /// Suspiciously large PADDING frames — covert channel heuristic
    PaddingAbuse { padding_ratio: f64 },
    /// QUIC connection drained unexpectedly without proper FIN — potential tunnel teardown
    AbnormalConnectionDrain { cid: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicAlert {
    pub id: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub alert_type: QuicAlertType,
    pub severity: AlertSeverity,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity { Low, Medium, High, Critical }

// ── QUIC Long Header Parser ───────────────────────────────────────────────────

/// Parsed representation of a QUIC Long Header packet.
/// Long headers are used for Initial, 0-RTT, Handshake, and Retry packets.
/// The Initial packet is the only one with unencrypted metadata visible
/// before QUIC-TLS key exchange completes.
#[derive(Debug, Clone)]
pub struct QuicLongHeader {
    pub version: QuicVersion,
    pub packet_type: QuicPacketType,
    /// Destination Connection ID (chosen by server)
    pub dcid: Vec<u8>,
    /// Source Connection ID (chosen by client)
    pub scid: Vec<u8>,
    /// Token field (present in Initial packets for retry validation)
    pub token: Vec<u8>,
    /// Whether the packet has the QUIC Early Data (0-RTT) type bit set
    pub is_zero_rtt: bool,
    /// Total payload length
    pub payload_len: usize,
    /// Raw padding byte count (estimated)
    pub padding_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short, // short header (encrypted data)
}

/// Attempt to parse a QUIC long header from a UDP payload.
/// Returns None if the payload is too short or not a QUIC long header.
pub fn parse_quic_long_header(data: &[u8]) -> Option<QuicLongHeader> {
    if data.len() < 7 { return None; }

    let first_byte = data[0];

    // Must have Header Form bit (bit 7) set for Long Header
    if first_byte & 0x80 == 0 { return None; }
    // Fixed bit (bit 6) must be set (QUIC invariant)
    if first_byte & 0x40 == 0 { return None; }

    // Bytes 1–4: version
    let version_u32 = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let version = QuicVersion::from_u32(version_u32);

    // Version negotiation has special format
    if version == QuicVersion::VersionNegotiation {
        return Some(QuicLongHeader {
            version, packet_type: QuicPacketType::Initial,
            dcid: vec![], scid: vec![], token: vec![],
            is_zero_rtt: false, payload_len: 0, padding_bytes: 0,
        });
    }

    // Packet type from Long Header Type (bits 4–5)
    let packet_type = match (first_byte & 0x30) >> 4 {
        0x00 => QuicPacketType::Initial,
        0x01 => QuicPacketType::ZeroRtt,
        0x02 => QuicPacketType::Handshake,
        0x03 => QuicPacketType::Retry,
        _    => QuicPacketType::Initial,
    };

    let is_zero_rtt = packet_type == QuicPacketType::ZeroRtt;

    // DCID length at byte 5
    let mut pos = 5usize;
    if pos >= data.len() { return None; }
    let dcid_len = data[pos] as usize;
    pos += 1;

    if pos + dcid_len > data.len() { return None; }
    let dcid = data[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // SCID length
    if pos >= data.len() { return None; }
    let scid_len = data[pos] as usize;
    pos += 1;

    if pos + scid_len > data.len() { return None; }
    let scid = data[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Token (Initial packets only)
    let mut token = vec![];
    if packet_type == QuicPacketType::Initial {
        if pos < data.len() {
            let token_len = data[pos] as usize & 0x3F; // variable-length encoding (simplified)
            pos += 1;
            if pos + token_len <= data.len() {
                token = data[pos..pos + token_len].to_vec();
                pos += token_len;
            }
        }
    }

    let remaining = data.len().saturating_sub(pos);

    // Estimate padding: count trailing zero bytes in remainder
    let padding = data[pos..].iter().rev().take_while(|&&b| b == 0).count();

    Some(QuicLongHeader {
        version, packet_type,
        dcid, scid, token,
        is_zero_rtt, payload_len: remaining,
        padding_bytes: padding,
    })
}

/// Extract SNI from QUIC Initial packet's crypto stream.
/// Real extraction requires QUIC packet number decryption and TLS record
/// parsing — this is a best-effort heuristic that scans for TLS ClientHello
/// SNI extension bytes in the Initial payload without full decryption.
pub fn extract_sni_heuristic(data: &[u8]) -> Option<String> {
    // Look for TLS 0x00 0x00 (SNI extension type) followed by server_name_list
    // This is a heuristic for unencrypted portions; QUIC Initial packets are
    // encrypted with the QUIC Initial secret derived from DCID (RFC 9001 §5.2).
    // This heuristic only works if run BEFORE TLS layer encryption (rare edge case).
    const SNI_EXT_TYPE: &[u8] = &[0x00, 0x00, 0x00]; // type=0 (SNI), list type=0 (host_name)
    for window in data.windows(5) {
        if window[0] == 0x00 && window[1] == 0x00 && window[2] == 0x00 {
            // Found potential SNI extension — try to read the length and hostname
            // Not reliable without full decryption; bail out
            break;
        }
    }

    // Alternative: scan for printable ASCII sequences that look like domains
    let mut best: Option<String> = None;
    let mut run = String::new();
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
            run.push(b as char);
        } else {
            if run.len() >= 6 && run.contains('.') && run.matches('.').count() >= 1 {
                let candidate = run.clone();
                if best.as_ref().map(|s: &String| candidate.len() > s.len()).unwrap_or(true) {
                    best = Some(candidate);
                }
            }
            run.clear();
        }
    }
    best
}

// ── Connection State Tracker ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct QuicConnectionState {
    dcid_hex: String,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    first_seen: u64,
    last_seen: u64,
    total_packets: u32,
    initial_count: u32,
    zero_rtt_seen: bool,
    migrated: bool,
    sni: Option<String>,
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicStats {
    pub packets_inspected: u64,
    pub short_headers_skipped: u64,
    pub long_headers_parsed: u64,
    pub connections_tracked: usize,
    pub alerts_generated: u64,
    pub zero_rtt_count: u64,
    pub migration_count: u64,
    pub unknown_version_count: u64,
}

// ── QUIC Inspector ────────────────────────────────────────────────────────────

pub struct QuicInspector {
    connections: RwLock<HashMap<String, QuicConnectionState>>,
    /// IP → count of Initial packets in current window (for retry flood)
    initial_counter: RwLock<HashMap<IpAddr, (u32, u64)>>,
    alerts: RwLock<VecDeque<QuicAlert>>,
    pkts_inspected: AtomicU64,
    pkts_short: AtomicU64,
    pkts_long: AtomicU64,
    alert_count: AtomicU64,
    zero_rtt_count: AtomicU64,
    migration_count: AtomicU64,
    unknown_ver_count: AtomicU64,
    seq: AtomicU64,
    /// Blocked SNI patterns (loaded from threat intelligence)
    blocked_sni: RwLock<Vec<String>>,
    /// Max initial packets per IP per 10s before alerting
    initial_flood_threshold: u32,
}

impl QuicInspector {
    pub fn new() -> Self {
        let engine = Self {
            connections: RwLock::new(HashMap::new()),
            initial_counter: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::with_capacity(256)),
            pkts_inspected: AtomicU64::new(0),
            pkts_short: AtomicU64::new(0),
            pkts_long: AtomicU64::new(0),
            alert_count: AtomicU64::new(0),
            zero_rtt_count: AtomicU64::new(0),
            migration_count: AtomicU64::new(0),
            unknown_ver_count: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            blocked_sni: RwLock::new(vec![]),
            initial_flood_threshold: 20,
        };
        info!("🔍 QUIC/HTTP3 Inspector initialized");
        engine
    }

    fn next_id(&self) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("QUIC-{}-{}", unix_secs(), n)
    }

    fn push_alert(&self, alert: QuicAlert) {
        warn!("🔍 QUIC alert: {:?} from {}:{}", alert.alert_type, alert.src_ip, alert.src_port);
        self.alert_count.fetch_add(1, Ordering::Relaxed);
        let mut q = self.alerts.write();
        if q.len() >= 256 { q.pop_front(); }
        q.push_back(alert);
    }

    pub fn add_blocked_sni(&self, sni: &str) {
        self.blocked_sni.write().push(sni.to_lowercase());
    }

    /// Inspect a UDP payload for QUIC traffic.
    pub fn inspect_udp_payload(
        &self,
        src_ip: IpAddr, src_port: u16,
        dst_ip: IpAddr, dst_port: u16,
        data: &[u8],
    ) -> Vec<QuicAlert> {
        self.pkts_inspected.fetch_add(1, Ordering::Relaxed);
        let mut generated = Vec::new();

        // Quick check: QUIC uses well-known destination ports 443 and 80 (and others)
        // But QUIC can run on any UDP port — check the header bit instead.
        if data.is_empty() { return generated; }

        // Short header check (bit 7 = 0 means short header — encrypted data flow)
        if data[0] & 0x80 == 0 {
            self.pkts_short.fetch_add(1, Ordering::Relaxed);
            return generated; // can't inspect encrypted payload
        }

        // Also need Fixed bit (bit 6) set
        if data[0] & 0x40 == 0 { return generated; }

        let header = match parse_quic_long_header(data) {
            Some(h) => h,
            None => return generated,
        };

        self.pkts_long.fetch_add(1, Ordering::Relaxed);

        // ── 1. Unknown Version Alert ─────────────────────────────────────────
        if !header.version.is_known() {
            if let QuicVersion::Unknown(v) = header.version {
                self.unknown_ver_count.fetch_add(1, Ordering::Relaxed);
                let alert = QuicAlert {
                    id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                    alert_type: QuicAlertType::UnknownVersion { version: v },
                    severity: AlertSeverity::Medium,
                    timestamp: unix_secs(),
                };
                self.push_alert(alert.clone());
                generated.push(alert);
            }
        }

        // ── 2. 0-RTT Early Data Alert ────────────────────────────────────────
        if header.is_zero_rtt {
            self.zero_rtt_count.fetch_add(1, Ordering::Relaxed);
            let sni = extract_sni_heuristic(data);
            let alert = QuicAlert {
                id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                alert_type: QuicAlertType::ZeroRttEarlyData { sni: sni.clone() },
                severity: AlertSeverity::Medium,
                timestamp: unix_secs(),
            };
            self.push_alert(alert.clone());
            generated.push(alert);
        }

        // ── 3. Excessive Handshake Retry (Initial flood) ─────────────────────
        if header.packet_type == QuicPacketType::Initial {
            let mut counter = self.initial_counter.write();
            let now = unix_secs();
            let entry = counter.entry(src_ip).or_insert((0, now));
            if now - entry.1 > 10 {
                *entry = (1, now); // reset window
            } else {
                entry.0 += 1;
                if entry.0 == self.initial_flood_threshold {
                    let alert = QuicAlert {
                        id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                        alert_type: QuicAlertType::ExcessiveHandshakeRetry { count: entry.0 },
                        severity: AlertSeverity::High,
                        timestamp: now,
                    };
                    self.push_alert(alert.clone());
                    generated.push(alert);
                }
            }
        }

        // ── 4. Connection Migration ───────────────────────────────────────────
        let dcid_hex = hex::encode(&header.dcid);
        {
            let mut conns = self.connections.write();
            if let Some(state) = conns.get_mut(&dcid_hex) {
                if state.src_ip != src_ip && !state.migrated {
                    state.migrated = true;
                    self.migration_count.fetch_add(1, Ordering::Relaxed);
                    let alert = QuicAlert {
                        id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                        alert_type: QuicAlertType::ConnectionMigration {
                            old_ip: state.src_ip,
                            new_ip: src_ip,
                            cid: dcid_hex.clone(),
                        },
                        severity: AlertSeverity::Medium,
                        timestamp: unix_secs(),
                    };
                    self.push_alert(alert.clone());
                    generated.push(alert);
                }
                state.src_ip = src_ip;
                state.src_port = src_port;
                state.last_seen = unix_secs();
                state.total_packets += 1;
                if header.packet_type == QuicPacketType::Initial {
                    state.initial_count += 1;
                }
            } else {
                let sni = extract_sni_heuristic(data);
                conns.insert(dcid_hex.clone(), QuicConnectionState {
                    dcid_hex: dcid_hex.clone(),
                    src_ip, src_port, dst_ip, dst_port,
                    first_seen: unix_secs(), last_seen: unix_secs(),
                    total_packets: 1, initial_count: 1,
                    zero_rtt_seen: header.is_zero_rtt,
                    migrated: false, sni: sni.clone(),
                });

                // ── 5. Malicious SNI check ────────────────────────────────────
                if let Some(ref sni_str) = sni {
                    let blocked = self.blocked_sni.read();
                    for pattern in blocked.iter() {
                        if sni_str.to_lowercase().contains(pattern.as_str()) {
                            let alert = QuicAlert {
                                id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                                alert_type: QuicAlertType::MaliciousSni {
                                    sni: sni_str.clone(),
                                    reason: format!("matches blocked pattern '{}'", pattern),
                                },
                                severity: AlertSeverity::High,
                                timestamp: unix_secs(),
                            };
                            self.push_alert(alert.clone());
                            generated.push(alert);
                            break;
                        }
                    }
                }
            }
        }

        // ── 6. Padding Abuse ─────────────────────────────────────────────────
        if header.payload_len > 64 {
            let ratio = header.padding_bytes as f64 / header.payload_len as f64;
            if ratio > 0.60 {
                let alert = QuicAlert {
                    id: self.next_id(), src_ip, src_port, dst_ip, dst_port,
                    alert_type: QuicAlertType::PaddingAbuse { padding_ratio: ratio },
                    severity: AlertSeverity::Low,
                    timestamp: unix_secs(),
                };
                self.push_alert(alert.clone());
                generated.push(alert);
            }
        }

        generated
    }

    /// Clean up stale connections (last seen > 120 seconds ago).
    pub fn cleanup(&self) {
        let now = unix_secs();
        self.connections.write().retain(|_, v| now - v.last_seen < 120);
        self.initial_counter.write().retain(|_, v| now - v.1 < 60);
    }

    pub fn drain_alerts(&self) -> Vec<QuicAlert> {
        self.alerts.write().drain(..).collect()
    }

    pub fn stats(&self) -> QuicStats {
        QuicStats {
            packets_inspected: self.pkts_inspected.load(Ordering::Relaxed),
            short_headers_skipped: self.pkts_short.load(Ordering::Relaxed),
            long_headers_parsed: self.pkts_long.load(Ordering::Relaxed),
            connections_tracked: self.connections.read().len(),
            alerts_generated: self.alert_count.load(Ordering::Relaxed),
            zero_rtt_count: self.zero_rtt_count.load(Ordering::Relaxed),
            migration_count: self.migration_count.load(Ordering::Relaxed),
            unknown_version_count: self.unknown_ver_count.load(Ordering::Relaxed),
        }
    }
}
