// Rudras Micro-Segmentation Engine — Zone-based network isolation
// FULL ENFORCEMENT: evaluate_traffic() now enforces zone policy, NOT always-allow.
// Implements East-West lateral movement prevention via zone isolation rules.
#![allow(dead_code, unused_imports, unused_variables)]

use ipnetwork::IpNetwork as IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Only explicitly allowed zone-to-zone traffic passes; all else blocked
    Strict,
    /// Cross-zone traffic is allowed unless explicit deny rule exists
    Moderate,
    /// Log cross-zone traffic but do not block
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityZone {
    pub name: String,
    pub description: String,
    pub networks: Vec<IpNet>,
    pub isolation: IsolationLevel,
    pub allowed_zones: Vec<String>,
    /// Specific ports allowed into this zone (None = all allowed for allowed_zones)
    pub allowed_ports: Option<Vec<u16>>,
}

impl SecurityZone {
    pub fn new(name: &str, networks: Vec<&str>, isolation: IsolationLevel) -> anyhow::Result<Self> {
        let nets = networks.iter()
            .filter_map(|n| n.parse().ok())
            .collect();
        Ok(Self {
            name: name.to_string(),
            description: String::new(),
            networks: nets,
            isolation,
            allowed_zones: vec![],
            allowed_ports: None,
        })
    }
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string(); self
    }
    pub fn allow_zone(mut self, zone: &str) -> Self {
        self.allowed_zones.push(zone.to_string()); self
    }
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = Some(ports); self
    }

    /// Returns true if this IP belongs to this zone
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(*ip))
    }
}

// ── Segmentation Policy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationPolicy {
    pub src_zone: String,
    pub dst_zone: String,
    pub allowed_ports: Vec<u16>,   // empty = all ports
    pub allowed_protocols: Vec<String>, // "tcp","udp","icmp","any"
    pub action: SegmentAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SegmentAction { Allow, Deny, Inspect }

// ── Traffic Verdict ───────────────────────────────────────────────────────────

pub struct TrafficVerdict {
    pub allowed: bool,
    pub reason: String,
    pub src_zone: Option<String>,
    pub dst_zone: Option<String>,
    pub action: SegmentAction,
}

// ── Lateral Movement Detection ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementAlert {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub technique: LateralTechnique,
    pub timestamp: u64,
    pub zone_hop: bool, // True if traffic crosses zone boundaries
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LateralTechnique {
    PsExec,          // TCP 445, PSEXESVC pattern
    WmiExecution,    // TCP 135 (RPC), WMI calls
    RdpSession,      // TCP 3389
    SmbFileAccess,   // TCP 445, C$, ADMIN$
    WinRm,           // TCP 5985/5986
    SshTunnel,       // TCP 22 from non-admin zone
    DcomRpc,         // TCP 135 DCOM
    NetLogon,        // TCP 445 NetLogon
    KerberosAbuse,   // Kerberoasting, Pass-the-Ticket
}

// ── Connection Graph (for zone hop tracking) ──────────────────────────────────

#[derive(Debug, Default)]
struct ConnectionTracker {
    /// src_ip -> set of (dst_ip, dst_port, timestamp) in last 300s
    recent_connections: HashMap<IpAddr, VecDeque<(IpAddr, u16, u64)>>,
}

impl ConnectionTracker {
    fn record(&mut self, src: IpAddr, dst: IpAddr, port: u16) {
        let now = unix_now();
        let entry = self.recent_connections.entry(src).or_default();
        // Evict connections older than 300 seconds
        while entry.front().is_some_and(|(_, _, t)| now - t > 300) {
            entry.pop_front();
        }
        entry.push_back((dst, port, now));
    }

    fn unique_destinations(&self, src: &IpAddr) -> usize {
        self.recent_connections.get(src)
            .map(|q| q.iter().map(|(dst, _, _)| dst).cloned().collect::<HashSet<_>>().len())
            .unwrap_or(0)
    }
}

// ── Micro-Segmentation Engine ─────────────────────────────────────────────────

pub struct MicroSegmentationEngine {
    enabled: bool,
    zones: Vec<SecurityZone>,
    policies: Vec<SegmentationPolicy>,
    conn_tracker: RwLock<ConnectionTracker>,
    // Stats
    total_evaluated: AtomicU64,
    total_blocked: AtomicU64,
    total_allowed: AtomicU64,
    lateral_alerts_generated: AtomicU64,
}

impl MicroSegmentationEngine {
    pub fn new() -> Self {
        Self {
            enabled: false,
            zones: vec![],
            policies: vec![],
            conn_tracker: RwLock::new(ConnectionTracker::default()),
            total_evaluated: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            lateral_alerts_generated: AtomicU64::new(0),
        }
    }

    pub fn load_zones(&mut self, zones: Vec<SecurityZone>) {
        self.zones = zones;
    }

    pub fn load_policies(&mut self, policies: Vec<SegmentationPolicy>) {
        self.policies = policies;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Resolve which zone an IP belongs to; returns None if not in any zone
    pub fn zone_for_ip(&self, ip: &IpAddr) -> Option<&SecurityZone> {
        self.zones.iter().find(|z| z.contains_ip(ip))
    }

    /// FULLY ENFORCED: evaluate whether traffic from src→dst:port is permitted.
    /// In strict zones, traffic is DENIED unless dst_zone is in src_zone.allowed_zones.
    /// In moderate zones, traffic is ALLOWED unless a deny policy exists.
    pub fn evaluate_traffic(
        &self,
        src: &IpAddr,
        dst: &IpAddr,
        port: u16,
        proto: &str,
    ) -> TrafficVerdict {
        // Record connection for lateral movement tracking
        {
            let mut tracker = self.conn_tracker.write();
            tracker.record(*src, *dst, port);
        }

        self.total_evaluated.fetch_add(1, Ordering::Relaxed);

        // If segmentation is disabled, allow everything (monitor only)
        if !self.enabled {
            return TrafficVerdict {
                allowed: true,
                reason: "Segmentation disabled — monitor only".to_string(),
                src_zone: None,
                dst_zone: None,
                action: SegmentAction::Allow,
            };
        }

        let src_zone = self.zone_for_ip(src);
        let dst_zone = self.zone_for_ip(dst);

        // Traffic between same zone is always allowed
        if let (Some(sz), Some(dz)) = (src_zone, dst_zone) {
            if sz.name == dz.name {
                self.total_allowed.fetch_add(1, Ordering::Relaxed);
                return TrafficVerdict {
                    allowed: true,
                    reason: format!("Intra-zone traffic in '{}' — allowed", sz.name),
                    src_zone: Some(sz.name.clone()),
                    dst_zone: Some(dz.name.clone()),
                    action: SegmentAction::Allow,
                };
            }

            // Check explicit policies first (most specific wins)
            for policy in &self.policies {
                if policy.src_zone == sz.name && policy.dst_zone == dz.name {
                    let port_ok = policy.allowed_ports.is_empty()
                        || policy.allowed_ports.contains(&port);
                    let proto_ok = policy.allowed_protocols.is_empty()
                        || policy.allowed_protocols.iter().any(|p| p == "any" || p == proto);
                    if port_ok && proto_ok {
                        let allowed = policy.action == SegmentAction::Allow
                            || policy.action == SegmentAction::Inspect;
                        if allowed {
                            self.total_allowed.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.total_blocked.fetch_add(1, Ordering::Relaxed);
                            warn!("🔒 MicroSeg: BLOCKED {}({})→{}({}) port={} — explicit deny policy",
                                src, sz.name, dst, dz.name, port);
                        }
                        return TrafficVerdict {
                            allowed,
                            reason: format!("Explicit policy: {}→{}", sz.name, dz.name),
                            src_zone: Some(sz.name.clone()),
                            dst_zone: Some(dz.name.clone()),
                            action: policy.action.clone(),
                        };
                    }
                }
            }

            // Apply zone isolation rules
            match sz.isolation {
                IsolationLevel::Strict => {
                    // Strict: only allowed if dst_zone is in sz.allowed_zones
                    //         AND port is in dst_zone.allowed_ports (if specified)
                    let zone_allowed = sz.allowed_zones.contains(&dz.name);
                    let port_allowed = dz.allowed_ports.as_ref()
                        .map(|ports| ports.contains(&port))
                        .unwrap_or(true);

                    if zone_allowed && port_allowed {
                        self.total_allowed.fetch_add(1, Ordering::Relaxed);
                        TrafficVerdict {
                            allowed: true,
                            reason: format!("Zone '{}' allows '{}'", sz.name, dz.name),
                            src_zone: Some(sz.name.clone()),
                            dst_zone: Some(dz.name.clone()),
                            action: SegmentAction::Allow,
                        }
                    } else {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        let reason = if !zone_allowed {
                            format!("STRICT: Zone '{}' does not allow access to '{}'", sz.name, dz.name)
                        } else {
                            format!("STRICT: Port {} not allowed into zone '{}'", port, dz.name)
                        };
                        warn!("🔒 MicroSeg: BLOCKED {} → {} on port {} — {}", src, dst, port, reason);
                        TrafficVerdict {
                            allowed: false,
                            reason,
                            src_zone: Some(sz.name.clone()),
                            dst_zone: Some(dz.name.clone()),
                            action: SegmentAction::Deny,
                        }
                    }
                }
                IsolationLevel::Moderate => {
                    // Moderate: allow unless dst_zone is NOT in allowed_zones
                    // (Zones not in allowed_zones are treated as blocked)
                    if !sz.allowed_zones.is_empty() && !sz.allowed_zones.contains(&dz.name) {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        warn!("🔒 MicroSeg: MODERATE BLOCK {} → {} — zone '{}' not in allowed list",
                            src, dst, dz.name);
                        TrafficVerdict {
                            allowed: false,
                            reason: format!("MODERATE: '{}' not in '{}' allowed zones", dz.name, sz.name),
                            src_zone: Some(sz.name.clone()),
                            dst_zone: Some(dz.name.clone()),
                            action: SegmentAction::Deny,
                        }
                    } else {
                        self.total_allowed.fetch_add(1, Ordering::Relaxed);
                        TrafficVerdict {
                            allowed: true,
                            reason: format!("MODERATE: cross-zone {}→{} permitted", sz.name, dz.name),
                            src_zone: Some(sz.name.clone()),
                            dst_zone: Some(dz.name.clone()),
                            action: SegmentAction::Inspect,
                        }
                    }
                }
                IsolationLevel::Minimal => {
                    // Minimal: always allow but log the cross-zone hop
                    debug!("MicroSeg: Cross-zone {}({})→{}({}) port={} [MINIMAL — logged only]",
                        src, sz.name, dst, dz.name, port);
                    self.total_allowed.fetch_add(1, Ordering::Relaxed);
                    TrafficVerdict {
                        allowed: true,
                        reason: format!("MINIMAL: cross-zone {}→{} logged", sz.name, dz.name),
                        src_zone: Some(sz.name.clone()),
                        dst_zone: Some(dz.name.clone()),
                        action: SegmentAction::Allow,
                    }
                }
            }
        } else {
            // Traffic from/to unknown zone — use permissive default to avoid
            // blocking legitimate non-segmented traffic (e.g. internet traffic)
            // but flag it for inspection
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            TrafficVerdict {
                allowed: true,
                reason: "Source or destination not in any defined zone".to_string(),
                src_zone: src_zone.map(|z| z.name.clone()),
                dst_zone: dst_zone.map(|z| z.name.clone()),
                action: SegmentAction::Inspect,
            }
        }
    }

    pub fn get_stats(&self) -> SegmentationStats {
        SegmentationStats {
            total_evaluated: self.total_evaluated.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            lateral_alerts: self.lateral_alerts_generated.load(Ordering::Relaxed),
            zones_count: self.zones.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentationStats {
    pub total_evaluated: u64,
    pub total_blocked: u64,
    pub total_allowed: u64,
    pub lateral_alerts: u64,
    pub zones_count: u64,
}

// ── Lateral Movement Detector ─────────────────────────────────────────────────
// Detects protocols and patterns commonly used for lateral movement (not just
// zone crossing). Works independently of zone membership.

pub struct LateralMovementDetector {
    // Per-source recent lateral move attempts (IP -> list of alerts in last 60s)
    alert_history: RwLock<HashMap<IpAddr, VecDeque<LateralMovementAlert>>>,
    total_detections: AtomicU64,
}

impl LateralMovementDetector {
    pub fn new() -> Self {
        Self {
            alert_history: RwLock::new(HashMap::new()),
            total_detections: AtomicU64::new(0),
        }
    }

    /// Inspect a connection for lateral movement indicators.
    /// Returns Some(alert) if a technique is identified.
    pub fn inspect(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        zone_hop: bool,
    ) -> Option<LateralMovementAlert> {
        let technique = match dst_port {
            445 => Some(LateralTechnique::SmbFileAccess),
            135 => Some(LateralTechnique::WmiExecution),
            3389 => Some(LateralTechnique::RdpSession),
            5985 | 5986 => Some(LateralTechnique::WinRm),
            22 if zone_hop => Some(LateralTechnique::SshTunnel),
            _ => None,
        };

        if let Some(tech) = technique {
            let alert = LateralMovementAlert {
                src_ip,
                dst_ip,
                dst_port,
                technique: tech.clone(),
                timestamp: unix_now(),
                zone_hop,
            };
            let mut history = self.alert_history.write();
            let entry = history.entry(src_ip).or_default();
            let now = unix_now();
            while entry.front().is_some_and(|a| now - a.timestamp > 60) {
                entry.pop_front();
            }
            entry.push_back(alert.clone());
            self.total_detections.fetch_add(1, Ordering::Relaxed);

            // Alert if the same source has hit multiple lateral movement ports
            if entry.len() >= 3 {
                warn!("🚨 LateralMove: {} has used {} lateral techniques in 60s — possible active pivot",
                    src_ip, entry.len());
            }
            return Some(alert);
        }
        None
    }

    pub fn total_detections(&self) -> u64 {
        self.total_detections.load(Ordering::Relaxed)
    }
}

// ── Default example policies (zones in config/rudras.toml) ───────────────────

pub fn create_example_policies() -> Vec<SegmentationPolicy> {
    vec![
        // DMZ can reach application tier on HTTP/HTTPS
        SegmentationPolicy {
            src_zone: "dmz".to_string(),
            dst_zone: "application".to_string(),
            allowed_ports: vec![80, 443, 8080, 8443],
            allowed_protocols: vec!["tcp".to_string()],
            action: SegmentAction::Allow,
        },
        // Application tier can reach database on standard DB ports
        SegmentationPolicy {
            src_zone: "application".to_string(),
            dst_zone: "database".to_string(),
            allowed_ports: vec![3306, 5432, 1433, 27017, 6379],
            allowed_protocols: vec!["tcp".to_string()],
            action: SegmentAction::Allow,
        },
        // Management can SSH to all zones
        SegmentationPolicy {
            src_zone: "management".to_string(),
            dst_zone: "dmz".to_string(),
            allowed_ports: vec![22],
            allowed_protocols: vec!["tcp".to_string()],
            action: SegmentAction::Inspect,
        },
        // Guest zone has no access to anything internal — explicit deny
        SegmentationPolicy {
            src_zone: "guest".to_string(),
            dst_zone: "application".to_string(),
            allowed_ports: vec![],
            allowed_protocols: vec!["any".to_string()],
            action: SegmentAction::Deny,
        },
        SegmentationPolicy {
            src_zone: "guest".to_string(),
            dst_zone: "database".to_string(),
            allowed_ports: vec![],
            allowed_protocols: vec!["any".to_string()],
            action: SegmentAction::Deny,
        },
    ]
}
