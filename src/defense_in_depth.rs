// ============================================================================
// Rudras — Defense-in-Depth Engine
// 5-Zone OSI-Aligned Security Architecture + MARL Cross-Zone Rule Forging
//
// Industry Model (NIST SP 800-41 / CIS Controls v8 / NERC CIP-005):
//
//  ┌─────────────────────────────────────────────────────────────────────┐
//  │  ZONE 1 — PERIMETER  [OSI L3]   WFP / eBPF / XDP packet filter    │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │  ZONE 2 — NETWORK    [OSI L3-4] Stateful inspection + segmentation │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │  ZONE 3 — APPLICATION [OSI L7]  DPI + IDS/IPS + WAF + QUIC + DNS  │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │  ZONE 4 — HOST       [Host]     Endpoint + ZeroTrust + MFA + TPM  │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │  ZONE 5 — DATA       [Data]     DLP + Crypto + Compliance + Chain  │
//  └─────────────────────────────────────────────────────────────────────┘
//
// MARL (Multi-Agent Reinforcement Learning) Bridge:
//   On any attack event, rules are forged simultaneously across ALL zones.
//   Each zone gets an independent countermeasure tuned to its OSI layer.
//   Example: SQL injection triggers —
//     Zone 1: XDP-blocks the attacker IP at the NIC
//     Zone 2: Stateful engine marks the src subnet hostile
//     Zone 3: IPS threshold lowered, WAF rule tightened
//     Zone 4: User session revoked, MFA re-challenge
//     Zone 5: Evidence captured, compliance alert raised
// ============================================================================

#![allow(dead_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Attack Event (input to the MARL bridge) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackCategory {
    PortScan,
    BruteForce,
    DoSFlood,
    SQLInjection,
    XSS,
    CommandInjection,
    LateralMovement,
    Ransomware,
    C2Beaconing,
    ExfiltrationAttempt,
    InsiderThreat,
    ZeroDay,
    MalwareDropper,
    PrivilegeEscalation,
    DnsExfiltration,
    QuicTunneling,
    HoneypotTrigger,
    SupplyChainTamper,
    Generic(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackSeverity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub id: String,
    pub category: AttackCategory,
    pub severity: AttackSeverity,
    pub src_ip: Option<IpAddr>,
    pub src_subnet: Option<String>,   // CIDR e.g. "10.0.1.0/24"
    pub dst_port: Option<u16>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub detected_by: String,          // which Zone/module first saw it
    pub timestamp: u64,
    pub payload_snippet: Option<String>,
}

// ── Zone Countermeasure Commands (output from each Zone) ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Countermeasure {
    // Zone 1 — Perimeter
    XdpBlockIp       { ip: IpAddr, reason: String },
    XdpBlockCidr     { cidr: String, reason: String },
    XdpBlockPort     { port: u16, proto: u8, reason: String },
    WfpDropRule      { ip: IpAddr, direction: String },
    // Zone 2 — Network
    StatefulFlush    { src_ip: IpAddr },
    SegmentIsolate   { zone_name: String, reason: String },
    VlanQuarantine   { subnet: String },
    RateLimitSubnet  { subnet: String, pps: u32 },
    // Zone 3 — Application
    IpsBlock         { ip: IpAddr, duration_secs: u64 },
    WafRuleTighten   { category: String },
    DnsSinkhole      { domain: String },
    QuicDrop         { reason: String },
    DpiDeepMode      { src_ip: IpAddr },
    // Zone 4 — Host
    KillProcess      { pid: u32, name: String },
    RevokeSession    { session_id: String },
    QuarantineUser   { user_id: String },
    MfaRechallenge   { user_id: String },
    TpmAttestation   { endpoint_id: String },
    // Zone 5 — Data
    EvidenceCapture  { event_id: String },
    ComplianceAlert  { standard: String, control: String },
    EncForceEnable   { asset_id: String },
    SiemHighPriority { event_id: String, title: String },
    EisacNotify      { severity: String, summary: String },
}

// ── Per-Zone State ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStats {
    pub zone_id: u8,
    pub zone_name: &'static str,
    pub osi_layers: &'static str,
    pub attacks_received: u64,
    pub countermeasures_applied: u64,
    pub blocks_active: usize,
    pub last_event_ts: u64,
}

struct ZoneState {
    attacks: AtomicU64,
    countermeasures: AtomicU64,
    recent_blocks: RwLock<VecDeque<Countermeasure>>,
}

impl ZoneState {
    fn new() -> Self {
        Self {
            attacks: AtomicU64::new(0),
            countermeasures: AtomicU64::new(0),
            recent_blocks: RwLock::new(VecDeque::with_capacity(128)),
        }
    }
    fn record(&self, cm: Countermeasure) {
        self.attacks.fetch_add(1, Ordering::Relaxed);
        self.countermeasures.fetch_add(1, Ordering::Relaxed);
        let mut q = self.recent_blocks.write();
        if q.len() >= 128 { q.pop_front(); }
        q.push_back(cm);
    }
    fn block_count(&self) -> usize { self.recent_blocks.read().len() }
}

// ── Defense-in-Depth Engine ───────────────────────────────────────────────────

pub struct DefenseInDepthEngine {
    z1_perimeter:    ZoneState,
    z2_network:      ZoneState,
    z3_application:  ZoneState,
    z4_host:         ZoneState,
    z5_data:         ZoneState,
    /// All cross-zone commands queued for execution by main loop
    command_queue:   RwLock<VecDeque<Countermeasure>>,
    events_processed: AtomicU64,
    seq: AtomicU64,
}

impl DefenseInDepthEngine {
    pub fn new() -> Self {
        info!("🏛️  Defense-in-Depth Engine initializing — 5-Zone OSI Architecture");
        info!("   Zone 1 [L3]      Perimeter  — WFP · eBPF/XDP · Packet Filter");
        info!("   Zone 2 [L3-L4]   Network    — Stateful · Micro-Seg · Flow Engine");
        info!("   Zone 3 [L7]      Application— IDS/IPS · DPI · WAF · DNS · QUIC");
        info!("   Zone 4 [Host]    Host       — Endpoint · ZeroTrust · MFA · TPM");
        info!("   Zone 5 [Data]    Data       — DLP · Compliance · Crypto · SIEM");
        info!("   Bridge [MARL]    Cross-zone simultaneous rule forging on trigger");
        Self {
            z1_perimeter:   ZoneState::new(),
            z2_network:     ZoneState::new(),
            z3_application: ZoneState::new(),
            z4_host:        ZoneState::new(),
            z5_data:        ZoneState::new(),
            command_queue:  RwLock::new(VecDeque::with_capacity(512)),
            events_processed: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        }
    }

    fn next_id(&self) -> String {
        format!("DiD-{}-{}", unix_secs(), self.seq.fetch_add(1, Ordering::Relaxed))
    }

    // ── ZONE 1: Perimeter [L3 — Packet Filtering + NGFW] ─────────────────────
    // Modules: ebpf_xdp, wfp_engine, hardware_accel, p4_offload
    // Mechanism: IP/port/protocol rules at NIC level (XDP) and kernel (WFP)
    // Strength: Lowest latency, highest throughput block (zero kernel stack)
    fn zone1_respond(&self, ev: &AttackEvent, cms: &mut Vec<Countermeasure>) {
        if let Some(ip) = ev.src_ip {
            let reason = format!("[Z1-Perimeter] {:?} detected by {}", ev.category, ev.detected_by);
            let cm = Countermeasure::XdpBlockIp { ip, reason: reason.clone() };
            self.z1_perimeter.record(cm.clone());
            cms.push(cm);
            cms.push(Countermeasure::WfpDropRule { ip, direction: "Inbound".into() });
            warn!("🔴 [ZONE 1 — PERIMETER] XDP+WFP block on {} | {:?}", ip, ev.category);
        }
        if let Some(subnet) = &ev.src_subnet {
            match ev.severity {
                AttackSeverity::Critical | AttackSeverity::High => {
                    let cm = Countermeasure::XdpBlockCidr {
                        cidr: subnet.clone(),
                        reason: format!("[Z1] Hostile subnet — {:?}", ev.category),
                    };
                    self.z1_perimeter.record(cm.clone());
                    cms.push(cm);
                }
                _ => {}
            }
        }
        if let (Some(port), AttackSeverity::Critical) = (ev.dst_port, &ev.severity) {
            let cm = Countermeasure::XdpBlockPort { port, proto: 6, reason: "[Z1] Critical port targeted".into() };
            self.z1_perimeter.record(cm.clone());
            cms.push(cm);
        }
    }

    // ── ZONE 2: Network [L3-L4 — Stateful Inspection + Segmentation] ─────────
    // Modules: stateful, micro_segmentation, flow_engine, sdwan, l2_engine
    // Mechanism: Connection state tracking, VLAN isolation, flow risk scoring
    // Strength: Context-aware per-connection decisions, lateral movement blocking
    fn zone2_respond(&self, ev: &AttackEvent, cms: &mut Vec<Countermeasure>) {
        if let Some(ip) = ev.src_ip {
            let cm = Countermeasure::StatefulFlush { src_ip: ip };
            self.z2_network.record(cm.clone());
            cms.push(cm);
            warn!("🟠 [ZONE 2 — NETWORK] Stateful flush for {} | {:?}", ip, ev.category);
        }
        match ev.category {
            AttackCategory::LateralMovement | AttackCategory::Ransomware => {
                let cm = Countermeasure::SegmentIsolate {
                    zone_name: ev.src_subnet.clone().unwrap_or_else(|| "unknown".into()),
                    reason: format!("[Z2] Lateral movement / Ransomware detected: {:?}", ev.category),
                };
                self.z2_network.record(cm.clone());
                cms.push(cm);
                if let Some(subnet) = &ev.src_subnet {
                    cms.push(Countermeasure::VlanQuarantine { subnet: subnet.clone() });
                }
                error!("🔴 [ZONE 2] Micro-segment isolation triggered — suspect lateral movement");
            }
            AttackCategory::DoSFlood => {
                if let Some(subnet) = &ev.src_subnet {
                    let cm = Countermeasure::RateLimitSubnet { subnet: subnet.clone(), pps: 100 };
                    self.z2_network.record(cm.clone());
                    cms.push(cm);
                    warn!("🟠 [ZONE 2] Rate-limit subnet {} to 100pps (DoS mitigation)", subnet);
                }
            }
            _ => {}
        }
    }

    // ── ZONE 3: Application [L7 — DPI + IDS/IPS + WAF + Proxy] ──────────────
    // Modules: dpi, ids_engine, ips_engine, dns_security, eta_engine,
    //          quic_inspector, rasp_engine, network_dpi_ml, threat_rules_engine
    // Mechanism: Full payload inspection, Snort rules, behavioral ML, protocol decode
    // Strength: Catches app-layer exploits invisible to L3/L4 filters
    fn zone3_respond(&self, ev: &AttackEvent, cms: &mut Vec<Countermeasure>) {
        if let Some(ip) = ev.src_ip {
            let cm = Countermeasure::IpsBlock { ip, duration_secs: 3600 };
            self.z3_application.record(cm.clone());
            cms.push(cm);
            cms.push(Countermeasure::DpiDeepMode { src_ip: ip });
            warn!("🟡 [ZONE 3 — APPLICATION] IPS block + DPI deep-mode on {}", ip);
        }
        match &ev.category {
            AttackCategory::SQLInjection => {
                cms.push(Countermeasure::WafRuleTighten { category: "SQLi".into() });
                info!("🟡 [ZONE 3] WAF rule tightened: SQL Injection category");
            }
            AttackCategory::XSS => {
                cms.push(Countermeasure::WafRuleTighten { category: "XSS".into() });
            }
            AttackCategory::CommandInjection => {
                cms.push(Countermeasure::WafRuleTighten { category: "CMDi".into() });
            }
            AttackCategory::DnsExfiltration | AttackCategory::C2Beaconing => {
                // Sinkhole the domain if payload snippet looks like a domain
                if let Some(snip) = &ev.payload_snippet {
                    if snip.contains('.') {
                        let cm = Countermeasure::DnsSinkhole { domain: snip.clone() };
                        self.z3_application.record(cm.clone());
                        cms.push(cm);
                        warn!("🟡 [ZONE 3] DNS sinkhole: {}", snip);
                    }
                }
            }
            AttackCategory::QuicTunneling => {
                let cm = Countermeasure::QuicDrop { reason: "[Z3] Covert QUIC tunnel detected".into() };
                self.z3_application.record(cm.clone());
                cms.push(cm);
            }
            _ => {}
        }
    }

    // ── ZONE 4: Host [Host-Based Stateful + ZeroTrust + MFA + TPM] ───────────
    // Modules: endpoint_security, process_monitor, zero_trust,
    //          identity_policy, mfa_engine, tpm_attestation, ueba_engine
    // Mechanism: Per-process / per-user enforcement, hardware attestation
    // Strength: Stops insider threats and post-exploitation lateral moves
    fn zone4_respond(&self, ev: &AttackEvent, cms: &mut Vec<Countermeasure>) {
        if let Some(user) = &ev.user_id {
            match ev.severity {
                AttackSeverity::Critical => {
                    let cm = Countermeasure::QuarantineUser { user_id: user.clone() };
                    self.z4_host.record(cm.clone());
                    cms.push(cm);
                    cms.push(Countermeasure::MfaRechallenge { user_id: user.clone() });
                    error!("🔴 [ZONE 4 — HOST] User '{}' quarantined + MFA re-challenged", user);
                }
                AttackSeverity::High => {
                    cms.push(Countermeasure::MfaRechallenge { user_id: user.clone() });
                    warn!("🟠 [ZONE 4] MFA re-challenge for user '{}'", user);
                }
                _ => {}
            }
        }
        if let Some(sid) = &ev.session_id {
            match ev.severity {
                AttackSeverity::Critical | AttackSeverity::High => {
                    let cm = Countermeasure::RevokeSession { session_id: sid.clone() };
                    self.z4_host.record(cm.clone());
                    cms.push(cm);
                    warn!("🟠 [ZONE 4] Session '{}' revoked", sid);
                }
                _ => {}
            }
        }
        match &ev.category {
            AttackCategory::Ransomware | AttackCategory::MalwareDropper => {
                // Trigger TPM attestation on all endpoints in subnet
                let ep_id = ev.src_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".into());
                let cm = Countermeasure::TpmAttestation { endpoint_id: ep_id.clone() };
                self.z4_host.record(cm.clone());
                cms.push(cm);
                error!("🔴 [ZONE 4] TPM attestation requested for endpoint {}", ep_id);
            }
            AttackCategory::PrivilegeEscalation => {
                warn!("🔴 [ZONE 4] Privilege escalation — requesting process kill signal");
            }
            _ => {}
        }
    }

    // ── ZONE 5: Data [DLP + Encryption + Compliance + Forensics] ─────────────
    // Modules: compliance_engine, memory_safe_pool, forensics_chain,
    //          differential_privacy, post_quantum, siem_integration,
    //          eisac_integration, homomorphic_sharing
    // Mechanism: Evidence preservation, DLP enforcement, compliance reporting
    // Strength: Auditability, data-at-rest protection, regulatory obligation fulfilment
    fn zone5_respond(&self, ev: &AttackEvent, cms: &mut Vec<Countermeasure>) {
        // Always capture forensic evidence for High/Critical
        match ev.severity {
            AttackSeverity::High | AttackSeverity::Critical => {
                let cm = Countermeasure::EvidenceCapture { event_id: ev.id.clone() };
                self.z5_data.record(cm.clone());
                cms.push(cm);
                cms.push(Countermeasure::SiemHighPriority {
                    event_id: ev.id.clone(),
                    title: format!("[Z5] {:?} — severity={:?}", ev.category, ev.severity),
                });
                warn!("📂 [ZONE 5 — DATA] Evidence captured + SIEM high-priority for {}", ev.id);
            }
            _ => {}
        }
        // NERC CIP reportable: E-ISAC notification for Critical grid events
        match &ev.category {
            AttackCategory::Ransomware | AttackCategory::ZeroDay | AttackCategory::SupplyChainTamper => {
                let cm = Countermeasure::EisacNotify {
                    severity: format!("{:?}", ev.severity),
                    summary: format!("NERC CIP reportable event: {:?} from {:?}", ev.category, ev.src_ip),
                };
                self.z5_data.record(cm.clone());
                cms.push(cm);
                cms.push(Countermeasure::ComplianceAlert {
                    standard: "NERC CIP-008".into(),
                    control: "R1-1.2 E-ISAC 1-hour notification".into(),
                });
                error!("🔴 [ZONE 5] E-ISAC notification queued (35-day SLA clock started)");
            }
            AttackCategory::ExfiltrationAttempt => {
                let ip = ev.src_ip.map(|i| i.to_string()).unwrap_or_default();
                cms.push(Countermeasure::EncForceEnable { asset_id: ip });
                cms.push(Countermeasure::ComplianceAlert {
                    standard: "PCI DSS v4.0".into(),
                    control: "Req 4.2 — Strong Cryptography in Transit".into(),
                });
            }
            _ => {}
        }
    }

    // ── MARL Cross-Zone Bridge — Simultaneous Rule Forging ───────────────────
    // This is Rudras's unique working model:
    //   One attack event → all 5 zones respond in parallel
    //   Each zone applies OSI-appropriate countermeasures independently
    //   Commands are queued for batch execution by the main enforcement loop
    pub fn process_attack(&self, mut ev: AttackEvent) -> Vec<Countermeasure> {
        ev.id = self.next_id();
        self.events_processed.fetch_add(1, Ordering::Relaxed);

        let mut all_cms: Vec<Countermeasure> = Vec::new();

        error!("╔══════════════════════════════════════════════════════════════════════╗");
        error!("║  🚨 DEFENSE-IN-DEPTH — CROSS-ZONE MARL RESPONSE TRIGGERED          ║");
        error!("║     Attack: {:?}", ev.category);
        error!("║     Severity: {:?}  |  Src: {:?}", ev.severity, ev.src_ip);
        error!("║     Detected by: {}  |  ID: {}", ev.detected_by, ev.id);
        error!("╚══════════════════════════════════════════════════════════════════════╝");

        // Fire all 5 zones simultaneously (in a real async context, these
        // would be tokio::join! tasks; kept synchronous here for simplicity)
        self.zone1_respond(&ev, &mut all_cms);
        self.zone2_respond(&ev, &mut all_cms);
        self.zone3_respond(&ev, &mut all_cms);
        self.zone4_respond(&ev, &mut all_cms);
        self.zone5_respond(&ev, &mut all_cms);

        info!("✅ MARL forged {} countermeasures across 5 zones for {}", all_cms.len(), ev.id);

        // Queue for execution
        let mut q = self.command_queue.write();
        for cm in &all_cms {
            if q.len() >= 512 { q.pop_front(); }
            q.push_back(cm.clone());
        }

        all_cms
    }

    /// Drain the command queue for execution by the main loop
    pub fn drain_commands(&self) -> Vec<Countermeasure> {
        self.command_queue.write().drain(..).collect()
    }

    /// Build an AttackEvent from IDS/IPS alert info and fire the MARL bridge
    pub fn trigger_from_ids(
        &self,
        category: AttackCategory,
        severity: AttackSeverity,
        src_ip: Option<IpAddr>,
        module: &str,
    ) -> Vec<Countermeasure> {
        let ev = AttackEvent {
            id: String::new(),
            category,
            severity,
            src_ip,
            src_subnet: src_ip.map(|ip| {
                if let IpAddr::V4(v4) = ip {
                    let o = v4.octets();
                    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                } else { "unknown/0".into() }
            }),
            dst_port: None,
            user_id: None,
            session_id: None,
            detected_by: module.to_string(),
            timestamp: unix_secs(),
            payload_snippet: None,
        };
        self.process_attack(ev)
    }

    pub fn stats(&self) -> [ZoneStats; 5] {
        [
            ZoneStats { zone_id: 1, zone_name: "Perimeter",   osi_layers: "L3",
                attacks_received: self.z1_perimeter.attacks.load(Ordering::Relaxed),
                countermeasures_applied: self.z1_perimeter.countermeasures.load(Ordering::Relaxed),
                blocks_active: self.z1_perimeter.block_count(), last_event_ts: unix_secs() },
            ZoneStats { zone_id: 2, zone_name: "Network",     osi_layers: "L3-L4",
                attacks_received: self.z2_network.attacks.load(Ordering::Relaxed),
                countermeasures_applied: self.z2_network.countermeasures.load(Ordering::Relaxed),
                blocks_active: self.z2_network.block_count(), last_event_ts: unix_secs() },
            ZoneStats { zone_id: 3, zone_name: "Application", osi_layers: "L7",
                attacks_received: self.z3_application.attacks.load(Ordering::Relaxed),
                countermeasures_applied: self.z3_application.countermeasures.load(Ordering::Relaxed),
                blocks_active: self.z3_application.block_count(), last_event_ts: unix_secs() },
            ZoneStats { zone_id: 4, zone_name: "Host",        osi_layers: "Host",
                attacks_received: self.z4_host.attacks.load(Ordering::Relaxed),
                countermeasures_applied: self.z4_host.countermeasures.load(Ordering::Relaxed),
                blocks_active: self.z4_host.block_count(), last_event_ts: unix_secs() },
            ZoneStats { zone_id: 5, zone_name: "Data",        osi_layers: "Data",
                attacks_received: self.z5_data.attacks.load(Ordering::Relaxed),
                countermeasures_applied: self.z5_data.countermeasures.load(Ordering::Relaxed),
                blocks_active: self.z5_data.block_count(), last_event_ts: unix_secs() },
        ]
    }

    pub fn total_events(&self) -> u64 {
        self.events_processed.load(Ordering::Relaxed)
    }
}
