// ============================================================================
// Rudras — Deployment Mode Profiles
// ============================================================================
// CLIENT MODE  → Endpoint / workstation / laptop protection
//   • Protects a single device running on user networks
//   • Focus on: outbound C2 detection, data exfiltration, malware callbacks,
//     credential theft, browser-based attacks
//   • Lower packet volume → more aggressive AI threshold (to catch subtle threats)
//   • Allows all well-known inbound ports unless explicit block rule
//   • Stealth-friendly: minimal UI / log noise
//
// SERVER MODE  → Gateway / rack / perimeter protection
//   • Protects a server or network segment from INBOUND attacks
//   • Focus on: port scans, login brute force, exploit attempts, DDoS,
//     lateral movement between segments
//   • High packet volume → flow engine fast-path optimised
//   • Strict inbound default-deny; only whitelisted services exposed
//   • Verbose logging for audit/compliance
// ============================================================================

#![allow(dead_code, unused_imports)]

use serde::{Deserialize, Serialize};
use tracing::info;

// ── Deployment Mode ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Endpoint / workstation protection
    Client,
    /// Server / gateway / perimeter protection
    Server,
    /// Auto-detect based on open ports and traffic patterns
    Auto,
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentMode::Client => write!(f, "CLIENT"),
            DeploymentMode::Server => write!(f, "SERVER"),
            DeploymentMode::Auto => write!(f, "AUTO"),
        }
    }
}

impl DeploymentMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "client" => DeploymentMode::Client,
            "server" => DeploymentMode::Server,
            _ => DeploymentMode::Auto,
        }
    }
}

// ── Mode-Specific Engine Tuning ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModeProfile {
    pub name: &'static str,
    pub description: &'static str,

    // Traffic direction weighting
    pub monitor_inbound: bool,  // Inspect inbound traffic
    pub monitor_outbound: bool, // Inspect outbound traffic
    pub inbound_priority: f32,  // 0.0–1.0, higher = more attention inbound

    // IPS thresholds — LOWER = more aggressive blocking
    pub ips_rate_limit_thresh: f32,    // Penalty before rate-limiting
    pub ips_rst_thresh: f32,           // Penalty before TCP RST
    pub ips_block_thresh: f32,         // Penalty before WFP kernel block
    pub ips_quarantine_thresh: f32,    // Penalty before quarantine
    pub ips_blacklist_thresh: f32,     // Penalty before permanent blacklist
    pub ips_auto_block_high: bool,     // Instantly block HIGH IDS alerts
    pub ips_auto_block_critical: bool, // Instantly block CRITICAL IDS alerts

    // AI Engine thresholds
    pub ai_susp_threshold: f32,  // Score to mark flow suspicious
    pub ai_block_threshold: f32, // Score to instantly block

    // Flow Engine thresholds
    pub flow_susp_threshold: f32, // Flow risk threshold for full inspection
    pub flow_block_threshold: f32, // Flow risk threshold for direct block

    // Feature flags
    pub enable_port_scan_detect: bool, // Detect port-scanning
    pub enable_brute_force: bool,      // Detect credential brute-force
    pub enable_c2_detect: bool,        // Detect C2 callback patterns
    pub enable_exfil_detect: bool,     // Detect data exfiltration
    pub enable_lateral_movement: bool, // Detect lateral movement (server-critical)
    pub enable_tls_fingerprint: bool,  // JA3 fingerprint suspicious TLS clients
    pub enable_dns_tunneling: bool,    // Detect DNS tunneling

    // Logging verbosity
    pub verbose_logging: bool,
    pub log_allowed_flows: bool, // Log every allowed flow (server audit mode)

    // Services to expose (server only) — ports allowed inbound
    pub allowed_inbound_ports: Vec<u16>,
}

// ── Client Profile ────────────────────────────────────────────────────────────

pub fn client_profile() -> ModeProfile {
    ModeProfile {
        name: "CLIENT",
        description: "Endpoint / workstation / laptop protection",
        monitor_inbound: true,
        monitor_outbound: true,
        inbound_priority: 0.4, // 60% focus on outbound (C2/exfil)

        // Highly aggressive on inbound, maximum security posture
        ips_rate_limit_thresh: 20.0,
        ips_rst_thresh: 50.0,
        ips_block_thresh: 80.0,
        ips_quarantine_thresh: 150.0,
        ips_blacklist_thresh: 250.0,
        ips_auto_block_high: true,
        ips_auto_block_critical: true,

        // AI is extremely sensitive for upgraded zero-day detection
        ai_susp_threshold: 0.40,
        ai_block_threshold: 0.65,

        // Flow engine thresholds upgraded
        flow_susp_threshold: 0.50,
        flow_block_threshold: 0.70,

        // Feature flags — all features forcibly enabled for max security
        enable_port_scan_detect: true,
        enable_brute_force: true,
        enable_c2_detect: true,
        enable_exfil_detect: true,
        enable_lateral_movement: true,
        enable_tls_fingerprint: true,
        enable_dns_tunneling: true,

        verbose_logging: false,   // Quiet mode for desktop
        log_allowed_flows: false, // Don't flood logs with allowed traffic

        // Client: only accept connections on loopback by default; browsers connect outbound
        allowed_inbound_ports: vec![], // No exposed services expected
    }
}

// ── Server Profile ────────────────────────────────────────────────────────────

pub fn server_profile() -> ModeProfile {
    ModeProfile {
        name: "SERVER",
        description: "Gateway / rack / perimeter protection",
        monitor_inbound: true,
        monitor_outbound: true,
        inbound_priority: 0.8, // 80% focus on inbound attacks

        // Hyper-aggressive inbound protection for servers
        ips_rate_limit_thresh: 10.0,  // Immediate rate-limiting
        ips_rst_thresh: 25.0,         // Instant RST on suspicious events
        ips_block_thresh: 50.0,       // Fast blocking
        ips_quarantine_thresh: 100.0, // Fast quarantine
        ips_blacklist_thresh: 200.0,  // Blacklist effectively doubled
        ips_auto_block_high: true,
        ips_auto_block_critical: true,

        // Upgraded AI sensitivity for zero-days
        ai_susp_threshold: 0.45,
        ai_block_threshold: 0.70,

        // Upgraded Flow engine thresholds
        flow_susp_threshold: 0.55,
        flow_block_threshold: 0.75,

        // Feature flags — server protection priorities
        enable_port_scan_detect: true, // CRITICAL — servers are always scanned
        enable_brute_force: true,      // CRITICAL — SSH/RDP/admin login attempts
        enable_c2_detect: true,        // Compromised server calling back to C2
        enable_exfil_detect: true,     // Prevent database exfiltration
        enable_lateral_movement: true, // CRITICAL — SMB/WMI lateral spread
        enable_tls_fingerprint: true,  // Detect attack tools (curl/metasploit)
        enable_dns_tunneling: true,

        verbose_logging: true,    // Full audit trail
        log_allowed_flows: false, // Would be too much volume; set true for max audit

        // Typical server services — customise in rudras.toml [mode]
        allowed_inbound_ports: vec![
            80,   // HTTP
            443,  // HTTPS
            22,   // SSH management
            8080, // alt-HTTP
            8443, // alt-HTTPS
            3000, // common dev/API port
        ],
    }
}

// ── Auto-detect ───────────────────────────────────────────────────────────────

/// Heuristic: if this machine has any listening server ports (80, 443, 22, etc.)
/// → server mode. Otherwise → client mode.
pub fn auto_detect_mode() -> DeploymentMode {
    use std::net::TcpListener;

    let server_ports = [
        80u16, 443, 22, 25, 3306, 5432, 8080, 8443, 6379, 27017, 9200, 5000, 3000,
    ];

    let has_server_port = server_ports.iter().any(|&port| {
        // If we CANNOT bind → something is already listening → server mode
        TcpListener::bind(format!("0.0.0.0:{}", port)).is_err()
    });

    if has_server_port {
        info!("🔎 Auto-detect: open server ports found → SERVER mode");
        DeploymentMode::Server
    } else {
        info!("🔎 Auto-detect: no public server ports → CLIENT mode");
        DeploymentMode::Client
    }
}

// ── Mode Summary ──────────────────────────────────────────────────────────────

pub fn print_mode_profile(profile: &ModeProfile) {
    info!("╔══════════════════════════════════════════════════════════════════╗");
    info!("║  🎯 DEPLOYMENT MODE: {:44} ║", profile.name);
    info!("║  {:<66} ║", profile.description);
    info!("╠══════════════════════════════════════════════════════════════════╣");
    info!(
        "║  📡 Direction Focus   — Inbound:{:.0}%  Outbound:{:.0}%{:>20} ║",
        profile.inbound_priority * 100.0,
        (1.0 - profile.inbound_priority) * 100.0,
        ""
    );
    info!(
        "║  🛡️  IPS Thresholds   — RateLimit:{:.0} | RST:{:.0} | Block:{:.0}{:>14} ║",
        profile.ips_rate_limit_thresh, profile.ips_rst_thresh, profile.ips_block_thresh, ""
    );
    info!(
        "║  🧠 AI Thresholds    — Suspicious:{:.2} | Block:{:.2}{:>23} ║",
        profile.ai_susp_threshold, profile.ai_block_threshold, ""
    );
    info!(
        "║  ⚡ Flow Thresholds  — Suspicious:{:.2} | Block:{:.2}{:>23} ║",
        profile.flow_susp_threshold, profile.flow_block_threshold, ""
    );
    info!("╠══════════════════════════════════════════════════════════════════╣");
    info!(
        "║  Feature     C2:{} | Exfil:{} | PortScan:{} | BruteForce:{}{:>9} ║",
        yn(profile.enable_c2_detect),
        yn(profile.enable_exfil_detect),
        yn(profile.enable_port_scan_detect),
        yn(profile.enable_brute_force),
        ""
    );
    info!(
        "║  Feature     LateralMove:{} | TLS-FP:{} | DNSTunnel:{}{:>14} ║",
        yn(profile.enable_lateral_movement),
        yn(profile.enable_tls_fingerprint),
        yn(profile.enable_dns_tunneling),
        ""
    );
    info!(
        "║  AutoBlock   HIGH:{} | CRITICAL:{}{:>33} ║",
        yn(profile.ips_auto_block_high),
        yn(profile.ips_auto_block_critical),
        ""
    );
    if !profile.allowed_inbound_ports.is_empty() {
        let ports_str = profile
            .allowed_inbound_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        info!("║  Open ports  {:<54} ║", ports_str);
    }
    info!("╚══════════════════════════════════════════════════════════════════╝");
}

fn yn(b: bool) -> &'static str {
    if b {
        "✅"
    } else {
        "❌"
    }
}
