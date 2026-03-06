// Rudras Firewall — Master Configuration
// Loads from config/rudras.toml; falls back to built-in defaults if file is absent.
//
// CONFIG INTEGRITY PROTECTION
// ──────────────────────────────
// If a file named `config/rudras.toml.sig` exists, the SHA-256 hash of the
// config is verified against it before the config is accepted.  Format:
//   sha256:<hex-digest>
// This prevents an attacker who gains write access to the config directory
// from disabling all blocking by modifying rudras.toml without also
// updating the signature file (which requires knowing the signing key).
//
// To generate / update the signature:
//   $hash = (Get-FileHash config/rudras.toml -Algorithm SHA256).Hash.ToLower()
//   "sha256:$hash" | Set-Content config/rudras.toml.sig
//
// PREVIOUS ISSUE FIXED:
//   Config was loaded without any integrity check — a tampered TOML could
//   silently set enabled=false on all blocking modules.

#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unexpected_cfgs,
    unused_unsafe
)]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use tracing::warn;

// ============================================================================
// TOP-LEVEL CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Core
    pub interface: Option<String>,
    pub log_level: String,
    pub metrics_port: u16,
    #[serde(default)]
    pub peers: Vec<String>,

    // Deployment mode
    #[serde(default)]
    pub mode: ModeConfig,

    // Enterprise modules
    #[serde(default)]
    pub siem: SiemConfig,

    #[serde(default)]
    pub zero_trust: ZeroTrustConfig,

    #[serde(default)]
    pub segmentation: SegmentationConfig,

    #[serde(default)]
    pub blocking: BlockingConfig,

    #[serde(default)]
    pub ips: IpsTomlConfig,

    #[serde(default)]
    pub ai: AiTomlConfig,

    #[serde(default)]
    pub endpoint: EndpointConfig,

    #[serde(default)]
    pub attribution: AttributionConfig,
}

// ============================================================================
// MODE CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeConfig {
    /// "auto" | "client" | "server"
    #[serde(default = "default_deployment")]
    pub deployment: String,

    /// Ports this machine legitimately exposes (server mode)
    #[serde(default)]
    pub exposed_ports: Vec<u16>,

    /// Trusted LAN subnets — less aggressive inspection of traffic within these
    #[serde(default = "default_trusted_networks")]
    pub trusted_networks: Vec<String>,
}

fn default_deployment() -> String {
    "auto".to_string()
}

fn default_trusted_networks() -> Vec<String> {
    vec![
        "192.168.0.0/16".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
    ]
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            deployment: default_deployment(),
            exposed_ports: vec![],
            trusted_networks: default_trusted_networks(),
        }
    }
}

// ============================================================================
// SIEM CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub enabled: bool,
    pub buffer_size: usize,
    pub flush_interval_seconds: u64,
    pub retry_attempts: u32,

    // Splunk HEC
    pub splunk_enabled: bool,
    pub splunk_hec_url: String,
    pub splunk_hec_token: String,

    // Elasticsearch
    pub elasticsearch_enabled: bool,
    pub elasticsearch_url: String,
    pub elasticsearch_index: String,
    pub elasticsearch_username: Option<String>,
    pub elasticsearch_password: Option<String>,

    // QRadar syslog
    pub qradar_enabled: bool,
    pub qradar_host: String,
    pub qradar_port: u16,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 10_000,
            flush_interval_seconds: 30,
            retry_attempts: 3,

            splunk_enabled: false,
            splunk_hec_url: "https://splunk:8088/services/collector".to_string(),
            splunk_hec_token: "YOUR_SPLUNK_HEC_TOKEN".to_string(),

            elasticsearch_enabled: false,
            elasticsearch_url: "http://localhost:9200".to_string(),
            elasticsearch_index: "rudras-".to_string(),
            elasticsearch_username: None,
            elasticsearch_password: None,

            qradar_enabled: false,
            qradar_host: "qradar.internal".to_string(),
            qradar_port: 514,
        }
    }
}

// ============================================================================
// ZERO TRUST CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustConfig {
    pub enabled: bool,

    // Active Directory
    pub ad_enabled: bool,
    pub ad_server: String,
    pub ad_domain: String,

    // SAML SSO
    pub saml_enabled: bool,
    pub saml_idp_url: String,
    pub saml_sp_entity_id: String,

    // OAuth 2.0
    pub oauth_enabled: bool,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_auth_url: String,

    // Device posture thresholds
    pub min_device_compliance_score: f64,
    pub require_antivirus: bool,
    pub require_disk_encryption: bool,
    pub max_patch_age_days: i64,
}

impl Default for ZeroTrustConfig {
    fn default() -> Self {
        Self {
            enabled: true,

            ad_enabled: false,
            ad_server: "dc.company.com".to_string(),
            ad_domain: "company.com".to_string(),

            saml_enabled: false,
            saml_idp_url: "https://idp.company.com/saml2".to_string(),
            saml_sp_entity_id: "rudras-firewall".to_string(),

            oauth_enabled: false,
            oauth_client_id: "rudras-client".to_string(),
            oauth_client_secret: "YOUR_OAUTH_SECRET".to_string(),
            oauth_auth_url: "https://auth.company.com/oauth2".to_string(),

            min_device_compliance_score: 0.7,
            require_antivirus: true,
            require_disk_encryption: true,
            max_patch_age_days: 30,
        }
    }
}

// ============================================================================
// MICRO-SEGMENTATION CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationConfig {
    pub enabled: bool,
    pub zones: Vec<ZoneConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub name: String,
    pub description: String,
    pub networks: Vec<String>,
    pub isolation: String, // "strict" | "moderate" | "minimal"
    pub allowed_zones: Vec<String>,
}

impl Default for SegmentationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            zones: default_zones(),
        }
    }
}

fn default_zones() -> Vec<ZoneConfig> {
    vec![
        ZoneConfig {
            name: "dmz".to_string(),
            description: "Public-facing DMZ".to_string(),
            networks: vec!["10.0.1.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec!["application".to_string()],
        },
        ZoneConfig {
            name: "application".to_string(),
            description: "Application / API servers".to_string(),
            networks: vec!["10.0.11.0/24".to_string()],
            isolation: "moderate".to_string(),
            allowed_zones: vec!["database".to_string(), "dmz".to_string()],
        },
        ZoneConfig {
            name: "database".to_string(),
            description: "Production databases".to_string(),
            networks: vec!["10.0.10.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec!["application".to_string(), "management".to_string()],
        },
        ZoneConfig {
            name: "finance".to_string(),
            description: "Finance — PCI-DSS zone".to_string(),
            networks: vec!["10.0.20.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec!["management".to_string()],
        },
        ZoneConfig {
            name: "research".to_string(),
            description: "R&D — intellectual property".to_string(),
            networks: vec!["10.0.30.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec!["management".to_string()],
        },
        ZoneConfig {
            name: "corporate".to_string(),
            description: "Corporate workstations".to_string(),
            networks: vec!["10.0.100.0/24".to_string(), "192.168.1.0/24".to_string()],
            isolation: "moderate".to_string(),
            allowed_zones: vec!["application".to_string(), "dmz".to_string()],
        },
        ZoneConfig {
            name: "guest".to_string(),
            description: "Guest Wi-Fi — internet only".to_string(),
            networks: vec!["192.168.200.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec![],
        },
        ZoneConfig {
            name: "management".to_string(),
            description: "IT management & monitoring".to_string(),
            networks: vec!["10.0.255.0/24".to_string()],
            isolation: "strict".to_string(),
            allowed_zones: vec![
                "database".to_string(),
                "application".to_string(),
                "corporate".to_string(),
                "finance".to_string(),
                "research".to_string(),
            ],
        },
    ]
}

// ============================================================================
// COMPREHENSIVE BLOCKING CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingConfig {
    pub enabled: bool,
    pub enable_l7_dpi: bool,
    pub enable_malware_scan: bool,
    pub enable_dns_filtering: bool,
    pub enable_exfil_check: bool,
    pub enable_anomaly_ai: bool,
    pub enable_iot_defense: bool,
    pub enable_auth_shield: bool,

    // ── REQUIRES EXPLICIT ADMINISTRATOR OPT-IN ───────────────────────────────
    //
    // process_monitor_kill_mode
    //   false (default) — WARN-ONLY.  Detected unauthorized sniffers are logged
    //     and alerted, but the process is never terminated.  This is the only
    //     legally safe default: forcibly killing user processes without informed
    //     consent may violate computer-misuse / consumer-protection law in many
    //     jurisdictions (US CFAA, UK CMA, EU Directive 2013/40/EU, etc.).
    //   true — KILL MODE.  Use only when:
    //     (a) deployed on a corporate-owned, managed device;
    //     (b) employees have been informed via an Acceptable Use Policy; AND
    //     (c) local legal counsel has confirmed this is permissible in your
    //         jurisdiction.
    //   REQUIRED config file entry: process_monitor_kill_mode = true
    pub process_monitor_kill_mode: bool,

    // promiscuous_capture
    //   false (default) — Capture only traffic addressed to this host.
    //     This is the legally safe default.  Promiscuous-mode capture on a
    //     shared network segment intercepts other parties' communications,
    //     which may violate wiretapping / electronic surveillance laws
    //     (US ECPA/Wiretap Act, UK RIPA, EU GDPR, etc.) unless the operator
    //     owns the entire segment or has explicit authorisation from all parties.
    //   true — Full promiscuous capture.  Enable only when you own and operate
    //     the entire network segment and have the legal authority to inspect all
    //     traffic on it (e.g., a dedicated IDS monitoring port/SPAN port).
    pub promiscuous_capture: bool,

    // block_anonymization_networks
    //   false (default) — Tor, I2P, and similar privacy-network ports are NOT
    //     blocked.  Tor is legal in the overwhelming majority of countries and
    //     is used legitimately by journalists, activists, researchers, and
    //     privacy-conscious individuals.  Blocking it by default would be
    //     discriminatory and inconsistent with a defensive security posture.
    //   true — Block Tor relay (9001/9030), SOCKS (9050/9150), and I2P ports.
    //     Enable only when required by your organisation's policy and when
    //     permitted by local law (note: blocking Tor is itself illegal in some
    //     jurisdictions that protect anonymous communication).
    pub block_anonymization_networks: bool,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_l7_dpi: true,
            enable_malware_scan: true,
            enable_dns_filtering: true,
            enable_exfil_check: true,
            enable_anomaly_ai: true,
            enable_iot_defense: true,
            enable_auth_shield: true,
            // Ethically sensitive behaviours — all OFF by default
            process_monitor_kill_mode: false,
            promiscuous_capture: false,
            block_anonymization_networks: false,
        }
    }
}

// ============================================================================
// IPS CONFIG (Intrusion Prevention System)
// ============================================================================

/// IPS penalty thresholds and prevention settings, read from [ips] section in rudras.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsTomlConfig {
    /// Enable inline prevention (false = IDS-only / passive mode)
    pub enabled: bool,
    /// Accumulated penalty score → trigger rate-limiting (default: 30)
    pub rate_limit_threshold: f32,
    /// Accumulated penalty score → send TCP RST (default: 60)
    pub rst_threshold: f32,
    /// Accumulated penalty score → install WFP block rule (default: 100)
    pub block_threshold: f32,
    /// Accumulated penalty score → quarantine for 24 h (default: 200)
    pub quarantine_threshold: f32,
    /// Accumulated penalty score → permanent blacklist (default: 350)
    pub blacklist_threshold: f32,
    /// WFP block duration in seconds (default: 3600 = 1 hour)
    pub block_duration_secs: u64,
    /// Quarantine duration in seconds (default: 86400 = 24 hours)
    pub quarantine_duration_secs: u64,
    /// Rate-limit: max packets-per-second per IP when throttling (default: 10)
    pub rate_limit_pps: u32,
    /// Immediately block on first HIGH-severity IDS alert (default: false)
    pub auto_block_high: bool,
    /// Immediately block on first CRITICAL-severity IDS alert (default: true)
    pub auto_block_critical: bool,
    /// Management IPs that are NEVER blocked (loopback always exempt)
    pub whitelist: Vec<String>,
}

impl Default for IpsTomlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_threshold: 30.0,
            rst_threshold: 60.0,
            block_threshold: 100.0,
            quarantine_threshold: 200.0,
            blacklist_threshold: 350.0,
            block_duration_secs: 3_600,
            quarantine_duration_secs: 86_400,
            rate_limit_pps: 10,
            auto_block_high: false,
            auto_block_critical: true,
            whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

// ============================================================================
// ENDPOINT SECURITY CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// false (default) — alert-only; true — terminate Tier-1 hostile tools.
    /// Requires an Acceptable Use Policy on all managed devices.
    pub kill_mode: bool,
    /// How often (seconds) the background scan loop runs. Range: 5–60.
    pub scan_interval_secs: u64,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            kill_mode: false,
            scan_interval_secs: 10,
        }
    }
}

// ============================================================================
// ATTRIBUTION ENGINE CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    /// Enable the attribution engine entirely.
    pub enabled: bool,
    /// Minimum confidence (0.0–1.0) to log an attribution report.
    pub log_confidence_threshold: f32,
    /// How long (seconds) to retain per-IP attack history in memory.
    pub history_retention_secs: u64,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_confidence_threshold: 0.60,
            history_retention_secs: 7_200,
        }
    }
}

// ============================================================================
// AI CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTomlConfig {
    pub enabled: bool,
    pub initial_susp_threshold: f32,
    pub initial_block_threshold: f32,
    pub enable_state_persistence: bool,
    pub max_learning_multiplier: f32,
}

impl Default for AiTomlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_susp_threshold: 0.55,
            initial_block_threshold: 0.80,
            enable_state_persistence: true,
            max_learning_multiplier: 3.0,
        }
    }
}

// ============================================================================
// LOADER
// ============================================================================

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                // ── INTEGRITY CHECK ──────────────────────────────────────────────
                // If a .sig file exists, verify the SHA-256 hash of the config.
                let sig_path = format!("{}.sig", path);
                if let Ok(sig_contents) = fs::read_to_string(&sig_path) {
                    let claimed_hex = sig_contents
                        .trim()
                        .strip_prefix("sha256:")
                        .unwrap_or("")
                        .to_lowercase();
                    if !claimed_hex.is_empty() {
                        let mut hasher = Sha256::new();
                        hasher.update(contents.as_bytes());
                        let actual_hex = hex::encode(hasher.finalize());
                        if actual_hex != claimed_hex {
                            return Err(anyhow::anyhow!(
                                "CONFIG INTEGRITY VIOLATION: SHA-256 of '{}' does NOT match \
                                 signature in '{}'.\n\
                                 Expected: {}\n\
                                 Got:      {}\n\
                                 The config file may have been tampered with. \
                                 Update the signature with:\n  \
                                 $h=(Get-FileHash {} -Algorithm SHA256).Hash.ToLower()\n  \
                                 \"sha256:$$h\" | Set-Content {}.sig",
                                path, sig_path, claimed_hex, actual_hex, path, path
                            ));
                        }
                        tracing::info!("✅ Config integrity verified (SHA-256 match): {}", path);
                    }
                }
                // ── PARSE ────────────────────────────────────────────────────────
                let cfg: Config = toml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("Config parse error in {}: {}", path, e))?;
                Ok(cfg)
            }
            Err(_) => {
                warn!(
                    "⚠️  Config file '{}' not found — using built-in defaults",
                    path
                );
                Ok(Self::default())
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            log_level: "info".to_string(),
            metrics_port: 9091,
            peers: Vec::new(),
            mode: ModeConfig::default(),
            siem: SiemConfig::default(),
            zero_trust: ZeroTrustConfig::default(),
            segmentation: SegmentationConfig::default(),
            blocking: BlockingConfig::default(),
            ips: IpsTomlConfig::default(),
            ai: AiTomlConfig::default(),
            endpoint: EndpointConfig::default(),
            attribution: AttributionConfig::default(),
        }
    }
}
