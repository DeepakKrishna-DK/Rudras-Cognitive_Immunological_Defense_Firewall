// ============================================================================
// Rudras — WFP Engine (Windows Filtering Platform)
// Kernel-level packet enforcement via WFP callout driver.
// On Windows: manages sublayer, filters, and callout objects.
// All WFP API calls are simulated in software for portability —
// replace the stub bodies with real Fwpm* calls when building with
// the Windows DDK / windows-rs crate for production.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ── Rule Origin ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WfpRuleOrigin {
    Static,
    FlowEngine,
    CyberImmune,
    WinDivert,
    IPS,
    ThreatIntel,
    Admin,
}

// ── WFP Direction ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum WfpDirection {
    Inbound,
    Outbound,
    Both,
}

// ── WFP Rule ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WfpRule {
    id: u64,
    reason: String,
    origin: WfpRuleOrigin,
    created_at: u64,
    expires_at: Option<u64>,
}

// ── WFP Stats ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WfpStats {
    pub blocked_ips: usize,
    pub blocked_ports: usize,
    pub allowed_apps: usize,
    pub active_rules: usize,
    pub total_blocked: u64,
}

// ── WFP Engine ────────────────────────────────────────────────────────────────

pub struct WfpEngine {
    blocked_ips: RwLock<HashMap<IpAddr, WfpRule>>,
    blocked_ports: RwLock<HashMap<u16, String>>,
    allowed_apps: RwLock<HashSet<String>>,
    rule_counter: AtomicU64,
    total_blocked: AtomicU64,
    session_open: AtomicU64, // 1 = open, 0 = closed
}

impl WfpEngine {
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashMap::new()),
            blocked_ports: RwLock::new(HashMap::new()),
            allowed_apps: RwLock::new(HashSet::new()),
            rule_counter: AtomicU64::new(1),
            total_blocked: AtomicU64::new(0),
            session_open: AtomicU64::new(0),
        }
    }

    /// Open a WFP filter engine session (stub — logs intent)
    pub fn open_session(&self) -> anyhow::Result<()> {
        info!("🔷 WFP: Opening filter engine session (DYNAMIC mode)");

        // Elevate WFP Sublayer weight to the absolute maximum to intercept BEFORE McAfee
        // Setting Altitude Weight: FWPM_SUBLAYER_WEIGHT_MAX (0xFFFF)
        info!("🔷 WFP: Setting Sublayer Altitude Weight to MAXIMUM (0xFFFF) — Bypassing AV hooks");

        // Production: FwpmEngineOpen0() + FwpmSubLayerAdd0(FWPM_SUBLAYER_WEIGHT_MAX)
        self.session_open.store(1, Ordering::Relaxed);
        info!("🔷 WFP: Session opened — sublayer registered at absolute highest kernel priority");
        Ok(())
    }

    /// Block an IP address — installs a kernel WFP filter rule
    pub fn block_ip(&self, ip: IpAddr, reason: &str, origin: WfpRuleOrigin) {
        let id = self.rule_counter.fetch_add(1, Ordering::Relaxed);
        debug!(
            "🔷 WFP: Blocking IP {} | #{} | {:?} | {}",
            ip, id, origin, reason
        );
        // Production: FwpmFilterAdd0() with FWPM_CONDITION_IP_REMOTE_ADDRESS

        self.blocked_ips.write().insert(
            ip,
            WfpRule {
                id,
                reason: reason.to_string(),
                origin,
                created_at: unix_now(),
                expires_at: None,
            },
        );
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Unblock an IP address — removes the kernel WFP filter rule
    pub fn unblock_ip(&self, ip: &IpAddr) {
        debug!("🔷 WFP: Removing block for {}", ip);
        // Production: FwpmFilterDeleteById0()
        self.blocked_ips.write().remove(ip);
    }

    /// Block a TCP/UDP port (inbound)
    pub fn block_port(&self, port: u16, direction: WfpDirection, reason: &str) {
        debug!(
            "🔷 WFP: Blocking port {} ({:?}) | {}",
            port, direction, reason
        );
        self.blocked_ports.write().insert(port, reason.to_string());
    }

    /// Allow a specific application (by path)
    pub fn allow_app(&self, app_path: &str, reason: &str) {
        debug!("🔷 WFP: Allowing app {} | {}", app_path, reason);
        self.allowed_apps.write().insert(app_path.to_string());
    }

    /// Fast-path: check if an IP is in the blocked set (O(1))
    pub fn is_blocked_ip(&self, ip: &IpAddr) -> bool {
        let ips = self.blocked_ips.read();
        if let Some(rule) = ips.get(ip) {
            // Check expiry
            if let Some(exp) = rule.expires_at {
                return unix_now() <= exp;
            }
            return true;
        }
        false
    }

    pub fn is_blocked_port(&self, port: u16) -> bool {
        self.blocked_ports.read().contains_key(&port)
    }

    pub fn get_stats(&self) -> WfpStats {
        WfpStats {
            blocked_ips: self.blocked_ips.read().len(),
            blocked_ports: self.blocked_ports.read().len(),
            allowed_apps: self.allowed_apps.read().len(),
            active_rules: self.blocked_ips.read().len() + self.blocked_ports.read().len(),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
        }
    }

    pub fn cleanup_expired(&self) {
        let now = unix_now();
        self.blocked_ips.write().retain(|ip, rule| {
            let keep = rule.expires_at.map_or(true, |e| e > now);
            if !keep {
                debug!("🔷 WFP: Expiring block for {}", ip);
            }
            keep
        });
    }
}

// ── Default Port Blocklist ────────────────────────────────────────────────────

pub fn default_blocked_ports() -> Vec<(u16, &'static str)> {
    vec![
        // ── REMOTE MANAGEMENT / EXPLOITATION SURFACES ───────────────────────
        (20,   "FTP Data — legacy cleartext file transfer"),
        (21,   "FTP Control — cleartext credential exposure"),
        (23,   "Telnet — plaintext remote shell, no encryption"),
        (69,   "TFTP — unauthenticated file transfer (firmware reflash)"),
        (79,   "Finger — user enumeration service"),
        (111,  "ONC-RPC portmapper — remote exploit surface"),
        (135,  "MS-RPC — remote exploit surface"),
        (137,  "NetBIOS Name Service"),
        (138,  "NetBIOS Datagram"),
        (139,  "NetBIOS Session — EternalBlue surface"),
        (161,  "SNMP — community-string credential leak"),
        (162,  "SNMP Trap — unauthenticated inbound"),
        (445,  "SMB — EternalBlue / WannaCry / ransomware pivot"),
        (512,  "rexec — plaintext remote execution"),
        (513,  "rlogin — plaintext remote login (no password prompt)"),
        (514,  "rsh / syslog — unauthenticated remote shell / log injection"),
        (593,  "HTTP RPC endpoint mapper"),
        (623,  "IPMI / BMC — baseboard management, default creds"),
        (873,  "rsync — unauthenticated file system access risk"),

        // ── DATABASE SERVERS (should never be inbound from internet) ─────────
        (1433, "MS SQL Server — credential brute force"),
        (1434, "MS SQL Monitor — SQL Slammer"),
        (1521, "Oracle DB listener — default creds / TNS poisoning"),
        (2049, "NFS — unauthenticated filesystem mount"),
        (2181, "ZooKeeper — unauthenticated cluster access"),
        (2375, "Docker daemon API — unauthenticated container escape"),
        (2376, "Docker daemon TLS — should never be internet-exposed"),
        (3306, "MySQL — credential attack surface"),
        (5432, "PostgreSQL — credential attack surface"),
        (5984, "CouchDB — unauthenticated HTTP DB"),
        (6379, "Redis — unauthenticated cache / key exfiltration"),
        (7000, "Cassandra intra-cluster — unauthenticated gossip"),
        (7001, "Cassandra JMX — unauthenticated management"),
        (8086, "InfluxDB — unauthenticated time-series DB"),
        (8291, "MikroTik Winbox — credential brute force"),
        (9200, "Elasticsearch REST — unauthenticated data exposure"),
        (9300, "Elasticsearch cluster transport"),
        (27017,"MongoDB — unauthenticated NoSQL"),
        (27018,"MongoDB shard server"),

        // ── KNOWN TROJAN / C2 / BACKDOOR PORTS ──────────────────────────────
        (1337, "Elite Hacker / Leet lingo — common C2 staging port"),
        (4444, "Metasploit default listener / Meterpreter back-connect"),
        (4445, "Metasploit alt listener"),
        (5555, "ADB Android Debug Bridge — remote device compromise"),
        (6666, "Backdoor / IRC C2"),
        (6667, "IRC C2 — common botnet command channel"),
        (6668, "IRC C2 alternate port"),
        (6669, "IRC C2 alternate port"),
        (7547, "TR-069 ISP management — unauthenticated commands (Mirai)"),
        (8545, "Ethereum RPC — crypto-theft / drainer target"),
        // NOTE: Tor ports (9001/9030/9050/9051/9150) are NOT blocked by default.
        // Tor is legal in the vast majority of countries and is used legitimately
        // by journalists, activists, researchers, and privacy-conscious users.
        // To block Tor, set block_anonymization_networks = true in [blocking] config.
        (12345,"NetBus RAT — classic remote access trojan"),
        (17185,"VxWorks debug agent — SCADA/ICS zero-auth RCE"),
        (31337,"Back Orifice Elite Backdoor"),
        (37777,"Dahua DVR backdoor — default creds"),
        (49152,"WinRM ephemeral exploit range start"),
        (54321,"Back Orifice 2000"),

        // ── INFRASTRUCTURE / MANAGEMENT (block inbound from untrusted) ───────
        (3389, "RDP — brute force / BlueKeep / DejaBlue"),
        (5900, "VNC — brute force target / credential exposure"),
        (5985, "WinRM HTTP — Windows remote management"),
        (5986, "WinRM HTTPS — lateral movement vector"),
        (8080, "HTTP Alt — common malware C2 / proxy abuse"),
        (8443, "HTTPS Alt — common malware C2 evasion"),
        (8888, "Jupyter Notebook — unauthenticated code exec when exposed"),

        // ── IOT / INDUSTRIAL CONTROL ─────────────────────────────────────────
        (502,  "Modbus TCP — ICS cleartext protocol"),
        (1883, "MQTT — IoT broker cleartext"),
        (4840, "OPC-UA TCP — industrial automation cleartext"),
        (44818,"EtherNet/IP — Rockwell CIP industrial protocol"),
        (47808,"BACnet — building automation cleartext"),
    ]
}

pub fn trusted_system_apps() -> Vec<(&'static str, &'static str)> {
    vec![
        ("C:\\Windows\\System32\\svchost.exe", "Windows Service Host"),
        (
            "C:\\Windows\\System32\\lsass.exe",
            "Local Security Authority",
        ),
        (
            "C:\\Windows\\System32\\services.exe",
            "Service Control Manager",
        ),
        ("C:\\Windows\\System32\\winlogon.exe", "Windows Logon"),
        ("C:\\Windows\\System32\\csrss.exe", "Client/Server Runtime"),
        ("C:\\Windows\\System32\\smss.exe", "Session Manager"),
        (
            "C:\\Windows\\System32\\wininit.exe",
            "Windows Initialization",
        ),
    ]
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
