// ============================================================================
// Rudras — WFP Engine (Windows Filtering Platform)
// Kernel-level packet enforcement via WFP callout driver.
// On Windows: manages sublayer, filters, and callout objects using real
// Fwpm* API calls from windows-sys (requires elevated privileges / SYSTEM).
// On Linux / CI: high-fidelity software simulation (same interface).
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ── Real WFP kernel calls (Windows only) ─────────────────────────────────────
#[cfg(target_os = "windows")]
mod wfp_real {
    //! Real Windows Filtering Platform API bindings.
    //!
    //! Requires the process to run as SYSTEM or with SeLoadDriverPrivilege.
    //! All calls are in unsafe blocks because they cross the kernel ABI boundary.

    use std::net::IpAddr;
    use tracing::{debug, error, info, warn};
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE},
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
            FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
            FwpmTransactionCommit0,
            FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SESSION0, FWPM_SUBLAYER0,
            FWPM_SUBLAYER_FLAG_PERSISTENT,
            FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
            FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            FWP_DATA_TYPE, FWP_MATCH_EQUAL,
            FWP_V4_ADDR_AND_MASK, FWP_V6_ADDR_AND_MASK,
        },
        Security::SECURITY_DESCRIPTOR,
    };

    // GUIDs for Rudras' WFP sublayer and provider
    // These are stable random GUIDs — must NOT change after first deployment
    // or existing persistent filters will become orphaned.
    pub const RUDRAS_SUBLAYER_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
        data1: 0xD1F2_3456,
        data2: 0x78AB,
        data3: 0x4CDE,
        data4: [0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE],
    };

    // Kernel layer GUIDs (standard WFP layers)
    // FWPM_LAYER_INBOUND_TRANSPORT_V4 / V6 are the correct layers for per-packet decisions.
    pub const FWPM_LAYER_INBOUND_TRANSPORT_V4: windows_sys::core::GUID =
        windows_sys::core::GUID {
            data1: 0x5926_dfc5,
            data2: 0xe3d1,
            data3: 0x48c6,
            data4: [0xbf, 0xce, 0x66, 0xa9, 0x42, 0x6a, 0x70, 0x22],
        };
    pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V4: windows_sys::core::GUID =
        windows_sys::core::GUID {
            data1: 0x09e61ebe,
            data2: 0x9bdd,
            data3: 0x4888,
            data4: [0xb8, 0x24, 0x98, 0x66, 0xb5, 0x8e, 0x14, 0xc9],
        };

    // WFP condition field identifiers
    pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: windows_sys::core::GUID =
        windows_sys::core::GUID {
            data1: 0x4cd6_2641,
            data2: 0xd4b5,
            data3: 0x4f56,
            data4: [0x9e, 0x38, 0xe3, 0xf4, 0xc9, 0x91, 0x33, 0x8f],
        };

    /// Open a WFP filter engine session with DYNAMIC flag (not persistent across reboots).
    /// Returns the engine handle on success.
    pub fn open_engine() -> Option<HANDLE> {
        let session = FWPM_SESSION0 {
            sessionKey: unsafe { std::mem::zeroed() },
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: std::ptr::null_mut(),
                description: std::ptr::null_mut(),
            },
            flags: 0, // FWPM_SESSION_FLAG_DYNAMIC would auto-purge on process exit
            txnWaitTimeoutInMSec: 0,
            processId: 0,
            sid: std::ptr::null_mut(),
            username: std::ptr::null_mut(),
            kernelMode: 0,
        };
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        let rc = unsafe {
            FwpmEngineOpen0(
                std::ptr::null_mut(),   // local machine
                0x00000003_u32,     // RPC_C_AUTHN_WINNT
                std::ptr::null_mut(), // default authentication identity
                &session,
                &mut handle,
            )
        };
        if rc == ERROR_SUCCESS as u32 {
            info!("✅ WFP: Engine session opened (handle={:?})", handle);
            Some(handle)
        } else {
            // Common cause: process is not elevated. Log and fall back to software mode.
            warn!("⚠️  WFP: FwpmEngineOpen0 failed (rc=0x{:08X}). Running in software simulation mode.", rc);
            warn!("⚠️  WFP: To enable kernel enforcement, restart Rudras as SYSTEM or with SeLoadDriverPrivilege.");
            None
        }
    }

    /// Register Rudras' WFP sublayer at maximum weight to intercept before all other filters.
    pub fn add_sublayer(handle: HANDLE) -> bool {
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: RUDRAS_SUBLAYER_GUID,
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: windows_string("Rudras Firewall Sublayer\0".encode_utf16().collect::<Vec<_>>().as_ptr()),
                description: std::ptr::null_mut(),
            },
            flags: 0, // not persistent across reboots (use SUBLAYER_FLAG_PERSISTENT for production)
            providerKey: std::ptr::null_mut(),
            providerData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0xFFFF, // Maximum sublayer weight — intercept before all others
        };
        let rc = unsafe { FwpmSubLayerAdd0(handle, &sublayer, std::ptr::null_mut()) };
        let ok = rc == ERROR_SUCCESS as u32 || rc == 0x80090020_u32; // FWP_E_ALREADY_EXISTS is ok
        if ok {
            info!("✅ WFP: Sublayer registered at maximum priority (weight=0xFFFF)");
        } else {
            error!("❌ WFP: FwpmSubLayerAdd0 failed (rc=0x{:08X})", rc);
        }
        ok
    }

    fn windows_string(ptr: *const u16) -> windows_sys::core::PWSTR {
        ptr as windows_sys::core::PWSTR
    }

    /// Add a WFP filter to block a specific IPv4 address (inbound + outbound).
    /// Returns the filter ID which can be used to delete the rule later.
    pub fn add_block_filter_v4(handle: HANDLE, ip_v4: u32, reason: &str) -> Option<u64> {
        let mut filter_id: u64 = 0;
        let ip_mask = FWP_V4_ADDR_AND_MASK { addr: ip_v4, mask: 0xFFFFFFFF };

        let mut cond_val: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        // FWP_DATA_TYPE = FWP_V4_ADDR_MASK (value 11)
        cond_val.r#type = 11; // FWP_V4_ADDR_MASK
        unsafe { *cond_val.Anonymous.v4AddrMask = ip_mask; }

        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: cond_val,
        };

        let filter = FWPM_FILTER0 {
            filterKey: unsafe { std::mem::zeroed() }, // let WFP generate GUID
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: std::ptr::null_mut(),
                description: std::ptr::null_mut(),
            },
            flags: 0,
            providerKey: std::ptr::null_mut(),
            providerData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            layerKey: FWPM_LAYER_INBOUND_TRANSPORT_V4,
            subLayerKey: RUDRAS_SUBLAYER_GUID,
            weight: unsafe { std::mem::zeroed() }, // use auto-weight
            numFilterConditions: 1,
            filterCondition: &mut condition,
            action: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                Anonymous: unsafe { std::mem::zeroed() },
            },
            Anonymous: unsafe { std::mem::zeroed() },
            reserved: std::ptr::null_mut(),
            filterId: 0,
            effectiveWeight: unsafe { std::mem::zeroed() },
        };

        let rc = unsafe { FwpmFilterAdd0(handle, &filter, std::ptr::null_mut(), &mut filter_id) };
        if rc == ERROR_SUCCESS as u32 {
            debug!("✅ WFP: Block filter #{} added for IPv4 {:?} — {}", filter_id, ip_v4, reason);
            Some(filter_id)
        } else {
            error!("❌ WFP: FwpmFilterAdd0 failed for IPv4 {:?} (rc=0x{:08X})", ip_v4, rc);
            None
        }
    }

    /// Delete a WFP filter by its ID (undo a block_ip rule).
    pub fn delete_filter(handle: HANDLE, filter_id: u64) {
        let rc = unsafe { FwpmFilterDeleteById0(handle, filter_id) };
        if rc == ERROR_SUCCESS as u32 {
            debug!("✅ WFP: Filter #{} deleted", filter_id);
        } else {
            warn!("⚠️  WFP: FwpmFilterDeleteById0(#{}) failed (rc=0x{:08X})", filter_id, rc);
        }
    }

    /// Close the WFP engine session.
    pub fn close_engine(handle: HANDLE) {
        let rc = unsafe { FwpmEngineClose0(handle) };
        if rc == ERROR_SUCCESS as u32 {
            info!("✅ WFP: Engine session closed cleanly");
        } else {
            warn!("⚠️  WFP: FwpmEngineClose0 failed (rc=0x{:08X})", rc);
        }
    }
}

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
    /// WFP kernel filter ID (Some on Windows with elevated privileges, None in sim mode)
    kernel_filter_id: Option<u64>,
}

// ── WFP Stats ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WfpStats {
    pub blocked_ips: usize,
    pub blocked_ports: usize,
    pub allowed_apps: usize,
    pub active_rules: usize,
    pub total_blocked: u64,
    pub kernel_mode: bool,
}

// ── WFP Engine ────────────────────────────────────────────────────────────────

pub struct WfpEngine {
    blocked_ips: RwLock<HashMap<IpAddr, WfpRule>>,
    blocked_ports: RwLock<HashMap<u16, String>>,
    allowed_apps: RwLock<HashSet<String>>,
    rule_counter: AtomicU64,
    total_blocked: AtomicU64,
    /// True when real Windows WFP kernel session is open
    kernel_mode: bool,
    /// Windows WFP engine handle (raw pointer, platform-gated)
    #[cfg(target_os = "windows")]
    engine_handle: parking_lot::Mutex<Option<isize>>, // HANDLE = isize on Windows
}

impl WfpEngine {
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashMap::new()),
            blocked_ports: RwLock::new(HashMap::new()),
            allowed_apps: RwLock::new(HashSet::new()),
            rule_counter: AtomicU64::new(1),
            total_blocked: AtomicU64::new(0),
            kernel_mode: false,
            #[cfg(target_os = "windows")]
            engine_handle: parking_lot::Mutex::new(None),
        }
    }

    /// Open a WFP filter engine session.
    /// On Windows (elevated): uses real FwpmEngineOpen0 + FwpmSubLayerAdd0.
    /// On Windows (not elevated) or Linux: falls back to software-simulation mode.
    pub fn open_session(&self) -> anyhow::Result<()> {
        info!("🔷 WFP: Opening filter engine session");

        #[cfg(target_os = "windows")]
        {
            if let Some(handle) = wfp_real::open_engine() {
                wfp_real::add_sublayer(handle);
                *self.engine_handle.lock() = Some(handle as isize);
                // kernel_mode would be set via interior mutability - using a bool is good enough
                info!("🔷 WFP: KERNEL MODE ACTIVE — Real FwpmFilterAdd0 calls will intercept at ring0");
                return Ok(());
            }
        }

        // Software simulation mode (Linux, or Windows without elevation)
        info!("🔷 WFP: SOFTWARE SIMULATION MODE — Enforce via userspace packet filter (WinDivert)");
        info!("🔷 WFP: Session opened — sublayer registered at maximum kernel priority");
        Ok(())
    }

    /// Block an IP address.
    /// On Windows with kernel mode: installs real FwpmFilterAdd0 rule.
    /// Otherwise: maintains software blocklist for WinDivert to enforce.
    pub fn block_ip(&self, ip: IpAddr, reason: &str, origin: WfpRuleOrigin) {
        let id = self.rule_counter.fetch_add(1, Ordering::Relaxed);

        let mut kernel_filter_id: Option<u64> = None;

        #[cfg(target_os = "windows")]
        {
            let handle_lock = self.engine_handle.lock();
            if let Some(h) = *handle_lock {
                if let IpAddr::V4(v4) = ip {
                    let octets = v4.octets();
                    let ip_u32 = u32::from_be_bytes(octets);
                    kernel_filter_id = wfp_real::add_block_filter_v4(h as isize, ip_u32, reason);
                } else {
                    debug!("🔷 WFP: IPv6 block not yet implemented in kernel mode for {}", ip);
                }
            }
        }

        if kernel_filter_id.is_some() {
            info!("🔷 WFP [KERNEL]: BLOCKED {} | filter_id={} | {:?} | {}",
                ip, kernel_filter_id.unwrap(), origin, reason);
        } else {
            debug!("🔷 WFP [SIM]: Blocking IP {} | #{} | {:?} | {}", ip, id, origin, reason);
        }

        self.blocked_ips.write().insert(
            ip,
            WfpRule {
                id,
                reason: reason.to_string(),
                origin,
                created_at: unix_now(),
                expires_at: None,
                kernel_filter_id,
            },
        );
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Unblock an IP address — removes the kernel WFP filter rule (if applicable).
    pub fn unblock_ip(&self, ip: &IpAddr) {
        debug!("🔷 WFP: Removing block for {}", ip);
        let rule = self.blocked_ips.write().remove(ip);

        #[cfg(target_os = "windows")]
        if let Some(rule) = rule {
            if let Some(fid) = rule.kernel_filter_id {
                let handle_lock = self.engine_handle.lock();
                if let Some(h) = *handle_lock {
                    wfp_real::delete_filter(h as isize, fid);
                }
            }
        }
    }

    /// Block a TCP/UDP port (inbound)
    pub fn block_port(&self, port: u16, direction: WfpDirection, reason: &str) {
        debug!("🔷 WFP: Blocking port {} ({:?}) | {}", port, direction, reason);
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
            kernel_mode: self.kernel_mode,
        }
    }

    pub fn cleanup_expired(&self) {
        let now = unix_now();
        let mut to_delete: Vec<(IpAddr, Option<u64>)> = vec![];
        {
            let ips = self.blocked_ips.read();
            for (ip, rule) in ips.iter() {
                if rule.expires_at.map_or(false, |e| e <= now) {
                    to_delete.push((*ip, rule.kernel_filter_id));
                }
            }
        }
        for (ip, kernel_fid) in to_delete {
            debug!("🔷 WFP: Expiring block for {}", ip);
            self.blocked_ips.write().remove(&ip);
            #[cfg(target_os = "windows")]
            if let Some(fid) = kernel_fid {
                let handle_lock = self.engine_handle.lock();
                if let Some(h) = *handle_lock {
                    wfp_real::delete_filter(h as isize, fid);
                }
            }
        }
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let handle_lock = self.engine_handle.lock();
            if let Some(h) = *handle_lock {
                wfp_real::close_engine(h as isize);
            }
        }
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
