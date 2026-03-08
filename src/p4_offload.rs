#![allow(dead_code, unused_imports, unused_variables)]

//! P4 Offload Engine — P4Runtime control-plane client for installing flow rules
//! onto P4-programmable SmartNICs / ASICs (e.g. Intel Tofino, NVIDIA BlueField DPU).
//!
//! Communicates over a TCP connection using P4Runtime-style JSON messages.
//! Supplements `hardware_accel.rs` which auto-detects the P4Runtime backend;
//! this module performs the actual rule CRUD operations.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// Re-use the P4 types defined in hardware_accel so all P4 code shares the same vocabulary.
use crate::hardware_accel::{P4Action, P4MatchField, P4MatchType, P4Rule};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// P4 table model (higher-level than hardware_accel's P4Rule)
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a P4 table's schema (the data-plane programmer's view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4Table {
    /// e.g. "MyIngress.acl_table"
    pub table_name: String,
    pub table_id: u32,
    pub match_fields: Vec<P4TableMatchField>,
    pub actions: Vec<P4TableAction>,
    pub max_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4TableMatchField {
    pub field_name: String,
    pub field_id: u32,
    pub match_type: P4MatchType,
    pub bit_width: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4TableAction {
    pub action_name: String,
    pub action_id: u32,
    pub params: Vec<P4ActionParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4ActionParam {
    pub param_name: String,
    pub param_id: u32,
    pub bit_width: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Table entry (the wire format sent to the device)
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete entry to be written into a P4 table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4TableEntry {
    pub table_id: u32,
    pub priority: u32,
    pub match_fields: Vec<P4EntryMatch>,
    pub action: P4EntryAction,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4EntryMatch {
    pub field_id: u32,
    pub match_type: P4MatchType,
    pub value: Vec<u8>,
    pub mask: Option<Vec<u8>>,
    pub prefix_len: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P4EntryAction {
    pub action_id: u32,
    pub params: Vec<(u32, Vec<u8>)>, // (param_id, value)
}

// ─────────────────────────────────────────────────────────────────────────────
// P4Runtime write request (simplified wire format)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
enum P4WriteType {
    Insert,
    Modify,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct P4WriteRequest {
    device_id: u64,
    write_type: P4WriteType,
    entry: P4TableEntry,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct P4WriteResponse {
    success: bool,
    error_message: Option<String>,
    entry_handle: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// P4Runtime TCP client
// ─────────────────────────────────────────────────────────────────────────────

/// Thin TCP client for P4Runtime JSON messages.
///
/// Production deployments would use a gRPC channel; this implementation sends
/// length-prefixed JSON over TCP which is compatible with the reference
/// P4Runtime agent (`p4rt-agent`) listening on the configured endpoint.
struct P4RuntimeClient {
    endpoint: SocketAddr,
    device_id: u64,
    connect_timeout: Duration,
}

impl P4RuntimeClient {
    fn new(endpoint: SocketAddr, device_id: u64) -> Self {
        P4RuntimeClient {
            endpoint,
            device_id,
            connect_timeout: Duration::from_secs(3),
        }
    }

    /// Send a single write request and return the response.
    fn write_table_entry(&self, entry: P4TableEntry, write_type: P4WriteType) -> Result<P4WriteResponse, String> {
        let request = P4WriteRequest {
            device_id: self.device_id,
            write_type,
            entry,
            timestamp: unix_secs(),
        };

        let payload = serde_json::to_vec(&request)
            .map_err(|e| format!("serialise error: {e}"))?;

        let mut stream = TcpStream::connect_timeout(&self.endpoint, self.connect_timeout)
            .map_err(|e| format!("connect to {} failed: {e}", self.endpoint))?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        // 4-byte big-endian length prefix + JSON payload.
        let len_prefix = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_prefix).map_err(|e| format!("send length: {e}"))?;
        stream.write_all(&payload).map_err(|e| format!("send body: {e}"))?;

        // Read 4-byte response length then response body.
        let mut rlen = [0u8; 4];
        stream.read_exact(&mut rlen).map_err(|e| format!("recv length: {e}"))?;
        let rlen = u32::from_be_bytes(rlen) as usize;
        if rlen > 65_536 {
            return Err(format!("response too large: {rlen} bytes"));
        }
        let mut rbuf = vec![0u8; rlen];
        stream.read_exact(&mut rbuf).map_err(|e| format!("recv body: {e}"))?;

        serde_json::from_slice::<P4WriteResponse>(&rbuf)
            .map_err(|e| format!("deserialise response: {e}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Known P4 table IDs (must match the compiled P4 program)
// ─────────────────────────────────────────────────────────────────────────────

/// Table IDs assigned by the P4 compiler for Rudras's reference P4 program.
mod table_ids {
    pub const ACL_BLOCK_TABLE: u32 = 0x0001_0001;
    pub const IPV4_FORWARD_TABLE: u32 = 0x0001_0002;
    pub const RATE_LIMIT_TABLE: u32 = 0x0001_0003;
    pub const DNS_FILTER_TABLE: u32 = 0x0001_0004;
}

mod action_ids {
    pub const DROP: u32 = 0x0002_0001;
    pub const FORWARD: u32 = 0x0002_0002;
    pub const RATE_LIMIT: u32 = 0x0002_0003;
    pub const REDIRECT_TO_IDS: u32 = 0x0002_0004;
}

mod field_ids {
    pub const IPV4_SRC_ADDR: u32 = 1;
    pub const IPV4_DST_ADDR: u32 = 2;
    pub const IPV4_PROTOCOL: u32 = 3;
    pub const TCP_DST_PORT: u32 = 4;
    pub const UDP_DST_PORT: u32 = 5;
    pub const ETH_ETHERTYPE: u32 = 6;
}

// ─────────────────────────────────────────────────────────────────────────────
// P4 Offload Engine
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct P4OffloadStats {
    pub rules_installed: AtomicU64,
    pub rules_removed: AtomicU64,
    pub write_errors: AtomicU64,
    pub total_writes: AtomicU64,
}

pub struct P4OffloadEngine {
    client: Option<P4RuntimeClient>,
    /// Tracks installed rules: handle → entry snapshot.
    installed_rules: RwLock<HashMap<u64, P4TableEntry>>,
    /// Auto-increment handle counter (local, not hardware-assigned).
    handle_counter: AtomicU64,
    pub stats: Arc<P4OffloadStats>,
    /// Whether a real hardware device is reachable.
    hardware_available: bool,
}

impl P4OffloadEngine {
    /// Create with a live P4Runtime endpoint.
    pub fn new(grpc_endpoint: &str, device_id: u64) -> Self {
        let endpoint = grpc_endpoint.parse::<SocketAddr>().ok();
        let (client, hardware_available) = if let Some(addr) = endpoint {
            (Some(P4RuntimeClient::new(addr, device_id)), true)
        } else {
            warn!(endpoint = %grpc_endpoint, "P4OffloadEngine: invalid endpoint, running in software-only mode");
            (None, false)
        };

        info!(
            endpoint = %grpc_endpoint,
            device_id = %device_id,
            hw = hardware_available,
            "P4OffloadEngine: initialised"
        );

        P4OffloadEngine {
            client,
            installed_rules: RwLock::new(HashMap::new()),
            handle_counter: AtomicU64::new(1),
            stats: Arc::new(P4OffloadStats::default()),
            hardware_available,
        }
    }

    /// Create in software-only / simulation mode (no real P4 device).
    pub fn new_software_only() -> Self {
        P4OffloadEngine {
            client: None,
            installed_rules: RwLock::new(HashMap::new()),
            handle_counter: AtomicU64::new(1),
            stats: Arc::new(P4OffloadStats::default()),
            hardware_available: false,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // High-level rule helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Install a block rule for a specific source IPv4 address.
    /// Maps to the `acl_block_table` with action `DROP`.
    pub fn install_block_rule(&self, src_ip: IpAddr) -> Option<u64> {
        let src_bytes = match src_ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(_) => {
                warn!("P4OffloadEngine: IPv6 block rules not yet supported");
                return None;
            }
        };

        let entry = P4TableEntry {
            table_id: table_ids::ACL_BLOCK_TABLE,
            priority: 100,
            match_fields: vec![P4EntryMatch {
                field_id: field_ids::IPV4_SRC_ADDR,
                match_type: P4MatchType::Exact,
                value: src_bytes,
                mask: None,
                prefix_len: None,
            }],
            action: P4EntryAction {
                action_id: action_ids::DROP,
                params: vec![],
            },
            metadata: {
                let mut m = HashMap::new();
                m.insert("reason".into(), "rudras-block".into());
                m.insert("installed_at".into(), unix_secs().to_string());
                m
            },
        };

        self.write_entry(entry, P4WriteType::Insert)
    }

    /// Install a rate-limit rule for a destination port (e.g. HTTP/HTTPS under SYN flood).
    pub fn install_rate_limit_rule(&self, dst_port: u16, packets_per_sec: u32) -> Option<u64> {
        let port_bytes = dst_port.to_be_bytes().to_vec();
        let pps_bytes = packets_per_sec.to_be_bytes().to_vec();

        let entry = P4TableEntry {
            table_id: table_ids::RATE_LIMIT_TABLE,
            priority: 50,
            match_fields: vec![P4EntryMatch {
                field_id: field_ids::TCP_DST_PORT,
                match_type: P4MatchType::Exact,
                value: port_bytes,
                mask: None,
                prefix_len: None,
            }],
            action: P4EntryAction {
                action_id: action_ids::RATE_LIMIT,
                params: vec![(1, pps_bytes)], // param_id=1 = "pps_limit"
            },
            metadata: {
                let mut m = HashMap::new();
                m.insert("pps".into(), packets_per_sec.to_string());
                m
            },
        };

        self.write_entry(entry, P4WriteType::Insert)
    }

    /// Install a DNS redirect rule (sends DNS traffic to the IDS engine for deep inspection).
    pub fn install_dns_redirect_rule(&self) -> Option<u64> {
        let entry = P4TableEntry {
            table_id: table_ids::DNS_FILTER_TABLE,
            priority: 200, // High priority — checked before generic forward rules.
            match_fields: vec![P4EntryMatch {
                field_id: field_ids::UDP_DST_PORT,
                match_type: P4MatchType::Exact,
                value: 53u16.to_be_bytes().to_vec(),
                mask: None,
                prefix_len: None,
            }],
            action: P4EntryAction {
                action_id: action_ids::REDIRECT_TO_IDS,
                params: vec![],
            },
            metadata: HashMap::new(),
        };

        self.write_entry(entry, P4WriteType::Insert)
    }

    /// Remove a previously installed rule by its local handle.
    pub fn remove_rule(&self, handle: u64) -> bool {
        let entry = self.installed_rules.read().get(&handle).cloned();
        if let Some(entry) = entry {
            let success = self.send_write(entry, P4WriteType::Delete).is_some();
            if success {
                self.installed_rules.write().remove(&handle);
                self.stats.rules_removed.fetch_add(1, Ordering::Relaxed);
                info!(handle = %handle, "P4OffloadEngine: rule removed");
            }
            success
        } else {
            warn!(handle = %handle, "P4OffloadEngine: remove_rule — handle not found");
            false
        }
    }

    /// Install a generic `P4Rule` (from the hardware_accel module's types).
    pub fn install_p4_rule(&self, rule: &P4Rule) -> Option<u64> {
        let fields: Vec<P4EntryMatch> = rule
            .match_fields
            .iter()
            .enumerate()
            .map(|(i, f)| P4EntryMatch {
                field_id: i as u32 + 1,
                match_type: f.match_type.clone(),
                value: f.value.clone(),
                mask: f.mask.clone(),
                prefix_len: None,
            })
            .collect();

        let action_id = match &rule.action {
            P4Action::Drop => action_ids::DROP,
            P4Action::Forward { .. } => action_ids::FORWARD,
            P4Action::Redirect { .. } => action_ids::REDIRECT_TO_IDS,
            P4Action::RateLimit { .. } => action_ids::RATE_LIMIT,
            P4Action::Mark { .. } => action_ids::FORWARD,
            P4Action::SendToController => action_ids::REDIRECT_TO_IDS,
        };

        let entry = P4TableEntry {
            table_id: 0x0001_0001, // Default to ACL table; real impl would resolve by table name.
            priority: rule.priority,
            match_fields: fields,
            action: P4EntryAction { action_id, params: vec![] },
            metadata: HashMap::new(),
        };

        self.write_entry(entry, P4WriteType::Insert)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal write plumbing
    // ─────────────────────────────────────────────────────────────────────

    fn write_entry(&self, entry: P4TableEntry, write_type: P4WriteType) -> Option<u64> {
        let handle = self.handle_counter.fetch_add(1, Ordering::Relaxed);
        if let Some(h) = self.send_write(entry.clone(), write_type) {
            self.installed_rules.write().insert(handle, entry);
            self.stats.rules_installed.fetch_add(1, Ordering::Relaxed);
            Some(handle)
        } else {
            None
        }
    }

    fn send_write(&self, entry: P4TableEntry, write_type: P4WriteType) -> Option<u64> {
        self.stats.total_writes.fetch_add(1, Ordering::Relaxed);

        if let Some(ref client) = self.client {
            match client.write_table_entry(entry, write_type) {
                Ok(resp) if resp.success => {
                    debug!(handle = ?resp.entry_handle, "P4OffloadEngine: write success");
                    Some(resp.entry_handle.unwrap_or(0))
                }
                Ok(resp) => {
                    error!(err = ?resp.error_message, "P4OffloadEngine: write rejected by device");
                    self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
                Err(e) => {
                    error!(err = %e, "P4OffloadEngine: TCP write failed");
                    self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        } else {
            // Software mode: simulate success.
            debug!("P4OffloadEngine: software mode — write simulated");
            Some(0)
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Accessors
    // ─────────────────────────────────────────────────────────────────────

    pub fn installed_rule_count(&self) -> usize {
        self.installed_rules.read().len()
    }

    pub fn is_hardware_available(&self) -> bool {
        self.hardware_available
    }

    pub fn list_installed_handles(&self) -> Vec<u64> {
        self.installed_rules.read().keys().copied().collect()
    }

    /// Flush all installed rules from the device.
    pub fn flush_all(&self) {
        let handles: Vec<u64> = self.installed_rules.read().keys().copied().collect();
        for h in handles {
            self.remove_rule(h);
        }
        info!("P4OffloadEngine: all rules flushed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared Arc wrapper
// ─────────────────────────────────────────────────────────────────────────────

pub type SharedP4OffloadEngine = Arc<P4OffloadEngine>;

pub fn new_shared_engine(grpc_endpoint: &str, device_id: u64) -> SharedP4OffloadEngine {
    Arc::new(P4OffloadEngine::new(grpc_endpoint, device_id))
}
