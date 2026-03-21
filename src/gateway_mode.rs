// ============================================================================
// Rudras — Gateway Mode (Perimeter + VRRP-style HA)
// Active/passive High Availability failover with heartbeat protocol.
// Primary node broadcasts heartbeat every 1s; standby node takes over
// after 3 missed heartbeats (3 second failure detection window).
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── HA Role ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HaRole {
    Primary,
    Standby,
    Initializing,
    Fault,    // Failed state — waiting for manual recovery
}

// ── Heartbeat Message ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    pub version: u8,            // Protocol version (1)
    pub sender_id: String,      // Unique node identifier (UUID or hostname)
    pub role: HaRole,
    pub seq: u64,               // Monotonically increasing
    pub timestamp: u64,         // Unix seconds
    pub priority: u8,           // 1-255; higher = preferred primary
    pub virtual_ip: String,     // The protected VIP (e.g. 192.168.1.1)
    pub active_connections: u32,
    pub cpu_load_pct: u8,
    pub health_ok: bool,
}

impl HeartbeatMsg {
    /// Encode to 64-byte fixed frame for UDP multicasting.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(0xAB); // magic byte 1
        buf.push(0xCD); // magic byte 2
        buf.push(self.version);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.push(self.priority);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(if self.health_ok { 1 } else { 0 });
        buf.push(match self.role {
            HaRole::Primary      => 1,
            HaRole::Standby      => 2,
            HaRole::Initializing => 3,
            HaRole::Fault        => 4,
        });
        buf.extend_from_slice(&self.active_connections.to_be_bytes());
        buf.push(self.cpu_load_pct);
        // Sender ID (up to 16 bytes)
        let id_bytes = self.sender_id.as_bytes();
        let copy_len = id_bytes.len().min(16);
        buf.extend_from_slice(&id_bytes[..copy_len]);
        buf.extend(std::iter::repeat_n(0u8, 16 - copy_len));
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 38 { return None; }
        if data[0] != 0xAB || data[1] != 0xCD { return None; }
        let version = data[2];
        let seq = u64::from_be_bytes(data[3..11].try_into().ok()?);
        let priority = data[11];
        let timestamp = u64::from_be_bytes(data[12..20].try_into().ok()?);
        let health_ok = data[20] == 1;
        let role = match data[21] {
            1 => HaRole::Primary,
            2 => HaRole::Standby,
            3 => HaRole::Initializing,
            _ => HaRole::Fault,
        };
        let active_connections = u32::from_be_bytes(data[22..26].try_into().ok()?);
        let cpu_load_pct = data[26];
        let id_end = data[27..].iter().position(|&b| b == 0).map(|p| 27 + p).unwrap_or(data.len().min(43));
        let sender_id = String::from_utf8_lossy(&data[27..id_end]).to_string();
        Some(HeartbeatMsg {
            version,
            sender_id,
            role,
            seq,
            timestamp,
            priority,
            virtual_ip: String::new(),
            active_connections,
            cpu_load_pct,
            health_ok,
        })
    }
}

// ── HA Peer State ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HaPeer {
    pub address: SocketAddr,
    pub node_id: String,
    pub priority: u8,
    pub last_heartbeat: u64,  // Unix seconds
    pub last_seq: u64,
    pub missed_heartbeats: u32,
    pub reachable: bool,
    pub health_ok: bool,
}

impl HaPeer {
    pub fn new(address: SocketAddr, node_id: &str, priority: u8) -> Self {
        Self {
            address,
            node_id: node_id.to_string(),
            priority,
            last_heartbeat: 0,
            last_seq: 0,
            missed_heartbeats: 0,
            reachable: false,
            health_ok: false,
        }
    }

    pub fn update_from_heartbeat(&mut self, msg: &HeartbeatMsg) {
        self.last_heartbeat = unix_secs();
        self.last_seq = msg.seq;
        self.missed_heartbeats = 0;
        self.reachable = true;
        self.health_ok = msg.health_ok;
    }

    pub fn staleness_secs(&self) -> u64 {
        unix_secs().saturating_sub(self.last_heartbeat)
    }
}

// ── Gateway Mode ──────────────────────────────────────────────────────────────

pub struct GatewayMode {
    pub enabled: bool,
    pub node_id: String,
    pub virtual_ip: Option<String>,
    pub role: RwLock<HaRole>,
    pub ha_peers: RwLock<Vec<HaPeer>>,
    /// Heartbeat sequence counter
    heartbeat_seq: AtomicU64,
    /// Timestamp of last received primary heartbeat
    last_primary_seen: AtomicU64,
    /// Total failovers this session
    failover_count: AtomicU64,
    /// Priority (1-255; higher = stronger preference for primary)
    priority: u8,
    /// Heartbeat interval in milliseconds
    heartbeat_interval_ms: u64,
    /// Number of missed heartbeats before failover trigger
    failover_threshold: u32,
    /// Failover event log
    failover_history: RwLock<VecDeque<FailoverEvent>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub timestamp: u64,
    pub old_role: HaRole,
    pub new_role: HaRole,
    pub trigger: String,
}

impl GatewayMode {
    pub fn new() -> Self {
        let node_id = hostname_or_default();
        Self {
            enabled: false,
            node_id: node_id.clone(),
            virtual_ip: None,
            role: RwLock::new(HaRole::Initializing),
            ha_peers: RwLock::new(vec![]),
            heartbeat_seq: AtomicU64::new(0),
            last_primary_seen: AtomicU64::new(0),
            failover_count: AtomicU64::new(0),
            priority: 100,
            heartbeat_interval_ms: 1000,
            failover_threshold: 3,
            failover_history: RwLock::new(VecDeque::new()),
        }
    }

    pub fn with_ha(self, peer_addr: &str) -> Self {
        if let Ok(addr) = peer_addr.parse::<SocketAddr>() {
            self.ha_peers.write().push(HaPeer::new(addr, peer_addr, 90));
            info!("🌐 Gateway: HA peer added: {}", peer_addr);
        } else {
            warn!("🌐 Gateway: Invalid peer address '{}' — skipped", peer_addr);
        }
        self
    }

    pub fn with_virtual_ip(mut self, vip: &str) -> Self {
        self.virtual_ip = Some(vip.to_string());
        self
    }

    pub fn with_priority(mut self, prio: u8) -> Self {
        self.priority = prio;
        self
    }

    pub fn enable(&mut self) {
        self.enabled = true;
        *self.role.write() = if self.priority >= 100 {
            HaRole::Primary
        } else {
            HaRole::Standby
        };
        let role = self.role.read().clone();
        info!("🌐 Gateway Mode: ENABLED | node_id={} | priority={} | role={:?} | vip={:?}",
            self.node_id, self.priority, role, self.virtual_ip);
    }

    /// Generate a heartbeat message for broadcast to HA peers.
    pub fn generate_heartbeat(&self) -> HeartbeatMsg {
        let seq = self.heartbeat_seq.fetch_add(1, Ordering::Relaxed);
        HeartbeatMsg {
            version: 1,
            sender_id: self.node_id.clone(),
            role: self.role.read().clone(),
            seq,
            timestamp: unix_secs(),
            priority: self.priority,
            virtual_ip: self.virtual_ip.clone().unwrap_or_default(),
            active_connections: 0,
            cpu_load_pct: 0,
            health_ok: true,
        }
    }

    /// Process an incoming heartbeat from a peer.
    /// This updates peer state and may trigger role transitions.
    pub fn receive_heartbeat(&self, msg: &HeartbeatMsg) {
        let now = unix_secs();
        let mut peers = self.ha_peers.write();
        if let Some(peer) = peers.iter_mut().find(|p| p.node_id == msg.sender_id) {
            peer.update_from_heartbeat(msg);
        }

        // If we're standby and we received a primary heartbeat → record it
        let role = self.role.read().clone();
        if msg.role == HaRole::Primary && role == HaRole::Standby {
            self.last_primary_seen.store(now, Ordering::Relaxed);
            debug!("🌐 HA: Received heartbeat from primary {} (seq={})", msg.sender_id, msg.seq);
        }

        // If a standby receives a heartbeat from a node with lower priority claiming primary,
        // and our priority is higher — we assert primary role (split-brain recovery)
        if msg.role == HaRole::Primary
            && role == HaRole::Standby
            && msg.priority < self.priority
        {
            warn!("🌐 HA: Priority dispute — remote primary priority {} < our priority {} — asserting primary",
                msg.priority, self.priority);
            drop(role);
            self.transition_role(HaRole::Primary, "Priority preemption");
        }
    }

    /// Periodic tick — call every heartbeat_interval_ms.
    /// Detects missed heartbeats and triggers failover.
    pub fn tick(&self) {
        if !self.enabled { return; }

        let now = unix_secs();

        {
            let mut peers = self.ha_peers.write();
            for peer in peers.iter_mut() {
                let age = now.saturating_sub(peer.last_heartbeat);
                // Each heartbeat_interval_ms gap = one missed heartbeat
                let expected_missed = (age * 1000 / self.heartbeat_interval_ms) as u32;
                peer.missed_heartbeats = expected_missed;
                if expected_missed > 0 && peer.reachable {
                    debug!("🌐 HA: Peer {} missed {} heartbeats", peer.node_id, expected_missed);
                }
                if expected_missed >= self.failover_threshold {
                    peer.reachable = false;
                }
            }
        }

        // If we're standby and primary has been absent too long → failover
        let role = self.role.read().clone();
        if role == HaRole::Standby {
            let last = self.last_primary_seen.load(Ordering::Relaxed);
            if last > 0 {
                let gap_ms = now.saturating_sub(last) * 1000;
                let threshold_ms = self.heartbeat_interval_ms * self.failover_threshold as u64;
                if gap_ms >= threshold_ms {
                    warn!("🚨 HA FAILOVER: Primary absent for {}s (threshold={}ms) — Assuming primary role",
                        gap_ms / 1000, threshold_ms);
                    drop(role);
                    self.transition_role(HaRole::Primary, &format!("Primary absent {}s", gap_ms / 1000));
                    self.failover_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn transition_role(&self, new_role: HaRole, trigger: &str) {
        let old_role = self.role.read().clone();
        *self.role.write() = new_role.clone();

        let event = FailoverEvent {
            timestamp: unix_secs(),
            old_role: old_role.clone(),
            new_role: new_role.clone(),
            trigger: trigger.to_string(),
        };

        let mut history = self.failover_history.write();
        history.push_back(event);
        if history.len() > 20 { history.pop_front(); }

        info!("🌐 HA ROLE CHANGE: {:?} → {:?} | reason={}", old_role, new_role, trigger);

        // In production: advertise GARP (Gratuitous ARP) for VIP takeover,
        // update routing tables, and notify load balancer via health endpoint.
        if new_role == HaRole::Primary {
            if let Some(ref vip) = self.virtual_ip {
                info!("🌐 HA: Asserting Virtual IP {} — send GARP to update ARP caches", vip);
                // Production: send 3x GARP packets to broadcast (ff:ff:ff:ff:ff:ff)
            }
        }
    }

    pub fn get_role(&self) -> HaRole {
        self.role.read().clone()
    }

    pub fn failover_count(&self) -> u64 {
        self.failover_count.load(Ordering::Relaxed)
    }

    pub fn get_failover_history(&self) -> Vec<FailoverEvent> {
        self.failover_history.read().iter().cloned().collect()
    }
}

fn hostname_or_default() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "rudras-node".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "rudras-node".to_string())
    }
}

