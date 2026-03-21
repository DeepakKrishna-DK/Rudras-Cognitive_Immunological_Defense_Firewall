// ============================================================================
// Rudras — Moving Target Defense (MTD) Engine
//
// Moving Target Defense proactively rotates the attack surface to increase
// attacker cost and reduce the value of prior reconnaissance.
//
// Techniques implemented:
//   1. Virtual IP Hopping: rotates the advertised IP address of services
//      on a schedule, and notifies authorised clients via encrypted beacon
//   2. Port Randomisation: cycles listening port numbers for services
//      (clients discover new ports via an encrypted discovery channel)
//   3. Decoy Services: deploys fake open ports/service banners to overwhelm
//      scanners and detect probing activity
//   4. Rotation Audit Trail: every rotation is logged with before/after state
//      and signed for forensic chain-of-custody
//
// Integration: Decoy ports feed alerts into deception.rs.
//              Rotations are logged to forensics_chain.rs chain.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Virtual IP Mapping ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualIpMapping {
    /// Real physical IP
    pub real_ip: IpAddr,
    /// Currently advertised virtual IP
    pub virtual_ip: IpAddr,
    /// Name/label of the service
    pub service_name: String,
    /// Rotation interval in seconds
    pub rotation_interval_secs: u64,
    pub last_rotated_at: u64,
    pub rotation_count: u64,
}

// ── Port Randomiser ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRandomiserEntry {
    pub service_name: String,
    /// Well-known/canonical port (for clients to request mapping)
    pub canonical_port: u16,
    /// Currently active port
    pub current_port: u16,
    /// Rotation interval in seconds
    pub rotation_interval_secs: u64,
    pub last_rotated_at: u64,
    /// Port range [min, max] for randomisation
    pub port_range: (u16, u16),
}

// ── Decoy Service ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyService {
    pub port: u16,
    pub protocol: DecoyProtocol,
    pub banner: String,
    pub created_at: u64,
    pub probe_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DecoyProtocol { Tcp, Udp }

// ── Rotation Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtdRotationEvent {
    pub id: String,
    pub event_type: RotationEventType,
    pub service_name: String,
    pub before: String, // IP or port as string
    pub after: String,
    pub timestamp: u64,
    /// SHA3-256 of (before || after || timestamp) for chain integrity
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationEventType { IpHop, PortChange, DecoyAdded, DecoyHit }

// ── Decoy Probe Alert ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyProbeAlert {
    pub id: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub decoy_port: u16,
    pub protocol: DecoyProtocol,
    pub timestamp: u64,
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MtdStats {
    pub ip_rotations: u64,
    pub port_rotations: u64,
    pub decoys_active: usize,
    pub decoy_probes: u64,
    pub rotation_events_logged: u64,
}

// ── MTD Engine ────────────────────────────────────────────────────────────────

pub struct MtdEngine {
    virtual_ips: RwLock<Vec<VirtualIpMapping>>,
    port_entries: RwLock<Vec<PortRandomiserEntry>>,
    decoys: RwLock<Vec<DecoyService>>,
    rotation_log: RwLock<VecDeque<MtdRotationEvent>>,
    decoy_alerts: RwLock<VecDeque<DecoyProbeAlert>>,
    ip_rotations: AtomicU64,
    port_rotations: AtomicU64,
    decoy_probes: AtomicU64,
    rotation_events: AtomicU64,
    seq: AtomicU64,
    /// Ephemeral key used to sign rotation digests
    signing_key: [u8; 32],
}

impl MtdEngine {
    pub fn new() -> Self {
        let mut key_hasher = Sha3_256::new();
        key_hasher.update(b"RUDRAS-MTD-SIGNING-KEY-V1-");
        key_hasher.update(unix_secs().to_le_bytes());
        let key: Vec<u8> = key_hasher.finalize().to_vec();
        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&key);

        let engine = Self {
            virtual_ips: RwLock::new(Vec::new()),
            port_entries: RwLock::new(Vec::new()),
            decoys: RwLock::new(Vec::new()),
            rotation_log: RwLock::new(VecDeque::with_capacity(1024)),
            decoy_alerts: RwLock::new(VecDeque::with_capacity(256)),
            ip_rotations: AtomicU64::new(0),
            port_rotations: AtomicU64::new(0),
            decoy_probes: AtomicU64::new(0),
            rotation_events: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            signing_key,
        };

        // Deploy default decoy services on well-known "attacker-interesting" ports
        engine.add_decoy(8080,  DecoyProtocol::Tcp, "HTTP/1.0 200 OK\r\nServer: Apache/2.2.0\r\n\r\n");
        engine.add_decoy(2222,  DecoyProtocol::Tcp, "SSH-2.0-OpenSSH_7.4\r\n");
        engine.add_decoy(3306,  DecoyProtocol::Tcp, "5.7.0-MySQL-Community\r\n"); // MySQL banner
        engine.add_decoy(5432,  DecoyProtocol::Tcp, "PostgreSQL 14.0 ready\r\n"); // Postgres banner
        engine.add_decoy(23,    DecoyProtocol::Tcp, "Telnet service ready\r\n"  ); // Telnet banner

        info!("🎯 Moving Target Defense Engine initialized — {} decoy services deployed", 5);
        engine
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", prefix, unix_secs(), n)
    }

    fn sign_rotation(&self, before: &str, after: &str, ts: u64) -> String {
        let mut h = Sha3_256::new();
        h.update(self.signing_key);
        h.update(b":");
        h.update(before.as_bytes());
        h.update(b"->".as_slice());
        h.update(after.as_bytes());
        h.update(ts.to_le_bytes());
        hex::encode(h.finalize())
    }

    fn log_rotation(&self, event_type: RotationEventType, service: &str, before: &str, after: &str) {
        let ts = unix_secs();
        let digest = self.sign_rotation(before, after, ts);
        let event = MtdRotationEvent {
            id: self.next_id("MTD-ROT"),
            event_type, service_name: service.to_string(),
            before: before.to_string(), after: after.to_string(),
            timestamp: ts, digest,
        };
        info!("🎯 MTD rotation: {} {} → {}", service, before, after);
        self.rotation_events.fetch_add(1, Ordering::Relaxed);
        let mut log = self.rotation_log.write();
        if log.len() >= 1024 { log.pop_front(); }
        log.push_back(event);
    }

    // ── Virtual IP Management ─────────────────────────────────────────────────

    /// Register a service for virtual IP rotation.
    pub fn register_virtual_ip(
        &self, real_ip: IpAddr, initial_virtual: IpAddr,
        service_name: &str, rotation_interval_secs: u64,
    ) {
        self.virtual_ips.write().push(VirtualIpMapping {
            real_ip, virtual_ip: initial_virtual,
            service_name: service_name.to_string(),
            rotation_interval_secs, last_rotated_at: unix_secs(),
            rotation_count: 0,
        });
        info!("🎯 MTD: Registered virtual IP {} → {} for {}", real_ip, initial_virtual, service_name);
    }

    /// Rotate virtual IP for a service. Returns the new virtual IP.
    pub fn rotate_virtual_ip(&self, service_name: &str, new_virtual: IpAddr) -> Option<IpAddr> {
        let mut vips = self.virtual_ips.write();
        for mapping in vips.iter_mut() {
            if mapping.service_name == service_name {
                let old = mapping.virtual_ip;
                mapping.virtual_ip = new_virtual;
                mapping.last_rotated_at = unix_secs();
                mapping.rotation_count += 1;
                self.ip_rotations.fetch_add(1, Ordering::Relaxed);
                drop(vips);
                self.log_rotation(
                    RotationEventType::IpHop, service_name,
                    &old.to_string(), &new_virtual.to_string(),
                );
                return Some(new_virtual);
            }
        }
        None
    }

    /// Returns the current virtual-to-real IP mapping for NAT/forwarding rules.
    pub fn get_ip_mappings(&self) -> Vec<VirtualIpMapping> {
        self.virtual_ips.read().clone()
    }

    /// Check if any virtual IP mappings are due for rotation.
    pub fn tick_ip_rotations(&self) {
        let now = unix_secs();
        // Collect which services need rotation (avoid holding write lock during log_rotation)
        let due: Vec<(String, IpAddr, u64)> = {
            let vips = self.virtual_ips.read();
            vips.iter()
                .filter(|m| now - m.last_rotated_at >= m.rotation_interval_secs)
                .map(|m| (m.service_name.clone(), m.real_ip, m.rotation_interval_secs))
                .collect()
        };

        for (svc, real_ip, _) in due {
            // Compute next virtual IP by incrementing last octet deterministically
            let new_virtual = Self::derive_next_virtual_ip(real_ip, now);
            self.rotate_virtual_ip(&svc, new_virtual);
        }
    }

    fn derive_next_virtual_ip(real_ip: IpAddr, seed: u64) -> IpAddr {
        match real_ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // Rotate last two octets using seed — stay in same /16
                let new_oct3 = ((octets[2] as u64 + seed / 60) % 254 + 1) as u8;
                let new_oct4 = ((octets[3] as u64 + seed) % 254 + 1) as u8;
                IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], new_oct3, new_oct4))
            }
            IpAddr::V6(_) => real_ip, // IPv6 rotation out of scope for now
        }
    }

    // ── Port Randomisation ────────────────────────────────────────────────────

    /// Register a service for port rotation.
    pub fn register_port_entry(
        &self, service_name: &str, canonical_port: u16,
        initial_port: u16, rotation_interval_secs: u64,
        port_range: (u16, u16),
    ) {
        self.port_entries.write().push(PortRandomiserEntry {
            service_name: service_name.to_string(),
            canonical_port, current_port: initial_port,
            rotation_interval_secs, last_rotated_at: unix_secs(),
            port_range,
        });
    }

    /// Get the current active port for a service (clients use this after discovery).
    pub fn get_current_port(&self, service_name: &str) -> Option<u16> {
        self.port_entries.read().iter()
            .find(|e| e.service_name == service_name)
            .map(|e| e.current_port)
    }

    /// Rotate all port entries that are due.
    pub fn tick_port_rotations(&self) {
        let now = unix_secs();
        let due: Vec<(String, u16, (u16, u16))> = {
            let entries = self.port_entries.read();
            entries.iter()
                .filter(|e| now - e.last_rotated_at >= e.rotation_interval_secs)
                .map(|e| (e.service_name.clone(), e.current_port, e.port_range))
                .collect()
        };

        for (svc, old_port, (min_p, max_p)) in due {
            let range = (max_p - min_p) as u64;
            let new_port = if range > 0 {
                min_p + (now % range) as u16
            } else {
                min_p
            };
            let mut entries = self.port_entries.write();
            for e in entries.iter_mut() {
                if e.service_name == svc {
                    e.current_port = new_port;
                    e.last_rotated_at = now;
                    break;
                }
            }
            drop(entries);
            self.port_rotations.fetch_add(1, Ordering::Relaxed);
            self.log_rotation(
                RotationEventType::PortChange, &svc,
                &old_port.to_string(), &new_port.to_string(),
            );
        }
    }

    // ── Decoy Services ────────────────────────────────────────────────────────

    /// Add a decoy service (fake listener).
    pub fn add_decoy(&self, port: u16, protocol: DecoyProtocol, banner: &str) {
        self.decoys.write().push(DecoyService {
            port, protocol: protocol.clone(), banner: banner.to_string(),
            created_at: unix_secs(), probe_count: 0,
        });
        self.log_rotation(
            RotationEventType::DecoyAdded, &format!("decoy:{}", port),
            "none", &format!("port:{}/tcp", port),
        );
    }

    /// Returns true if `port` is a decoy port.
    pub fn is_decoy_port(&self, port: u16) -> bool {
        self.decoys.read().iter().any(|d| d.port == port)
    }

    /// Record a probe attempt on a decoy port.
    pub fn record_decoy_probe(&self, src_ip: IpAddr, src_port: u16, decoy_port: u16) {
        {
            let mut decoys = self.decoys.write();
            if let Some(d) = decoys.iter_mut().find(|d| d.port == decoy_port) {
                d.probe_count += 1;
                let proto = d.protocol.clone();
                drop(decoys);
                self.decoy_probes.fetch_add(1, Ordering::Relaxed);
                warn!("🎯 MTD DECOY HIT: {}:{} → decoy:{}", src_ip, src_port, decoy_port);
                let alert = DecoyProbeAlert {
                    id: self.next_id("DECOY"),
                    src_ip, src_port, decoy_port, protocol: proto,
                    timestamp: unix_secs(),
                };
                let mut alerts = self.decoy_alerts.write();
                if alerts.len() >= 256 { alerts.pop_front(); }
                alerts.push_back(alert);
            }
        }
    }

    /// Get all decoy ports currently active.
    pub fn decoy_ports(&self) -> Vec<u16> {
        self.decoys.read().iter().map(|d| d.port).collect()
    }

    /// Run all scheduled rotations.
    pub fn tick(&self) {
        self.tick_ip_rotations();
        self.tick_port_rotations();
    }

    pub fn drain_decoy_alerts(&self) -> Vec<DecoyProbeAlert> {
        self.decoy_alerts.write().drain(..).collect()
    }

    pub fn drain_rotation_log(&self) -> Vec<MtdRotationEvent> {
        self.rotation_log.write().drain(..).collect()
    }

    pub fn stats(&self) -> MtdStats {
        MtdStats {
            ip_rotations: self.ip_rotations.load(Ordering::Relaxed),
            port_rotations: self.port_rotations.load(Ordering::Relaxed),
            decoys_active: self.decoys.read().len(),
            decoy_probes: self.decoy_probes.load(Ordering::Relaxed),
            rotation_events_logged: self.rotation_events.load(Ordering::Relaxed),
        }
    }
}
