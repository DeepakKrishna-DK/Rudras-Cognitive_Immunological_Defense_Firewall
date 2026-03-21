// ============================================================================
// Rudras — Deception Engine
// Honey infrastructure for attacker detection and intelligence collection.
//
// ETHICAL DESIGN:  All honey services are PASSIVE — they only listen and record.
//                  No active counterattack, no exploit injection, no hack-back.
//                  All collected data is for defense / forensics only.
//
// Implements:
//   • HoneyService listeners (SSH/HTTP/FTP/SMB/RDP/Telnet fake banners)
//   • HoneyToken tracking (fake credentials, fake API keys, fake files)
//   • HoneySubnet detection (traffic to dark IP space triggers instant alert)
//   • Deception alert pipeline with attacker fingerprinting
//   • Token canary embedding for document exfiltration detection
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Service Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HoneyServiceType {
    Ssh,
    Http,
    Https,
    Ftp,
    Smb,
    Rdp,
    Telnet,
    Mysql,
    Mssql,
    Redis,
    Elasticsearch,
    Vnc,
    Custom(String),
}

impl HoneyServiceType {
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Http => 80,
            Self::Https => 443,
            Self::Ftp => 21,
            Self::Smb => 445,
            Self::Rdp => 3389,
            Self::Telnet => 23,
            Self::Mysql => 3306,
            Self::Mssql => 1433,
            Self::Redis => 6379,
            Self::Elasticsearch => 9200,
            Self::Vnc => 5900,
            Self::Custom(_) => 0,
        }
    }

    /// High-fidelity banner to fool automated scanners and human attackers.
    pub fn banner(&self) -> Vec<u8> {
        match self {
            Self::Ssh =>
                b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n".to_vec(),
            Self::Http | Self::Https =>
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n".to_vec(),
            Self::Ftp =>
                b"220 ProFTPD 1.3.5e Server (ProFTPD) [127.0.0.1]\r\n".to_vec(),
            Self::Smb =>
                b"\x00\x00\x00\x54\xff\x53\x4d\x42\x72\x00\x00\x00\x00".to_vec(), // SMB Negotiate response head
            Self::Telnet =>
                b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27\r\nUbuntu 20.04.3 LTS\r\nlogin: ".to_vec(),
            Self::Mysql =>
                b"j\x00\x00\x00\x0a8.0.26\x00\x0f\x00\x00\x00".to_vec(), // Partial MySQL handshake
            Self::Mssql =>
                b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00\x1b\x00\x01\x02".to_vec(),
            Self::Redis =>
                b"+PONG\r\n".to_vec(),
            Self::Elasticsearch =>
                br#"{"name":"node-1","cluster_name":"honeypot","version":{"number":"7.17.0"}}"#.to_vec(),
            Self::Rdp =>
                b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x00\x00\x00\x00".to_vec(),
            _ => b"Welcome\r\n".to_vec(),
        }
    }
}

// ── Honey Service Config ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyService {
    pub id: String,
    pub service_type: HoneyServiceType,
    pub bind_port: u16,
    pub enabled: bool,
    pub description: String,
    pub interactions: u64,
    pub unique_attackers: HashSet<IpAddr>,
    pub created_at: u64,
}

impl HoneyService {
    pub fn new(service_type: HoneyServiceType, bind_port: Option<u16>) -> Self {
        let port = bind_port.unwrap_or_else(|| service_type.default_port());
        let id = format!("{:?}:{}", service_type, port);
        Self {
            id,
            service_type,
            bind_port: port,
            enabled: true,
            description: String::new(),
            interactions: 0,
            unique_attackers: HashSet::new(),
            created_at: unix_secs(),
        }
    }
}

// ── Honey Tokens ──────────────────────────────────────────────────────────────
// Fake credentials, API keys, secrets embedded in monitored locations.
// If seen in traffic → data exfiltration confirmed.

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    ApiKey,
    Password,
    AwsAccessKey,
    JwtToken,
    DatabaseCredential,
    SshPrivateKey,
    DocumentCanary,  // Embedded in Office/PDF docs
    DnsCanary,       // DNS lookup based canary (e.g., token.attacker-logs.attacker-domain.com)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyToken {
    pub id: String,
    pub token_type: TokenType,
    /// The actual fake token value to monitor for
    pub value: String,
    /// Human-readable description: where this token was planted
    pub planted_location: String,
    pub enabled: bool,
    pub triggered: bool,
    pub trigger_count: u64,
    pub last_seen_from: Option<IpAddr>,
    pub created_at: u64,
}

impl HoneyToken {
    pub fn new(token_type: TokenType, value: String, planted_location: &str) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(value.as_bytes());
        let id = hex::encode(hasher.finalize())[..16].to_string();
        Self {
            id,
            token_type,
            value,
            planted_location: planted_location.to_string(),
            enabled: true,
            triggered: false,
            trigger_count: 0,
            last_seen_from: None,
            created_at: unix_secs(),
        }
    }

    /// Generate a realistic-looking fake AWS access key
    pub fn fake_aws_key() -> Self {
        // AKIA prefix is real AWS format — using AHNY (Honey) prefix instead.
        // This is NOT a real AWS key; it will not authenticate anywhere.
        let key = format!("AHNY{}HONEYPOT", &hex::encode(Sha3_256::digest(
            format!("honey_{}", unix_secs()).as_bytes()
        ))[..16].to_uppercase());
        Self::new(TokenType::AwsAccessKey, key, "config/aws.env (honeypot)")
    }

    /// Generate a fake JWT token (header.payload.signature — all invalid)
    pub fn fake_jwt() -> Self {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
        let payload = base64_encode(b"{\"sub\":\"admin\",\"honey\":true,\"iat\":0}");
        let sig = "HONEYPOT_INVALID_DO_NOT_USE";
        let token = format!("{}.{}.{}", header, payload, sig);
        Self::new(TokenType::JwtToken, token, "auth/token_cache (honeypot)")
    }
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        result.push(CHARS[(b0 >> 2) & 63]);
        result.push(CHARS[((b0 << 4) | (b1 >> 4)) & 63]);
        result.push(if chunk.len() > 1 { CHARS[((b1 << 2) | (b2 >> 6)) & 63] } else { b'=' });
        result.push(if chunk.len() > 2 { CHARS[b2 & 63] } else { b'=' });
    }
    String::from_utf8_lossy(&result).to_string()
}

// ── Honey Subnets ─────────────────────────────────────────────────────────────
// IP ranges that should NEVER have legitimate traffic. Any packet here = alert.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneySubnet {
    pub cidr: String,   // e.g., "10.99.99.0/24"
    pub description: String,
    pub alert_count: u64,
}

// ── Deception Alert ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeceptionTrigger {
    HoneypotInteraction { service: HoneyServiceType, port: u16 },
    TokenSeen { token_id: String, token_type: TokenType },
    HoneySubnetAccess { cidr: String, destination_ip: IpAddr },
    PortScan { ports_touched: Vec<u16>, scan_rate_per_sec: f32 },
    MultiHoneypotAttacker { services_touched: Vec<HoneyServiceType> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionAlert {
    pub id: String,
    pub attacker_ip: IpAddr,
    pub trigger: DeceptionTrigger,
    pub severity: DeceptionSeverity,
    pub credentials_used: Option<String>,
    pub payload_snippet: Option<String>,
    pub attacker_user_agent: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeceptionSeverity {
    Low,      // Single port knock
    Medium,   // Honeypot login attempt
    High,     // Token exfiltration or dark IP access
    Critical, // Multiple honeypots + token use → active attacker
}

impl DeceptionAlert {
    fn new(attacker_ip: IpAddr, trigger: DeceptionTrigger) -> Self {
        let severity = match &trigger {
            DeceptionTrigger::TokenSeen { .. } |
            DeceptionTrigger::HoneySubnetAccess { .. } => DeceptionSeverity::High,
            DeceptionTrigger::MultiHoneypotAttacker { .. } => DeceptionSeverity::Critical,
            DeceptionTrigger::PortScan { scan_rate_per_sec, .. } if *scan_rate_per_sec > 50.0 => DeceptionSeverity::High,
            DeceptionTrigger::HoneypotInteraction { .. } => DeceptionSeverity::Medium,
            _ => DeceptionSeverity::Low,
        };
        let id = format!("DEC-{:x}", unix_secs() ^ (attacker_ip.to_string().len() as u64 * 0xDEAD));
        Self {
            id,
            attacker_ip,
            trigger,
            severity,
            credentials_used: None,
            payload_snippet: None,
            attacker_user_agent: None,
            timestamp: unix_secs(),
        }
    }
}

// ── Attacker Session Tracker ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AttackerSession {
    ip: IpAddr,
    first_seen: u64,
    last_seen: u64,
    honeypots_touched: HashSet<HoneyServiceType>,
    port_touches: Vec<u16>,
    token_hits: u32,
    honey_subnet_hits: u32,
}

// ── Deception Engine ──────────────────────────────────────────────────────────

pub struct DeceptionEngine {
    honey_services: RwLock<Vec<HoneyService>>,
    honey_tokens: RwLock<HashMap<String, HoneyToken>>,
    honey_subnets: RwLock<Vec<HoneySubnet>>,
    alerts: RwLock<VecDeque<DeceptionAlert>>,
    attacker_sessions: RwLock<HashMap<IpAddr, AttackerSession>>,
    total_alerts: AtomicU64,
    token_triggers: AtomicU64,
    honeypot_hits: AtomicU64,
}

impl DeceptionEngine {
    pub fn new() -> Self {
        let engine = Self {
            honey_services: RwLock::new(vec![]),
            honey_tokens: RwLock::new(HashMap::new()),
            honey_subnets: RwLock::new(vec![]),
            alerts: RwLock::new(VecDeque::new()),
            attacker_sessions: RwLock::new(HashMap::new()),
            total_alerts: AtomicU64::new(0),
            token_triggers: AtomicU64::new(0),
            honeypot_hits: AtomicU64::new(0),
        };

        // Default honeypots
        {
            let mut svcs = engine.honey_services.write();
            svcs.push(HoneyService::new(HoneyServiceType::Ssh, Some(2222)));
            svcs.push(HoneyService::new(HoneyServiceType::Http, Some(8080)));
            svcs.push(HoneyService::new(HoneyServiceType::Ftp, None));
            svcs.push(HoneyService::new(HoneyServiceType::Telnet, None));
            svcs.push(HoneyService::new(HoneyServiceType::Redis, None));
            svcs.push(HoneyService::new(HoneyServiceType::Elasticsearch, None));
        }
        // Default tokens
        {
            let mut tokens = engine.honey_tokens.write();
            let aws = HoneyToken::fake_aws_key();
            let jwt = HoneyToken::fake_jwt();
            tokens.insert(aws.value.clone(), aws);
            tokens.insert(jwt.value.clone(), jwt);
        }

        info!("🍯 Deception: Engine online — {} honeypots, {} tokens",
            engine.honey_services.read().len(), engine.honey_tokens.read().len());
        engine
    }

    /// Register a custom honey token
    pub fn register_token(&self, token: HoneyToken) {
        let val = token.value.clone();
        info!("🍯 Deception: Registered token type={:?} at '{}'", token.token_type, token.planted_location);
        self.honey_tokens.write().insert(val, token);
    }

    /// Register a honey subnet
    pub fn add_honey_subnet(&self, cidr: &str, description: &str) {
        self.honey_subnets.write().push(HoneySubnet {
            cidr: cidr.to_string(),
            description: description.to_string(),
            alert_count: 0,
        });
    }

    /// Check if an inbound connection hit a honeypot port.
    pub fn check_honeypot_connection(&self, src_ip: IpAddr, dst_port: u16) -> Option<DeceptionAlert> {
        let svcs = self.honey_services.read();
        let hit = svcs.iter().find(|s| s.enabled && s.bind_port == dst_port)?;
        let service_type = hit.service_type.clone();
        drop(svcs);

        self.honeypot_hits.fetch_add(1, Ordering::Relaxed);
        self.update_attacker_session(src_ip, Some(&service_type), None, false);

        let trigger = DeceptionTrigger::HoneypotInteraction {
            service: service_type.clone(),
            port: dst_port,
        };

        // Check if this attacker has hit multiple honeypots → escalate
        let multi = {
            let sessions = self.attacker_sessions.read();
            sessions.get(&src_ip)
                .map(|s| s.honeypots_touched.len() >= 3)
                .unwrap_or(false)
        };

        let alert = if multi {
            let touched: Vec<HoneyServiceType> = self.attacker_sessions.read()
                .get(&src_ip)
                .map(|s| s.honeypots_touched.iter().cloned().collect())
                .unwrap_or_default();
            DeceptionAlert::new(src_ip, DeceptionTrigger::MultiHoneypotAttacker { services_touched: touched })
        } else {
            DeceptionAlert::new(src_ip, trigger)
        };

        warn!("🍯 DECEPTION ALERT [{:?}]: {} → port {} ({:?})",
            alert.severity, src_ip, dst_port, service_type);
        self.push_alert(alert.clone());
        Some(alert)
    }

    /// Scan payload/headers for known honey token values.
    pub fn scan_payload_for_tokens(&self, src_ip: IpAddr, payload: &[u8]) -> Vec<DeceptionAlert> {
        let payload_str = String::from_utf8_lossy(payload);
        let tokens = self.honey_tokens.read();
        let mut alerts = vec![];

        for (value, token) in tokens.iter() {
            if !token.enabled { continue; }
            if payload_str.contains(value.as_str()) {
                self.token_triggers.fetch_add(1, Ordering::Relaxed);
                let trigger = DeceptionTrigger::TokenSeen {
                    token_id: token.id.clone(),
                    token_type: token.token_type.clone(),
                };
                let mut alert = DeceptionAlert::new(src_ip, trigger);
                alert.payload_snippet = Some(payload_str.chars().take(200).collect());
                alert.credentials_used = Some(value[..value.len().min(20)].to_string() + "…");
                warn!("🍯 TOKEN EXFILTRATION: {} used honey token type={:?} planted at '{}'",
                    src_ip, token.token_type, token.planted_location);
                self.push_alert(alert.clone());
                alerts.push(alert);
            }
        }
        alerts
    }

    /// Check if destination IP is in a honey subnet.
    pub fn check_honey_subnet(&self, src_ip: IpAddr, dst_ip: IpAddr) -> Option<DeceptionAlert> {
        let mut subnets = self.honey_subnets.write();
        for subnet in subnets.iter_mut() {
            if cidr_contains(&subnet.cidr, dst_ip) {
                subnet.alert_count += 1;
                let cidr = subnet.cidr.clone();
                drop(subnets);

                let trigger = DeceptionTrigger::HoneySubnetAccess {
                    cidr: cidr.clone(),
                    destination_ip: dst_ip,
                };
                let alert = DeceptionAlert::new(src_ip, trigger);
                warn!("🍯 DARK IP ALERT: {} → honey subnet {} (dst: {})", src_ip, cidr, dst_ip);
                self.push_alert(alert.clone());
                return Some(alert);
            }
        }
        None
    }

    /// Get banner bytes to return to a connecting attacker
    pub fn get_banner(&self, dst_port: u16) -> Option<Vec<u8>> {
        let svcs = self.honey_services.read();
        svcs.iter()
            .find(|s| s.enabled && s.bind_port == dst_port)
            .map(|s| s.service_type.banner())
    }

    fn update_attacker_session(&self, ip: IpAddr, svc: Option<&HoneyServiceType>, port: Option<u16>, token_hit: bool) {
        let mut sessions = self.attacker_sessions.write();
        let session = sessions.entry(ip).or_insert_with(|| AttackerSession {
            ip,
            first_seen: unix_secs(),
            last_seen: unix_secs(),
            honeypots_touched: HashSet::new(),
            port_touches: vec![],
            token_hits: 0,
            honey_subnet_hits: 0,
        });
        session.last_seen = unix_secs();
        if let Some(s) = svc { session.honeypots_touched.insert(s.clone()); }
        if let Some(p) = port { session.port_touches.push(p); }
        if token_hit { session.token_hits += 1; }
    }

    fn push_alert(&self, alert: DeceptionAlert) {
        self.total_alerts.fetch_add(1, Ordering::Relaxed);
        let mut alerts = self.alerts.write();
        alerts.push_back(alert);
        if alerts.len() > 10_000 { alerts.pop_front(); }
    }

    pub fn recent_alerts(&self, n: usize) -> Vec<DeceptionAlert> {
        self.alerts.read().iter().rev().take(n).cloned().collect()
    }

    /// Drain all pending alerts (for SOAR integration).
    pub fn drain_alerts(&self) -> Vec<DeceptionAlert> {
        let mut q = self.alerts.write();
        q.drain(..).collect()
    }

    /// Return number of registered honeypot services.
    pub fn honeypot_count(&self) -> usize {
        self.honey_services.read().len()
    }

    pub fn stats(&self) -> DeceptionStats {
        DeceptionStats {
            total_alerts: self.total_alerts.load(Ordering::Relaxed),
            token_triggers: self.token_triggers.load(Ordering::Relaxed),
            honeypot_hits: self.honeypot_hits.load(Ordering::Relaxed),
            unique_attackers: self.attacker_sessions.read().len() as u64,
        }
    }
}

impl Default for DeceptionEngine {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct DeceptionStats {
    pub total_alerts: u64,
    pub token_triggers: u64,
    pub honeypot_hits: u64,
    pub unique_attackers: u64,
}

// ── CIDR helper ───────────────────────────────────────────────────────────────

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 { return false; }
    let (IpAddr::V4(net_ip), Ok(prefix_len)) = (
        parts[0].parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        parts[1].parse::<u32>()
    ) else { return false; };
    if let IpAddr::V4(check_ip) = ip {
        if prefix_len == 0 { return true; }
        if prefix_len > 32 { return false; }
        let mask = !0u32 << (32 - prefix_len);
        (u32::from(net_ip) & mask) == (u32::from(check_ip) & mask)
    } else {
        false
    }
}
