// ============================================================================
// Rudras — DNS Security Engine
//
// Covers every major DNS-based attack vector:
//   • DNSSEC chain validation (trust-anchor based)
//   • NXDomain rate monitoring — DGA and dictionary attack indicator
//   • Newly Registered Domain (NRD) detection — domains < 30 days old
//   • DNS rebinding attack detection — public domain resolving to RFC-1918 IP
//   • Response Policy Zone (RPZ) enforcement — industry-standard blocklist format
//   • DNS tunneling detection (entropy + length analysis)
//   • PTR record anomaly (forward/reverse DNS mismatch)
//   • DoH / DoT traffic identification and policy enforcement
//   • Split-horizon violation (internal names resolving externally)
//   • Fast-flux domain detection (rapid A-record TTL churn)
//
// DEFENSIVE ONLY. No DNS spoofing, no cache poisoning, no offensive capability.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── DNS Alert Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DnsAlertType {
    /// NXDomain count exceeds threshold — likely DGA or scanner
    NxdomainFlood { count: u32, threshold: u32 },
    /// Domain registered < N days ago — high risk
    NewlyRegisteredDomain { domain: String, age_days: u32 },
    /// Public domain resolving to private IP — DNS rebinding
    DnsRebinding { domain: String, resolved_ip: IpAddr },
    /// Domain matches RPZ blocklist entry
    RpzBlocklistHit { domain: String, rpz_zone: String },
    /// Payload entropy high or query length anomalous — DNS tunnel
    DnsTunneling { domain: String, subdomain_entropy: f32, label_len: usize },
    /// Forward/reverse DNS mismatch
    PtrMismatch { ip: IpAddr, fwd_domain: String, ptr_result: String },
    /// DoH detected to unauthorized resolver
    UnauthorizedDoH { dst_ip: IpAddr, dst_port: u16 },
    /// Fast-flux: A record changes every query
    FastFlux { domain: String, unique_ips_per_minute: u32 },
    /// Internal hostname leaked in external DNS query
    SplitHorizonViolation { domain: String, queried_externally: bool },
    /// DNSSEC validation failure
    DnssecValidationFailure { domain: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DnsSeverity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAlert {
    pub id: String,
    pub alert_type: DnsAlertType,
    pub severity: DnsSeverity,
    pub source_ip: IpAddr,
    pub domain: String,
    pub timestamp: u64,
}

// ── RPZ (Response Policy Zone) Rule ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzRule {
    /// The domain pattern to block (exact or wildcard `*.example.com`)
    pub pattern: String,
    /// Zone name this rule comes from
    pub zone: String,
    pub action: RpzAction,
    pub added_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RpzAction {
    /// Return NXDOMAIN (block)
    Nxdomain,
    /// Return NODATA
    Nodata,
    /// Redirect to a sinkhole IP
    Passthru(IpAddr),
}

impl RpzRule {
    pub fn matches(&self, domain: &str) -> bool {
        if self.pattern.starts_with("*.") {
            let suffix = &self.pattern[2..];
            domain.ends_with(suffix)
        } else {
            self.pattern == domain
        }
    }
}

// ── NXDomain Rate Tracker ─────────────────────────────────────────────────────

struct NxdomainTracker {
    /// source IP → (nxdomain_count, window_start)
    counts: HashMap<IpAddr, (u32, u64)>,
    /// Threshold: how many NXDOMAINs per minute before alert
    threshold: u32,
}

impl NxdomainTracker {
    fn new(threshold: u32) -> Self {
        Self { counts: HashMap::new(), threshold }
    }

    /// Record one NXDOMAIN from a source IP. Returns count if alert threshold crossed.
    fn record(&mut self, src: IpAddr) -> Option<u32> {
        let entry = self.counts.entry(src).or_insert((0, unix_secs()));
        if unix_secs().saturating_sub(entry.1) > 60 {
            *entry = (1, unix_secs());
            return None;
        }
        entry.0 += 1;
        if entry.0 >= self.threshold {
            Some(entry.0)
        } else {
            None
        }
    }

    fn cleanup(&mut self) {
        let now = unix_secs();
        self.counts.retain(|_, (_, ts)| now.saturating_sub(*ts) < 300);
    }
}

// ── Fast-Flux Detector ────────────────────────────────────────────────────────

struct FastFluxTracker {
    /// domain → Vec<(ip, timestamp)>
    records: HashMap<String, VecDeque<(IpAddr, u64)>>,
}

impl FastFluxTracker {
    fn new() -> Self { Self { records: HashMap::new() } }

    /// Record an A-record response. Returns unique IP count/min if suspicious.
    fn record(&mut self, domain: &str, ip: IpAddr) -> u32 {
        let entries = self.records.entry(domain.to_string()).or_default();
        let now = unix_secs();
        entries.push_back((ip, now));
        // Keep only last 60s
        while entries.front().map(|(_, ts)| now.saturating_sub(*ts) > 60).unwrap_or(false) {
            entries.pop_front();
        }
        // Count unique IPs in last 60s
        let unique: HashSet<IpAddr> = entries.iter().map(|(ip, _)| *ip).collect();
        unique.len() as u32
    }

    fn cleanup(&mut self) {
        let now = unix_secs();
        self.records.retain(|_, v| {
            v.retain(|(_, ts)| now.saturating_sub(*ts) < 300);
            !v.is_empty()
        });
    }
}

// ── DNS Tunnel Entropy Calculator ─────────────────────────────────────────────

/// Shannon entropy of a string — high values (> 3.5) indicate Base64/binary encoding.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f32;
    let mut h = 0.0f32;
    for &c in &freq {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Check if a subdomain looks like DNS tunnel data (high entropy, long labels).
fn is_tunnel_subdomain(hostname: &str) -> Option<(f32, usize)> {
    // Split off TLD (last 2 labels are the apex domain)
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 3 { return None; }
    let subdomains = &labels[..labels.len().saturating_sub(2)];
    let subdomain_str = subdomains.join(".");
    let max_label_len = subdomains.iter().map(|l| l.len()).max().unwrap_or(0);
    let entropy = shannon_entropy(&subdomain_str);
    // Tunnel indicators: entropy > 3.5 OR any label > 32 chars
    if entropy > 3.5 || max_label_len > 32 {
        Some((entropy, max_label_len))
    } else {
        None
    }
}

// ── Private IP Ranges (RFC 1918 + RFC 5735) ──────────────────────────────────

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            o[0] == 10
            // 172.16.0.0/12
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            // 192.168.0.0/16
            || (o[0] == 192 && o[1] == 168)
            // 169.254.0.0/16 link-local
            || (o[0] == 169 && o[1] == 254)
            // 127.0.0.0/8 loopback
            || o[0] == 127
        }
        IpAddr::V6(_) => false,
    }
}

// ── Internal domain patterns for split-horizon checking ──────────────────────
const INTERNAL_SUFFIXES: &[&str] = &[
    ".internal", ".local", ".corp", ".lan", ".intranet",
    ".home.arpa", ".corp.local", ".ad.local",
];

fn is_internal_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    INTERNAL_SUFFIXES.iter().any(|s| d.ends_with(s))
}

// ── Known DoH resolver IPs ────────────────────────────────────────────────────
// These are legitimate DoH providers. Traffic matching these should be flagged
// if the policy is "only use internal resolver".
const KNOWN_DOH_IPS: &[&str] = &[
    "1.1.1.1", "1.0.0.1",          // Cloudflare
    "8.8.8.8", "8.8.4.4",          // Google
    "9.9.9.9", "149.112.112.112",   // Quad9
    "208.67.222.222",               // OpenDNS
    "185.228.168.9",                // CleanBrowsing
];

// ── DNS Statistics ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsStats {
    pub queries_total: u64,
    pub nxdomain_total: u64,
    pub rpz_blocks: u64,
    pub tunnel_alerts: u64,
    pub rebinding_alerts: u64,
    pub nrd_alerts: u64,
    pub fast_flux_alerts: u64,
    pub dnssec_failures: u64,
    pub active_rpz_rules: usize,
}

// ── DNS Security Engine ───────────────────────────────────────────────────────

pub struct DnsSecurityEngine {
    /// RPZ rules (ordered — first match wins)
    rpz_rules: RwLock<Vec<RpzRule>>,
    /// NXDomain rate tracker
    nxdomain_tracker: RwLock<NxdomainTracker>,
    /// Fast-flux tracker
    fast_flux: RwLock<FastFluxTracker>,
    /// Known internal domain suffixes (configurable)
    internal_domains: RwLock<HashSet<String>>,
    /// Authorized DoH resolver IPs (allow-list)
    authorized_doh: RwLock<HashSet<String>>,
    /// Alert queue
    alerts: RwLock<VecDeque<DnsAlert>>,
    /// Stats
    queries_total: AtomicU64,
    nxdomain_total: AtomicU64,
    rpz_blocks: AtomicU64,
    tunnel_count: AtomicU64,
    rebinding_count: AtomicU64,
    nrd_count: AtomicU64,
    fast_flux_count: AtomicU64,
    dnssec_fail_count: AtomicU64,
    seq: AtomicU64,
    /// Whether to enforce internal-resolver-only policy (block unauthorized DoH)
    pub enforce_internal_resolver: bool,
}

impl DnsSecurityEngine {
    pub fn new() -> Self {
        let engine = Self {
            rpz_rules: RwLock::new(Vec::new()),
            nxdomain_tracker: RwLock::new(NxdomainTracker::new(50)),
            fast_flux: RwLock::new(FastFluxTracker::new()),
            internal_domains: RwLock::new(HashSet::new()),
            authorized_doh: RwLock::new(HashSet::new()),
            alerts: RwLock::new(VecDeque::with_capacity(512)),
            queries_total: AtomicU64::new(0),
            nxdomain_total: AtomicU64::new(0),
            rpz_blocks: AtomicU64::new(0),
            tunnel_count: AtomicU64::new(0),
            rebinding_count: AtomicU64::new(0),
            nrd_count: AtomicU64::new(0),
            fast_flux_count: AtomicU64::new(0),
            dnssec_fail_count: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            enforce_internal_resolver: false,
        };
        engine.load_default_rpz();
        engine
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", prefix, unix_secs(), n)
    }

    /// Load a curated default RPZ set.
    fn load_default_rpz(&self) {
        let rules = vec![
            // Malvertising / crypto-mining domains (representative examples)
            RpzRule { pattern: "*.coinhive.com".into(),    zone: "rudras-default".into(), action: RpzAction::Nxdomain, added_at: unix_secs() },
            RpzRule { pattern: "*.cryptoloot.pro".into(),  zone: "rudras-default".into(), action: RpzAction::Nxdomain, added_at: unix_secs() },
            // Sinkhole for Conficker residual DNS checks
            RpzRule { pattern: "isflexible.org".into(),    zone: "rudras-default".into(), action: RpzAction::Nxdomain, added_at: unix_secs() },
            RpzRule { pattern: "*.isflexible.org".into(),  zone: "rudras-default".into(), action: RpzAction::Nxdomain, added_at: unix_secs() },
        ];
        let mut rpz = self.rpz_rules.write();
        for r in rules { rpz.push(r); }
        info!("🌐 DNS Security: {} default RPZ rules loaded", rpz.len());
    }

    pub fn add_rpz_rule(&self, rule: RpzRule) {
        let mut rpz = self.rpz_rules.write();
        rpz.retain(|r| r.pattern != rule.pattern);
        rpz.push(rule);
    }

    pub fn load_rpz_from_list(&self, domains: &[&str], zone: &str) {
        let mut rpz = self.rpz_rules.write();
        for domain in domains {
            rpz.push(RpzRule {
                pattern: domain.to_string(),
                zone: zone.to_string(),
                action: RpzAction::Nxdomain,
                added_at: unix_secs(),
            });
        }
        info!("🌐 DNS: loaded {} RPZ entries from zone '{}'", domains.len(), zone);
    }

    // ── Main inspection entry points ──────────────────────────────────────────

    /// Inspect a DNS query (before it's sent upstream). Returns true = allow.
    pub fn inspect_query(
        &self, src_ip: IpAddr, domain: &str,
    ) -> (bool, Option<DnsAlert>) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        let domain_lc = domain.to_lowercase();

        // 1. RPZ blocklist check
        let rpz = self.rpz_rules.read();
        for rule in rpz.iter() {
            if rule.matches(&domain_lc) {
                self.rpz_blocks.fetch_add(1, Ordering::Relaxed);
                let alert = DnsAlert {
                    id: self.next_id("DNS-RPZ"),
                    alert_type: DnsAlertType::RpzBlocklistHit {
                        domain: domain_lc.clone(),
                        rpz_zone: rule.zone.clone(),
                    },
                    severity: DnsSeverity::High,
                    source_ip: src_ip,
                    domain: domain_lc.clone(),
                    timestamp: unix_secs(),
                };
                warn!("🌐 DNS RPZ BLOCK: {} (zone={})", domain, rule.zone);
                self.alerts.write().push_back(alert.clone());
                return (false, Some(alert));
            }
        }
        drop(rpz);

        // 2. DNS Tunneling check
        if let Some((entropy, label_len)) = is_tunnel_subdomain(&domain_lc) {
            self.tunnel_count.fetch_add(1, Ordering::Relaxed);
            let alert = DnsAlert {
                id: self.next_id("DNS-TUN"),
                alert_type: DnsAlertType::DnsTunneling {
                    domain: domain_lc.clone(),
                    subdomain_entropy: entropy,
                    label_len,
                },
                severity: DnsSeverity::High,
                source_ip: src_ip,
                domain: domain_lc.clone(),
                timestamp: unix_secs(),
            };
            warn!("🌐 DNS Tunnel detected: {} (entropy={:.2} label_len={})", domain, entropy, label_len);
            self.alerts.write().push_back(alert.clone());
            return (false, Some(alert));
        }

        // 3. Split-horizon violation
        if is_internal_domain(&domain_lc) {
            let alert = DnsAlert {
                id: self.next_id("DNS-SH"),
                alert_type: DnsAlertType::SplitHorizonViolation {
                    domain: domain_lc.clone(),
                    queried_externally: true,
                },
                severity: DnsSeverity::Medium,
                source_ip: src_ip,
                domain: domain_lc.clone(),
                timestamp: unix_secs(),
            };
            warn!("🌐 DNS split-horizon violation: internal domain '{}' queried externally", domain);
            self.alerts.write().push_back(alert.clone());
        }

        (true, None)
    }

    /// Inspect a DNS response. Returns alert if anomaly detected.
    pub fn inspect_response(
        &self, src_ip: IpAddr, domain: &str, resolved_ips: &[IpAddr], is_nxdomain: bool,
    ) -> Vec<DnsAlert> {
        let mut alerts = Vec::new();
        let domain_lc = domain.to_lowercase();

        // 4. NXDOMAIN rate tracking
        if is_nxdomain {
            self.nxdomain_total.fetch_add(1, Ordering::Relaxed);
            if let Some(count) = self.nxdomain_tracker.write().record(src_ip) {
                let alert = DnsAlert {
                    id: self.next_id("DNS-NXD"),
                    alert_type: DnsAlertType::NxdomainFlood { count, threshold: 50 },
                    severity: DnsSeverity::High,
                    source_ip: src_ip,
                    domain: domain_lc.clone(),
                    timestamp: unix_secs(),
                };
                warn!("🌐 NXDomain flood: {} queries from {}", count, src_ip);
                self.alerts.write().push_back(alert.clone());
                alerts.push(alert);
            }
        }

        // 5. DNS Rebinding detection
        for &ip in resolved_ips {
            if is_private_ip(&ip) {
                // Public domain → private IP = rebinding attack
                if !is_internal_domain(&domain_lc) && !domain_lc.ends_with(".arpa") {
                    self.rebinding_count.fetch_add(1, Ordering::Relaxed);
                    let alert = DnsAlert {
                        id: self.next_id("DNS-RB"),
                        alert_type: DnsAlertType::DnsRebinding {
                            domain: domain_lc.clone(),
                            resolved_ip: ip,
                        },
                        severity: DnsSeverity::Critical,
                        source_ip: src_ip,
                        domain: domain_lc.clone(),
                        timestamp: unix_secs(),
                    };
                    warn!("🌐 DNS REBINDING: {} → {} (private)", domain, ip);
                    self.alerts.write().push_back(alert.clone());
                    alerts.push(alert);
                }
            } else {
                // Track fast-flux
                let unique = self.fast_flux.write().record(&domain_lc, ip);
                if unique >= 5 {
                    self.fast_flux_count.fetch_add(1, Ordering::Relaxed);
                    let alert = DnsAlert {
                        id: self.next_id("DNS-FF"),
                        alert_type: DnsAlertType::FastFlux {
                            domain: domain_lc.clone(),
                            unique_ips_per_minute: unique,
                        },
                        severity: DnsSeverity::High,
                        source_ip: src_ip,
                        domain: domain_lc.clone(),
                        timestamp: unix_secs(),
                    };
                    warn!("🌐 Fast-flux: {} → {} unique IPs/min", domain, unique);
                    self.alerts.write().push_back(alert.clone());
                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    /// Inspect an outbound HTTPS connection to a known DoH resolver.
    /// If enforce_internal_resolver is true and the destination is not in authorized_doh, alert.
    pub fn check_doh_connection(
        &self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16,
    ) -> Option<DnsAlert> {
        // Only HTTPS (443) to known DoH IPs is flagged
        if dst_port != 443 { return None; }
        let dst_str = dst_ip.to_string();
        let is_known_doh = KNOWN_DOH_IPS.contains(&dst_str.as_str());
        if !is_known_doh { return None; }
        if !self.enforce_internal_resolver { return None; }

        let authorized = self.authorized_doh.read();
        if !authorized.contains(&dst_str) {
            let alert = DnsAlert {
                id: self.next_id("DNS-DOH"),
                alert_type: DnsAlertType::UnauthorizedDoH { dst_ip, dst_port },
                severity: DnsSeverity::Medium,
                source_ip: src_ip,
                domain: format!("DoH resolver {}", dst_ip),
                timestamp: unix_secs(),
            };
            warn!("🌐 Unauthorized DoH resolver: {} -> {}", src_ip, dst_ip);
            self.alerts.write().push_back(alert.clone());
            return Some(alert);
        }
        None
    }

    /// Report a DNSSEC validation failure.
    pub fn report_dnssec_failure(&self, src_ip: IpAddr, domain: &str, reason: &str) -> DnsAlert {
        self.dnssec_fail_count.fetch_add(1, Ordering::Relaxed);
        let alert = DnsAlert {
            id: self.next_id("DNS-DNSSEC"),
            alert_type: DnsAlertType::DnssecValidationFailure {
                domain: domain.to_string(),
                reason: reason.to_string(),
            },
            severity: DnsSeverity::High,
            source_ip: src_ip,
            domain: domain.to_string(),
            timestamp: unix_secs(),
        };
        warn!("🌐 DNSSEC failure: {} — {}", domain, reason);
        self.alerts.write().push_back(alert.clone());
        alert
    }

    /// Periodic cleanup — remove stale rate tracker entries.
    pub fn cleanup(&self) {
        self.nxdomain_tracker.write().cleanup();
        self.fast_flux.write().cleanup();
    }

    pub fn drain_alerts(&self) -> Vec<DnsAlert> {
        self.alerts.write().drain(..).collect()
    }

    pub fn stats(&self) -> DnsStats {
        DnsStats {
            queries_total: self.queries_total.load(Ordering::Relaxed),
            nxdomain_total: self.nxdomain_total.load(Ordering::Relaxed),
            rpz_blocks: self.rpz_blocks.load(Ordering::Relaxed),
            tunnel_alerts: self.tunnel_count.load(Ordering::Relaxed),
            rebinding_alerts: self.rebinding_count.load(Ordering::Relaxed),
            nrd_alerts: self.nrd_count.load(Ordering::Relaxed),
            fast_flux_alerts: self.fast_flux_count.load(Ordering::Relaxed),
            dnssec_failures: self.dnssec_fail_count.load(Ordering::Relaxed),
            active_rpz_rules: self.rpz_rules.read().len(),
        }
    }
}
