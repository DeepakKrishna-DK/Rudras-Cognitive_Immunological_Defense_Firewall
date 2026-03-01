// ============================================================================
// Rudras — Threat Intelligence Hub (Intelligence Plane)
// Live threat feeds: Feodo Tracker, URLhaus, SSL Blacklist (abuse.ch)
// Downloads and parses real-time C2 and Malware databases.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ── Threat Record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub ip: IpAddr,
    pub source: String,
    pub category: ThreatCategory,
    pub confidence: f32,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Botnet,
    C2Server,
    Ransomware,
    Phishing,
    Malware,
    Scanner,
    Spam,
    Unknown,
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub update_interval_secs: u64,
    pub feodo_enabled: bool,
    pub urlhaus_enabled: bool,
    pub sslbl_enabled: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            update_interval_secs: 3600, // Update hourly
            feodo_enabled: true,
            urlhaus_enabled: true,
            sslbl_enabled: true,
        }
    }
}

// ── Threat Intelligence Hub ───────────────────────────────────────────────────
//
// Blocks SPECIFIC malicious actors — NOT entire countries.
// Feeds (all free, no API key required):
//   Feodo Tracker  — active C2 botnet IPs          (abuse.ch)
//   SSL Blacklist  — malicious TLS cert IPs         (abuse.ch)
//   CINS Score     — confirmed attack-source IPs    (cinsscore.com)
//   Emerging Threats — compromised hosts            (emergingthreats.net)
//   ThreatFox      — multi-family IOCs: IPs+domains (abuse.ch)
//   URLhaus        — malware delivery hostnames     (abuse.ch)

pub struct ThreatIntelligenceHub {
    config: ThreatIntelConfig,
    /// Known malicious IPs → threat record (O(1) lookup)
    ioc_db: RwLock<HashMap<IpAddr, ThreatRecord>>,
    /// Known malicious domains / hostnames (exact + parent match)
    malicious_domains: RwLock<HashSet<String>>,
}

impl ThreatIntelligenceHub {
    pub fn new(config: ThreatIntelConfig) -> Self {
        let hub = Self {
            config,
            ioc_db: RwLock::new(HashMap::with_capacity(200_000)),
            malicious_domains: RwLock::new(HashSet::with_capacity(50_000)),
        };
        hub.load_ioc_from_disk();
        hub
    }

    /// Returns `true` if this exact domain — or its registered parent domain —
    /// is a known malware C2, phishing, or malware-delivery host.
    /// Example: "sub.evil.com" matches if "evil.com" is in the blocklist.
    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_lowercase();
        if d.is_empty() { return false; }
        let db = self.malicious_domains.read();
        if db.contains(&d) { return true; }
        // Parent (registered) domain check — catches all subdomains
        let parts: Vec<&str> = d.split('.').collect();
        if parts.len() > 2 {
            let parent = parts[parts.len() - 2..].join(".");
            if db.contains(&parent) { return true; }
        }
        false
    }

    pub fn add_malicious_domain(&self, domain: &str) {
        let d = domain.trim_end_matches('.').to_lowercase();
        if !d.is_empty() && d.contains('.') {
            self.malicious_domains.write().insert(d);
        }
    }

    pub fn domain_count(&self) -> usize {
        self.malicious_domains.read().len()
    }

    /// O(1) lookup: is this IP in any global threat intelligence feed?
    pub fn is_malicious_ip(&self, ip: &IpAddr) -> Option<ThreatRecord> {
        self.ioc_db.read().get(ip).cloned()
    }

    /// Add an IP to the local threat database (Memory block)
    pub fn add_ioc(&self, record: ThreatRecord) {
        self.ioc_db.write().insert(record.ip, record);
    }

    /// Background task: fetch + parse all enabled global feeds
    pub async fn start_continuous_updates(self: Arc<Self>) {
        let interval = tokio::time::Duration::from_secs(self.config.update_interval_secs);

        // Initial immediate load
        self.update_feeds().await;

        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            self.update_feeds().await;
        }
    }

    async fn update_feeds(&self) {
        info!("🌐 Intelligence Plane: Syncing live global threat intelligence feeds...");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        // 1. Feodo Tracker (C2 Botnets)
        if self.config.feodo_enabled {
            if let Ok(res) = client
                .get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
                .send()
                .await
            {
                if let Ok(text) = res.text().await {
                    let mut count = 0;
                    for line in text.lines() {
                        if line.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            if let Ok(ip) = parts[1].parse::<IpAddr>() {
                                let record = ThreatRecord {
                                    ip,
                                    source: "FeodoTracker (abuse.ch)".to_string(),
                                    category: ThreatCategory::C2Server,
                                    confidence: 0.95,
                                    first_seen: 0,
                                    last_seen: 0,
                                };
                                self.add_ioc(record);
                                count += 1;
                            }
                        }
                    }
                    info!("  ✅ Feodo Tracker: Ingested {} C2 botnet IPs", count);
                }
            } else {
                warn!("  ❌ Failed to reach Feodo Tracker");
            }
        }

        // 2. SSL Blacklist (Malicious Cert IPs)
        if self.config.sslbl_enabled {
            if let Ok(res) = client
                .get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv")
                .send()
                .await
            {
                if let Ok(text) = res.text().await {
                    let mut count = 0;
                    for line in text.lines() {
                        if line.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                                let record = ThreatRecord {
                                    ip,
                                    source: "SSLBL (abuse.ch)".to_string(),
                                    category: ThreatCategory::Malware,
                                    confidence: 0.90,
                                    first_seen: 0,
                                    last_seen: 0,
                                };
                                self.add_ioc(record);
                                count += 1;
                            }
                        }
                    }
                    info!("  ✅ SSL BL Tracker: Ingested {} Malicious IPs", count);
                }
            } else {
                warn!("  ❌ Failed to reach SSL BL");
            }
        }

        // 3. CINS Score — Confirmed attack-source IPs (no API key needed)
        if let Ok(res) = client
            .get("https://cinsscore.com/list/ci-badguys.txt")
            .send()
            .await
        {
            if let Ok(text) = res.text().await {
                let mut count = 0;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    if let Ok(ip) = line.parse::<IpAddr>() {
                        self.add_ioc(ThreatRecord {
                            ip,
                            source: "CINS Score (cinsscore.com)".to_string(),
                            category: ThreatCategory::Scanner,
                            confidence: 0.85,
                            first_seen: 0,
                            last_seen: 0,
                        });
                        count += 1;
                    }
                }
                info!("  ✅ CINS Score: Ingested {} confirmed attack-source IPs", count);
            }
        } else {
            warn!("  ❌ Failed to reach CINS Score feed");
        }

        // 4. Emerging Threats — Compromised / actively attacking hosts
        if let Ok(res) = client
            .get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
            .send()
            .await
        {
            if let Ok(text) = res.text().await {
                let mut count = 0;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    if let Ok(ip) = line.parse::<IpAddr>() {
                        self.add_ioc(ThreatRecord {
                            ip,
                            source: "Emerging Threats (compromised)".to_string(),
                            category: ThreatCategory::Botnet,
                            confidence: 0.88,
                            first_seen: 0,
                            last_seen: 0,
                        });
                        count += 1;
                    }
                }
                info!("  ✅ Emerging Threats: Ingested {} compromised host IPs", count);
            }
        } else {
            warn!("  ❌ Failed to reach Emerging Threats feed");
        }

        // 5. ThreatFox recent IOCs — Multi-family malware IPs AND domains (abuse.ch)
        // CSV: "date","id","ioc_type","ioc_value","malware",... ioc_type=ip:port|domain|url
        if let Ok(res) = client
            .get("https://threatfox.abuse.ch/export/csv/recent/")
            .send()
            .await
        {
            if let Ok(text) = res.text().await {
                let mut ip_count = 0;
                let mut dom_count = 0;
                for line in text.lines() {
                    if line.starts_with('#') { continue; }
                    let clean = line.replace('"', "");
                    let parts: Vec<&str> = clean.splitn(7, ',').collect();
                    if parts.len() < 4 { continue; }
                    let ioc_type  = parts[2].trim();
                    let ioc_value = parts[3].trim();
                    let malware   = parts.get(4).unwrap_or(&"unknown").trim();
                    match ioc_type {
                        "ip:port" => {
                            if let Some(ip_str) = ioc_value.split(':').next() {
                                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                    self.add_ioc(ThreatRecord {
                                        ip,
                                        source: format!("ThreatFox/{}", malware),
                                        category: ThreatCategory::C2Server,
                                        confidence: 0.92,
                                        first_seen: 0,
                                        last_seen: 0,
                                    });
                                    ip_count += 1;
                                }
                            }
                        }
                        "domain" => {
                            self.add_malicious_domain(ioc_value);
                            dom_count += 1;
                        }
                        "url" => {
                            // Extract hostname from URL
                            if let Some(host) = ioc_value
                                .trim_start_matches("http://")
                                .trim_start_matches("https://")
                                .split('/')
                                .next()
                            {
                                // Strip port if present
                                let host = host.split(':').next().unwrap_or(host);
                                self.add_malicious_domain(host);
                                dom_count += 1;
                            }
                        }
                        _ => {}
                    }
                }
                info!("  ✅ ThreatFox: Ingested {} malware IPs + {} malicious domains", ip_count, dom_count);
            }
        } else {
            warn!("  ❌ Failed to reach ThreatFox feed");
        }

        // 6. URLhaus — Malware delivery domain/hostname list (abuse.ch)
        // Format: hosts file — "127.0.0.1 malware.domain.com" per line
        if let Ok(res) = client
            .get("https://urlhaus.abuse.ch/downloads/hostfile/")
            .send()
            .await
        {
            if let Ok(text) = res.text().await {
                let mut count = 0;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let host = parts[1];
                        if host != "localhost" && host.contains('.') {
                            self.add_malicious_domain(host);
                            count += 1;
                        }
                    }
                }
                info!("  ✅ URLhaus: Ingested {} malware-delivery domains", count);
            }
        } else {
            warn!("  ❌ Failed to reach URLhaus domain hostfile");
        }

        info!(
            "🌐 Intelligence Plane: Feed sync complete — {} malicious IPs | {} malicious domains",
            self.ioc_count(), self.domain_count()
        );
        self.save_ioc_to_disk();
    }

    pub fn ioc_count(&self) -> usize {
        self.ioc_db.read().len()
    }

    /// Save the Live Intelligence Database to disk
    fn save_ioc_to_disk(&self) {
        let _ = fs::create_dir_all("data/intel");
        // Save IP IOC database
        {
            let db = self.ioc_db.read();
            if let Ok(json) = serde_json::to_string(&*db) {
                if let Ok(mut file) = File::create("data/intel/global_iocs.json") {
                    let _ = file.write_all(json.as_bytes());
                    debug!("💾 Saved {} malicious IPs to disk", db.len());
                }
            }
        }
        // Save domain blocklist (one per line — plain text, fast to load)
        {
            let domains = self.malicious_domains.read();
            if let Ok(mut file) = File::create("data/intel/malicious_domains.txt") {
                let mut buf = String::new();
                for d in domains.iter() { buf.push_str(d); buf.push('\n'); }
                let _ = file.write_all(buf.as_bytes());
                debug!("💾 Saved {} malicious domains to disk", domains.len());
            }
        }
    }

    /// Load the Intelligence Database from disk on startup
    fn load_ioc_from_disk(&self) {
        // Load IP IOCs
        if let Ok(mut file) = File::open("data/intel/global_iocs.json") {
            let mut json = String::new();
            if file.read_to_string(&mut json).is_ok() {
                if let Ok(loaded) = serde_json::from_str::<HashMap<IpAddr, ThreatRecord>>(&json) {
                    let count = loaded.len();
                    *self.ioc_db.write() = loaded;
                    info!("📥 Loaded {} malicious IPs from disk cache", count);
                }
            }
        }
        // Load domain blocklist
        if let Ok(mut file) = File::open("data/intel/malicious_domains.txt") {
            let mut text = String::new();
            if file.read_to_string(&mut text).is_ok() {
                let mut count = 0usize;
                let mut db = self.malicious_domains.write();
                for line in text.lines() {
                    let d = line.trim();
                    if !d.is_empty() { db.insert(d.to_string()); count += 1; }
                }
                info!("📥 Loaded {} malicious domains from disk cache", count);
            }
        }
    }
}
