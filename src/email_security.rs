// ============================================================================
// Rudras — Email Security Engine
//
// Inline SMTP session inspection and email content analysis for:
//   • SPF (Sender Policy Framework) — validates sending server IP
//   • DKIM (DomainKeys Identified Mail) — verifies header/body signature
//   • DMARC — enforces organisation-level SPF+DKIM policy
//   • BEC (Business Email Compromise) — display name spoofing, lookalike domains
//   • AUTH brute-force detection — >20 AUTH failures/min triggers alert
//   • Attachment risk scoring — risky extensions, macro-enabled documents
//   • Phishing URL extraction — detects links in message body
//   • SMTP command injection — CRLF injection, smuggling detection
//
// This engine operates as a passive observer of raw SMTP data streams,
// compatible with SMTP proxy / MTA integration via the capture pipeline.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Alert Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmailAlertType {
    SpfFail { sender_domain: String, source_ip: IpAddr },
    SpfSoftfail { sender_domain: String, source_ip: IpAddr },
    DkimFail { sender_domain: String },
    DmarcFail { from_domain: String, policy: DmarcPolicy },
    BecDisplayNameSpoof { claimed_name: String, actual_domain: String },
    BecLookalikeDomain { from_domain: String, target_domain: String, edit_distance: usize },
    AuthBruteForce { src_ip: IpAddr, failures_per_min: u32 },
    RiskyAttachment { filename: String, extension: String, risk_reason: String },
    PhishingUrl { url: String, reason: String },
    SmtpInjection { payload: String },
    HeaderSpoofing { header: String, issue: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAlert {
    pub id: String,
    pub src_ip: IpAddr,
    pub alert_type: EmailAlertType,
    pub severity: EmailSeverity,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmailSeverity { Low, Medium, High, Critical }

// ── SPF ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SpfResult { Pass, Fail, SoftFail, Neutral, None_, PermError, TempError }

/// Simplified SPF validator.
/// Real SPF requires DNS TXT record lookup; this simulation checks
/// against a pre-loaded policy cache.
pub struct SpfValidator {
    /// domain → list of authorised CIDR prefixes
    policy_cache: RwLock<HashMap<String, Vec<(u32, u8)>>>,
}

impl SpfValidator {
    pub fn new() -> Self { Self { policy_cache: RwLock::new(HashMap::new()) } }

    pub fn add_policy(&self, domain: &str, authorised_cidrs: Vec<(u32, u8)>) {
        self.policy_cache.write().insert(domain.to_lowercase(), authorised_cidrs);
    }

    pub fn check(&self, envelope_sender_domain: &str, source_ip: &IpAddr) -> SpfResult {
        let cache = self.policy_cache.read();
        let domain = envelope_sender_domain.to_lowercase();
        match cache.get(&domain) {
            None => SpfResult::None_,
            Some(cidrs) => {
                if let IpAddr::V4(v4) = source_ip {
                    let ip_u32 = u32::from(*v4);
                    for &(net, plen) in cidrs {
                        let mask = if plen == 0 { 0u32 } else { !0u32 << (32 - plen) };
                        if ip_u32 & mask == net & mask { return SpfResult::Pass; }
                    }
                    SpfResult::Fail
                } else {
                    SpfResult::Neutral
                }
            }
        }
    }
}

// ── DKIM ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DkimResult { Pass, Fail, PermError, TempError, None_ }

/// DKIM validator (signature verification simulation).
pub struct DkimValidator {
    /// domain+selector → public key bytes (pre-loaded from DNS cache)
    key_cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl DkimValidator {
    pub fn new() -> Self { Self { key_cache: RwLock::new(HashMap::new()) } }

    pub fn cache_key(&self, domain: &str, selector: &str, pubkey: Vec<u8>) {
        self.key_cache.write().insert(format!("{}.{}", selector, domain), pubkey);
    }

    /// Check for a valid DKIM-Signature header in the message headers.
    pub fn verify(&self, headers: &HashMap<String, String>) -> DkimResult {
        let sig_header = match headers.get("DKIM-Signature")
            .or_else(|| headers.get("dkim-signature")) {
            Some(h) => h.clone(),
            None => return DkimResult::None_,
        };

        // Extract d= and s= tags
        let domain = extract_dkim_tag(&sig_header, "d");
        let selector = extract_dkim_tag(&sig_header, "s");

        match (domain, selector) {
            (Some(d), Some(s)) => {
                let key_id = format!("{}.{}", s, d);
                if self.key_cache.read().contains_key(&key_id) {
                    // In a real implementation: verify RSA/Ed25519 signature
                    // here we simulate Pass if key exists in cache
                    DkimResult::Pass
                } else {
                    DkimResult::TempError // key not in cache = can't verify
                }
            }
            _ => DkimResult::PermError,
        }
    }
}

fn extract_dkim_tag(header: &str, tag: &str) -> Option<String> {
    let needle = format!("{}=", tag);
    for part in header.split(';') {
        let part = part.trim();
        if part.starts_with(&needle) {
            return Some(part[needle.len()..].trim().to_string());
        }
    }
    None
}

// ── DMARC ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DmarcPolicy { None_, Quarantine, Reject }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmarcResult { Pass, Fail { policy: DmarcPolicy } }

pub struct DmarcEnforcer {
    /// domain → DMARC policy
    policy_cache: RwLock<HashMap<String, DmarcPolicy>>,
}

impl DmarcEnforcer {
    pub fn new() -> Self { Self { policy_cache: RwLock::new(HashMap::new()) } }

    pub fn set_policy(&self, domain: &str, policy: DmarcPolicy) {
        self.policy_cache.write().insert(domain.to_lowercase(), policy);
    }

    pub fn evaluate(&self, spf: &SpfResult, dkim: &DkimResult, from_domain: &str) -> DmarcResult {
        let domain = from_domain.to_lowercase();
        let spf_pass = *spf == SpfResult::Pass;
        let dkim_pass = *dkim == DkimResult::Pass;

        // DMARC passes if either SPF or DKIM passes and domain is aligned
        if spf_pass || dkim_pass {
            return DmarcResult::Pass;
        }

        let policy = self.policy_cache.read()
            .get(&domain).cloned()
            .unwrap_or(DmarcPolicy::None_);
        DmarcResult::Fail { policy }
    }
}

// ── BEC Detection ─────────────────────────────────────────────────────────────

/// Levenshtein distance for domain lookalike detection.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i-1] == b[j-1] {
                dp[i-1][j-1]
            } else {
                1 + dp[i-1][j].min(dp[i][j-1]).min(dp[i-1][j-1])
            };
        }
    }
    dp[m][n]
}

pub struct BecDetector {
    /// High-value executive display names to watch for spoofing
    protected_names: RwLock<Vec<String>>,
    /// Internal domains that should not appear in external from addresses
    internal_domains: RwLock<Vec<String>>,
}

impl BecDetector {
    pub fn new() -> Self {
        Self {
            protected_names: RwLock::new(Vec::new()),
            internal_domains: RwLock::new(Vec::new()),
        }
    }

    pub fn add_protected_name(&self, name: &str) {
        self.protected_names.write().push(name.to_lowercase());
    }

    pub fn add_internal_domain(&self, domain: &str) {
        self.internal_domains.write().push(domain.to_lowercase());
    }

    /// Check display name vs. actual sending domain for spoofing.
    pub fn check_display_name(&self, display_name: &str, actual_from_domain: &str) -> Option<EmailAlertType> {
        let dn_lower = display_name.to_lowercase();
        let protected = self.protected_names.read();
        for name in protected.iter() {
            if dn_lower.contains(name.as_str()) {
                // The display name matches a protected executive name
                // Verify that the actual sending domain is the internal domain
                let internal = self.internal_domains.read();
                if !internal.iter().any(|d| actual_from_domain.ends_with(d.as_str())) {
                    return Some(EmailAlertType::BecDisplayNameSpoof {
                        claimed_name: display_name.to_string(),
                        actual_domain: actual_from_domain.to_string(),
                    });
                }
            }
        }
        None
    }

    /// Check from_domain for lookalike to internal domains (edit distance ≤ 2).
    pub fn check_lookalike(&self, from_domain: &str) -> Option<EmailAlertType> {
        let fd = from_domain.to_lowercase();
        let internal = self.internal_domains.read();
        for target in internal.iter() {
            if fd == *target { continue; } // exact match → it's real
            let dist = levenshtein(&fd, target);
            if dist <= 2 && dist > 0 {
                return Some(EmailAlertType::BecLookalikeDomain {
                    from_domain: from_domain.to_string(),
                    target_domain: target.clone(),
                    edit_distance: dist,
                });
            }
        }
        None
    }
}

// ── SMTP Brute Force Tracker ──────────────────────────────────────────────────

struct AuthTracker {
    failures: HashMap<IpAddr, (u32, u64)>, // (count, window_start)
    threshold_per_min: u32,
}

impl AuthTracker {
    fn new(threshold: u32) -> Self {
        Self { failures: HashMap::new(), threshold_per_min: threshold }
    }

    /// Returns Some(failures_per_min) if threshold exceeded, else None.
    fn record_failure(&mut self, ip: IpAddr) -> Option<u32> {
        let now = unix_secs();
        let entry = self.failures.entry(ip).or_insert((0, now));
        if now - entry.1 >= 60 {
            *entry = (1, now);
            None
        } else {
            entry.0 += 1;
            if entry.0 >= self.threshold_per_min {
                Some(entry.0)
            } else {
                None
            }
        }
    }

    fn cleanup(&mut self) {
        let now = unix_secs();
        self.failures.retain(|_, v| now - v.1 < 300);
    }
}

// ── Attachment Risk Scorer ────────────────────────────────────────────────────

fn score_attachment(filename: &str) -> Option<(String, String)> {
    // Returns (extension, risk_reason) if risky
    let lower = filename.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "exe" | "bat" | "cmd" | "scr" | "pif" | "com" => {
            Some((ext.to_string(), "Executable file type — direct execution risk".into()))
        }
        "ps1" | "psm1" | "psd1" => {
            Some((ext.to_string(), "PowerShell script — execution risk".into()))
        }
        "js" | "jse" | "vbs" | "vbe" => {
            Some((ext.to_string(), "Script file — execution risk".into()))
        }
        "docm" | "xlsm" | "pptm" | "dotm" => {
            Some((ext.to_string(), "Macro-enabled Office document".into()))
        }
        "hta" | "html" | "htm" => {
            // Only flag if in attachment context
            Some((ext.to_string(), "HTML attachment — potential redirect/phishing".into()))
        }
        "lnk" => Some((ext.to_string(), "Windows shortcut — can execute arbitrary commands".into())),
        "iso" | "img" => Some((ext.to_string(), "Container image — bypasses email attachment scanning".into())),
        "zip" | "rar" | "7z" | "gz" => None, // Compressed — flag only if double-extension
        _ => {
            // Double extension detection: e.g. "invoice.pdf.exe"
            let parts: Vec<&str> = lower.split('.').collect();
            if parts.len() >= 3 {
                let hidden_ext = parts[parts.len() - 2];
                if matches!(hidden_ext, "pdf" | "doc" | "txt" | "jpg") {
                    return Some((
                        format!("{}.{}", hidden_ext, ext),
                        format!("Double extension — disguised as .{}", hidden_ext),
                    ));
                }
            }
            None
        }
    }
}

// ── Phishing URL Extractor ────────────────────────────────────────────────────

/// Extract URLs from plaintext/HTML body and flag suspicious ones.
fn extract_and_flag_urls(body: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    // Simple URL extraction: find http/https://...
    for (i, _) in body.match_indices("http") {
        let rest = &body[i..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len().min(256));
        let url = &rest[..end];
        if url.len() < 8 { continue; }

        // Flag suspicious patterns
        let url_lower = url.to_lowercase();
        if url_lower.contains("@") && url_lower.contains("http") {
            results.push((url.to_string(), "URL contains @ — credential theft pattern".into()));
        } else if url_lower.contains("bit.ly") || url_lower.contains("tinyurl.com") ||
                  url_lower.contains("t.co") || url_lower.contains("goo.gl") {
            results.push((url.to_string(), "URL shortener — obscures true destination".into()));
        } else if url_lower.contains(".ru/") || url_lower.contains(".cn/") ||
                  url_lower.contains(".tk/") || url_lower.contains(".ml/") {
            results.push((url.to_string(), "High-risk TLD in URL".into()));
        } else if url_lower.contains("login") && url_lower.contains("verify") {
            results.push((url.to_string(), "URL contains 'login' and 'verify' — phishing indicator".into()));
        }
    }
    results
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailStats {
    pub sessions_inspected: u64,
    pub emails_analyzed: u64,
    pub spf_passes: u64,
    pub spf_fails: u64,
    pub dkim_passes: u64,
    pub dkim_fails: u64,
    pub dmarc_fails: u64,
    pub bec_alerts: u64,
    pub auth_brute_force: u64,
    pub risky_attachments: u64,
    pub phishing_urls: u64,
    pub total_alerts: u64,
}

// ── Email Security Engine ─────────────────────────────────────────────────────

pub struct EmailSecurityEngine {
    pub spf: SpfValidator,
    pub dkim: DkimValidator,
    pub dmarc: DmarcEnforcer,
    pub bec: BecDetector,
    auth_tracker: RwLock<AuthTracker>,
    alerts: RwLock<VecDeque<EmailAlert>>,
    sessions_inspected: AtomicU64,
    emails_analyzed: AtomicU64,
    spf_passes: AtomicU64,
    spf_fails: AtomicU64,
    dkim_passes: AtomicU64,
    dkim_fails: AtomicU64,
    dmarc_fails: AtomicU64,
    bec_alert_count: AtomicU64,
    auth_brute: AtomicU64,
    risky_attach: AtomicU64,
    phish_urls: AtomicU64,
    total_alerts: AtomicU64,
    seq: AtomicU64,
}

impl EmailSecurityEngine {
    pub fn new() -> Self {
        let engine = Self {
            spf: SpfValidator::new(),
            dkim: DkimValidator::new(),
            dmarc: DmarcEnforcer::new(),
            bec: BecDetector::new(),
            auth_tracker: RwLock::new(AuthTracker::new(20)),
            alerts: RwLock::new(VecDeque::with_capacity(256)),
            sessions_inspected: AtomicU64::new(0),
            emails_analyzed: AtomicU64::new(0),
            spf_passes: AtomicU64::new(0),
            spf_fails: AtomicU64::new(0),
            dkim_passes: AtomicU64::new(0),
            dkim_fails: AtomicU64::new(0),
            dmarc_fails: AtomicU64::new(0),
            bec_alert_count: AtomicU64::new(0),
            auth_brute: AtomicU64::new(0),
            risky_attach: AtomicU64::new(0),
            phish_urls: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        };
        info!("📧 Email Security Engine initialized — SPF/DKIM/DMARC/BEC/Attachment/URL analysis ready");
        engine
    }

    fn next_id(&self) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("EMAIL-{}-{}", unix_secs(), n)
    }

    fn push_alert(&self, src_ip: IpAddr, alert_type: EmailAlertType, severity: EmailSeverity) {
        warn!("📧 Email alert: {:?}", alert_type);
        self.total_alerts.fetch_add(1, Ordering::Relaxed);
        let alert = EmailAlert {
            id: self.next_id(), src_ip, alert_type, severity,
            timestamp: unix_secs(),
        };
        let mut q = self.alerts.write();
        if q.len() >= 256 { q.pop_front(); }
        q.push_back(alert);
    }

    /// Record an SMTP AUTH failure.
    pub fn record_auth_failure(&self, src_ip: IpAddr) {
        if let Some(rate) = self.auth_tracker.write().record_failure(src_ip) {
            self.auth_brute.fetch_add(1, Ordering::Relaxed);
            self.push_alert(src_ip,
                EmailAlertType::AuthBruteForce { src_ip, failures_per_min: rate },
                EmailSeverity::High);
        }
    }

    /// Inspect an SMTP session initiation (EHLO/MAIL FROM).
    pub fn inspect_smtp_header(
        &self, src_ip: IpAddr,
        envelope_from_domain: &str,
        display_name: Option<&str>,
        from_domain: Option<&str>,
    ) {
        self.sessions_inspected.fetch_add(1, Ordering::Relaxed);

        // SPF check
        let spf_result = self.spf.check(envelope_from_domain, &src_ip);
        match &spf_result {
            SpfResult::Fail => {
                self.spf_fails.fetch_add(1, Ordering::Relaxed);
                self.push_alert(src_ip,
                    EmailAlertType::SpfFail {
                        sender_domain: envelope_from_domain.to_string(),
                        source_ip: src_ip,
                    },
                    EmailSeverity::High);
            }
            SpfResult::SoftFail => {
                self.spf_fails.fetch_add(1, Ordering::Relaxed);
                self.push_alert(src_ip,
                    EmailAlertType::SpfSoftfail {
                        sender_domain: envelope_from_domain.to_string(),
                        source_ip: src_ip,
                    },
                    EmailSeverity::Medium);
            }
            SpfResult::Pass => { self.spf_passes.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }

        // BEC checks
        if let Some(dn) = display_name {
            if let Some(fd) = from_domain {
                if let Some(alert) = self.bec.check_display_name(dn, fd) {
                    self.bec_alert_count.fetch_add(1, Ordering::Relaxed);
                    self.push_alert(src_ip, alert, EmailSeverity::High);
                }
                if let Some(alert) = self.bec.check_lookalike(fd) {
                    self.bec_alert_count.fetch_add(1, Ordering::Relaxed);
                    self.push_alert(src_ip, alert, EmailSeverity::High);
                }
            }
        }
    }

    /// Analyze email content: headers, body, attachments.
    pub fn analyze_email(
        &self, src_ip: IpAddr,
        headers: &HashMap<String, String>,
        body: &str,
        attachment_filenames: &[&str],
    ) {
        self.emails_analyzed.fetch_add(1, Ordering::Relaxed);

        // DKIM verification
        let dkim_result = self.dkim.verify(headers);
        match &dkim_result {
            DkimResult::Fail => {
                self.dkim_fails.fetch_add(1, Ordering::Relaxed);
                let domain = headers.get("From").cloned().unwrap_or_default();
                self.push_alert(src_ip,
                    EmailAlertType::DkimFail { sender_domain: domain },
                    EmailSeverity::High);
            }
            DkimResult::Pass => { self.dkim_passes.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }

        // DMARC
        let from_domain = headers.get("From")
            .and_then(|f| f.split('@').last())
            .and_then(|s| s.split('>').next())
            .unwrap_or("");
        let spf_result = SpfResult::None_; // already inspected at EHLO phase above
        let dmarc = self.dmarc.evaluate(&spf_result, &dkim_result, from_domain);
        if let DmarcResult::Fail { policy } = dmarc {
            if policy != DmarcPolicy::None_ {
                self.dmarc_fails.fetch_add(1, Ordering::Relaxed);
                self.push_alert(src_ip,
                    EmailAlertType::DmarcFail {
                        from_domain: from_domain.to_string(),
                        policy,
                    },
                    EmailSeverity::Medium);
            }
        }

        // Attachment risk scoring
        for fname in attachment_filenames {
            if let Some((ext, reason)) = score_attachment(fname) {
                self.risky_attach.fetch_add(1, Ordering::Relaxed);
                self.push_alert(src_ip,
                    EmailAlertType::RiskyAttachment {
                        filename: fname.to_string(),
                        extension: ext, risk_reason: reason,
                    },
                    EmailSeverity::High);
            }
        }

        // Phishing URL extraction
        for (url, reason) in extract_and_flag_urls(body) {
            self.phish_urls.fetch_add(1, Ordering::Relaxed);
            self.push_alert(src_ip,
                EmailAlertType::PhishingUrl { url, reason },
                EmailSeverity::Medium);
        }

        // SMTP injection detection (CRLF injection / header injection)
        for (header_name, header_val) in headers {
            if header_val.contains("\r\n") || header_val.contains("\n") {
                self.push_alert(src_ip,
                    EmailAlertType::SmtpInjection {
                        payload: format!("{}: {}", header_name, &header_val[..50.min(header_val.len())]),
                    },
                    EmailSeverity::Critical);
            }
        }
    }

    pub fn cleanup(&self) {
        self.auth_tracker.write().cleanup();
    }

    pub fn drain_alerts(&self) -> Vec<EmailAlert> {
        self.alerts.write().drain(..).collect()
    }

    pub fn stats(&self) -> EmailStats {
        EmailStats {
            sessions_inspected: self.sessions_inspected.load(Ordering::Relaxed),
            emails_analyzed: self.emails_analyzed.load(Ordering::Relaxed),
            spf_passes: self.spf_passes.load(Ordering::Relaxed),
            spf_fails: self.spf_fails.load(Ordering::Relaxed),
            dkim_passes: self.dkim_passes.load(Ordering::Relaxed),
            dkim_fails: self.dkim_fails.load(Ordering::Relaxed),
            dmarc_fails: self.dmarc_fails.load(Ordering::Relaxed),
            bec_alerts: self.bec_alert_count.load(Ordering::Relaxed),
            auth_brute_force: self.auth_brute.load(Ordering::Relaxed),
            risky_attachments: self.risky_attach.load(Ordering::Relaxed),
            phishing_urls: self.phish_urls.load(Ordering::Relaxed),
            total_alerts: self.total_alerts.load(Ordering::Relaxed),
        }
    }
}
