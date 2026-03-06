// ============================================================================
// Rudras — Attack Attribution Scoring Engine
// ============================================================================
//
// PURPOSE
// ───────
// Estimates the probable *type, origin, and sophistication* of an attack
// by scoring observed network behaviours against known threat actor archetypes.
//
// IMPORTANT — LEGAL AND ETHICAL DESIGN CONSTRAINTS
// ─────────────────────────────────────────────────
// ⚠️  Attribution is probabilistic classification, NOT legal proof.
//
// This engine deliberately:
//   1. Uses probabilistic language at all times ("Likely", "Possible",
//      "High probability of") — never definitive claims.
//   2. Does NOT name specific individuals, organisations, or nation states.
//   3. Classifies attacks into *archetype categories* (Botnet, APT-style,
//      Script Kiddie, etc.) aligned with the MITRE ATT&CK framework's
//      threat actor model — no proprietary group naming.
//   4. Marks every AttributionReport with a legal disclaimer.
//
// FRAMEWORK ALIGNMENT
// ───────────────────
// Scoring heuristics are derived from MITRE ATT&CK behavioural indicators:
//   • Tactic diversity     → higher diversity suggests planned, skilled attack
//   • Timing regularity   → constant intervals = automated/botnet
//   • Target specificity  → single service targeted = knowledge-based attack
//   • Persistence         → long-term repeat activity = APT-style campaign
//   • Payload complexity  → obfuscated/encoded = higher actor skill
//   • Port selection      → well-known exploit ports = scripted tooling
//
// USAGE
// ─────
//   let engine = Arc::new(AttributionEngine::new());
//   // call per-alert or per-burst from IDS:
//   let report = engine.attribute(src_ip, &ids_alerts);
//   info!("{}", report.primary_label);   // "Likely automated botnet scan"
// ============================================================================

#![allow(dead_code, unused_imports)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::ids_engine::{IdsAlert, IdsCategory, IdsSeverity};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Actor archetypes ──────────────────────────────────────────────────────────

/// Broad threat actor archetypes for probabilistic classification.
/// These are NOT linked to any specific named group or individual.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorCategory {
    /// Fully automated, indiscriminate mass-scanning or exploitation tool
    /// (e.g., Mirai-style botnet scanner, opportunistic exploit sprayer).
    AutomatedBotnet,
    /// Low-skill opportunistic attacker using off-the-shelf tools with
    /// minimal customisation (script kiddie, commodity malware dropper).
    OpportunisticAttacker,
    /// Likely authorised security assessment (penetration test / red team).
    /// Detected when tool signatures match pentest frameworks without
    /// matching C2 beaconing patterns.
    AuthorizedPentester,
    /// Financially motivated organised crime — targeted, uses commercial C2
    /// tools (Cobalt Strike, Emotet chains), focuses on credential/banking.
    CybercriminalGroup,
    /// Advanced, targeted, persistent campaign with broad TTP diversity —
    /// consistent with APT-style tradecraft.  NOT attributed to any nation.
    AdvancedPersistentThreat,
    /// Traffic originates from inside the network perimeter —
    /// possible insider threat or compromised internal host.
    InsiderOrLateralMovement,
    /// Too few signals to place in any archetype.
    Unknown,
}

impl ActorCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AutomatedBotnet            => "Automated Botnet / Mass Scanner",
            Self::OpportunisticAttacker      => "Opportunistic Attacker / Script Kiddie",
            Self::AuthorizedPentester        => "Possible Authorized Penetration Test",
            Self::CybercriminalGroup         => "Possible Cybercriminal Group",
            Self::AdvancedPersistentThreat   => "APT-Style Campaign (targeted, persistent)",
            Self::InsiderOrLateralMovement   => "Insider Threat / Lateral Movement",
            Self::Unknown                    => "Unknown / Insufficient Data",
        }
    }
    pub fn mitre_group_hint(&self) -> &'static str {
        match self {
            Self::AutomatedBotnet            => "TA0043 Reconnaissance | T1595 Scanning",
            Self::OpportunisticAttacker      => "T1190 Exploit Public-Facing | T1110 Brute Force",
            Self::AuthorizedPentester        => "Pentest tooling patterns (Metasploit/Nmap TTPs)",
            Self::CybercriminalGroup         => "T1071 C2 | T1486 Ransomware | T1566 Phishing",
            Self::AdvancedPersistentThreat   => "TA0008 Lateral Movement | TA0010 Exfiltration",
            Self::InsiderOrLateralMovement   => "TA0008 Lateral Movement | T1078 Valid Accounts",
            Self::Unknown                    => "N/A",
        }
    }
}

// ── Attack pattern ───────────────────────────────────────────────────────────

/// Describes the *operational pattern* of the observed attack, independent
/// of the actor archetype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Mass-sweep, no specific target — opportunistic drive-by
    OpportunisticSweep,
    /// A single service or IP is repeatedly targeted — shows knowledge
    TargetedSpecific,
    /// Highly regular packet timing → scripted or bot-driven
    AutomatedScripted,
    /// Irregular timing, adaptive port selection → human operator
    InteractiveHandsOnKeyboard,
    /// Attack campaign measured in hours or days — persistent campaign
    PersistentCampaign,
    /// Originates from an internal subnet — lateral or insider
    InternalLateral,
    /// Insufficient data to categorise
    Unknown,
}

impl AttackPattern {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpportunisticSweep          => "Opportunistic sweep (mass-targeting)",
            Self::TargetedSpecific            => "Targeted attack (service-specific)",
            Self::AutomatedScripted           => "Automated / scripted attack tool",
            Self::InteractiveHandsOnKeyboard  => "Likely interactive (human operator)",
            Self::PersistentCampaign          => "Persistent campaign (multi-hour/day)",
            Self::InternalLateral             => "Internal / lateral movement",
            Self::Unknown                     => "Unknown pattern",
        }
    }
}

// ── Attribution report ────────────────────────────────────────────────────────

/// The output of the attribution engine for a source IP.
///
/// IMPORTANT LEGAL NOTE (present on every report):
/// Attribution is probabilistic classification based on network behaviour.
/// It is NOT legal proof of identity, origin, or criminal responsibility.
/// Treat all attributions as investigative starting points only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionReport {
    pub src_ip: IpAddr,
    pub timestamp: u64,
    /// Human-readable primary label — always uses probabilistic language.
    /// Examples: "Likely automated botnet traffic"
    ///           "Possible brute-force attack from script kiddie"
    ///           "High probability of C2 communication"
    pub primary_label: String,
    /// Overall confidence in the primary label (0.0–1.0).
    pub confidence: f32,
    /// Probability distribution across actor archetypes (sums to ~1.0).
    pub actor_probabilities: Vec<(ActorCategory, f32)>,
    /// Detected operational pattern.
    pub attack_pattern: AttackPattern,
    /// Most relevant MITRE ATT&CK tactic/technique hints.
    pub mitre_hints: Vec<String>,
    /// Observable indicators that drove this attribution (non-PII).
    pub ioc_signals: Vec<String>,
    /// Total IDS alerts observed from this source.
    pub total_alerts_observed: u32,
    /// How long this IP has been observed (seconds).
    pub observation_duration_secs: u64,
    /// Legal disclaimer — always populated.
    pub disclaimer: &'static str,
}

// ── Per-IP attack history ─────────────────────────────────────────────────────

#[derive(Debug)]
struct IpHistory {
    first_seen: u64,
    last_seen: u64,
    alert_count: u32,
    /// Unique IDS categories seen — diversity indicates sophistication
    categories: HashSet<String>,
    /// Targeted destination ports
    dst_ports: HashSet<u16>,
    /// Alert timestamps for timing analysis (last 50)
    timestamps: VecDeque<u64>,
    /// Whether source is private/internal
    is_internal: bool,
    /// Highest severity seen
    max_severity: u8, // 0=Low 1=Medium 2=High 3=Critical
    /// Payload obfuscation signals seen
    obfuscation_signals: u32,
    /// C2/beaconing signals seen
    c2_signals: u32,
    /// Brute force signals seen  
    bruteforce_signals: u32,
    /// Exfiltration signals seen
    exfil_signals: u32,
    /// Exploit attempt signals
    exploit_signals: u32,
    /// Scan signals seen
    scan_signals: u32,
}

impl IpHistory {
    fn new(is_internal: bool) -> Self {
        let now = unix_now();
        Self {
            first_seen: now,
            last_seen: now,
            alert_count: 0,
            categories: HashSet::new(),
            dst_ports: HashSet::new(),
            timestamps: VecDeque::with_capacity(50),
            is_internal,
            max_severity: 0,
            obfuscation_signals: 0,
            c2_signals: 0,
            bruteforce_signals: 0,
            exfil_signals: 0,
            exploit_signals: 0,
            scan_signals: 0,
        }
    }

    fn ingest(&mut self, alert: &IdsAlert) {
        let now = unix_now();
        self.last_seen = now;
        self.alert_count += 1;
        self.categories.insert(alert.category.label().to_string());
        self.dst_ports.insert(alert.dst_port);
        if self.timestamps.len() >= 50 {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back(now);

        let sev = match alert.severity {
            IdsSeverity::Low      => 0,
            IdsSeverity::Medium   => 1,
            IdsSeverity::High     => 2,
            IdsSeverity::Critical => 3,
        };
        if sev > self.max_severity {
            self.max_severity = sev;
        }

        // Classify signal type from category
        match &alert.category {
            IdsCategory::C2Communication
            | IdsCategory::TrojanCommunication
            | IdsCategory::BackdoorAccess
            | IdsCategory::DgaActivity
            | IdsCategory::BankingMalwareComm => self.c2_signals += 1,

            IdsCategory::BruteForce
            | IdsCategory::PasswordSpraying
            | IdsCategory::CredentialStuffing => self.bruteforce_signals += 1,

            IdsCategory::DataExfiltration
            | IdsCategory::DnsTunneling
            | IdsCategory::SpywareExfiltration
            | IdsCategory::InsiderDataExfiltration => self.exfil_signals += 1,

            IdsCategory::ExploitAttempt
            | IdsCategory::RceAttempt
            | IdsCategory::BufferOverflowAttempt
            | IdsCategory::InitialAccessExploit
            | IdsCategory::ZeroDayAnomaly => self.exploit_signals += 1,

            IdsCategory::PortScan
            | IdsCategory::ServiceEnumeration
            | IdsCategory::IotMalwarePropagation => self.scan_signals += 1,

            IdsCategory::DefenseEvasionNetwork
            | IdsCategory::LivingOffLand
            | IdsCategory::TlsAnomaly => self.obfuscation_signals += 1,

            _ => {}
        }
    }

    fn observation_duration(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }

    /// Compute regularity of alert timing (0.0 = totally random, 1.0 = perfectly regular).
    /// Regular intervals strongly suggest automated tooling.
    fn timing_regularity(&self) -> f32 {
        if self.timestamps.len() < 3 {
            return 0.5; // not enough data
        }
        let intervals: Vec<f64> = self
            .timestamps
            .iter()
            .zip(self.timestamps.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a) as f64)
            .filter(|v| *v > 0.0)
            .collect();
        if intervals.len() < 2 {
            return 0.5;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { 1.0 };
        // Low CV (< 0.2) = highly regular = automated
        (1.0 - cv.min(1.0) as f32).max(0.0)
    }
}

// ── Attribution Engine ────────────────────────────────────────────────────────

pub struct AttributionEngine {
    ip_histories: RwLock<HashMap<IpAddr, IpHistory>>,
}

impl AttributionEngine {
    pub fn new() -> Self {
        info!("🎯 Attribution Engine: initialised (probabilistic, MITRE ATT&CK aligned)");
        Self {
            ip_histories: RwLock::new(HashMap::with_capacity(10_000)),
        }
    }

    /// Ingest a batch of IDS alerts for a source IP and return an updated
    /// AttributionReport.  Call this after every IDS alert burst.
    pub fn attribute(&self, src_ip: IpAddr, alerts: &[IdsAlert]) -> Option<AttributionReport> {
        if alerts.is_empty() {
            return None;
        }

        let is_internal = is_private_ip(src_ip);

        // Ingest all alerts into per-IP history
        {
            let mut histories = self.ip_histories.write();
            let history = histories
                .entry(src_ip)
                .or_insert_with(|| IpHistory::new(is_internal));
            for alert in alerts {
                history.ingest(alert);
            }
        }

        let histories = self.ip_histories.read();
        let h = histories.get(&src_ip)?;

        // ── Score each archetype ──────────────────────────────────────────────
        let mut scores: HashMap<ActorCategory, f32> = HashMap::new();

        // AUTOMATED BOTNET:
        // • Very regular timing
        // • High scan signal / IoT malware
        // • Low category diversity (single-purpose scanner)
        // • Low max severity early on
        {
            let mut s = 0.0_f32;
            s += h.timing_regularity() * 0.40;
            s += (h.scan_signals as f32).min(5.0) / 5.0 * 0.30;
            if h.categories.len() <= 2 { s += 0.20; }
            if h.max_severity <= 1 { s += 0.10; }
            scores.insert(ActorCategory::AutomatedBotnet, s);
        }

        // OPPORTUNISTIC ATTACKER:
        // • Moderate scan + exploit signals
        // • Well-known exploit ports targeted (22, 80, 443, 3389, etc.)
        // • Low timing regularity (manual tool usage)
        // • Low category diversity
        {
            let mut s = 0.0_f32;
            let known_exploit_ports = [22u16, 23, 80, 443, 445, 3389, 8080, 8443, 21, 25, 110];
            let known_port_hits = h
                .dst_ports
                .iter()
                .filter(|p| known_exploit_ports.contains(p))
                .count();
            s += (known_port_hits as f32).min(4.0) / 4.0 * 0.35;
            s += (h.exploit_signals as f32).min(5.0) / 5.0 * 0.25;
            s += (h.bruteforce_signals as f32).min(3.0) / 3.0 * 0.20;
            if h.timing_regularity() < 0.4 { s += 0.10; }
            if h.categories.len() <= 3 { s += 0.10; }
            scores.insert(ActorCategory::OpportunisticAttacker, s);
        }

        // AUTHORIZED PENTESTER:
        // • Diverse category coverage (recon + exploit + post-exploit)  
        // • No persistent C2 beaconing
        // • High confidence alerts from scanning + exploit tools together
        // • No exfiltration signals
        {
            let mut s = 0.0_f32;
            let has_scan = h.scan_signals > 0;
            let has_exploit = h.exploit_signals > 0;
            let has_brute = h.bruteforce_signals > 0;
            let diversity_count = [has_scan, has_exploit, has_brute].iter().filter(|&&b| b).count();
            s += diversity_count as f32 / 3.0 * 0.40;
            if h.c2_signals == 0 { s += 0.25; }
            if h.exfil_signals == 0 { s += 0.20; }
            if h.obfuscation_signals == 0 { s += 0.15; }
            scores.insert(ActorCategory::AuthorizedPentester, s);
        }

        // CYBERCRIMINAL GROUP:
        // • C2 + exfil signals prominent
        // • High severity (targetted exploitation)
        // • Credential/banking malware patterns
        // • Some obfuscation
        {
            let mut s = 0.0_f32;
            s += (h.c2_signals as f32).min(5.0) / 5.0 * 0.35;
            s += (h.exfil_signals as f32).min(3.0) / 3.0 * 0.25;
            if h.max_severity >= 2 { s += 0.15; }
            s += (h.obfuscation_signals as f32).min(3.0) / 3.0 * 0.10;
            s += (h.exploit_signals as f32).min(2.0) / 2.0 * 0.15;
            scores.insert(ActorCategory::CybercriminalGroup, s);
        }

        // APT-STYLE:
        // • Long observation duration (hours/days)
        // • High tactic diversity (recon → access → lateral → exfil)
        // • Obfuscation + C2 + lateral movement together
        // • Low noise relative to impact (targeted, patient)
        {
            let mut s = 0.0_f32;
            let duration = h.observation_duration();
            if duration > 3600 { s += 0.15; }
            if duration > 86400 { s += 0.15; }
            s += (h.categories.len().min(6) as f32) / 6.0 * 0.25;
            if h.c2_signals > 0 && h.exfil_signals > 0 { s += 0.20; }
            if h.obfuscation_signals > 0 { s += 0.10; }
            if h.max_severity >= 3 { s += 0.15; }
            scores.insert(ActorCategory::AdvancedPersistentThreat, s);
        }

        // INSIDER / LATERAL:
        // • Source IP is in private range
        // • Lateral movement signals (wmi, psexec patterns)
        {
            let mut s = 0.0_f32;
            if is_internal { s += 0.50; }
            // If categories include lateral movement indicators
            if h.categories.contains("LATERAL") || h.categories.contains("SUSP_INTERNAL") {
                s += 0.30;
            }
            if h.c2_signals > 0 && is_internal { s += 0.20; }
            scores.insert(ActorCategory::InsiderOrLateralMovement, s);
        }

        // UNKNOWN:
        // Base score inversely proportional to total signals — more signals → less unknown
        {
            let total_signals = (h.scan_signals + h.c2_signals + h.exfil_signals
                + h.exploit_signals + h.bruteforce_signals) as f32;
            let unknown_score = (1.0 - (total_signals / 10.0).min(1.0)) * 0.4;
            scores.insert(ActorCategory::Unknown, unknown_score.max(0.05));
        }

        // Normalise to sum to 1.0
        let total: f32 = scores.values().sum();
        let mut normalised: Vec<(ActorCategory, f32)> = scores
            .into_iter()
            .map(|(cat, s)| (cat, if total > 0.0 { s / total } else { 1.0 / 7.0 }))
            .collect();
        normalised.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (primary_actor, primary_prob) = &normalised[0];
        let confidence = *primary_prob;

        // ── Attack pattern ────────────────────────────────────────────────────
        let attack_pattern = if h.is_internal {
            AttackPattern::InternalLateral
        } else if h.observation_duration() > 14400 && h.categories.len() >= 4 {
            AttackPattern::PersistentCampaign
        } else if h.timing_regularity() > 0.70 {
            AttackPattern::AutomatedScripted
        } else if h.dst_ports.len() == 1 && h.exploit_signals > 0 {
            AttackPattern::TargetedSpecific
        } else if h.timing_regularity() < 0.25 && h.alert_count >= 3 {
            AttackPattern::InteractiveHandsOnKeyboard
        } else if h.scan_signals > 0 && h.dst_ports.len() > 10 {
            AttackPattern::OpportunisticSweep
        } else {
            AttackPattern::Unknown
        };

        // ── IOC signals (observable, non-PII) ────────────────────────────────
        let mut ioc_signals: Vec<String> = Vec::new();
        if h.scan_signals > 0 {
            ioc_signals.push(format!("{} port-scan signal(s)", h.scan_signals));
        }
        if h.c2_signals > 0 {
            ioc_signals.push(format!("{} C2 beaconing signal(s)", h.c2_signals));
        }
        if h.exfil_signals > 0 {
            ioc_signals.push(format!("{} exfiltration signal(s)", h.exfil_signals));
        }
        if h.exploit_signals > 0 {
            ioc_signals.push(format!("{} exploit attempt(s)", h.exploit_signals));
        }
        if h.bruteforce_signals > 0 {
            ioc_signals.push(format!("{} brute-force signal(s)", h.bruteforce_signals));
        }
        if h.obfuscation_signals > 0 {
            ioc_signals.push(format!("{} obfuscation/evasion signal(s)", h.obfuscation_signals));
        }
        ioc_signals.push(format!("{} unique category(ies) observed", h.categories.len()));
        ioc_signals.push(format!(
            "timing_regularity={:.2} (1.0=fully automated)",
            h.timing_regularity()
        ));

        // ── MITRE hints ───────────────────────────────────────────────────────
        let mut mitre_hints: Vec<String> = vec![primary_actor.mitre_group_hint().to_string()];
        if h.c2_signals > 0 {
            mitre_hints.push("T1071 Application Layer Protocol (C2)".to_string());
        }
        if h.exfil_signals > 0 {
            mitre_hints.push("T1048 Exfiltration Over Alternative Protocol".to_string());
        }
        if h.scan_signals > 0 {
            mitre_hints.push("T1046 Network Service Discovery".to_string());
        }
        if h.bruteforce_signals > 0 {
            mitre_hints.push("T1110 Brute Force".to_string());
        }

        // ── Primary label (always probabilistic language) ─────────────────────
        let qualifier = if confidence > 0.70 {
            "High probability of"
        } else if confidence > 0.50 {
            "Likely"
        } else {
            "Possible"
        };

        let actor_desc = match primary_actor {
            ActorCategory::AutomatedBotnet          => "automated botnet / mass-scanning traffic",
            ActorCategory::OpportunisticAttacker    => "opportunistic attack (script kiddie / commodity tooling)",
            ActorCategory::AuthorizedPentester      => "authorized penetration test or security scan",
            ActorCategory::CybercriminalGroup       => "cybercriminal group activity (C2/exfil patterns observed)",
            ActorCategory::AdvancedPersistentThreat => "APT-style campaign (targeted, persistent, multi-tactic)",
            ActorCategory::InsiderOrLateralMovement => "insider threat or lateral movement from compromised host",
            ActorCategory::Unknown                  => "unknown attack origin (insufficient data for classification)",
        };

        let primary_label = format!("{} {}", qualifier, actor_desc);

        // ── Log the report ────────────────────────────────────────────────────
        debug!(
            "🎯 ATTRIBUTION [{}]: {} | confidence={:.0}% | pattern={} | alerts={}",
            src_ip,
            primary_label,
            confidence * 100.0,
            attack_pattern.label(),
            h.alert_count
        );

        Some(AttributionReport {
            src_ip,
            timestamp: unix_now(),
            primary_label,
            confidence,
            actor_probabilities: normalised,
            attack_pattern,
            mitre_hints,
            ioc_signals,
            total_alerts_observed: h.alert_count,
            observation_duration_secs: h.observation_duration(),
            disclaimer: "LEGAL NOTICE: Attribution is probabilistic classification \
                         based on network behaviour only. It is NOT legal proof of \
                         identity, origin, or criminal responsibility. Treat as an \
                         investigative signal, not a legal finding.",
        })
    }

    /// Prune stale IP histories older than `max_age_secs`.
    pub fn cleanup(&self, max_age_secs: u64) {
        let now = unix_now();
        let mut histories = self.ip_histories.write();
        histories.retain(|_, h| now.saturating_sub(h.last_seen) < max_age_secs);
    }

    /// Get attribution stats for monitoring.
    pub fn stats(&self) -> AttributionStats {
        let histories = self.ip_histories.read();
        AttributionStats {
            tracked_sources: histories.len(),
            with_c2_signals: histories.values().filter(|h| h.c2_signals > 0).count(),
            with_exfil_signals: histories.values().filter(|h| h.exfil_signals > 0).count(),
            with_apt_indicators: histories
                .values()
                .filter(|h| h.categories.len() >= 4 && h.observation_duration() > 3600)
                .count(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionStats {
    pub tracked_sources: usize,
    pub with_c2_signals: usize,
    pub with_exfil_signals: usize,
    pub with_apt_indicators: usize,
}

// ── Private IP helper (mirrors capture.rs) ───────────────────────────────────

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(o,
                [10, ..] |
                [172, 16..=31, ..] |
                [192, 168, ..] |
                [127, ..]
            )
        }
        IpAddr::V6(_) => false,
    }
}
