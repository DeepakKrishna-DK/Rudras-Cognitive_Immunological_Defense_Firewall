// ============================================================================
// Rudras — LLM Explainability Engine
//
// Produces human-readable, analyst-grade explanations for every alert.
// This is NOT an LLM inference engine — it is a rule-based language
// generation system that uses structured templates + feature attributions
// to produce natural-language explanations without any external AI call.
//
// Design: LIME-inspired text explanations derived from feature importance
// vectors (SHAP-style, from AdvancedMlEngine) + structured reasoning chains.
//
// Implements:
//   • AlertExplainer: natural language narrative for any alert type
//   • FeatureExplainer: "Top 3 contributing factors" sentences
//   • MitreMapper: maps detections to MITRE ATT&CK tactic/technique
//   • ConfidenceNarrator: explains why a score is 0.87 vs 0.43
//   • RecommendationEngine: actionable next steps for each alert type
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Alert Type Taxonomy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    NetworkAnomaly,
    MalwareDetection,
    LateralMovement,
    CommandAndControl,
    DataExfiltration,
    BruteForce,
    PolicyViolation,
    VulnerableComponent,
    InsiderThreat,
    OtProtocolAnomaly,
    DeceptionTriggered,
    CryptoAnomaly,
}

// ── Feature Attribution ───────────────────────────────────────────────────────
// Provided by ML engines; we convert to human sentences.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureAttribution {
    pub feature_name: String,
    pub value: f32,  // Actual value
    pub importance: f32,  // SHAP-like importance score (can be negative)
    pub normal_range: Option<(f32, f32)>,  // (mean, std)
}

impl FeatureAttribution {
    pub fn is_elevated(&self) -> bool {
        if let Some((mean, std)) = self.normal_range {
            self.value > mean + 2.0 * std
        } else {
            self.importance > 0.1
        }
    }

    pub fn deviation_description(&self) -> String {
        if let Some((mean, std)) = self.normal_range {
            let z = if std > 0.0 { (self.value - mean) / std } else { 0.0 };
            let direction = if self.value > mean { "above" } else { "below" };
            format!("{:.1} ({}x {}, {:.1}σ)", self.value, direction, mean, z.abs())
        } else {
            format!("{:.3}", self.value)
        }
    }
}

// ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic_id: String,
    pub tactic_name: String,
    pub technique_id: String,
    pub technique_name: String,
    pub sub_technique: Option<String>,
}

fn mitre_db() -> HashMap<AlertCategory, Vec<MitreMapping>> {
    let mut db = HashMap::new();

    db.insert(AlertCategory::BruteForce, vec![
        MitreMapping {
            tactic_id: "TA0006".to_string(), tactic_name: "Credential Access".to_string(),
            technique_id: "T1110".to_string(), technique_name: "Brute Force".to_string(),
            sub_technique: Some("T1110.001 Password Guessing".to_string()),
        },
    ]);
    db.insert(AlertCategory::LateralMovement, vec![
        MitreMapping {
            tactic_id: "TA0008".to_string(), tactic_name: "Lateral Movement".to_string(),
            technique_id: "T1021".to_string(), technique_name: "Remote Services".to_string(),
            sub_technique: None,
        },
    ]);
    db.insert(AlertCategory::CommandAndControl, vec![
        MitreMapping {
            tactic_id: "TA0011".to_string(), tactic_name: "Command and Control".to_string(),
            technique_id: "T1071".to_string(), technique_name: "Application Layer Protocol".to_string(),
            sub_technique: Some("T1071.001 Web Protocols".to_string()),
        },
    ]);
    db.insert(AlertCategory::DataExfiltration, vec![
        MitreMapping {
            tactic_id: "TA0010".to_string(), tactic_name: "Exfiltration".to_string(),
            technique_id: "T1048".to_string(), technique_name: "Exfiltration Over Alternative Protocol".to_string(),
            sub_technique: None,
        },
    ]);
    db.insert(AlertCategory::MalwareDetection, vec![
        MitreMapping {
            tactic_id: "TA0002".to_string(), tactic_name: "Execution".to_string(),
            technique_id: "T1204".to_string(), technique_name: "User Execution".to_string(),
            sub_technique: Some("T1204.002 Malicious File".to_string()),
        },
    ]);
    db.insert(AlertCategory::DeceptionTriggered, vec![
        MitreMapping {
            tactic_id: "TA0007".to_string(), tactic_name: "Discovery".to_string(),
            technique_id: "T1046".to_string(), technique_name: "Network Service Scanning".to_string(),
            sub_technique: None,
        },
    ]);
    db.insert(AlertCategory::OtProtocolAnomaly, vec![
        MitreMapping {
            tactic_id: "TA0040".to_string(), tactic_name: "Impact".to_string(),
            technique_id: "T0831".to_string(), technique_name: "Manipulation of Control".to_string(),
            sub_technique: None,
        },
    ]);
    db
}

// ── Explanation ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertExplanation {
    pub alert_id: String,
    pub category: AlertCategory,
    /// One-sentence headline
    pub headline: String,
    /// 2-4 sentence narrative explaining the detection
    pub narrative: String,
    /// Top contributing factors (bullet points)
    pub key_factors: Vec<String>,
    /// What this behavior looks like in normal operations
    pub normal_context: String,
    /// Why it's anomalous
    pub anomaly_reasoning: String,
    /// MITRE ATT&CK mappings
    pub mitre: Vec<MitreMapping>,
    /// Confidence explanation
    pub confidence_explanation: String,
    /// Recommended analyst actions
    pub recommendations: Vec<String>,
    /// False positive risk (0=very unlikely, 1=very possible)
    pub false_positive_risk: f32,
    pub generated_at: u64,
}

// ── LLM Explainability Engine ─────────────────────────────────────────────────

pub struct LlmExplainabilityEngine {
    mitre_db: HashMap<AlertCategory, Vec<MitreMapping>>,
    explanations_generated: AtomicU64,
    explanation_cache: RwLock<HashMap<String, AlertExplanation>>,
}

impl LlmExplainabilityEngine {
    pub fn new() -> Self {
        info!("🧪 LLM-Explain: Alert Explainability Engine initialized");
        info!("  → Rule-based NLG + MITRE ATT&CK mapping + SHAP feature attribution");
        Self {
            mitre_db: mitre_db(),
            explanations_generated: AtomicU64::new(0),
            explanation_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a full analyst-grade explanation for an alert.
    pub fn explain(
        &self,
        alert_id: &str,
        category: AlertCategory,
        src_ip: &str,
        dst_ip: &str,
        confidence: f32,
        features: &[FeatureAttribution],
        raw_context: &str,
    ) -> AlertExplanation {
        self.explanations_generated.fetch_add(1, Ordering::Relaxed);

        let mitre = self.mitre_db.get(&category).cloned().unwrap_or_default();
        let key_factors = self.extract_key_factors(features);
        let anomaly_reasoning = self.build_anomaly_reasoning(features, raw_context);
        let confidence_explanation = self.explain_confidence(confidence, features);
        let recommendations = self.build_recommendations(&category, confidence);
        let false_positive_risk = self.estimate_fp_risk(&category, confidence, features);

        let (headline, narrative, normal_context) = self.build_narrative(
            &category, src_ip, dst_ip, confidence, features
        );

        let explanation = AlertExplanation {
            alert_id: alert_id.to_string(),
            category,
            headline,
            narrative,
            key_factors,
            normal_context,
            anomaly_reasoning,
            mitre,
            confidence_explanation,
            recommendations,
            false_positive_risk,
            generated_at: unix_secs(),
        };

        self.explanation_cache.write().insert(alert_id.to_string(), explanation.clone());
        explanation
    }

    fn build_narrative(
        &self,
        category: &AlertCategory,
        src_ip: &str,
        dst_ip: &str,
        confidence: f32,
        features: &[FeatureAttribution],
    ) -> (String, String, String) {
        let conf_pct = (confidence * 100.0) as u8;
        let (headline, narrative, normal) = match category {
            AlertCategory::NetworkAnomaly => (
                format!("Anomalous traffic pattern detected from {}", src_ip),
                format!(
                    "Host {} is generating network traffic that deviates significantly from its \
                     established behavioral baseline (confidence: {}%). The flow characteristics \
                     including packet rate, byte volume, and timing patterns suggest unusual activity. \
                     This may indicate automated scanning, data staging, or C2 beacon behavior.",
                    src_ip, conf_pct
                ),
                "Normal hosts exhibit consistent traffic patterns within predictable hour-by-hour \
                 volume ranges and access familiar destinations on familiar ports.".to_string()
            ),
            AlertCategory::MalwareDetection => (
                format!("Malware family signature matched: {} → {}", src_ip, dst_ip),
                format!(
                    "The TLS fingerprint (JA3 hash) of the connection from {} to {} matches a \
                     known malware family's network communication profile (confidence: {}%). \
                     This fingerprint has been associated with C2 beacon traffic in threat \
                     intelligence databases. The connection may represent an infected host \
                     checking in with a command-and-control server.",
                    src_ip, dst_ip, conf_pct
                ),
                "Legitimate software uses standard TLS libraries with typical cipher suite \
                 selections that produce different JA3 fingerprints.".to_string()
            ),
            AlertCategory::LateralMovement => (
                format!("Lateral movement pivot detected at {}", src_ip),
                format!(
                    "Host {} appears to be pivoting across the network, making connections to {} \
                     and other internal hosts using protocols typically associated with remote \
                     execution (SMB, WMI, RDP, WinRM) — confidence {}%. \
                     This pattern is consistent with an attacker who has compromised this host \
                     and is attempting to spread to additional systems. \
                     The host's out-degree in the network graph has increased significantly \
                     from its baseline.",
                    src_ip, dst_ip, conf_pct
                ),
                "Workstations typically communicate with a small, consistent set of internal \
                 servers (domain controllers, file servers, DNS). Cross-workstation connections \
                 are rare in healthy networks.".to_string()
            ),
            AlertCategory::CommandAndControl => (
                format!("C2 beacon communication detected from {}", src_ip),
                format!(
                    "Host {} is exhibiting periodic, low-entropy communication to external \
                     endpoint {} that matches C2 beacon profiles (confidence: {}%). \
                     The connection timing, packet size consistency, and TLS fingerprint \
                     are inconsistent with normal web browsing or business traffic. \
                     C2 channels enable an attacker to issue commands and retrieve data \
                     from compromised systems.",
                    src_ip, dst_ip, conf_pct
                ),
                "Legitimate HTTPS traffic shows variable inter-request timing driven by \
                 user behavior, not periodic machine-driven check-ins.".to_string()
            ),
            AlertCategory::DataExfiltration => (
                format!("Potential data exfiltration from {} to {}", src_ip, dst_ip),
                format!(
                    "An unusually large volume of data is being transferred from {} to \
                     external host {} (confidence: {}%). The transfer volume is significantly \
                     above the established baseline for this host and user. Combined with \
                     access to sensitive file paths or databases, this raises concern for \
                     intentional or malware-driven data theft.",
                    src_ip, dst_ip, conf_pct
                ),
                "Normal file transfers and cloud sync operations follow predictable schedules \
                 and size distributions established in the behavioral baseline.".to_string()
            ),
            AlertCategory::BruteForce => (
                format!("Credential brute-force attack from {}", src_ip),
                format!(
                    "Source IP {} is generating a high rate of authentication failures against \
                     {} (confidence: {}%). The pattern — many attempts with varying credentials \
                     over a short time window — is consistent with automated password spraying \
                     or credential stuffing. This type of attack attempts to gain unauthorized \
                     access by trying large numbers of username/password combinations.",
                    src_ip, dst_ip, conf_pct
                ),
                "Legitimate users occasionally mistype passwords but rarely make more than 3 \
                 failed attempts in a row before seeking IT support.".to_string()
            ),
            AlertCategory::DeceptionTriggered => (
                format!("Attacker probing honeypot infrastructure: {}", src_ip),
                format!(
                    "Source {} interacted with Rudras honeypot services (confidence: {}%). \
                     Honeypot services are designed to be invisible to legitimate users — \
                     only active reconnaissance or attack tools should discover and connect \
                     to them. This is a high-fidelity indicator of hostile intent. \
                     The source IP should be treated as confirmed adversarial.",
                    src_ip, conf_pct
                ),
                "Legitimate users and services never interact with deception infrastructure \
                 because it contains no actual business data or services.".to_string()
            ),
            AlertCategory::InsiderThreat => (
                "Insider threat behavioral anomaly detected for entity".to_string(),
                format!(
                    "The user/entity associated with source {} is exhibiting behavioral \
                     deviations from their established profile (confidence: {}%). \
                     This may include access outside normal hours, access from unusual \
                     locations, unusual data access volume, or access to resources outside \
                     their typical job function.",
                    src_ip, conf_pct
                ),
                "Users typically follow consistent behavioral patterns: same working hours, \
                 same systems accessed, similar data volumes per session.".to_string()
            ),
            _ => (
                format!("Security event detected: {} → {}", src_ip, dst_ip),
                format!("Anomalous activity detected from {} to {} (confidence: {}%).", src_ip, dst_ip, conf_pct),
                "Expected normal baseline behavior for this traffic type.".to_string()
            ),
        };
        (headline, narrative, normal)
    }

    fn extract_key_factors(&self, features: &[FeatureAttribution]) -> Vec<String> {
        let mut elevated: Vec<&FeatureAttribution> = features.iter()
            .filter(|f| f.importance.abs() > 0.05)
            .collect();
        elevated.sort_by(|a, b| b.importance.abs().partial_cmp(&a.importance.abs())
            .unwrap_or(std::cmp::Ordering::Equal));
        elevated.iter().take(5).map(|f| {
            let direction = if f.importance > 0.0 { "elevated" } else { "suppressed" };
            format!("• {} is {} at {} (importance: {:.2})",
                f.feature_name, direction, f.deviation_description(), f.importance.abs())
        }).collect()
    }

    fn build_anomaly_reasoning(&self, features: &[FeatureAttribution], raw_context: &str) -> String {
        let elevated_count = features.iter().filter(|f| f.is_elevated()).count();
        if elevated_count == 0 {
            return "No individual features were significantly elevated; \
                     the anomaly arises from an unusual combination of moderate deviations.".to_string();
        }
        format!(
            "{} of {} features were statistically elevated beyond 2 standard deviations \
             from the entity's historical baseline. The combination of elevated features \
             creates a composite anomaly that is unlikely to occur in normal operations.{}",
            elevated_count, features.len(),
            if raw_context.is_empty() { String::new() } else { format!(" Context: {}", raw_context) }
        )
    }

    fn explain_confidence(&self, confidence: f32, features: &[FeatureAttribution]) -> String {
        let pct = (confidence * 100.0) as u8;
        let supporting = features.iter().filter(|f| f.importance > 0.0).count();
        let opposing = features.iter().filter(|f| f.importance < 0.0).count();
        format!(
            "Confidence is {}% based on {} supporting indicators and {} opposing indicators. \
             {}",
            pct, supporting, opposing,
            match confidence {
                c if c >= 0.9 => "This is a HIGH confidence detection with strong multi-feature agreement.",
                c if c >= 0.7 => "This is a MODERATE-HIGH confidence detection. Manual verification is recommended.",
                c if c >= 0.5 => "This is a MODERATE confidence detection. Treat as a lead for investigation.",
                _ => "This is a LOW confidence detection — may be a false positive. Verify before acting.",
            }
        )
    }

    fn build_recommendations(&self, category: &AlertCategory, confidence: f32) -> Vec<String> {
        let mut recs = vec![];
        recs.push("1. Verify the alert is not a false positive by reviewing raw packet captures from the affected host".to_string());
        match category {
            AlertCategory::BruteForce => {
                recs.push("2. Immediately block source IP at the perimeter firewall and rate-limit further auth attempts".to_string());
                recs.push("3. Check auth logs for any successful logins from this source around the same timeframe".to_string());
                recs.push("4. Enable MFA for all accounts targeted in this attack if not already enabled".to_string());
            }
            AlertCategory::LateralMovement | AlertCategory::CommandAndControl => {
                recs.push("2. Isolate the suspected compromised host from all non-management network segments".to_string());
                recs.push("3. Collect a memory and disk forensic image before remediation".to_string());
                recs.push("4. Search all hosts for the same IOCs (JA3 hash, process, registry key)".to_string());
                recs.push("5. Initiate IR process and preserve evidence chain of custody".to_string());
            }
            AlertCategory::DataExfiltration => {
                recs.push("2. Immediately block outbound traffic from the source host to the external destination".to_string());
                recs.push("3. Determine what data was transferred and assess breach notification obligations".to_string());
                recs.push("4. Notify legal and compliance teams".to_string());
            }
            AlertCategory::DeceptionTriggered => {
                recs.push("2. Block attacker IP immediately — honeypot interaction is a near-zero FP indicator".to_string());
                recs.push("3. Review full connection log for this IP across all ports and services".to_string());
                recs.push("4. Feed this IP to threat intel sharing platforms (e.g., MISP, OpenCTI)".to_string());
            }
            AlertCategory::VulnerableComponent => {
                recs.push("2. Patch the vulnerable component to the fixed version identified in the CVE advisory".to_string());
                recs.push("3. Apply WAF/IPS virtual patching rule if immediate upgrade is not possible".to_string());
                recs.push("4. Scan all hosts for the same vulnerable component version".to_string());
            }
            AlertCategory::OtProtocolAnomaly => {
                recs.push("2. CRITICAL: Alert OT/ICS security team immediately — physical process may be at risk".to_string());
                recs.push("3. Verify physical process state is normal via independent panel/HMI".to_string());
                recs.push("4. Block unauthorized engineering workstation at the OT network perimeter".to_string());
            }
            _ => {
                recs.push("2. Review related alerts in the SIEM for correlated activity".to_string());
                recs.push("3. Escalate to Tier 2 analyst if additional context confirms malicious intent".to_string());
            }
        }
        recs
    }

    fn estimate_fp_risk(&self, category: &AlertCategory, confidence: f32, _features: &[FeatureAttribution]) -> f32 {
        let base = 1.0 - confidence;
        match category {
            AlertCategory::DeceptionTriggered => (base * 0.1).min(0.05),
            AlertCategory::OtProtocolAnomaly => (base * 0.2).min(0.1),
            AlertCategory::MalwareDetection => base * 0.15,
            AlertCategory::NetworkAnomaly => base * 0.4,
            _ => base * 0.25,
        }
    }

    pub fn get_cached(&self, alert_id: &str) -> Option<AlertExplanation> {
        self.explanation_cache.read().get(alert_id).cloned()
    }

    pub fn stats(&self) -> u64 {
        self.explanations_generated.load(Ordering::Relaxed)
    }
}

impl Default for LlmExplainabilityEngine {
    fn default() -> Self { Self::new() }
}
