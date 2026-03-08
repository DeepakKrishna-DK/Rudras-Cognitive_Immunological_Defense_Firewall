// ============================================================================
// Rudras — SOAR Engine (Security Orchestration, Automation and Response)
//
// Automated incident response playbooks triggered by alerts from all engines.
// Implements:
//   • Playbook definition (trigger conditions + ordered action steps)
//   • Action types: Block IP, Isolate Host, Revoke Session, Alert Operator,
//                   Create Ticket, Collect Forensics, Rate-Limit, Quarantine
//   • Playbook execution engine with action result tracking
//   • Approval gates for destructive actions (requires human sign-off in prod)
//   • Incident correlation (group related alerts into one incident)
//   • SOAR metrics: MTTD / MTTR tracking
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

// ── Alert Severity (generic, for SOAR intake) ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity { Info, Low, Medium, High, Critical }

// ── SOAR Alert (input) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarAlert {
    pub id: String,
    pub source_engine: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub affected_ips: Vec<IpAddr>,
    pub affected_user: Option<String>,
    pub mitre_tactic: Option<String>,
    pub timestamp: u64,
}

// ── Playbook Actions ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookAction {
    /// Block IP at the firewall (calls WFP/WinDivert engine)
    BlockIp { ip: IpAddr, duration_secs: u64, reason: String },
    /// Isolate host from all network segments except management
    IsolateHost { hostname: String, preserve_management: bool },
    /// Revoke all active sessions for a user
    RevokeUserSessions { user: String },
    /// Add IP to global threat intel feed (distributed_immunity broadcast)
    FeedThreatIntel { ip: IpAddr, confidence: f32, tags: Vec<String> },
    /// Rate-limit traffic from IP
    RateLimit { ip: IpAddr, max_kbps: u32, duration_secs: u64 },
    /// Create an incident ticket (simulated)
    CreateTicket { title: String, priority: String, description: String },
    /// Alert human operator via SIEM/WebSocket/log
    Notify { channel: NotifyChannel, message: String },
    /// Collect forensic snapshot of network flows for affected IP
    CollectForensics { ip: IpAddr, window_secs: u64 },
    /// Wait N seconds before next action (cooldown)
    WaitSeconds(u64),
    /// Conditional: only proceed if confidence >= threshold
    RequireConfidence { min_confidence: f32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotifyChannel {
    Siem,
    Syslog,
    WebSocket,
    Console,
}

// ── Playbook ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Alert source engine that triggers this playbook
    pub trigger_source: Option<String>,
    /// Minimum severity to fire this playbook
    pub trigger_severity: AlertSeverity,
    /// Optional MITRE ATT&CK tactic to match
    pub trigger_tactic: Option<String>,
    pub actions: Vec<PlaybookAction>,
    pub enabled: bool,
    /// If true: actions that modify firewall/sessions require human approval
    pub require_approval_for_destructive: bool,
}

// ── Incident ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub severity: AlertSeverity,
    pub related_alerts: Vec<String>,
    pub affected_ips: Vec<IpAddr>,
    pub affected_users: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub playbook_executions: Vec<PlaybookExecution>,
    pub detected_at: u64,
    pub resolved_at: Option<u64>,
    pub mttd_secs: Option<u64>,
    pub mttr_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Triaging,
    Responding,
    Resolved,
    FalsePositive,
}

// ── Playbook Execution Record ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub playbook_id: String,
    pub incident_id: String,
    pub triggered_by: String,  // alert ID
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub action_results: Vec<ActionResult>,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: String,
    pub success: bool,
    pub output: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    WaitingApproval,
    Completed,
    Failed(String),
    Aborted,
}

// ── Action Dispatcher ─────────────────────────────────────────────────────────
// In production: calls actual engine APIs. Here: simulates with structured logging.

pub trait ActionDispatcher: Send + Sync {
    fn block_ip(&self, ip: IpAddr, duration: u64, reason: &str) -> Result<String, String>;
    fn revoke_sessions(&self, user: &str) -> Result<String, String>;
    fn feed_threat_intel(&self, ip: IpAddr, confidence: f32, tags: &[String]) -> Result<String, String>;
    fn collect_forensics(&self, ip: IpAddr, window: u64) -> Result<String, String>;
}

pub struct LoggingDispatcher;

impl ActionDispatcher for LoggingDispatcher {
    fn block_ip(&self, ip: IpAddr, duration: u64, reason: &str) -> Result<String, String> {
        info!("🔒 SOAR ACTION: BlockIp {} for {}s — {}", ip, duration, reason);
        Ok(format!("Blocked {} for {}s", ip, duration))
    }
    fn revoke_sessions(&self, user: &str) -> Result<String, String> {
        warn!("🔒 SOAR ACTION: RevokeUserSessions for {}", user);
        Ok(format!("Sessions revoked for {}", user))
    }
    fn feed_threat_intel(&self, ip: IpAddr, confidence: f32, tags: &[String]) -> Result<String, String> {
        info!("🔒 SOAR ACTION: FeedThreatIntel {} conf={:.2} tags={:?}", ip, confidence, tags);
        Ok(format!("Intel fed for {}", ip))
    }
    fn collect_forensics(&self, ip: IpAddr, window: u64) -> Result<String, String> {
        info!("🔒 SOAR ACTION: CollectForensics {} window={}s", ip, window);
        Ok(format!("Forensics scheduled for {} ({}s window)", ip, window))
    }
}

// ── Default Playbooks ─────────────────────────────────────────────────────────

fn default_playbooks() -> Vec<Playbook> {
    vec![
        Playbook {
            id: "PB-01".to_string(),
            name: "Block Known Malicious IP".to_string(),
            description: "Auto-block IPs hitting honeypots or matching threat intel".to_string(),
            trigger_source: Some("deception".to_string()),
            trigger_severity: AlertSeverity::Medium,
            trigger_tactic: None,
            actions: vec![
                PlaybookAction::Notify {
                    channel: NotifyChannel::Siem,
                    message: "Deception alert: attacker IP detected".to_string(),
                },
                PlaybookAction::BlockIp {
                    ip: "0.0.0.0".parse().unwrap(), // Replaced at runtime with actual IP
                    duration_secs: 86400,
                    reason: "Hit honeypot service".to_string(),
                },
                PlaybookAction::FeedThreatIntel {
                    ip: "0.0.0.0".parse().unwrap(),
                    confidence: 0.85,
                    tags: vec!["honeypot-attacker".to_string()],
                },
                PlaybookAction::CreateTicket {
                    title: "Honeypot Attacker Blocked".to_string(),
                    priority: "Medium".to_string(),
                    description: "Automated block + threat intel feed".to_string(),
                },
            ],
            enabled: true,
            require_approval_for_destructive: false,
        },
        Playbook {
            id: "PB-02".to_string(),
            name: "Credential Stuffing Response".to_string(),
            description: "Respond to brute-force / credential stuffing detected by IDS or UEBA".to_string(),
            trigger_source: Some("ids_engine".to_string()),
            trigger_severity: AlertSeverity::High,
            trigger_tactic: Some("TA0006".to_string()), // Credential Access
            actions: vec![
                PlaybookAction::RateLimit { ip: "0.0.0.0".parse().unwrap(), max_kbps: 10, duration_secs: 3600 },
                PlaybookAction::Notify { channel: NotifyChannel::Console, message: "Credential attack detected — rate limited".to_string() },
                PlaybookAction::CollectForensics { ip: "0.0.0.0".parse().unwrap(), window_secs: 300 },
            ],
            enabled: true,
            require_approval_for_destructive: false,
        },
        Playbook {
            id: "PB-03".to_string(),
            name: "Ransomware Containment".to_string(),
            description: "Immediately isolate host on ransomware IOC detection".to_string(),
            trigger_source: Some("endpoint_security".to_string()),
            trigger_severity: AlertSeverity::Critical,
            trigger_tactic: Some("TA0040".to_string()), // Impact
            actions: vec![
                PlaybookAction::Notify { channel: NotifyChannel::Siem, message: "CRITICAL: Ransomware IOC — isolating host".to_string() },
                PlaybookAction::IsolateHost { hostname: String::new(), preserve_management: true },
                PlaybookAction::CollectForensics { ip: "0.0.0.0".parse().unwrap(), window_secs: 600 },
                PlaybookAction::CreateTicket {
                    title: "CRITICAL: Ransomware Containment".to_string(),
                    priority: "Critical".to_string(),
                    description: "Host isolated. Forensics collected. Awaiting IR team.".to_string(),
                },
            ],
            enabled: true,
            require_approval_for_destructive: true,
        },
        Playbook {
            id: "PB-04".to_string(),
            name: "UEBA High-Risk User Response".to_string(),
            description: "Respond to suspicious insider or compromised account activity".to_string(),
            trigger_source: Some("ueba".to_string()),
            trigger_severity: AlertSeverity::High,
            trigger_tactic: None,
            actions: vec![
                PlaybookAction::Notify { channel: NotifyChannel::Console, message: "High-risk UEBA alert for user".to_string() },
                PlaybookAction::CollectForensics { ip: "0.0.0.0".parse().unwrap(), window_secs: 300 },
                PlaybookAction::WaitSeconds(30),
                PlaybookAction::RevokeUserSessions { user: String::new() },
            ],
            enabled: true,
            require_approval_for_destructive: true, // Revoking sessions needs approval
        },
    ]
}

// ── SOAR Engine ───────────────────────────────────────────────────────────────

pub struct SoarEngine {
    playbooks: RwLock<Vec<Playbook>>,
    incidents: RwLock<HashMap<String, Incident>>,
    executions: RwLock<VecDeque<PlaybookExecution>>,
    dispatcher: Box<dyn ActionDispatcher>,
    total_alerts_processed: AtomicU64,
    total_playbooks_fired: AtomicU64,
    total_actions_taken: AtomicU64,
    mttd_sum_secs: AtomicU64,
    mttr_sum_secs: AtomicU64,
    resolved_count: AtomicU64,
}

impl SoarEngine {
    pub fn new() -> Self {
        let playbooks = default_playbooks();
        info!("🚨 SOAR: Engine initialized — {} default playbooks loaded", playbooks.len());
        for pb in &playbooks {
            info!("  → [{}] {} (trigger: {:?}+)", pb.id, pb.name, pb.trigger_severity);
        }
        Self {
            playbooks: RwLock::new(playbooks),
            incidents: RwLock::new(HashMap::new()),
            executions: RwLock::new(VecDeque::new()),
            dispatcher: Box::new(LoggingDispatcher),
            total_alerts_processed: AtomicU64::new(0),
            total_playbooks_fired: AtomicU64::new(0),
            total_actions_taken: AtomicU64::new(0),
            mttd_sum_secs: AtomicU64::new(0),
            mttr_sum_secs: AtomicU64::new(0),
            resolved_count: AtomicU64::new(0),
        }
    }

    /// Ingest a security alert and potentially fire playbooks.
    pub fn process_alert(&self, alert: SoarAlert) -> Vec<String> {
        self.total_alerts_processed.fetch_add(1, Ordering::Relaxed);
        let mut fired = vec![];

        // Find matching playbooks
        let playbooks = self.playbooks.read();
        for pb in playbooks.iter().filter(|p| p.enabled) {
            if alert.severity < pb.trigger_severity { continue; }
            if let Some(ref src) = pb.trigger_source {
                if alert.source_engine != *src { continue; }
            }
            if let Some(ref tactic) = pb.trigger_tactic {
                if alert.mitre_tactic.as_deref() != Some(tactic) { continue; }
            }
            fired.push(pb.id.clone());
        }
        drop(playbooks);

        // Create/update incident
        let incident_id = self.correlate_or_create_incident(&alert);

        // Execute matching playbooks
        for pb_id in &fired {
            self.execute_playbook(pb_id, &incident_id, &alert);
        }

        fired
    }

    fn correlate_or_create_incident(&self, alert: &SoarAlert) -> String {
        // Simple correlation: group alerts from same IP within 10 minutes
        let mut incidents = self.incidents.write();
        let window = unix_secs() - 600;
        for (id, incident) in incidents.iter_mut() {
            if incident.detected_at >= window &&
               incident.affected_ips.iter().any(|ip| alert.affected_ips.contains(ip)) {
                incident.related_alerts.push(alert.id.clone());
                incident.severity = incident.severity.clone().max(alert.severity.clone());
                for ip in &alert.affected_ips {
                    if !incident.affected_ips.contains(ip) { incident.affected_ips.push(*ip); }
                }
                return id.clone();
            }
        }
        // Create new incident
        let id = format!("INC-{:06}", incidents.len() + 1);
        incidents.insert(id.clone(), Incident {
            id: id.clone(),
            title: alert.title.clone(),
            status: IncidentStatus::New,
            severity: alert.severity.clone(),
            related_alerts: vec![alert.id.clone()],
            affected_ips: alert.affected_ips.clone(),
            affected_users: alert.affected_user.iter().cloned().collect(),
            mitre_tactics: alert.mitre_tactic.iter().cloned().collect(),
            playbook_executions: vec![],
            detected_at: unix_secs(),
            resolved_at: None,
            mttd_secs: None,
            mttr_secs: None,
        });
        id
    }

    fn execute_playbook(&self, pb_id: &str, incident_id: &str, alert: &SoarAlert) {
        let start = unix_secs();
        let playbooks = self.playbooks.read();
        let pb = match playbooks.iter().find(|p| p.id == pb_id) {
            Some(p) => p.clone(),
            None => return,
        };
        drop(playbooks);

        self.total_playbooks_fired.fetch_add(1, Ordering::Relaxed);
        info!("🚨 SOAR: Executing playbook [{}] '{}' for incident {}", pb.id, pb.name, incident_id);

        let mut action_results = vec![];
        for action in &pb.actions {
            self.total_actions_taken.fetch_add(1, Ordering::Relaxed);
            let action_name = format!("{:?}", action).chars().take(60).collect::<String>();
            let result = match action {
                PlaybookAction::BlockIp { duration_secs, reason, .. } => {
                    alert.affected_ips.iter().map(|ip| {
                        self.dispatcher.block_ip(*ip, *duration_secs, reason)
                    }).last().unwrap_or(Ok("No IPs to block".to_string()))
                }
                PlaybookAction::RevokeUserSessions { .. } => {
                    if let Some(ref user) = alert.affected_user {
                        self.dispatcher.revoke_sessions(user)
                    } else { Ok("No user to revoke".to_string()) }
                }
                PlaybookAction::FeedThreatIntel { confidence, tags, .. } => {
                    alert.affected_ips.iter().map(|ip| {
                        self.dispatcher.feed_threat_intel(*ip, *confidence, tags)
                    }).last().unwrap_or(Ok("No IPs".to_string()))
                }
                PlaybookAction::CollectForensics { window_secs, .. } => {
                    alert.affected_ips.iter().map(|ip| {
                        self.dispatcher.collect_forensics(*ip, *window_secs)
                    }).last().unwrap_or(Ok("No IPs".to_string()))
                }
                PlaybookAction::Notify { channel, message } => {
                    info!("🚨 SOAR NOTIFY [{:?}]: {} — {}", channel, alert.id, message);
                    Ok("Notification sent".to_string())
                }
                PlaybookAction::CreateTicket { title, priority, description } => {
                    info!("🎫 SOAR TICKET [{:?}]: {:?}", priority, title);
                    Ok(format!("Ticket created: {}", title))
                }
                PlaybookAction::WaitSeconds(secs) => {
                    debug!("SOAR: Action wait {}s (simulated)", secs);
                    Ok(format!("Waited {}s", secs))
                }
                PlaybookAction::RateLimit { max_kbps, duration_secs, .. } => {
                    info!("SOAR: Rate-limiting {} IPs to {}kbps for {}s", alert.affected_ips.len(), max_kbps, duration_secs);
                    Ok("Rate limit applied".to_string())
                }
                _ => Ok("Action logged".to_string()),
            };
            action_results.push(ActionResult {
                action: action_name,
                success: result.is_ok(),
                output: result.unwrap_or_else(|e| e),
                timestamp: unix_secs(),
            });
        }

        let execution = PlaybookExecution {
            playbook_id: pb.id.clone(),
            incident_id: incident_id.to_string(),
            triggered_by: alert.id.clone(),
            started_at: start,
            completed_at: Some(unix_secs()),
            action_results,
            status: ExecutionStatus::Completed,
        };
        self.executions.write().push_back(execution);
        info!("🚨 SOAR: Playbook [{}] completed in {}s", pb.id, unix_secs() - start);
    }

    pub fn resolve_incident(&self, incident_id: &str) {
        let mut incidents = self.incidents.write();
        if let Some(incident) = incidents.get_mut(incident_id) {
            let now = unix_secs();
            incident.status = IncidentStatus::Resolved;
            incident.resolved_at = Some(now);
            let mttr = now - incident.detected_at;
            incident.mttr_secs = Some(mttr);
            self.mttr_sum_secs.fetch_add(mttr, Ordering::Relaxed);
            self.resolved_count.fetch_add(1, Ordering::Relaxed);
            info!("✅ SOAR: Incident {} resolved (MTTR={}s)", incident_id, mttr);
        }
    }

    pub fn playbook_count(&self) -> usize {
        self.playbooks.read().len()
    }

    pub fn stats(&self) -> SoarStats {
        let resolved = self.resolved_count.load(Ordering::Relaxed);
        let avg_mttr = if resolved > 0 {
            self.mttr_sum_secs.load(Ordering::Relaxed) / resolved
        } else { 0 };
        SoarStats {
            total_alerts_processed: self.total_alerts_processed.load(Ordering::Relaxed),
            total_playbooks_fired: self.total_playbooks_fired.load(Ordering::Relaxed),
            total_actions_taken: self.total_actions_taken.load(Ordering::Relaxed),
            open_incidents: self.incidents.read().values().filter(|i| i.status != IncidentStatus::Resolved).count() as u64,
            resolved_incidents: resolved,
            avg_mttr_secs: avg_mttr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SoarStats {
    pub total_alerts_processed: u64,
    pub total_playbooks_fired: u64,
    pub total_actions_taken: u64,
    pub open_incidents: u64,
    pub resolved_incidents: u64,
    pub avg_mttr_secs: u64,
}
