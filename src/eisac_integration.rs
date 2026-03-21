// ============================================================================
// Rudras — E-ISAC Integration (CIP-008-R1-1.2)
//
// Electricity Information Sharing and Analysis Center (E-ISAC) integration.
// Closes the NERC CIP-008-R1 Part 1.2 gap: cybersecurity incidents must be
// reported to E-ISAC within 1 HOUR of identification.
//
// Modes:
//   Live   — HTTP POST to configured E-ISAC API endpoint (JSON)
//   Sim    — Logs what would be sent (when no endpoint configured)
//   Queue  — Buffers reports when network unreachable; retries automatically
//
// Wire into SIEM/NERC CIP: when a Critical alert is generated, call
//   eisac.report_incident(&alert).await
//
// Config (config/rudras.toml):
//   [eisac]
//   endpoint = "https://api.eisac.com/v2/incidents"
//   api_key  = "YOUR_EISAC_API_KEY"
//   org_name = "Your Registered Entity Name"
//   nerc_id  = "ABCDE-RE"
//   region   = "WECC"  # WECC / RFC / SERC / TRE / NPCC / MRO / SPP
// ============================================================================

#![allow(dead_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EisacConfig {
    /// E-ISAC REST API endpoint. Leave empty for simulation mode.
    pub endpoint: String,
    /// API key issued by E-ISAC
    pub api_key:  String,
    /// Registered Entity Name (your org)
    pub org_name: String,
    /// NERC Registered Entity ID (e.g. "ABCDE-RE")
    pub nerc_id:  String,
    /// NERC Region (WECC/RFC/SERC/TRE/NPCC/MRO/SPP)
    pub region:   String,
    /// Max reports to queue while offline (default: 50)
    pub queue_max: usize,
    /// Retry interval seconds when offline (default: 300 = 5 min)
    pub retry_secs: u64,
}

impl Default for EisacConfig {
    fn default() -> Self {
        Self {
            endpoint:    String::new(),     // empty = simulation mode
            api_key:     String::new(),
            org_name:    "Rudras Entity".into(),
            nerc_id:     "UNKNOWN-RE".into(),
            region:      "UNKNOWN".into(),
            queue_max:   50,
            retry_secs:  300,
        }
    }
}

impl EisacConfig {
    /// True when a real endpoint and API key are configured
    pub fn is_live(&self) -> bool {
        !self.endpoint.is_empty() && !self.api_key.is_empty()
    }
}

// ── Incident Severity ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EisacSeverity {
    /// Ongoing BES reliability impact — report IMMEDIATELY
    Critical,
    /// Significant threat, potential BES impact — report within 1 hour
    High,
    /// Noteworthy, no immediate BES impact — report within 24 hours
    Medium,
    /// Informational sharing — report at next opportunity
    Low,
}

impl EisacSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High     => "HIGH",
            Self::Medium   => "MEDIUM",
            Self::Low      => "LOW",
        }
    }
    /// NERC CIP-008 notification deadline in seconds
    pub fn deadline_secs(&self) -> u64 {
        match self {
            Self::Critical => 3600,        // 1 hour
            Self::High     => 3600,        // 1 hour
            Self::Medium   => 86400,       // 24 hours
            Self::Low      => 604800,      // 7 days
        }
    }
}

// ── Incident Report (CIP-008 format) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EisacIncidentReport {
    /// Unique report ID (auto-generated)
    pub report_id:          String,
    /// Unix timestamp of detection
    pub detected_at:        u64,
    /// Unix timestamp of this report
    pub reported_at:        u64,
    /// Severity classification
    pub severity:           EisacSeverity,
    /// NERC CIP requirement that triggered this (e.g. "CIP-008-R1-1.2")
    pub cip_requirement:    String,
    /// Short title of the incident
    pub title:              String,
    /// Detailed description
    pub description:        String,
    /// Affected BES Cyber System (asset name/ID)
    pub affected_asset:     String,
    /// Impact on BES operations
    pub bes_impact:         String,
    /// Actions taken so far
    pub actions_taken:      String,
    /// Reporting entity info
    pub org_name:           String,
    pub nerc_id:            String,
    pub region:             String,
    /// Gap type for NERC CIP tracking
    pub gap_type:           String,
    /// Remediation plan
    pub remediation_plan:   String,
    /// Was this sent successfully to E-ISAC?
    pub sent:               bool,
    /// HTTP status if sent
    pub http_status:        Option<u16>,
    /// Minutes since detection (1-hour SLA countdown)
    pub minutes_until_deadline: u64,
}

impl EisacIncidentReport {
    pub fn sla_status(&self) -> &'static str {
        let elapsed = self.reported_at.saturating_sub(self.detected_at);
        let deadline = self.severity.deadline_secs();
        let remaining = deadline.saturating_sub(elapsed);
        if remaining == 0         { "⛔ SLA BREACHED" }
        else if remaining < 900   { "🔴 CRITICAL — < 15 min remaining" }
        else if remaining < 1800  { "🟠 URGENT — < 30 min remaining" }
        else if remaining < 3600  { "🟡 ACTION REQUIRED — < 60 min" }
        else                      { "✅ Within SLA window" }
    }
}

// ── Queued Report ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct QueuedReport {
    report:     EisacIncidentReport,
    attempts:   u32,
    next_retry: u64,
}

// ── E-ISAC Integration Engine ─────────────────────────────────────────────────

pub struct EisacIntegration {
    config:           RwLock<EisacConfig>,
    queue:            RwLock<VecDeque<QueuedReport>>,
    reports_sent:     AtomicU64,
    reports_failed:   AtomicU64,
    reports_queued:   AtomicU64,
    sim_reports_logged: AtomicU64,
    report_counter:   AtomicU64,
}

impl EisacIntegration {
    pub fn new(config: EisacConfig) -> Self {
        let mode = if config.is_live() {
            format!("LIVE → {}", config.endpoint)
        } else {
            "SIMULATION (set [eisac] endpoint + api_key in rudras.toml to enable live reporting)".into()
        };
        info!("📡 E-ISAC Integration initialized | org={} | nerc_id={} | region={} | mode={}",
              config.org_name, config.nerc_id, config.region, mode);

        if !config.is_live() {
            warn!(
                "⚠️  E-ISAC GAP [CIP-008-R1-1.2] PARTIAL CLOSE: E-ISAC integration running in \
                 SIMULATION mode. Incidents will be logged but NOT sent to E-ISAC. \
                 To fully close CIP-005-R2-2.2 gap, add to config/rudras.toml:\n\
                 [eisac]\n\
                 endpoint = \"https://api.eisac.com/v2/incidents\"\n\
                 api_key  = \"YOUR_EISAC_API_KEY\"\n\
                 org_name = \"Your Registered Entity\"\n\
                 nerc_id  = \"ABCDE-RE\"\n\
                 region   = \"WECC\""
            );
        } else {
            info!("✅ E-ISAC GAP [CIP-008-R1-1.2] CLOSED: Live endpoint configured, \
                   incidents will be reported within 1-hour SLA.");
        }

        Self {
            config: RwLock::new(config),
            queue:  RwLock::new(VecDeque::new()),
            reports_sent:       AtomicU64::new(0),
            reports_failed:     AtomicU64::new(0),
            reports_queued:     AtomicU64::new(0),
            sim_reports_logged: AtomicU64::new(0),
            report_counter:     AtomicU64::new(0),
        }
    }

    /// Create a new incident report for a NERC CIP gap
    pub fn build_report(
        &self,
        severity:       EisacSeverity,
        cip_req:        &str,
        title:          &str,
        description:    &str,
        affected_asset: &str,
        bes_impact:     &str,
        actions_taken:  &str,
        gap_type:       &str,
        remediation:    &str,
    ) -> EisacIncidentReport {
        let cfg = self.config.read();
        let n   = self.report_counter.fetch_add(1, Ordering::Relaxed);
        let now = unix_secs();
        EisacIncidentReport {
            report_id:           format!("RUDRAS-EISAC-{}-{}", now, n),
            detected_at:         now,
            reported_at:         now,
            severity:            severity.clone(),
            cip_requirement:     cip_req.into(),
            title:               title.into(),
            description:         description.into(),
            affected_asset:      affected_asset.into(),
            bes_impact:          bes_impact.into(),
            actions_taken:       actions_taken.into(),
            org_name:            cfg.org_name.clone(),
            nerc_id:             cfg.nerc_id.clone(),
            region:              cfg.region.clone(),
            gap_type:            gap_type.into(),
            remediation_plan:    remediation.into(),
            sent:                false,
            http_status:         None,
            minutes_until_deadline: severity.deadline_secs() / 60,
        }
    }

    /// Submit an incident report to E-ISAC.
    /// - If live:    HTTP POST → E-ISAC endpoint
    /// - If failed:  enqueue for retry
    /// - If sim:     log the report, mark gap as partially closed
    pub async fn report_incident(&self, mut report: EisacIncidentReport) {
        let is_live = self.config.read().is_live();

        if is_live {
            match self.send_http(&report).await {
                Ok(status) => {
                    report.sent = true;
                    report.http_status = Some(status);
                    self.reports_sent.fetch_add(1, Ordering::Relaxed);
                    info!(
                        "✅ E-ISAC REPORT SENT | id={} | cip={} | severity={} | http={}",
                        report.report_id, report.cip_requirement,
                        report.severity.label(), status
                    );
                }
                Err(e) => {
                    self.reports_failed.fetch_add(1, Ordering::Relaxed);
                    error!(
                        "❌ E-ISAC SEND FAILED | id={} | err={} | queuing for retry",
                        report.report_id, e
                    );
                    self.enqueue(report);
                }
            }
        } else {
            // Simulation mode — log what would be sent
            self.sim_reports_logged.fetch_add(1, Ordering::Relaxed);
            warn!(
                "📡 E-ISAC SIM REPORT [{}] | id={} | cip={} | severity={} | sla={} | \
                 title='{}' | asset='{}' | impact='{}'",
                report.sla_status(),
                report.report_id, report.cip_requirement,
                report.severity.label(), report.minutes_until_deadline,
                report.title, report.affected_asset, report.bes_impact
            );
            warn!(
                "📋 E-ISAC SIM — Actions: {} | Remediation: {}",
                report.actions_taken, report.remediation_plan
            );
            warn!(
                "🔔 E-ISAC SIM — To send this LIVE: configure [eisac] endpoint + api_key in rudras.toml"
            );
        }
    }

    /// Report the two permanent NERC CIP structural gaps on startup
    pub async fn report_structural_gaps(&self, mfa_closed: bool) {
        // Gap 1: E-ISAC integration itself
        if !self.config.read().is_live() {
            let r = self.build_report(
                EisacSeverity::High,
                "CIP-008-R1-1.2",
                "E-ISAC Reporting Integration Not Fully Configured",
                "Rudras E-ISAC integration is running in simulation mode. \
                 CIP-008-R1 Part 1.2 requires incidents to be reported to E-ISAC \
                 within 1 hour. Configure endpoint + api_key to enable live reporting.",
                "Rudras Firewall — Management API",
                "No direct BES impact; compliance posture gap only",
                "E-ISAC integration module initialized in simulation mode",
                "INTEGRATION_GAP",
                "Add [eisac] endpoint + api_key to config/rudras.toml"
            );
            self.report_incident(r).await;
        }

        // Gap 2: MFA
        if !mfa_closed {
            let r = self.build_report(
                EisacSeverity::High,
                "CIP-005-R2-2.2",
                "MFA for Remote Access Not Enabled",
                "Interactive Remote Access to BES Cyber Systems lacks Multi-Factor \
                 Authentication. CIP-005-R2 Part 2.2 requires MFA for all IRA sessions. \
                 Rudras MFA Engine is present but no IdP provider has been configured.",
                "Rudras Firewall — Remote Management Interface",
                "Single-factor remote access creates credential theft risk for BES systems",
                "zero_trust enforces TLS 1.3 mTLS; RBAC active; MFA IdP pending configuration",
                "MFA_GAP",
                "Set mfa.provider in config/rudras.toml (totp/azure_ad/okta/duo)"
            );
            self.report_incident(r).await;
        }
    }

    /// Retry all queued reports that are due
    pub async fn flush_queue(&self) {
        let now = unix_secs();
        let due: Vec<QueuedReport> = {
            let mut q = self.queue.write();
            let mut out = Vec::new();
            q.retain(|r| {
                if r.next_retry <= now { out.push(r.clone()); false } else { true }
            });
            out
        };

        for mut qr in due {
            match self.send_http(&qr.report).await {
                Ok(status) => {
                    self.reports_sent.fetch_add(1, Ordering::Relaxed);
                    info!("✅ E-ISAC RETRY OK | id={} | http={} | attempt={}",
                          qr.report.report_id, status, qr.attempts + 1);
                }
                Err(e) => {
                    qr.attempts += 1;
                    let retry_secs = self.config.read().retry_secs;
                    qr.next_retry = now + retry_secs * (qr.attempts as u64).min(5);
                    warn!("⚠️  E-ISAC RETRY FAIL | id={} | attempt={} | next_retry={}s | err={}",
                          qr.report.report_id, qr.attempts, qr.next_retry - now, e);
                    self.queue.write().push_back(qr);
                }
            }
        }
    }

    pub fn stats(&self) -> EisacStats {
        let cfg = self.config.read();
        EisacStats {
            is_live:           cfg.is_live(),
            endpoint:          if cfg.is_live() { cfg.endpoint.clone() } else { "SIMULATION".into() },
            reports_sent:      self.reports_sent.load(Ordering::Relaxed),
            reports_failed:    self.reports_failed.load(Ordering::Relaxed),
            reports_queued:    self.queue.read().len() as u64,
            sim_reports_logged: self.sim_reports_logged.load(Ordering::Relaxed),
        }
    }

    pub fn is_live(&self) -> bool { self.config.read().is_live() }

    pub fn update_config(&self, new_cfg: EisacConfig) {
        let was_live = self.config.read().is_live();
        let now_live = new_cfg.is_live();
        *self.config.write() = new_cfg.clone();
        if !was_live && now_live {
            info!("✅ E-ISAC GAP [CIP-008-R1-1.2] CLOSED: Switched to live mode → {}",
                  new_cfg.endpoint);
        }
    }

    // ── Private ───────────────────────────────────────────────────────────────

    async fn send_http(&self, report: &EisacIncidentReport) -> anyhow::Result<u16> {
        let cfg = self.config.read().clone();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client
            .post(&cfg.endpoint)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", cfg.api_key))
            .header("X-Rudras-Version", "4.1")
            .header("X-NERC-ID", &cfg.nerc_id)
            .json(report)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} — {}", status, body);
        }
        Ok(status)
    }

    fn enqueue(&self, report: EisacIncidentReport) {
        let max      = self.config.read().queue_max;
        let retry    = self.config.read().retry_secs;
        let mut q    = self.queue.write();
        if q.len() >= max {
            warn!("⚠️  E-ISAC queue full ({} items), dropping oldest report", max);
            q.pop_front();
        }
        q.push_back(QueuedReport { report, attempts: 1, next_retry: unix_secs() + retry });
        self.reports_queued.fetch_add(1, Ordering::Relaxed);
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EisacStats {
    pub is_live:            bool,
    pub endpoint:           String,
    pub reports_sent:       u64,
    pub reports_failed:     u64,
    pub reports_queued:     u64,
    pub sim_reports_logged: u64,
}
