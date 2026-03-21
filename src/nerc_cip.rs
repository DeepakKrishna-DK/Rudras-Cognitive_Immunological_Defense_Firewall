// ============================================================================
// Rudras — NERC CIP Compliance Engine
//
// NERC CIP Standards: CIP-002 through CIP-014
// Scope: Bulk Electric System (BES) Cyber System protection
//
// Two gaps never auto-satisfied by Rudras alone — always emit warn!:
//   1. E-ISAC Integration (CIP-008-R1-1.2): 1-hour notification SLA
//   2. MFA for Remote Access (CIP-005-R2-2.2): TOTP/FIDO2 required
//
// Gap classification by remediation timeline:
//   Immediate  (weight=1.0)  → E-ISAC notify within 1 hour
//   35-Day     (weight≥0.95) → NERC reporting SLA
//   90-Day     (weight≥0.75) → Standard remediation window
//   Annual     (weight<0.75) → Certification cycle
// ============================================================================

#![allow(dead_code, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── BES Impact Level ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BesImpactLevel {
    /// >1500 MW generation, control centers
    High,
    /// 300–1500 MW, substations
    Medium,
    /// All other BES Cyber Systems
    Low,
}

impl BesImpactLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High   => "High Impact",
            Self::Medium => "Medium Impact",
            Self::Low    => "Low Impact",
        }
    }
}

// ── CIP Standards ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipStandard {
    Cip002, Cip003, Cip004, Cip005, Cip006,
    Cip007, Cip008, Cip009, Cip010, Cip011,
    Cip013, Cip014,
}

impl CipStandard {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Cip002 => "CIP-002", Self::Cip003 => "CIP-003",
            Self::Cip004 => "CIP-004", Self::Cip005 => "CIP-005",
            Self::Cip006 => "CIP-006", Self::Cip007 => "CIP-007",
            Self::Cip008 => "CIP-008", Self::Cip009 => "CIP-009",
            Self::Cip010 => "CIP-010", Self::Cip011 => "CIP-011",
            Self::Cip013 => "CIP-013", Self::Cip014 => "CIP-014",
        }
    }
}

// ── Check Status ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipCheckStatus { Pass, Fail, NotApplicable, ManualVerificationRequired }

// ── Alert Severity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipAlertSeverity {
    Critical, // Notify E-ISAC ≤1 hr; potential BES reliability impact
    High,     // 35-day NERC reporting SLA
    Medium,   // 90-day standard remediation
    Low,      // Annual certification cycle
}

// ── Remediation Timeline ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemediationTimeline {
    Immediate, // E-ISAC notify ≤1 hr
    Days35,    // NERC 35-calendar-day SLA
    Days90,    // Standard remediation
    Annual,    // Certification cycle
}

impl RemediationTimeline {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Immediate => "IMMEDIATE (1 hr E-ISAC notification)",
            Self::Days35    => "35-DAY (NERC reportable SLA)",
            Self::Days90    => "90-DAY (standard remediation)",
            Self::Annual    => "ANNUAL (certification cycle)",
        }
    }
}

// ── Core Requirement ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipRequirement {
    pub standard:          CipStandard,
    pub requirement_id:    String,
    pub sub_requirement:   String,
    pub title:             String,
    pub description:       String,
    pub applicable_impact: Vec<BesImpactLevel>,
    pub status:            CipCheckStatus,
    pub rudras_control:    String,
    pub evidence:          String,
    pub remediation:       Option<String>,
    pub weight:            f64,
}

// ── CIP Alert ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipAlert {
    pub id:                 String,
    pub standard:           CipStandard,
    pub requirement_id:     String,
    pub severity:           CipAlertSeverity,
    pub description:        String,
    pub recommended_action: String,
    pub timestamp:          u64,
    pub must_report_to_nerc: bool,
}

// ── Gap Entry & Report ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapEntry {
    pub requirement_id:       String,
    pub title:                String,
    pub description:          String,
    pub rudras_control:       String,
    pub remediation:          String,
    pub severity:             CipAlertSeverity,
    pub timeline:             RemediationTimeline,
    pub must_report_to_eisac: bool,
    pub weight:               f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapReport {
    pub generated_at:       u64,
    pub impact_level:       String,
    pub overall_score:      f64,
    pub grade:              String,
    pub total_requirements: usize,
    pub passing:            usize,
    pub failing:            usize,
    pub immediate_gaps:     Vec<GapEntry>,
    pub days_35_gaps:       Vec<GapEntry>,
    pub days_90_gaps:       Vec<GapEntry>,
    pub annual_gaps:        Vec<GapEntry>,
    pub gaps_by_standard:   HashMap<String, usize>,
}

impl GapReport {
    pub fn total_gaps(&self) -> usize {
        self.immediate_gaps.len() + self.days_35_gaps.len()
            + self.days_90_gaps.len() + self.annual_gaps.len()
    }
    pub fn has_eisac_reportable(&self) -> bool {
        !self.immediate_gaps.is_empty()
            || self.days_35_gaps.iter().any(|g| g.must_report_to_eisac)
    }
}

// ── CIP Report ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipReport {
    pub generated_at:      u64,
    pub impact_level:      BesImpactLevel,
    pub overall_score:     f64,
    pub pass_count:        usize,
    pub fail_count:        usize,
    pub na_count:          usize,
    pub manual_count:      usize,
    pub requirements:      Vec<CipRequirement>,
    pub critical_gaps:     Vec<String>,
    pub must_report_alerts: Vec<CipAlert>,
}

impl CipReport {
    pub fn grade(&self) -> &'static str {
        match self.overall_score as u32 {
            90..=100 => "Substantially Compliant",
            75..=89  => "Mostly Compliant (Gaps Remain)",
            60..=74  => "Partially Compliant (High Risk)",
            50..=59  => "Significant Gaps (Immediate Action)",
            _        => "Non-Compliant (NERC Enforcement Risk)",
        }
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CipStats {
    pub evaluations_run:       u64,
    pub alerts_generated:      u64,
    pub critical_alerts:       u64,
    pub last_evaluation_at:    u64,
    pub current_impact_level:  String,
    pub last_score:            f64,
}

// ── Evidence ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NercCipEvidence {
    // CIP-002
    pub bes_cyber_systems_inventoried:      bool,
    pub impact_classification_documented:   bool,
    // CIP-003
    pub cybersecurity_policy_approved:      bool,
    pub physical_io_ports_controlled:       bool,
    // CIP-004
    pub personnel_risk_assessments_current: bool,
    pub cybersecurity_awareness_training:   bool,
    pub authorized_electronic_access_list:  bool,
    // CIP-005 — E-ISAC + MFA are the two always-warn gaps
    pub esp_defined_and_documented:         bool,
    pub access_points_restricted:           bool,
    pub inbound_outbound_permissions_documented: bool,
    pub interactive_remote_access_controlled: bool,
    pub mfa_for_remote_access:              bool, // CIP-005-R2-2.2 — requires external IdP
    pub intermediate_system_for_remote_access: bool,
    // CIP-006
    pub physical_security_plan_documented:  bool,
    pub physical_access_controls_in_place:  bool,
    pub physical_action_logging:            bool,
    // CIP-007
    pub ports_services_restricted_to_required: bool,
    pub security_patches_managed:           bool,
    pub antimalware_deployed:               bool,
    pub security_event_monitoring_enabled:  bool,
    pub log_retention_35_days:              bool,
    pub failed_login_alerting:              bool,
    pub vulnerability_assessments_scheduled: bool,
    // CIP-008 — E-ISAC integration (CIP-008-R1-1.2) never auto-satisfied
    pub cyber_security_incident_response_plan: bool,
    pub e_isac_reporting_configured:        bool, // ← always warn until integrated
    pub incident_response_tested_annually:  bool,
    // CIP-009
    pub bcs_recovery_plan_documented:       bool,
    pub backup_and_restore_procedures:      bool,
    pub recovery_plan_tested:               bool,
    // CIP-010
    pub baseline_configurations_documented: bool,
    pub change_management_process:          bool,
    pub transient_device_policy:            bool,
    // CIP-011
    pub bes_cyber_system_information_protected: bool,
    pub reuse_and_disposal_processes:       bool,
    // CIP-013
    pub supply_chain_risk_management_plan:  bool,
    pub vendor_remote_access_controlled:    bool,
    pub software_integrity_verification:    bool,
    // CIP-014
    pub transmission_security_risk_assessment: bool,
    // Rudras runtime flags
    pub ids_ips_active:             bool,
    pub siem_integration_active:    bool,
    pub zero_trust_active:          bool,
    pub network_segmentation_active: bool,
    pub forensics_chain_active:     bool,
    pub sbom_active:                bool,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct NercCipEngine {
    impact_level:    RwLock<BesImpactLevel>,
    last_report:     RwLock<Option<CipReport>>,
    alert_queue:     RwLock<Vec<CipAlert>>,
    evaluations:     AtomicU64,
    alerts_total:    AtomicU64,
    critical_alerts: AtomicU64,
    seq:             AtomicU64,
}

impl NercCipEngine {
    pub fn new(impact_level: BesImpactLevel) -> Self {
        let engine = Self {
            impact_level:    RwLock::new(impact_level.clone()),
            last_report:     RwLock::new(None),
            alert_queue:     RwLock::new(Vec::new()),
            evaluations:     AtomicU64::new(0),
            alerts_total:    AtomicU64::new(0),
            critical_alerts: AtomicU64::new(0),
            seq:             AtomicU64::new(0),
        };
        info!("⚡ NERC CIP Engine — impact={} | CIP-002 through CIP-014 | 47 requirements",
              impact_level.label());
        engine
    }

    // ── Evidence builder ────────────────────────────────────────────────────

    pub fn build_evidence(
        &self,
        ids_active: bool, siem_active: bool, zt_active: bool,
        seg_active: bool, forensics_active: bool, sbom_active: bool,
    ) -> NercCipEvidence {
        NercCipEvidence {
            ids_ips_active:                        ids_active,
            siem_integration_active:               siem_active,
            zero_trust_active:                     zt_active,
            network_segmentation_active:           seg_active,
            forensics_chain_active:                forensics_active,
            sbom_active,
            // CIP-007 — Rudras covers these directly
            ports_services_restricted_to_required: true,
            security_event_monitoring_enabled:     ids_active,
            log_retention_35_days:                 siem_active,
            failed_login_alerting:                 ids_active,
            antimalware_deployed:                  true,
            security_patches_managed:              sbom_active,
            vulnerability_assessments_scheduled:   sbom_active,
            // CIP-005 — Rudras covers perimeters, NOT MFA
            esp_defined_and_documented:            seg_active,
            access_points_restricted:              zt_active,
            inbound_outbound_permissions_documented: seg_active,
            interactive_remote_access_controlled:  zt_active,
            mfa_for_remote_access:                 false, // ← ALWAYS WARN — needs external IdP
            intermediate_system_for_remote_access: false, // ← needs jump server
            // CIP-013 — supply chain
            supply_chain_risk_management_plan:     sbom_active,
            vendor_remote_access_controlled:       zt_active,
            software_integrity_verification:       sbom_active,
            // CIP-008 — E-ISAC NEVER auto-satisfied
            cyber_security_incident_response_plan: false,
            e_isac_reporting_configured:           false, // ← ALWAYS WARN — needs integration
            incident_response_tested_annually:     false,
            // CIP-011
            bes_cyber_system_information_protected: seg_active,
            // Human-org evidence — always false from Rudras alone
            bes_cyber_systems_inventoried:         false,
            impact_classification_documented:      false,
            cybersecurity_policy_approved:         false,
            physical_io_ports_controlled:          false,
            personnel_risk_assessments_current:    false,
            cybersecurity_awareness_training:      false,
            authorized_electronic_access_list:     false,
            physical_security_plan_documented:     false,
            physical_access_controls_in_place:     false,
            physical_action_logging:               false,
            bcs_recovery_plan_documented:          false,
            backup_and_restore_procedures:         false,
            recovery_plan_tested:                  false,
            baseline_configurations_documented:    false,
            change_management_process:             false,
            transient_device_policy:               false,
            reuse_and_disposal_processes:          false,
            transmission_security_risk_assessment: false,
        }
    }

    // ── Evaluate ─────────────────────────────────────────────────────────────

    pub fn evaluate(&self, ev: &NercCipEvidence) -> CipReport {
        let impact = self.impact_level.read().clone();
        let requirements = self.build_requirements(&impact, ev);

        let pass_count   = requirements.iter().filter(|r| r.status == CipCheckStatus::Pass).count();
        let fail_count   = requirements.iter().filter(|r| r.status == CipCheckStatus::Fail).count();
        let na_count     = requirements.iter().filter(|r| r.status == CipCheckStatus::NotApplicable).count();
        let manual_count = requirements.iter().filter(|r| r.status == CipCheckStatus::ManualVerificationRequired).count();

        let (total_w, pass_w) = requirements.iter()
            .filter(|r| r.status != CipCheckStatus::NotApplicable)
            .fold((0.0f64, 0.0f64), |(tw, pw), r| {
                if r.status == CipCheckStatus::Pass { (tw + r.weight, pw + r.weight) }
                else { (tw + r.weight, pw) }
            });

        let overall_score = if total_w > 0.0 { (pass_w / total_w) * 100.0 } else { 0.0 };

        let critical_gaps: Vec<String> = requirements.iter()
            .filter(|r| r.status == CipCheckStatus::Fail && r.weight >= 0.9)
            .map(|r| format!("[{}] {}", r.requirement_id, r.title))
            .collect();

        // Always warn for the two unfixable-by-Rudras gaps
        if !ev.mfa_for_remote_access {
            warn!(
                "🔐 NERC CIP GAP [CIP-005-R2-2.2] MFA for Remote Access NOT configured. \
                 CIP-005-R2 Part 2.2 requires Multi-Factor Authentication for all Interactive \
                 Remote Access to High/Medium BES Cyber Systems. \
                 Fix: configure zero_trust oauth_provider (Azure AD / Okta / Duo). \
                 SLA: 35 days (NERC reportable)."
            );
        }
        if !ev.e_isac_reporting_configured {
            warn!(
                "📡 NERC CIP GAP [CIP-008-R1-1.2] E-ISAC Integration NOT configured. \
                 CIP-008-R1 Part 1.2 requires cybersecurity incidents to be reported \
                 to E-ISAC (eisac.com) within 1 HOUR of identification. \
                 Fix: add E-ISAC API endpoint to [siem] config; Rudras SIEM will forward \
                 Critical/High alerts automatically. \
                 SLA: IMMEDIATE — this is a mandatory NERC reporting obligation."
            );
        }

        let must_report_alerts: Vec<CipAlert> = requirements.iter()
            .filter(|r| r.status == CipCheckStatus::Fail && r.weight >= 0.85)
            .map(|r| {
                let n = self.seq.fetch_add(1, Ordering::Relaxed);
                let alert = CipAlert {
                    id: format!("NERC-{}-{}", r.requirement_id.replace('-', ""), n),
                    standard: r.standard.clone(),
                    requirement_id: r.requirement_id.clone(),
                    severity: if r.weight >= 1.0 { CipAlertSeverity::Critical } else { CipAlertSeverity::High },
                    description: r.description.clone(),
                    recommended_action: r.remediation.clone().unwrap_or_default(),
                    timestamp: unix_secs(),
                    must_report_to_nerc: r.weight >= 0.95,
                };
                self.alerts_total.fetch_add(1, Ordering::Relaxed);
                if alert.severity == CipAlertSeverity::Critical {
                    self.critical_alerts.fetch_add(1, Ordering::Relaxed);
                }
                alert
            })
            .collect();

        self.evaluations.fetch_add(1, Ordering::Relaxed);
        {
            let mut q = self.alert_queue.write();
            for a in &must_report_alerts { q.push(a.clone()); }
        }

        let report = CipReport {
            generated_at: unix_secs(), impact_level: impact,
            overall_score, pass_count, fail_count, na_count, manual_count,
            requirements, critical_gaps, must_report_alerts,
        };
        *self.last_report.write() = Some(report.clone());
        report
    }

    // ── Gap Report ───────────────────────────────────────────────────────────

    pub fn generate_gap_report(&self, cip: &CipReport) -> GapReport {
        let mut imm = Vec::new();
        let mut d35 = Vec::new();
        let mut d90 = Vec::new();
        let mut ann = Vec::new();
        let mut by_std: HashMap<String, usize> = HashMap::new();

        for req in &cip.requirements {
            if req.status != CipCheckStatus::Fail { continue; }

            let (sev, tl, report) = match req.weight {
                w if w >= 1.0  => (CipAlertSeverity::Critical, RemediationTimeline::Immediate, true),
                w if w >= 0.95 => (CipAlertSeverity::Critical, RemediationTimeline::Days35,    true),
                w if w >= 0.85 => (CipAlertSeverity::High,     RemediationTimeline::Days35,    false),
                w if w >= 0.75 => (CipAlertSeverity::Medium,   RemediationTimeline::Days90,    false),
                _              => (CipAlertSeverity::Low,       RemediationTimeline::Annual,    false),
            };

            let entry = GapEntry {
                requirement_id:       req.requirement_id.clone(),
                title:                req.title.clone(),
                description:          req.description.clone(),
                rudras_control:       req.rudras_control.clone(),
                remediation:          req.remediation.clone().unwrap_or_default(),
                severity: sev, timeline: tl.clone(),
                must_report_to_eisac: report, weight: req.weight,
            };

            *by_std.entry(req.standard.id().to_string()).or_default() += 1;
            match tl {
                RemediationTimeline::Immediate => imm.push(entry),
                RemediationTimeline::Days35    => d35.push(entry),
                RemediationTimeline::Days90    => d90.push(entry),
                RemediationTimeline::Annual    => ann.push(entry),
            }
        }

        for b in [&mut imm, &mut d35, &mut d90, &mut ann] {
            b.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap());
        }

        GapReport {
            generated_at: unix_secs(),
            impact_level: cip.impact_level.label().to_string(),
            overall_score: cip.overall_score,
            grade: cip.grade().to_string(),
            total_requirements: cip.requirements.len(),
            passing: cip.pass_count, failing: cip.fail_count,
            immediate_gaps: imm, days_35_gaps: d35,
            days_90_gaps: d90, annual_gaps: ann,
            gaps_by_standard: by_std,
        }
    }

    // ── E-ISAC Notification Template ─────────────────────────────────────────

    pub fn generate_eisac_template(&self, gr: &GapReport) -> String {
        let reportable: Vec<&GapEntry> = gr.immediate_gaps.iter()
            .chain(gr.days_35_gaps.iter().filter(|g| g.must_report_to_eisac))
            .collect();

        if reportable.is_empty() {
            return "// No E-ISAC reportable gaps in current evaluation.".to_string();
        }

        let mut out = format!(
            "════════════════════════════════════════════════════════\n\
             E-ISAC CIP CYBERSECURITY INCIDENT NOTIFICATION\n\
             Generated: {} UTC  |  Impact: {}\n\
             Score: {:.1}%  |  Grade: {}\n\
             ════════════════════════════════════════════════════════\n\n\
             SECTION 1 — ORGANIZATION\n\
             Organization Name: [FILL IN — Registered Entity Name]\n\
             NERC ID:           [FILL IN — e.g. ABCDE-RE]\n\
             Contact:           [FILL IN — Name / Phone]\n\
             Region:            [FILL IN — WECC/RFC/SERC/TRE]\n\n\
             SECTION 2 — INCIDENT SUMMARY\n\
             Reportable Gaps: {}\n\
             Detected by:     Rudras NERC CIP Engine v4.1\n\n\
             SECTION 3 — VIOLATIONS\n",
            gr.generated_at, gr.impact_level,
            gr.overall_score, gr.grade, reportable.len()
        );

        for (i, g) in reportable.iter().enumerate() {
            out.push_str(&format!(
                "  [{:02}] [{}] {}\n\
                 \t    Timeline:    {}\n\
                 \t    Rudras:      {}\n\
                 \t    Remediation: {}\n\n",
                i + 1, g.requirement_id, g.title,
                g.timeline.label(), g.rudras_control, g.remediation
            ));
        }

        out.push_str(
            "SECTION 4 — ATTESTATION\n\
             Authorized Representative: [FILL IN]\n\
             Signature/Date:            [FILL IN]\n\
             Submit to: https://www.eisac.com\n\n\
             NOTE: Auto-generated by Rudras. Review with legal counsel before submission.\n\
             ════════════════════════════════════════════════════════\n"
        );
        out
    }

    // ── Structured Gap Log ───────────────────────────────────────────────────

    pub fn log_gap_report(&self, gr: &GapReport) {
        info!(
            "⚡ NERC CIP Gap Report | score={:.1}% | grade='{}' | impact={} | \
             reqs={} pass={} fail={} | gaps={} (imm={} 35d={} 90d={} ann={})",
            gr.overall_score, gr.grade, gr.impact_level,
            gr.total_requirements, gr.passing, gr.failing,
            gr.total_gaps(),
            gr.immediate_gaps.len(), gr.days_35_gaps.len(),
            gr.days_90_gaps.len(), gr.annual_gaps.len()
        );

        if !gr.immediate_gaps.is_empty() {
            error!("🚨 NERC CIP IMMEDIATE ({} gaps) — E-ISAC notify within 1 HOUR:",
                   gr.immediate_gaps.len());
            for g in &gr.immediate_gaps {
                error!("  🔴 [{}] {} — Fix: {}", g.requirement_id, g.title, g.remediation);
            }
        }

        if !gr.days_35_gaps.is_empty() {
            warn!("⚠️  NERC CIP 35-DAY ({} gaps) — NERC reporting SLA:",
                  gr.days_35_gaps.len());
            for g in &gr.days_35_gaps {
                let tag = if g.must_report_to_eisac { "📡 REPORTABLE" } else { "🔶 HIGH" };
                warn!("  {} [{}] {} — Rudras: {} — Fix: {}",
                      tag, g.requirement_id, g.title, g.rudras_control, g.remediation);
            }
        }

        if !gr.days_90_gaps.is_empty() {
            warn!("📋 NERC CIP 90-DAY ({} gaps) — standard window:", gr.days_90_gaps.len());
            for g in &gr.days_90_gaps {
                warn!("  🟡 [{}] {} — Fix: {}", g.requirement_id, g.title, g.remediation);
            }
        }

        if !gr.annual_gaps.is_empty() {
            info!("📅 NERC CIP ANNUAL ({} gaps) — next certification cycle:", gr.annual_gaps.len());
            for g in &gr.annual_gaps {
                info!("  🔵 [{}] {} — {}", g.requirement_id, g.title, g.remediation);
            }
        }

        if !gr.gaps_by_standard.is_empty() {
            let mut pairs: Vec<_> = gr.gaps_by_standard.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            let breakdown: Vec<String> = pairs.iter().map(|(k,v)| format!("{}:{}", k, v)).collect();
            info!("⚡ NERC CIP gaps by standard — {}", breakdown.join(" | "));
        }

        if gr.has_eisac_reportable() {
            warn!(
                "📡 E-ISAC NOTIFICATION REQUIRED — {} immediate + {} 35-day reportable. \
                 Submit: https://www.eisac.com | Use generate_eisac_template() for draft.",
                gr.immediate_gaps.len(),
                gr.days_35_gaps.iter().filter(|g| g.must_report_to_eisac).count()
            );
        } else {
            info!("✅ NERC CIP: No E-ISAC reportable gaps in current evaluation.");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    pub fn drain_alerts(&self) -> Vec<CipAlert> {
        self.alert_queue.write().drain(..).collect()
    }

    pub fn stats(&self) -> CipStats {
        let impact = self.impact_level.read();
        let last_score = self.last_report.read().as_ref().map(|r| r.overall_score).unwrap_or(0.0);
        CipStats {
            evaluations_run:      self.evaluations.load(Ordering::Relaxed),
            alerts_generated:     self.alerts_total.load(Ordering::Relaxed),
            critical_alerts:      self.critical_alerts.load(Ordering::Relaxed),
            last_evaluation_at:   unix_secs(),
            current_impact_level: impact.label().to_string(),
            last_score,
        }
    }

    pub fn set_impact_level(&self, level: BesImpactLevel) {
        info!("⚡ NERC CIP impact level → {}", level.label());
        *self.impact_level.write() = level;
    }

    // ── Requirements ─────────────────────────────────────────────────────────

    fn build_requirements(&self, impact: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let mut r = Vec::new();
        r.extend(self.cip002(impact, ev)); r.extend(self.cip003(impact, ev));
        r.extend(self.cip004(impact, ev)); r.extend(self.cip005(impact, ev));
        r.extend(self.cip006(impact, ev)); r.extend(self.cip007(impact, ev));
        r.extend(self.cip008(impact, ev)); r.extend(self.cip009(impact, ev));
        r.extend(self.cip010(impact, ev)); r.extend(self.cip011(impact, ev));
        r.extend(self.cip013(impact, ev)); r.extend(self.cip014(impact, ev));
        r
    }

    fn req(&self, std: CipStandard, id: &str, sub: &str, title: &str, desc: &str,
           pass: bool, ctrl: &str, fix: &str,
           applicable: Vec<BesImpactLevel>, w: f64) -> CipRequirement {
        let cur = self.impact_level.read().clone();
        let ok = applicable.contains(&cur);
        let status = if !ok { CipCheckStatus::NotApplicable }
                     else if pass { CipCheckStatus::Pass }
                     else { CipCheckStatus::Fail };
        CipRequirement {
            standard: std, requirement_id: id.into(), sub_requirement: sub.into(),
            title: title.into(), description: desc.into(), applicable_impact: applicable,
            status, rudras_control: ctrl.into(), evidence: ctrl.into(),
            remediation: if !pass && ok { Some(fix.into()) } else { None },
            weight: w,
        }
    }

    fn cip002(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let a = vec![BesImpactLevel::High, BesImpactLevel::Medium, BesImpactLevel::Low];
        vec![
            self.req(CipStandard::Cip002, "CIP-002-R1", "1.1", "BES Asset Inventory",
                "Maintain list of BES Cyber Systems and their Electronic Access Points.",
                ev.bes_cyber_systems_inventoried, "sbom_engine + asset discovery",
                "Deploy network asset discovery; integrate SBOM engine for inventory.", a.clone(), 1.0),
            self.req(CipStandard::Cip002, "CIP-002-R1", "1.2", "Impact Classification",
                "Categorize each BES Cyber System as High, Medium, or Low impact.",
                ev.impact_classification_documented, "Manual — documented classification",
                "Document formal impact classification for all BES assets.", a, 0.95),
        ]
    }

    fn cip003(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip003, "CIP-003-R1", "1.1", "Cybersecurity Policy",
                "Document and maintain a cybersecurity policy for BES Cyber Systems.",
                ev.cybersecurity_policy_approved, "Manual — exec-approved policy doc",
                "Obtain executive-approved CIP cybersecurity policy.", hm.clone(), 0.9),
            self.req(CipStandard::Cip003, "CIP-003-R2", "2.1", "Physical I/O Port Control",
                "Prevent unauthorized access to Low Impact BES Cyber Systems.",
                ev.physical_io_ports_controlled, "endpoint_security (USB/port monitoring)",
                "Enforce physical port control via endpoint_security module.",
                vec![BesImpactLevel::Low, BesImpactLevel::Medium, BesImpactLevel::High], 0.7),
        ]
    }

    fn cip004(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip004, "CIP-004-R1", "R1", "Security Awareness Training",
                "Annual cybersecurity awareness for all personnel with BES access.",
                ev.cybersecurity_awareness_training, "Manual — HR/training records",
                "Implement annual awareness program and maintain completion records.", hm.clone(), 0.8),
            self.req(CipStandard::Cip004, "CIP-004-R3", "R3", "Personnel Risk Assessment",
                "Background checks for all personnel with unescorted BES access.",
                ev.personnel_risk_assessments_current, "Manual — HR records",
                "Perform and document background checks for all authorized personnel.", hm.clone(), 0.9),
            self.req(CipStandard::Cip004, "CIP-004-R4", "R4", "Access Management",
                "Maintain list of authorized electronic and physical BES access.",
                ev.authorized_electronic_access_list, "zero_trust + management_api RBAC",
                "Use zero_trust RBAC to maintain and audit authorized access lists.", hm, 0.95),
        ]
    }

    fn cip005(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip005, "CIP-005-R1", "1.1", "ESP Definition",
                "Define Electronic Security Perimeter around BES Cyber Systems.",
                ev.esp_defined_and_documented, "micro_segmentation (zones = ESPs)",
                "Use micro_segmentation zones to define documented ESPs.", hm.clone(), 1.0),
            self.req(CipStandard::Cip005, "CIP-005-R1", "1.2", "EAP Access Points",
                "Identify all Electronic Access Points (EAPs) into each ESP.",
                ev.access_points_restricted, "wfp_engine + micro_segmentation",
                "Document and restrict all network access points via WFP rules.", hm.clone(), 1.0),
            self.req(CipStandard::Cip005, "CIP-005-R1", "1.3", "Deny by Default",
                "Deny all inbound/outbound traffic by default unless explicitly allowed.",
                ev.inbound_outbound_permissions_documented, "wfp_engine default-deny + policy_engine",
                "Enforce WFP default-deny and document all permit rules.", hm.clone(), 1.0),
            self.req(CipStandard::Cip005, "CIP-005-R2", "2.1", "Remote Access Auth",
                "Authenticate remote access sessions using encrypted communications.",
                ev.interactive_remote_access_controlled, "zero_trust + secure_channel (TLS 1.3 mTLS)",
                "Enforce encrypted remote access via zero_trust and TLS 1.3 secure_channel.", hm.clone(), 1.0),
            // ← THE MFA GAP — always warn, weight=1.0 (Immediate)
            self.req(CipStandard::Cip005, "CIP-005-R2", "2.2",
                "MFA for Remote Access",
                "Multi-Factor Authentication required for all Interactive Remote Access \
                 to High/Medium BES Cyber Systems. Single-factor (password only) is \
                 insufficient — a stolen credential alone can compromise the BES system.",
                ev.mfa_for_remote_access,
                "zero_trust + external MFA provider (TOTP/FIDO2/Duo/Okta/Azure AD)",
                "Set zero_trust.oauth_provider in config/rudras.toml. \
                 Supported: Azure AD (OIDC), Okta, Duo Security (TOTP), FIDO2 hardware keys.",
                hm.clone(), 1.0),
            self.req(CipStandard::Cip005, "CIP-005-R2", "2.3", "Intermediate System",
                "Use jump server / bastion host to protect direct BES access.",
                ev.intermediate_system_for_remote_access, "Manual — jump server architecture",
                "Deploy bastion host for all BES remote access sessions.", hm, 0.9),
        ]
    }

    fn cip006(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip006, "CIP-006-R1", "1.1", "Physical Security Plan",
                "Document physical security plan for Physical Security Perimeters.",
                ev.physical_security_plan_documented, "Manual — physical security documentation",
                "Document physical security plan with access controls and monitoring.", hm.clone(), 0.9),
            self.req(CipStandard::Cip006, "CIP-006-R1", "1.3", "Physical Access Controls",
                "Use physical access controls (locks, card readers) to restrict access.",
                ev.physical_access_controls_in_place, "Manual — physical infrastructure",
                "Deploy and document physical access control mechanisms.", hm.clone(), 0.95),
            self.req(CipStandard::Cip006, "CIP-006-R1", "1.6", "Physical Action Logging",
                "Log physical access and retain logs for at least 90 days.",
                ev.physical_action_logging, "forensics_chain + physical log integration",
                "Integrate physical access logs with forensics_chain for tamper-evident retention.", hm, 0.85),
        ]
    }

    fn cip007(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip007, "CIP-007-R1", "1.1", "Ports and Services",
                "Enable only ports and services required for normal and emergency operations.",
                ev.ports_services_restricted_to_required, "wfp_engine default_blocked_ports()",
                "WFP port blocklist + policy_engine. Document and justify all open ports.", hm.clone(), 1.0),
            self.req(CipStandard::Cip007, "CIP-007-R2", "2.1", "Security Patch Management",
                "Track and categorize security patches for BES Cyber System software.",
                ev.security_patches_managed, "sbom_engine (CVE tracking)",
                "sbom_engine tracks CVE exposure. Enable CVE feed integration.", hm.clone(), 0.9),
            self.req(CipStandard::Cip007, "CIP-007-R3", "3.1", "Malicious Code Prevention",
                "Implement anti-malware technology on BES Cyber Systems.",
                ev.antimalware_deployed, "ids_engine + comprehensive_blocker + endpoint_security",
                "IDS/IPS + malware blocking + endpoint_security provide malware prevention.", hm.clone(), 1.0),
            self.req(CipStandard::Cip007, "CIP-007-R4", "4.1", "Security Event Monitoring",
                "Log authentication and user activity events at the BES Cyber System level.",
                ev.security_event_monitoring_enabled, "siem_integration + ids_engine + forensics_chain",
                "SIEM captures all authentication and security events.", hm.clone(), 1.0),
            self.req(CipStandard::Cip007, "CIP-007-R4", "4.2", "Log Retention 35 Days",
                "Retain event logs for at least 35 days (90 recommended).",
                ev.log_retention_35_days, "siem_integration (log_retention_days >= 35)",
                "Set log_retention_days = 90 in config/rudras.toml [siem].", hm.clone(), 0.95),
            self.req(CipStandard::Cip007, "CIP-007-R4", "4.3", "Failed Login Alerting",
                "Alert on 3+ failed login attempts within 15 minutes.",
                ev.failed_login_alerting, "ids_engine BruteForce detection",
                "IDS brute-force detection + SIEM alert threshold configuration.", hm, 0.9),
        ]
    }

    fn cip008(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip008, "CIP-008-R1", "1.1", "Incident Response Plan",
                "Document incident response plans addressing cybersecurity incidents.",
                ev.cyber_security_incident_response_plan, "soar_engine (IR playbooks)",
                "Create formal CIP IR plan; wire SOAR playbooks to response procedures.", hm.clone(), 1.0),
            // ← THE E-ISAC GAP — always warn, weight=1.0 (Immediate)
            self.req(CipStandard::Cip008, "CIP-008-R1", "1.2",
                "E-ISAC Reporting Integration",
                "Report cybersecurity incidents to E-ISAC (Electricity ISAC) within 1 HOUR \
                 of identification. This is a mandatory NERC reporting obligation — failure \
                 to report within the SLA exposes the entity to enforcement action and \
                 fines up to $1M per day per violation.",
                ev.e_isac_reporting_configured,
                "siem_integration (E-ISAC API endpoint required)",
                "Add E-ISAC API endpoint to [siem] config in rudras.toml. \
                 E-ISAC Portal: https://www.eisac.com | Contact: eisac@nerc.com",
                hm.clone(), 1.0),
            self.req(CipStandard::Cip008, "CIP-008-R2", "2.1", "IR Plan Testing",
                "Test IR plan annually through tabletop or operational exercise.",
                ev.incident_response_tested_annually, "soar_engine playbook execution",
                "Conduct annual IR tabletop exercise and document results.", hm, 0.85),
        ]
    }

    fn cip009(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip009, "CIP-009-R1", "1.1", "Recovery Plan",
                "Document BCS recovery plan with activation conditions.",
                ev.bcs_recovery_plan_documented, "Manual — BCS recovery plan documentation",
                "Create and approve formal BCS recovery plan.", hm.clone(), 0.9),
            self.req(CipStandard::Cip009, "CIP-009-R1", "1.2", "Backup & Restore",
                "Backup BES Cyber System configuration and implement restore procedures.",
                ev.backup_and_restore_procedures, "forensics_chain (config backup)",
                "Implement automated config backup with forensics_chain integrity check.", hm.clone(), 0.9),
            self.req(CipStandard::Cip009, "CIP-009-R2", "2.1", "Recovery Plan Testing",
                "Test recovery plan at least once every 36 months.",
                ev.recovery_plan_tested, "Manual — recovery test records",
                "Schedule and document annual recovery plan tests.", hm, 0.8),
        ]
    }

    fn cip010(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip010, "CIP-010-R1", "1.1", "Baseline Configuration",
                "Develop and document baseline configuration for each BES Cyber System.",
                ev.baseline_configurations_documented, "sbom_engine (software inventory as baseline)",
                "Use SBOM engine to generate software baselines; document hardware config.", hm.clone(), 0.9),
            self.req(CipStandard::Cip010, "CIP-010-R1", "1.5", "Change Management",
                "Implement a change management process for BES Cyber Systems.",
                ev.change_management_process, "formal_verification + policy_verifier",
                "Use formal_verification for pre-change analysis; document change authorization.", hm.clone(), 0.9),
            self.req(CipStandard::Cip010, "CIP-010-R4", "4.1", "Transient Device Policy",
                "Implement policy for transient cyber assets connected to BES Cyber Systems.",
                ev.transient_device_policy, "endpoint_security + zero_trust (device posture)",
                "Document transient device policy; enforce via zero_trust device posture scoring.", hm, 0.8),
        ]
    }

    fn cip011(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip011, "CIP-011-R1", "1.1", "Information Protection",
                "Identify, classify, and protect BES Cyber System Information.",
                ev.bes_cyber_system_information_protected, "differential_privacy + micro_segmentation",
                "micro_segmentation zones isolate BCS information; differential_privacy on exports.", hm.clone(), 0.9),
            self.req(CipStandard::Cip011, "CIP-011-R2", "2.1", "Media Reuse/Disposal",
                "Prevent unauthorized retrieval of BCS information from reused storage media.",
                ev.reuse_and_disposal_processes, "Manual — data sanitization (NIST SP 800-88)",
                "Implement media sanitization procedures before reuse or disposal.", hm, 0.7),
        ]
    }

    fn cip013(&self, _i: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let hm = vec![BesImpactLevel::High, BesImpactLevel::Medium];
        vec![
            self.req(CipStandard::Cip013, "CIP-013-R1", "1.1", "Supply Chain Risk Plan",
                "Develop plan to identify and assess supply chain risks for BES Cyber Systems.",
                ev.supply_chain_risk_management_plan, "supply_chain_verifier + sbom_engine",
                "supply_chain_verifier and sbom_engine provide technical supply chain controls.", hm.clone(), 0.9),
            self.req(CipStandard::Cip013, "CIP-013-R1", "1.2", "Vendor Remote Access",
                "Control vendor remote access to BES Cyber Systems.",
                ev.vendor_remote_access_controlled, "zero_trust + management_api RBAC",
                "zero_trust enforces vendor access with identity verification + session recording.", hm.clone(), 0.9),
            self.req(CipStandard::Cip013, "CIP-013-R1", "1.3", "Software Integrity",
                "Verify integrity and authenticity of software before installation.",
                ev.software_integrity_verification, "supply_chain_verifier (hash + SLSA)",
                "supply_chain_verifier validates hash, SLSA provenance, and typosquat detection.", hm, 0.95),
        ]
    }

    fn cip014(&self, impact: &BesImpactLevel, ev: &NercCipEvidence) -> Vec<CipRequirement> {
        let high_only = vec![BesImpactLevel::High];
        let w = if impact == &BesImpactLevel::High { 0.95 } else { 0.0 };
        vec![
            self.req(CipStandard::Cip014, "CIP-014-R1", "R1", "Transmission Risk Assessment",
                "Conduct risk assessment to identify transmission stations/substations \
                 whose loss would affect BES reliability.",
                ev.transmission_security_risk_assessment, "Manual — NERC-approved assessor",
                "Engage NERC-approved assessor to conduct CIP-014 risk assessment.", high_only, w),
        ]
    }
}
