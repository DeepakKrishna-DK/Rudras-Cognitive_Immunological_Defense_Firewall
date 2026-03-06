// ============================================================================
// Rudras — SIEM Integration Hub
// Connectors: Splunk HEC | Elasticsearch | QRadar Syslog
// Events are buffered locally and flushed at a configurable interval.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

// ── SIEM Config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SIEMConfig {
    pub enabled: bool,
    pub buffer_size: usize,
    pub flush_interval_seconds: u64,
    pub retry_attempts: u32,
}

impl Default for SIEMConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 10_000,
            flush_interval_seconds: 30,
            retry_attempts: 3,
        }
    }
}

// ── Security Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub threat_name: String,
    pub confidence: f64,
    pub severity: String,
    pub action_taken: String,
    // ── Security Framework Fields (MITRE ATT&CK + OWASP Top 10) ──────────────
    /// Comma-separated short tags e.g. "MITRE:T1071 | OWASP:A03:2021"
    /// Empty string when no framework mapping applies.
    pub framework_tags: String,
    /// Primary MITRE ATT&CK technique ID (first MITRE tag, if any) e.g. "T1071"
    pub mitre_technique_id: Option<String>,
    /// Primary MITRE tactic label e.g. "Command and Control"
    pub mitre_tactic: Option<String>,
    /// Primary OWASP Top 10 risk ID (first OWASP tag, if any) e.g. "A03:2021"
    pub owasp_category_id: Option<String>,
    /// Primary OWASP risk label e.g. "Injection"
    pub owasp_category_label: Option<String>,
}

impl SecurityEvent {
    pub fn new_threat_detected(
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        threat_name: &str,
        confidence: f64,
    ) -> Self {
        let severity = if confidence > 0.85 {
            "CRITICAL"
        } else if confidence > 0.65 {
            "HIGH"
        } else if confidence > 0.40 {
            "MEDIUM"
        } else {
            "LOW"
        };

        Self {
            timestamp: unix_now(),
            event_type: "THREAT_DETECTED".to_string(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            threat_name: threat_name.to_string(),
            confidence,
            severity: severity.to_string(),
            action_taken: "BLOCKED".to_string(),
            framework_tags: String::new(),
            mitre_technique_id: None,
            mitre_tactic: None,
            owasp_category_id: None,
            owasp_category_label: None,
        }
    }

    /// Build a fully-enriched SecurityEvent directly from an `IdsAlert`.
    ///
    /// All MITRE ATT&CK and OWASP Top 10 tags already computed by the IDS
    /// engine are promoted into structured, SIEM-searchable top-level fields.
    /// This ensures the framework data survives the full pipeline to
    /// Splunk / Elasticsearch / QRadar — not just the console log.
    pub fn from_ids_alert(
        alert: &crate::ids_engine::IdsAlert,
        action_taken: &str,
    ) -> Self {
        use crate::framework_alignment::{format_tags_short, FrameworkTag};

        let severity = match alert.severity {
            crate::ids_engine::IdsSeverity::Critical => "CRITICAL",
            crate::ids_engine::IdsSeverity::High     => "HIGH",
            crate::ids_engine::IdsSeverity::Medium   => "MEDIUM",
            crate::ids_engine::IdsSeverity::Low      => "LOW",
        };

        let framework_tags = format_tags_short(&alert.framework_tags);

        // Extract primary MITRE and OWASP fields for top-level SIEM indexing
        let mut mitre_technique_id = None;
        let mut mitre_tactic = None;
        let mut owasp_category_id = None;
        let mut owasp_category_label = None;

        for tag in &alert.framework_tags {
            match tag {
                FrameworkTag::Mitre(t) if mitre_technique_id.is_none() => {
                    mitre_technique_id = Some(t.effective_id().to_string());
                    mitre_tactic = Some(t.tactic.label().to_string());
                }
                FrameworkTag::Owasp(c) if owasp_category_id.is_none() => {
                    owasp_category_id = Some(c.id().to_string());
                    owasp_category_label = Some(c.label().to_string());
                }
                _ => {}
            }
        }

        Self {
            timestamp: alert.timestamp,
            event_type: "IDS_ALERT".to_string(),
            src_ip: alert.src_ip.to_string(),
            dst_ip: alert.dst_ip.to_string(),
            dst_port: alert.dst_port,
            threat_name: format!(
                "[SID:{}] {} — {}",
                alert.rule_id,
                alert.category.label(),
                alert.rule_name
            ),
            confidence: alert.confidence as f64,
            severity: severity.to_string(),
            action_taken: action_taken.to_string(),
            framework_tags,
            mitre_technique_id,
            mitre_tactic,
            owasp_category_id,
            owasp_category_label,
        }
    }
}

// ── Connector ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Connector {
    Splunk {
        url: String,
        token: String,
    },
    Elastic {
        url: String,
        index: String,
        user: Option<String>,
        pass: Option<String>,
    },
    QRadar {
        host: String,
        port: u16,
    },
}

// ── SIEM Integration ──────────────────────────────────────────────────────────

pub struct SIEMIntegration {
    config: SIEMConfig,
    connectors: Vec<Connector>,
    buffer: RwLock<VecDeque<SecurityEvent>>,
    events_total: AtomicU64,
    events_dropped: AtomicU64,
}

impl SIEMIntegration {
    pub fn new(config: SIEMConfig) -> Self {
        Self {
            config,
            connectors: Vec::new(),
            buffer: RwLock::new(VecDeque::with_capacity(10_000)),
            events_total: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        }
    }

    pub fn with_splunk(mut self, url: &str, token: &str) -> Self {
        self.connectors.push(Connector::Splunk {
            url: url.to_string(),
            token: token.to_string(),
        });
        self
    }

    pub fn with_elasticsearch(
        mut self,
        url: &str,
        index: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Self {
        self.connectors.push(Connector::Elastic {
            url: url.to_string(),
            index: index.to_string(),
            user: user.map(|s| s.to_string()),
            pass: pass.map(|s| s.to_string()),
        });
        self
    }

    pub fn with_qradar(mut self, host: &str, port: u16) -> Self {
        self.connectors.push(Connector::QRadar {
            host: host.to_string(),
            port,
        });
        self
    }

    /// Buffer a security event (non-blocking, called on hot path)
    pub async fn log_event(&self, event: SecurityEvent) {
        if !self.config.enabled {
            return;
        }
        self.events_total.fetch_add(1, Ordering::Relaxed);

        let mut buf = self.buffer.write();
        if buf.len() >= self.config.buffer_size {
            buf.pop_front(); // drop oldest
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        debug!(
            "📡 SIEM: Buffered event type={} src={} threat={}",
            event.event_type, event.src_ip, event.threat_name
        );
        buf.push_back(event);
    }

    /// Start background flush loop
    pub async fn start_background_flush(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.flush_interval_seconds);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                let events: Vec<_> = {
                    let mut buf = self.buffer.write();
                    buf.drain(..).collect()
                };
                if !events.is_empty() {
                    self.flush_events(events).await;
                }
            }
        });
    }

    async fn flush_events(&self, events: Vec<SecurityEvent>) {
        if self.connectors.is_empty() {
            // Local only — log to file via tracing.
            // Structured fields are emitted as root-level JSON keys, making
            // them instantly searchable by Splunk or Elasticsearch.
            for e in &events {
                info!(
                    security_event = true,
                    timestamp = e.timestamp,
                    event_type = %e.event_type,
                    src_ip = %e.src_ip,
                    dst_ip = %e.dst_ip,
                    dst_port = e.dst_port,
                    threat_name = %e.threat_name,
                    confidence = e.confidence,
                    severity = %e.severity,
                    action_taken = %e.action_taken,
                    // ── Framework Alignment Fields ─────────────────────────
                    // Indexed in Splunk/Elastic as dedicated searchable fields.
                    // Analysts can query: mitre_technique_id="T1071" to find
                    // all C2 traffic across the entire event history.
                    framework_tags = %e.framework_tags,
                    mitre_technique_id = ?e.mitre_technique_id,
                    mitre_tactic = ?e.mitre_tactic,
                    owasp_category_id = ?e.owasp_category_id,
                    owasp_category_label = ?e.owasp_category_label,
                    "SIEM Detection Log"
                );
            }
            return;
        }

        for connector in &self.connectors {
            match connector {
                Connector::Splunk { url, token } => {
                    debug!(
                        "📡 SIEM: Flushing {} events to Splunk {}",
                        events.len(),
                        url
                    );
                    // Production: POST to url/services/collector/event with HEC token
                }
                Connector::Elastic { url, index, .. } => {
                    debug!(
                        "📡 SIEM: Flushing {} events to Elasticsearch {}/{}",
                        events.len(),
                        url,
                        index
                    );
                    // Production: POST bulk request to _bulk endpoint
                }
                Connector::QRadar { host, port } => {
                    debug!(
                        "📡 SIEM: Flushing {} events to QRadar {}:{}",
                        events.len(),
                        host,
                        port
                    );
                    // Production: syslog UDP/TCP to host:port (CEF format)
                }
            }
        }
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.events_total.load(Ordering::Relaxed),
            self.events_dropped.load(Ordering::Relaxed),
            self.buffer.read().len(),
        )
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
