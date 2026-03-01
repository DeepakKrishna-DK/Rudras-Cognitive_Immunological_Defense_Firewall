// ============================================================================
// Rudras — Policy Engine
// Stateful firewall policy: per-IP/port/protocol allow/deny rules.
// Stores a map of HybridRule per policy key; supports dynamic injection
// from CyberImmune, Distributed Immunity, and config-file static rules.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

// ── Action ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ActionType {
    Allow,
    Block,
    Quarantine(String),
    Monitor,
    RateLimit(u32),
}

// ── Rule Origin ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleOrigin {
    Static,
    CyberImmuneSystem,
    DistributedImmunity,
    FlowEngine,
    IPS,
    ThreatIntel,
    WinDivert,
    Admin,
}

// ── Hybrid Rule ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridRule {
    pub action: ActionType,
    pub confidence: f64,
    pub origin: RuleOrigin,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl HybridRule {
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            unix_now() > exp
        } else {
            false
        }
    }
}

// ── Policy Engine ─────────────────────────────────────────────────────────────

pub struct PolicyEngine {
    rules: RwLock<HashMap<String, HybridRule>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let rules = HashMap::new();
        // SECURITY: No static loopback bypass — see previous audit notes.

        Self {
            rules: RwLock::new(rules),
        }
    }

    /// Evaluate traffic — returns ActionType for the given src/dst/proto.
    ///
    /// DEFAULT BEHAVIOUR (Zero Trust): returns `Monitor` when no rule matches,
    /// NOT `Allow`. This means escalated flows without a specific policy entry
    /// fall through to the next shield layer (Threat Intel, Micro-Seg, IDS/IPS)
    /// rather than being silently allowed by the policy engine.
    /// Explicit `Allow` actions are only granted by dynamic engine rules.
    pub fn evaluate(&self, src: &str, dst: &str, _proto: &str) -> ActionType {
        let rules = self.rules.read();

        // Check src-specific rule first (highest priority — IPS blacklists / CyberImmune)
        if let Some(rule) = rules.get(&format!("src:{}", src)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }

        // Check dst-specific rule
        if let Some(rule) = rules.get(&format!("dst:{}", dst)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }

        // Zero Trust default: Monitor (continue to next shield)
        // Do NOT return Allow — no rule match is NOT the same as trusted.
        ActionType::Monitor
    }

    pub fn evaluate_with_port(
        &self,
        src: &str,
        dst: &str,
        proto: &str,
        port: u16,
    ) -> ActionType {
        let rules = self.rules.read();

        // src-based block rules (IPS penalty, CyberImmune, Distributed Immunity)
        if let Some(rule) = rules.get(&format!("src:{}", src)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }
        // Port-specific rules (e.g. admin interface restriction)
        if let Some(rule) = rules.get(&format!("port:{}", port)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }
        // dst-based rules
        if let Some(rule) = rules.get(&format!("dst:{}", dst)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }
        // Proto-specific rules
        if let Some(rule) = rules.get(&format!("proto:{}", proto)) {
            if !rule.is_expired() {
                return rule.action.clone();
            }
        }

        // Zero Trust default: Monitor (pass to next shield, not implicitly Allow)
        ActionType::Monitor
    }

    /// Add or update a dynamic rule (called by IPS / CyberImmune / Distributed Immunity)
    pub fn add_policy(&self, key: String, rule: HybridRule) {
        debug!(
            "📋 Policy: adding rule key={} action={:?} origin={:?}",
            key, rule.action, rule.origin
        );
        self.rules.write().insert(key, rule);
    }

    pub fn remove_policy(&self, key: &str) {
        self.rules.write().remove(key);
    }

    /// Returns empty list — country-level blocking replaced by IOC-based
    /// ThreatIntel blocking (specific malicious IPs/domains only).
    /// Kept for API compatibility.
    pub fn get_blocked_countries(&self) -> Vec<String> {
        vec![]
    }

    /// Remove all expired rules (called periodically)
    pub fn cleanup_expired(&self) {
        let mut rules = self.rules.write();
        rules.retain(|_, r| !r.is_expired());
    }

    pub fn get_rule_count(&self) -> usize {
        self.rules.read().len()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
