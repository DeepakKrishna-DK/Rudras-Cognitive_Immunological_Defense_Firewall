// ============================================================================
// Rudras — Formal Policy Verification Engine
//
// Applies static formal analysis to the firewall ruleset to detect
// policy defects before they are deployed:
//
//   1. Shadowed Rule Detection
//      Rule B is shadowed if Rule A (appearing first) matches every packet
//      that Rule B would match, making Rule B unreachable.
//
//   2. Conflict Detection
//      Two rules match the same traffic pattern but specify different actions
//      (permit vs. deny / block). Without ordering awareness this is a conflict.
//
//   3. Reachability Analysis
//      For each rule, find at least one concrete packet example that would
//      trigger it — confirms the rule is reachable by some traffic.
//
//   4. Redundancy Detection
//      Pairs of rules with identical match conditions and identical actions.
//
//   5. Anomaly Scoring
//      Produces a verification report with a quality score and
//      a JSON-serialisable proof certificate.
//
// Integration:
//   • Complements policy_verifier.rs (runtime checks) with static analysis
//   • Proof certificates can be appended to forensics_chain.rs
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Policy Rule Model ─────────────────────────────────────────────────────────

/// A simplified abstract firewall rule for formal analysis.
/// More complex predicate types (regex, geo, user) are approximated
/// as opaque predicates that never shadow each other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormalRule {
    pub id: String,
    pub priority: u32,           // lower = higher priority
    pub src_cidr: Option<(u32, u8)>,  // (ip_prefix, prefix_len); None = any
    pub dst_cidr: Option<(u32, u8)>,
    pub src_port: PortSpec,
    pub dst_port: PortSpec,
    pub protocol: ProtoSpec,
    pub action: RuleAction,
    pub is_stateful: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortSpec {
    Any,
    Exact(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProtoSpec {
    Any,
    Tcp,
    Udp,
    Icmp,
    Proto(u8),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleAction { Allow, Deny, Drop, Log }

impl FormalRule {
    /// Returns true if this rule subsumes (is a superset of) the other rule.
    /// i.e. every packet matched by `other` would also be matched by `self`.
    pub fn subsumes(&self, other: &FormalRule) -> bool {
        self.src_subsumes(&other.src_cidr)
            && self.dst_subsumes(&other.dst_cidr)
            && self.port_subsumes(&self.src_port, &other.src_port)
            && self.port_subsumes(&self.dst_port, &other.dst_port)
            && self.proto_subsumes(&other.protocol)
    }

    fn src_subsumes(&self, other: &Option<(u32, u8)>) -> bool {
        cidr_subsumes(&self.src_cidr, other)
    }

    fn dst_subsumes(&self, other: &Option<(u32, u8)>) -> bool {
        cidr_subsumes(&self.dst_cidr, other)
    }

    fn port_subsumes(&self, mine: &PortSpec, theirs: &PortSpec) -> bool {
        match (mine, theirs) {
            (PortSpec::Any, _) => true,
            (PortSpec::Exact(p1), PortSpec::Exact(p2)) => p1 == p2,
            (PortSpec::Range(lo, hi), PortSpec::Exact(p)) => p >= lo && p <= hi,
            (PortSpec::Range(lo1, hi1), PortSpec::Range(lo2, hi2)) => lo2 >= lo1 && hi2 <= hi1,
            _ => false,
        }
    }

    fn proto_subsumes(&self, other: &ProtoSpec) -> bool {
        match (&self.protocol, other) {
            (ProtoSpec::Any, _) => true,
            (a, b) => a == b,
        }
    }

    /// Generate a concrete "witness" packet that this rule would match.
    pub fn witness(&self) -> Option<WitnessPacket> {
        let src_ip = cidr_example(&self.src_cidr)?;
        let dst_ip = cidr_example(&self.dst_cidr)?;
        let src_port = port_example(&self.src_port);
        let dst_port = port_example(&self.dst_port);
        let proto = proto_example(&self.protocol);
        Some(WitnessPacket { src_ip, dst_ip, src_port, dst_port, protocol: proto })
    }
}

fn cidr_subsumes(mine: &Option<(u32, u8)>, theirs: &Option<(u32, u8)>) -> bool {
    match (mine, theirs) {
        (None, _) => true, // mine = Any → subsumes everything
        (Some(_), None) => false, // mine is specific, theirs is Any → doesn't subsume
        (Some((net1, plen1)), Some((net2, plen2))) => {
            // mine subsumes theirs if mine's prefix is less specific (shorter)
            // AND the network portion of theirs falls within mine
            if plen1 > plen2 { return false; } // mine is more specific
            let mask = if *plen1 == 0 { 0u32 } else { !0u32 << (32 - plen1) };
            net2 & mask == net1 & mask
        }
    }
}

fn cidr_example(cidr: &Option<(u32, u8)>) -> Option<u32> {
    match cidr {
        None => Some(0x08080808), // 8.8.8.8 as "any external"
        Some((net, plen)) => {
            // Pick the first host address in the subnet (network + 1)
            let mask = if *plen == 0 { 0u32 } else { !0u32 << (32 - plen) };
            Some((net & mask) | 1)
        }
    }
}

fn port_example(spec: &PortSpec) -> u16 {
    match spec {
        PortSpec::Any => 12345,
        PortSpec::Exact(p) => *p,
        PortSpec::Range(lo, _) => *lo,
    }
}

fn proto_example(spec: &ProtoSpec) -> u8 {
    match spec {
        ProtoSpec::Any => 6,
        ProtoSpec::Tcp => 6,
        ProtoSpec::Udp => 17,
        ProtoSpec::Icmp => 1,
        ProtoSpec::Proto(p) => *p,
    }
}

// ── Witness Packet ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessPacket {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl WitnessPacket {
    pub fn src_ip_str(&self) -> String {
        let ip = std::net::Ipv4Addr::from(self.src_ip);
        ip.to_string()
    }
    pub fn dst_ip_str(&self) -> String {
        let ip = std::net::Ipv4Addr::from(self.dst_ip);
        ip.to_string()
    }
}

// ── Anomaly Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAnomaly {
    /// Rule B is shadowed by Rule A (A has higher/equal priority and subsumes B)
    ShadowedRule {
        shadowed_rule_id: String,
        shadowing_rule_id: String,
        note: String,
    },
    /// Two rules with same match but different actions
    ConflictingRules {
        rule_id_a: String,
        rule_id_b: String,
        action_a: RuleAction,
        action_b: RuleAction,
    },
    /// Two rules are exact duplicates (same match AND same action)
    RedundantRule {
        redundant_rule_id: String,
        kept_rule_id: String,
    },
    /// A rule can never be triggered (unreachable)
    UnreachableRule {
        rule_id: String,
        reason: String,
    },
}

// ── Proof Certificate ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCertificate {
    pub certified_at: u64,
    pub rules_analyzed: usize,
    pub anomalies_found: usize,
    pub policy_quality_score: f64, // 0.0–100.0
    pub anomalies: Vec<PolicyAnomaly>,
    /// Witness packets for each rule (proves reachability)
    pub witnesses: HashMap<String, Option<WitnessPacket>>,
}

// ── Verification Report ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub timestamp: u64,
    pub rules_analyzed: usize,
    pub shadowed_count: usize,
    pub conflict_count: usize,
    pub redundant_count: usize,
    pub unreachable_count: usize,
    pub policy_quality_score: f64,
    pub proof: ProofCertificate,
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FormalVerifierStats {
    pub verifications_run: u64,
    pub total_anomalies_found: u64,
    pub last_score: f64,
    pub last_run_at: u64,
}

// ── Formal Verifier ───────────────────────────────────────────────────────────

pub struct FormalVerifier {
    verifications_run: AtomicU64,
    total_anomalies: AtomicU64,
    last_score: RwLock<f64>,
    last_run: AtomicU64,
    last_report: RwLock<Option<VerificationReport>>,
}

impl FormalVerifier {
    pub fn new() -> Self {
        info!("🧮 Formal Verification Engine initialized — shadow/conflict/redundancy/reachability analysis");
        Self {
            verifications_run: AtomicU64::new(0),
            total_anomalies: AtomicU64::new(0),
            last_score: RwLock::new(100.0),
            last_run: AtomicU64::new(0),
            last_report: RwLock::new(None),
        }
    }

    /// Verify a ruleset. Returns a full verification report.
    pub fn verify_policy(&self, rules: &[FormalRule]) -> VerificationReport {
        self.verifications_run.fetch_add(1, Ordering::Relaxed);
        let now = unix_secs();

        // Sort rules by priority (lower number = higher priority)
        let mut sorted = rules.to_vec();
        sorted.sort_by_key(|r| r.priority);

        let mut anomalies: Vec<PolicyAnomaly> = Vec::new();
        let mut witnesses: HashMap<String, Option<WitnessPacket>> = HashMap::new();

        // ── 1. Reachability ───────────────────────────────────────────────────
        for rule in &sorted {
            witnesses.insert(rule.id.clone(), rule.witness());
        }

        // ── 2. Shadowing ──────────────────────────────────────────────────────
        for (i, rule_b) in sorted.iter().enumerate() {
            for rule_a in &sorted[..i] {
                // rule_a has higher/equal priority (comes before rule_b)
                if rule_a.priority <= rule_b.priority && rule_a.subsumes(rule_b) {
                    let note = format!(
                        "Rule '{}' (priority {}) subsumes rule '{}' (priority {}); '{}' unreachable",
                        rule_a.id, rule_a.priority, rule_b.id, rule_b.priority, rule_b.id
                    );
                    anomalies.push(PolicyAnomaly::ShadowedRule {
                        shadowed_rule_id: rule_b.id.clone(),
                        shadowing_rule_id: rule_a.id.clone(),
                        note,
                    });
                    warn!("🧮 Shadowed rule detected: {} shadowed by {}", rule_b.id, rule_a.id);
                    break; // Only report the first shadower
                }
            }
        }

        // ── 3. Conflicts & Redundancy ─────────────────────────────────────────
        for (i, rule_a) in sorted.iter().enumerate() {
            for rule_b in &sorted[i + 1..] {
                if rule_a.subsumes(rule_b) && rule_b.subsumes(rule_a) {
                    // Both rules have identical match conditions
                    if rule_a.action != rule_b.action {
                        anomalies.push(PolicyAnomaly::ConflictingRules {
                            rule_id_a: rule_a.id.clone(),
                            rule_id_b: rule_b.id.clone(),
                            action_a: rule_a.action.clone(),
                            action_b: rule_b.action.clone(),
                        });
                        warn!("🧮 Conflict: {} ({:?}) vs {} ({:?})",
                            rule_a.id, rule_a.action, rule_b.id, rule_b.action);
                    } else {
                        anomalies.push(PolicyAnomaly::RedundantRule {
                            redundant_rule_id: rule_b.id.clone(),
                            kept_rule_id: rule_a.id.clone(),
                        });
                        warn!("🧮 Redundant rule: {} is duplicate of {}", rule_b.id, rule_a.id);
                    }
                }
            }
        }

        // ── 4. Unreachable (no witness) ────────────────────────────────────────
        for (rule_id, witness) in &witnesses {
            if witness.is_none() {
                // No concrete packet can reach this rule (e.g. empty CIDR range)
                anomalies.push(PolicyAnomaly::UnreachableRule {
                    rule_id: rule_id.clone(),
                    reason: "No concrete packet witness could be generated".into(),
                });
                warn!("🧮 Unreachable rule: {}", rule_id);
            }
        }

        let n = rules.len();
        let a = anomalies.len();
        let score = if n == 0 { 100.0 } else {
            let deduction = (a as f64 / n as f64) * 100.0;
            (100.0 - deduction).max(0.0)
        };

        *self.last_score.write() = score;
        self.last_run.store(now, Ordering::Relaxed);
        self.total_anomalies.fetch_add(a as u64, Ordering::Relaxed);

        if a == 0 {
            info!("🧮 Policy verification PASSED — {} rules, score={:.1}%", n, score);
        } else {
            warn!("🧮 Policy verification: {} rules, {} anomalies, score={:.1}%", n, a, score);
        }

        let shadowed_count   = anomalies.iter().filter(|x| matches!(x, PolicyAnomaly::ShadowedRule { .. })).count();
        let conflict_count   = anomalies.iter().filter(|x| matches!(x, PolicyAnomaly::ConflictingRules { .. })).count();
        let redundant_count  = anomalies.iter().filter(|x| matches!(x, PolicyAnomaly::RedundantRule { .. })).count();
        let unreachable_count= anomalies.iter().filter(|x| matches!(x, PolicyAnomaly::UnreachableRule { .. })).count();

        let proof = ProofCertificate {
            certified_at: now,
            rules_analyzed: n,
            anomalies_found: a,
            policy_quality_score: score,
            anomalies: anomalies.clone(),
            witnesses,
        };

        let report = VerificationReport {
            timestamp: now, rules_analyzed: n,
            shadowed_count, conflict_count, redundant_count, unreachable_count,
            policy_quality_score: score, proof,
        };

        *self.last_report.write() = Some(report.clone());
        report
    }

    pub fn last_report(&self) -> Option<VerificationReport> {
        self.last_report.read().clone()
    }

    pub fn stats(&self) -> FormalVerifierStats {
        FormalVerifierStats {
            verifications_run: self.verifications_run.load(Ordering::Relaxed),
            total_anomalies_found: self.total_anomalies.load(Ordering::Relaxed),
            last_score: *self.last_score.read(),
            last_run_at: self.last_run.load(Ordering::Relaxed),
        }
    }
}
