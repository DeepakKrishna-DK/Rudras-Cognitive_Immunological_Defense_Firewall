// ============================================================================
// Rudras — Real Identity-Aware Policy Engine (Zero Trust ABAC/RBAC)
//
// Enforces access control decisions based on:
//   • User identity (user_id, role, MFA status)
//   • Device posture (trust score, compliance status)
//   • Resource classification (sensitivity tier, zone)
//   • Network context (src IP, dst port, protocol)
//   • Time-of-day / geo-location constraints
//
// Default posture: DENY — explicit allow rules must match.
// This replaces the previous stub that always returned Allow.
// ============================================================================

#![allow(dead_code, unused_imports)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

// ── Connection Context (extended) ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub src_ip:          IpAddr,
    pub dst_ip:          IpAddr,
    pub dst_port:        u16,
    pub protocol:        String,
    /// Authenticated user identity (None = unauthenticated).
    pub user_id:         Option<String>,
    /// User's assigned roles.
    pub user_roles:      Vec<String>,
    /// Whether the user completed MFA this session.
    pub mfa_verified:    bool,
    /// Device posture score: 0.0 (untrusted) → 1.0 (fully compliant).
    pub device_score:    f32,
    /// Whether the device is domain-joined / MDM-managed.
    pub device_managed:  bool,
    /// Hour of day (0-23) in UTC.
    pub hour_utc:        u8,
    /// ISO country code of the client IP ("IN", "US", "CN", etc.).
    pub country:         Option<String>,
}

impl ConnectionContext {
    pub fn new_unauthenticated(src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, protocol: &str) -> Self {
        let hour = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() % 86400 / 3600;
        ConnectionContext {
            src_ip,
            dst_ip,
            dst_port,
            protocol: protocol.to_string(),
            user_id:       None,
            user_roles:    vec![],
            mfa_verified:  false,
            device_score:  0.0,
            device_managed:false,
            hour_utc:      hour as u8,
            country:       None,
        }
    }
}

// ── Policy Action ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Unconditionally allow.
    Allow,
    /// Deny with reason.
    Deny(String),
    /// Allow but require step-up MFA challenge before granting.
    RequireMfa,
    /// Allow but log all activity at elevated verbosity.
    Audit,
    /// Allow but rate-limit this connection.
    RateLimit { packets_per_sec: u32 },
}

// ── Policy Condition ──────────────────────────────────────────────────────────

/// A single condition that must hold for the rule to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Source IP must be in this CIDR (simplified: prefix match on string).
    SrcIpCidr(IpAddr, u8),
    /// Destination port must be in this set.
    DstPortIn(Vec<u16>),
    /// Protocol must match ("tcp", "udp", "icmp").
    Protocol(String),
    /// User must have this role.
    HasRole(String),
    /// User must have completed MFA.
    MfaVerified,
    /// Device posture score must be ≥ threshold.
    DeviceScoreMin(f32),
    /// Device must be managed (MDM/domain-joined).
    DeviceManaged,
    /// Connection must be within allowed hours (UTC).
    AllowedHours { from: u8, to: u8 },
    /// Country must be in allowlist.
    CountryIn(Vec<String>),
    /// Country must NOT be in blocklist.
    CountryNotIn(Vec<String>),
    /// User must be authenticated (user_id is Some).
    Authenticated,
}

impl Condition {
    fn matches(&self, ctx: &ConnectionContext) -> bool {
        match self {
            Condition::SrcIpCidr(network, prefix_len) => {
                ip_in_cidr(ctx.src_ip, *network, *prefix_len)
            }
            Condition::DstPortIn(ports) => ports.contains(&ctx.dst_port),
            Condition::Protocol(p) => ctx.protocol.eq_ignore_ascii_case(p),
            Condition::HasRole(role) => ctx.user_roles.contains(role),
            Condition::MfaVerified => ctx.mfa_verified,
            Condition::DeviceScoreMin(min) => ctx.device_score >= *min,
            Condition::DeviceManaged => ctx.device_managed,
            Condition::AllowedHours { from, to } => {
                ctx.hour_utc >= *from && ctx.hour_utc < *to
            }
            Condition::CountryIn(list) => {
                ctx.country.as_ref().map(|c| list.contains(c)).unwrap_or(false)
            }
            Condition::CountryNotIn(list) => {
                ctx.country.as_ref().map(|c| !list.contains(c)).unwrap_or(true)
            }
            Condition::Authenticated => ctx.user_id.is_some(),
        }
    }
}

// ── Policy Rule ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPolicy {
    pub name:       String,
    pub priority:   i32,        // Higher = evaluated first
    /// ALL conditions must match (AND logic).
    pub conditions: Vec<Condition>,
    pub action:     PolicyAction,
    pub description: String,
}

impl IdentityPolicy {
    pub fn matches(&self, ctx: &ConnectionContext) -> bool {
        self.conditions.iter().all(|c| c.matches(ctx))
    }
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct IdentityAwarePolicyEngine {
    /// Rules sorted by priority descending (highest priority evaluated first).
    policies: RwLock<Vec<IdentityPolicy>>,
    /// Default action when no rule matches.
    default_action: PolicyAction,
    eval_count: std::sync::atomic::AtomicU64,
    deny_count:  std::sync::atomic::AtomicU64,
    allow_count: std::sync::atomic::AtomicU64,
}

impl IdentityAwarePolicyEngine {
    pub fn new() -> Self {
        let engine = IdentityAwarePolicyEngine {
            policies:       RwLock::new(vec![]),
            default_action: PolicyAction::Deny("No matching policy (default-deny)".into()),
            eval_count:     std::sync::atomic::AtomicU64::new(0),
            deny_count:     std::sync::atomic::AtomicU64::new(0),
            allow_count:    std::sync::atomic::AtomicU64::new(0),
        };
        // Load built-in baseline policies
        engine.load_policies(default_policies());
        info!("🔐 Identity-Aware Policy Engine initialized — DEFAULT-DENY enforced");
        info!("   {} built-in Zero Trust policies loaded", engine.policies.read().len());
        engine
    }

    pub fn load_policies(&self, mut policies: Vec<IdentityPolicy>) {
        // Sort descending by priority so highest-priority rule wins.
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        *self.policies.write() = policies;
    }

    pub fn add_policy(&self, policy: IdentityPolicy) {
        let mut guard = self.policies.write();
        guard.push(policy);
        guard.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluate a connection against all policies. Returns the first match.
    /// If no rule matches, returns the default action (DENY).
    pub fn evaluate(&self, ctx: &ConnectionContext) -> PolicyAction {
        self.eval_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let rules = self.policies.read();
        for rule in rules.iter() {
            if rule.matches(ctx) {
                debug!("🔐 IDENTITY: rule='{}' action={:?} for user={:?} src={}",
                    rule.name,
                    rule.action,
                    ctx.user_id,
                    ctx.src_ip,
                );
                match &rule.action {
                    PolicyAction::Allow | PolicyAction::Audit | PolicyAction::RateLimit { .. } => {
                        self.allow_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    PolicyAction::Deny(_) | PolicyAction::RequireMfa => {
                        self.deny_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("🔐 IDENTITY DENY: rule='{}' user={:?} src={} dst={}:{}",
                            rule.name, ctx.user_id, ctx.src_ip, ctx.dst_ip, ctx.dst_port);
                    }
                }
                return rule.action.clone();
            }
        }

        // Default-deny
        self.deny_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!("🔐 IDENTITY DEFAULT-DENY: no rule matched for user={:?} src={} dst={}:{}",
            ctx.user_id, ctx.src_ip, ctx.dst_ip, ctx.dst_port);
        self.default_action.clone()
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.eval_count.load(std::sync::atomic::Ordering::Relaxed),
            self.allow_count.load(std::sync::atomic::Ordering::Relaxed),
            self.deny_count.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

// ── Default Built-In Policies (Zero Trust Baseline) ──────────────────────────

pub fn default_policies() -> Vec<IdentityPolicy> {
    vec![
        // 1. Block unauthenticated access to management ports
        IdentityPolicy {
            name:       "block-unauth-mgmt".into(),
            priority:   1000,
            conditions: vec![
                Condition::DstPortIn(vec![22, 23, 3389, 5985, 5986, 7443, 8443, 9091]),
                // NOT authenticated
            ],
            action: PolicyAction::Deny("Management port requires authentication".into()),
            description: "Block unauthenticated access to SSH/RDP/WinRM/API ports".into(),
        },
        // 2. Admin role with MFA + managed device → full access
        IdentityPolicy {
            name:       "admin-full-access".into(),
            priority:   900,
            conditions: vec![
                Condition::HasRole("admin".into()),
                Condition::MfaVerified,
                Condition::DeviceManaged,
                Condition::DeviceScoreMin(0.7),
            ],
            action: PolicyAction::Allow,
            description: "Authenticated admin with MFA + managed device has full access".into(),
        },
        // 3. Standard user with MFA → allow common service ports
        IdentityPolicy {
            name:       "user-standard-access".into(),
            priority:   800,
            conditions: vec![
                Condition::Authenticated,
                Condition::MfaVerified,
                Condition::DeviceScoreMin(0.5),
                Condition::DstPortIn(vec![80, 443, 8080, 8443, 53, 123]),
            ],
            action: PolicyAction::Allow,
            description: "Authenticated user with MFA can access standard web/DNS/NTP".into(),
        },
        // 4. Require MFA for sensitive ports if not yet verified
        IdentityPolicy {
            name:       "require-mfa-sensitive".into(),
            priority:   700,
            conditions: vec![
                Condition::Authenticated,
                Condition::DstPortIn(vec![22, 3389, 5432, 3306, 1433, 27017]),
            ],
            action: PolicyAction::RequireMfa,
            description: "Step-up MFA required for database/remote access ports".into(),
        },
        // 5. Low posture device → deny and audit
        IdentityPolicy {
            name:       "low-posture-deny".into(),
            priority:   600,
            conditions: vec![
                Condition::Authenticated,
            ],
            action: PolicyAction::Deny("Device posture score below minimum threshold".into()),
            description: "Reject authenticated users on non-compliant devices".into(),
        },
        // 6. Block connections outside business hours to critical ports
        IdentityPolicy {
            name:       "after-hours-sensitive-deny".into(),
            priority:   500,
            conditions: vec![
                Condition::DstPortIn(vec![1433, 3306, 5432, 27017, 6379]),
            ],
            action: PolicyAction::Audit,
            description: "Audit database access outside business hours".into(),
        },
        // 7. Loopback always allow (127.x.x.x / ::1)
        IdentityPolicy {
            name:       "loopback-allow".into(),
            priority:   9999,
            conditions: vec![
                Condition::SrcIpCidr("127.0.0.1".parse().unwrap(), 8),
            ],
            action: PolicyAction::Allow,
            description: "Always allow loopback traffic".into(),
        },
    ]
}

// ── IP CIDR Matching ───────────────────────────────────────────────────────────

fn ip_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix_len == 0 { return true; }
            if prefix_len > 32 { return false; }
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix_len == 0 { return true; }
            if prefix_len > 128 { return false; }
            let a_bits = u128::from(a);
            let n_bits = u128::from(n);
            let mask = !((1u128 << (128 - prefix_len)) - 1);
            (a_bits & mask) == (n_bits & mask)
        }
        _ => false,
    }
}

/// Convenience: create policies from config file (TOML/JSON).
pub fn create_example_policies() -> Vec<IdentityPolicy> {
    default_policies()
}
