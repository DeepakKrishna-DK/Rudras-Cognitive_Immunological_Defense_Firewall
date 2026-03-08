// Rudras Zero Trust Engine — "Never Trust, Always Verify"
// Implements: Identity verification, Device posture scoring, ABAC policy,
// Session token management, Continuous re-authentication, 
// Implicit trust elimination (no presumed trust based on network location).
#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Identity Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    MultiFactor,    // TOTP / FIDO2 second factor
    Certificate,    // X.509 mutual TLS
    SmartCard,
    Kerberos,       // AD Kerberos ticket
    Saml,           // SAML 2.0 assertion
    OAuth2Jwt,      // OAuth2 access token (JWT)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: String,
    pub email: String,
    pub groups: Vec<String>,
    pub auth_method: AuthMethod,
    pub auth_strength: u8,       // 0-100; MFA=90, certificate=95, password=40
    pub source_ip: IpAddr,
    pub source_country: Option<String>,
    pub last_seen: u64,
    pub session_start: u64,
}

impl Identity {
    pub fn new(user_id: &str, email: &str, method: AuthMethod, src_ip: IpAddr) -> Self {
        let strength = match &method {
            AuthMethod::Certificate  => 95,
            AuthMethod::SmartCard    => 92,
            AuthMethod::MultiFactor  => 88,
            AuthMethod::Kerberos     => 75,
            AuthMethod::Saml         => 70,
            AuthMethod::OAuth2Jwt    => 65,
            AuthMethod::Password     => 40,
        };
        let now = unix_now_secs();
        Self {
            user_id: user_id.to_string(),
            email: email.to_string(),
            groups: vec![],
            auth_method: method,
            auth_strength: strength,
            source_ip: src_ip,
            source_country: None,
            last_seen: now,
            session_start: now,
        }
    }

    pub fn session_age_secs(&self) -> u64 {
        unix_now_secs().saturating_sub(self.session_start)
    }
}

// ── Device Posture ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePosture {
    pub device_id: String,
    pub hostname: String,
    pub os_type: OsType,
    pub os_patch_age_days: u32,
    pub antivirus_running: bool,
    pub antivirus_updated: bool,
    pub disk_encrypted: bool,
    pub edr_agent_active: bool,
    pub firewall_enabled: bool,
    pub screen_lock_enabled: bool,
    pub managed: bool,   // Corp MDM managed
    pub last_scan: u64,
    pub posture_score: u8, // 0-100 computed by score()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OsType { Windows, Linux, MacOS, Android, IOS, Unknown }

impl DevicePosture {
    pub fn compute_score(&mut self) {
        let mut score: u32 = 0;
        // Core security controls (35 points)
        if self.disk_encrypted     { score += 15; }
        if self.antivirus_running  { score += 10; }
        if self.antivirus_updated  { score += 5; }
        if self.firewall_enabled   { score += 5; }
        // EDR / management (25 points)
        if self.edr_agent_active   { score += 15; }
        if self.managed            { score += 10; }
        // Patch currency (25 points)
        score += match self.os_patch_age_days {
            0..=7   => 25,
            8..=30  => 20,
            31..=90 => 10,
            _       => 0,
        };
        // Hygiene (15 points)
        if self.screen_lock_enabled { score += 10; }
        // Recent scan (5 points)
        let scan_age = unix_now_secs().saturating_sub(self.last_scan) / 86400;
        if scan_age <= 1 { score += 5; }
        self.posture_score = score.min(100) as u8;
    }

    pub fn is_compliant(&self) -> bool {
        self.posture_score >= 60
            && self.disk_encrypted
            && self.firewall_enabled
            && self.os_patch_age_days <= 90
    }
}

// ── Session Token ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtSession {
    pub token: String,
    pub user_id: String,
    pub device_id: String,
    pub trust_score: u8,      // 0-100; combined identity + posture
    pub granted_resources: HashSet<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: u64,
    pub revoked: bool,
    pub reauth_required: bool,
    pub anomaly_count: u32,
}

impl ZtSession {
    pub fn new(identity: &Identity, device: &DevicePosture, ttl_secs: u64) -> Self {
        let now = unix_now_secs();
        // Trust score = 60% identity strength + 40% device posture
        let trust = ((identity.auth_strength as u32 * 60
            + device.posture_score as u32 * 40) / 100) as u8;
        // Token = sha2 hash of user_id + device_id + timestamp (deterministic for session)
        let raw = format!("{}_{}_{}", identity.user_id, device.device_id, now);
        let token = format!("zt_{:x}", xxhash_simple(&raw));
        Self {
            token,
            user_id: identity.user_id.clone(),
            device_id: device.device_id.clone(),
            trust_score: trust,
            granted_resources: HashSet::new(),
            created_at: now,
            expires_at: now + ttl_secs,
            last_activity: now,
            revoked: false,
            reauth_required: false,
            anomaly_count: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = unix_now_secs();
        !self.revoked && !self.reauth_required && now < self.expires_at
    }

    pub fn refresh_activity(&mut self) {
        self.last_activity = unix_now_secs();
    }

    pub fn revoke(&mut self, reason: &str) {
        self.revoked = true;
        warn!("🔐 ZT Session {} revoked: {}", &self.token[..12], reason);
    }
}

fn xxhash_simple(s: &str) -> u64 {
    // Fast non-cryptographic hash for token IDs (aesthetics only, not security)
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ── Access Policy (ABAC: Attribute-Based Access Control) ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub resource: String,
    pub min_trust_score: u8,
    pub required_groups: Vec<String>,          // user must be in at least one
    pub required_auth_methods: Vec<AuthMethod>, // empty = any
    pub require_managed_device: bool,
    pub require_disk_encryption: bool,
    pub max_session_age_secs: u64,
    pub require_edr: bool,
}

impl AccessPolicy {
    pub fn evaluate(&self, session: &ZtSession, identity: &Identity, device: &DevicePosture) -> PolicyDecision {
        let mut violations = vec![];

        if session.trust_score < self.min_trust_score {
            violations.push(format!("Trust score {} < required {}", session.trust_score, self.min_trust_score));
        }
        if !self.required_groups.is_empty() {
            let in_required = self.required_groups.iter().any(|g| identity.groups.contains(g));
            if !in_required {
                violations.push(format!("User not in required groups: {:?}", self.required_groups));
            }
        }
        if !self.required_auth_methods.is_empty()
            && !self.required_auth_methods.contains(&identity.auth_method) {
            violations.push(format!("Auth method {:?} not in required set", identity.auth_method));
        }
        if self.require_managed_device && !device.managed {
            violations.push("Unmanaged device not permitted".to_string());
        }
        if self.require_disk_encryption && !device.disk_encrypted {
            violations.push("Disk encryption required".to_string());
        }
        if self.require_edr && !device.edr_agent_active {
            violations.push("EDR agent must be active".to_string());
        }
        let session_age = unix_now_secs().saturating_sub(session.created_at);
        if session_age > self.max_session_age_secs {
            violations.push(format!("Session age {}s exceeds max {}s", session_age, self.max_session_age_secs));
        }

        if violations.is_empty() {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny(violations)
        }
    }
}

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    Deny(Vec<String>),
    StepUpAuth(String), // Re-authenticate with stronger method
}

// ── Identity Provider Configuration ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdConfig {
    pub server: String,
    pub domain: String,
    pub port: u16,               // 389 LDAP, 636 LDAPS, 3268 GC
    pub use_tls: bool,
    pub bind_dn: String,         // e.g. "CN=rudras-bind,OU=ServiceAccounts,DC=corp,DC=com"
    pub search_base: String,     // "DC=corp,DC=com"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub idp_metadata_url: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String, // Assertion Consumer Service URL
    pub sign_assertions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String, // Should be loaded from secrets vault, not config file
    pub auth_url: String,
    pub token_url: String,
    pub jwks_uri: String,       // For JWT validation
    pub audience: String,
}

pub struct IdentityProvider {
    pub ad:    Option<AdConfig>,
    pub saml:  Option<SamlConfig>,
    pub oauth: Option<OAuthConfig>,
    // Trust decisions cache: user_id → (AuthMethod, expiry)
    verified_users: RwLock<HashMap<String, (AuthMethod, u64)>>,
    failed_auths: RwLock<HashMap<IpAddr, (u32, u64)>>, // IP → (count, window_start)
    total_auth_attempts: AtomicU64,
    total_auth_success: AtomicU64,
    total_auth_failures: AtomicU64,
}

impl IdentityProvider {
    pub fn new() -> Self {
        Self {
            ad: None,
            saml: None,
            oauth: None,
            verified_users: RwLock::new(HashMap::new()),
            failed_auths: RwLock::new(HashMap::new()),
            total_auth_attempts: AtomicU64::new(0),
            total_auth_success: AtomicU64::new(0),
            total_auth_failures: AtomicU64::new(0),
        }
    }

    pub fn with_active_directory(mut self, server: &str, domain: &str) -> Self {
        self.ad = Some(AdConfig {
            server: server.to_string(),
            domain: domain.to_string(),
            port: 636,
            use_tls: true,
            bind_dn: format!("CN=rudras-bind,DC={}", domain.replace('.', ",DC=")),
            search_base: format!("DC={}", domain.replace('.', ",DC=")),
        });
        info!("🔐 ZeroTrust: Active Directory configured — ldaps://{}:636 domain={}", server, domain);
        self
    }

    pub fn with_saml(mut self, idp_url: &str, sp_entity: &str) -> Self {
        self.saml = Some(SamlConfig {
            idp_metadata_url: idp_url.to_string(),
            sp_entity_id: sp_entity.to_string(),
            sp_acs_url: format!("{}/saml/acs", sp_entity),
            sign_assertions: true,
        });
        info!("🔐 ZeroTrust: SAML 2.0 configured — IdP={}", idp_url);
        self
    }

    pub fn with_oauth(mut self, client_id: &str, client_secret: &str, auth_url: &str) -> Self {
        self.oauth = Some(OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: auth_url.to_string(),
            token_url: format!("{}/token", auth_url),
            jwks_uri: format!("{}/jwks", auth_url),
            audience: client_id.to_string(),
        });
        info!("🔐 ZeroTrust: OAuth2/OIDC configured — auth_url={}", auth_url);
        self
    }

    /// Brute-force detection: block IP after 10 failures in 300 seconds
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        let lock = self.failed_auths.read();
        if let Some((count, window_start)) = lock.get(ip) {
            let age = unix_now_secs().saturating_sub(*window_start);
            return age < 300 && *count >= 10;
        }
        false
    }

    /// Record a failed authentication attempt from this IP
    pub fn record_failure(&self, ip: IpAddr) {
        let mut lock = self.failed_auths.write();
        let now = unix_now_secs();
        let entry = lock.entry(ip).or_insert((0, now));
        let age = now.saturating_sub(entry.1);
        if age >= 300 {
            // Reset window
            *entry = (1, now);
        } else {
            entry.0 += 1;
            if entry.0 >= 10 {
                warn!("🚨 ZeroTrust: IP {} BLOCKED — {} auth failures in {}s (credential stuffing?)",
                    ip, entry.0, age);
            }
        }
        self.total_auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Simulate an AD/LDAP group membership lookup.
    /// In production, this sends an LDAP search to the configured AD server.
    pub async fn lookup_user_groups(&self, user_id: &str) -> Vec<String> {
        if let Some(ad) = &self.ad {
            debug!("ZT: LDAP search at ldaps://{}:{} base='{}' filter='(sAMAccountName={})'",
                ad.server, ad.port, ad.search_base, user_id);
            // In production: bind to LDAP with bind_dn, search for user, return memberOf attributes
            // Here we return empty (would be populated by actual LDAP response)
            vec![]
        } else {
            vec![]
        }
    }

    /// Validate a JWT token from OAuth2 / OIDC IdP.
    /// In production, fetches JWKS from jwks_uri and verifies signature + claims.
    pub async fn validate_jwt(&self, token: &str) -> Option<String> {
        if let Some(oauth) = &self.oauth {
            debug!("ZT: Validating JWT against JWKS at {}", oauth.jwks_uri);
            // In production: 
            // 1. Decode JWT header → get kid
            // 2. Fetch JWKS from oauth.jwks_uri
            // 3. Find matching key by kid
            // 4. Verify RS256/ES256 signature
            // 5. Check iss, aud, exp, nbf claims
            // 6. Return user_id from "sub" claim
        }
        None
    }

    pub fn stats(&self) -> IdpStats {
        IdpStats {
            total_attempts: self.total_auth_attempts.load(Ordering::Relaxed),
            total_success: self.total_auth_success.load(Ordering::Relaxed),
            total_failures: self.total_auth_failures.load(Ordering::Relaxed),
            ad_configured: self.ad.is_some(),
            saml_configured: self.saml.is_some(),
            oauth_configured: self.oauth.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdpStats {
    pub total_attempts: u64,
    pub total_success: u64,
    pub total_failures: u64,
    pub ad_configured: bool,
    pub saml_configured: bool,
    pub oauth_configured: bool,
}

// ── Zero Trust Engine ─────────────────────────────────────────────────────────

pub struct ZeroTrustEngine {
    pub identity_provider: IdentityProvider,
    /// Active sessions: token → ZtSession
    sessions: RwLock<HashMap<String, ZtSession>>,
    /// Access policies per resource
    policies: RwLock<Vec<AccessPolicy>>,
    /// Device registry: device_id → DevicePosture
    device_registry: RwLock<HashMap<String, DevicePosture>>,
    /// Identity registry: user_id → Identity
    identity_registry: RwLock<HashMap<String, Identity>>,
    session_ttl_secs: u64,
    total_access_decisions: AtomicU64,
    total_access_denied: AtomicU64,
}

impl ZeroTrustEngine {
    pub fn new(provider: IdentityProvider) -> Self {
        Self {
            identity_provider: provider,
            sessions: RwLock::new(HashMap::new()),
            policies: RwLock::new(Vec::new()),
            device_registry: RwLock::new(HashMap::new()),
            identity_registry: RwLock::new(HashMap::new()),
            session_ttl_secs: 3600, // 1 hour default
            total_access_decisions: AtomicU64::new(0),
            total_access_denied: AtomicU64::new(0),
        }
    }

    pub fn with_session_ttl(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    pub fn register_policy(&self, policy: AccessPolicy) {
        self.policies.write().push(policy);
    }

    pub fn register_device(&self, device: DevicePosture) {
        info!("🔐 ZeroTrust: Registered device '{}' (hostname={}, posture={})",
            device.device_id, device.hostname, device.posture_score);
        self.device_registry.write().insert(device.device_id.clone(), device);
    }

    /// Establish a new ZT session after identity verification.
    pub fn establish_session(&self, identity: Identity, device_id: &str) -> Option<ZtSession> {
        let devices = self.device_registry.read();
        let Some(device) = devices.get(device_id) else {
            warn!("ZeroTrust: Unknown device '{}' — session denied", device_id);
            return None;
        };
        if !device.is_compliant() {
            warn!("🚫 ZeroTrust: Device '{}' posture score {} is non-compliant — session denied",
                device_id, device.posture_score);
            return None;
        }
        let session = ZtSession::new(&identity, device, self.session_ttl_secs);
        info!("✅ ZeroTrust: Session {} established for user={} device={} trust={}",
            &session.token[..12], identity.user_id, device_id, session.trust_score);
        self.identity_registry.write().insert(identity.user_id.clone(), identity);
        let token = session.token.clone();
        self.sessions.write().insert(token, session.clone());
        Some(session)
    }

    /// Core access decision: evaluate whether token is allowed to access resource.
    /// This runs on EVERY packet/connection in zero-trust mode — "never trust, always verify".
    pub fn evaluate_access(&self, token: &str, resource: &str) -> PolicyDecision {
        self.total_access_decisions.fetch_add(1, Ordering::Relaxed);

        let sessions = self.sessions.read();
        let Some(session) = sessions.get(token) else {
            self.total_access_denied.fetch_add(1, Ordering::Relaxed);
            return PolicyDecision::Deny(vec!["No valid session token".to_string()]);
        };

        if !session.is_valid() {
            self.total_access_denied.fetch_add(1, Ordering::Relaxed);
            if session.revoked {
                return PolicyDecision::Deny(vec!["Session has been revoked".to_string()]);
            }
            if session.reauth_required {
                return PolicyDecision::StepUpAuth("Re-authentication required".to_string());
            }
            return PolicyDecision::Deny(vec!["Session expired".to_string()]);
        }

        // Check re-authentication interval (step up every 30 min for sensitive resources)
        let last_activity_age = unix_now_secs().saturating_sub(session.last_activity);
        if last_activity_age > 1800 {
            return PolicyDecision::StepUpAuth(
                format!("Session inactive for {}min — re-authenticate", last_activity_age / 60));
        }

        let policies = self.policies.read();
        let identities = self.identity_registry.read();
        let devices = self.device_registry.read();

        let Some(identity) = identities.get(&session.user_id) else {
            return PolicyDecision::Deny(vec!["Identity not found for session".to_string()]);
        };
        let Some(device) = devices.get(&session.device_id) else {
            return PolicyDecision::Deny(vec!["Device not found for session".to_string()]);
        };

        // Find matching policy for this resource
        let matching_policy = policies.iter().find(|p| {
            resource.starts_with(&p.resource) || p.resource == "*"
        });

        if let Some(policy) = matching_policy {
            let decision = policy.evaluate(session, identity, device);
            if matches!(decision, PolicyDecision::Deny(_)) {
                self.total_access_denied.fetch_add(1, Ordering::Relaxed);
                warn!("🚫 ZeroTrust: DENY {}@{} → resource='{}' trust={}",
                    identity.user_id, identity.source_ip, resource, session.trust_score);
            }
            decision
        } else {
            // Zero trust default: no matching policy = DENY
            self.total_access_denied.fetch_add(1, Ordering::Relaxed);
            warn!("🚫 ZeroTrust: No policy for resource '{}' — default DENY", resource);
            PolicyDecision::Deny(vec![format!("No access policy defined for '{}'", resource)])
        }
    }

    /// Revoke all sessions for a user (e.g., on account compromise)
    pub fn revoke_user_sessions(&self, user_id: &str, reason: &str) {
        let mut sessions = self.sessions.write();
        let mut count = 0u32;
        for session in sessions.values_mut() {
            if session.user_id == user_id && !session.revoked {
                session.revoke(reason);
                count += 1;
            }
        }
        warn!("🔐 ZeroTrust: Revoked {} sessions for user '{}' — {}", count, user_id, reason);
    }

    /// Continuous re-evaluation: scan sessions for anomalies and stale state.
    /// Call periodically (e.g., every 60 seconds) from a background task.
    pub fn continuous_re_evaluation(&self) {
        let now = unix_now_secs();
        let mut sessions = self.sessions.write();
        let mut expired = 0u32;

        sessions.retain(|_, session| {
            if session.revoked { return false; }
            if now > session.expires_at {
                expired += 1;
                return false;
            }
            // Flag sessions idle > 30 min for step-up auth
            let idle = now.saturating_sub(session.last_activity);
            if idle > 1800 && !session.reauth_required {
                session.reauth_required = true;
                debug!("ZeroTrust: Session {} flagged for re-auth (idle {}s)", 
                    &session.token[..12], idle);
            }
            true
        });

        if expired > 0 {
            debug!("ZeroTrust: Purged {} expired sessions", expired);
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn stats(&self) -> ZtStats {
        ZtStats {
            total_decisions: self.total_access_decisions.load(Ordering::Relaxed),
            total_denied: self.total_access_denied.load(Ordering::Relaxed),
            active_sessions: self.active_session_count() as u64,
            registered_devices: self.device_registry.read().len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZtStats {
    pub total_decisions: u64,
    pub total_denied: u64,
    pub active_sessions: u64,
    pub registered_devices: u64,
}

// ── Default access policies for common resources ──────────────────────────────

pub fn create_default_policies() -> Vec<AccessPolicy> {
    vec![
        // Public Web: any valid session, minimal trust
        AccessPolicy {
            resource: "/web/public".to_string(),
            min_trust_score: 30,
            required_groups: vec![],
            required_auth_methods: vec![],
            require_managed_device: false,
            require_disk_encryption: false,
            max_session_age_secs: 86400,
            require_edr: false,
        },
        // Internal App: corp network, moderate trust
        AccessPolicy {
            resource: "/internal/app".to_string(),
            min_trust_score: 60,
            required_groups: vec!["employees".to_string()],
            required_auth_methods: vec![AuthMethod::MultiFactor, AuthMethod::Kerberos, AuthMethod::Certificate],
            require_managed_device: true,
            require_disk_encryption: true,
            max_session_age_secs: 3600,
            require_edr: false,
        },
        // Sensitive Data: high trust required
        AccessPolicy {
            resource: "/internal/sensitive".to_string(),
            min_trust_score: 80,
            required_groups: vec!["data-stewards".to_string(), "executives".to_string()],
            required_auth_methods: vec![AuthMethod::MultiFactor, AuthMethod::Certificate, AuthMethod::SmartCard],
            require_managed_device: true,
            require_disk_encryption: true,
            max_session_age_secs: 1800,
            require_edr: true,
        },
        // Admin/Privileged: highest trust, certificate only
        AccessPolicy {
            resource: "/admin".to_string(),
            min_trust_score: 90,
            required_groups: vec!["administrators".to_string()],
            required_auth_methods: vec![AuthMethod::Certificate, AuthMethod::SmartCard],
            require_managed_device: true,
            require_disk_encryption: true,
            max_session_age_secs: 900,
            require_edr: true,
        },
    ]
}

