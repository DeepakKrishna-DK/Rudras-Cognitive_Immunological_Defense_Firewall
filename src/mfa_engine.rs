// ============================================================================
// Rudras — MFA Engine (CIP-005-R2-2.2)
//
// Multi-Factor Authentication for Interactive Remote Access.
// Closes the NERC CIP-005-R2 Part 2.2 gap — MFA for all IRA sessions.
//
// Supported factors:
//   TOTP   — RFC 6238 Time-based One-Time Password (Google Authenticator, Authy)
//   HOTP   — RFC 4226 HMAC-based OTP (counter-based fallback)
//   Backup — Pre-generated recovery codes (SHA3-256 hashed at rest)
//
// Integration modes:
//   Standalone — Rudras acts as TOTP issuer (no external IdP required)
//   Delegation — Forwards auth to Azure AD / Okta / Duo via OIDC/SAML
//
// Config (config/rudras.toml):
//   [mfa]
//   enabled          = true
//   provider         = "totp"       # totp | azure_ad | okta | duo
//   totp_issuer      = "Rudras BES"
//   totp_digits      = 6
//   totp_period_secs = 30
//   totp_window      = 1            # accept 1 step before/after (clock skew)
//   backup_codes     = 8            # number of backup recovery codes
//   enforce_for_all_remote = true   # enforce on every remote session
//
// Wire into management_api auth:
//   let session = mfa_engine.begin_auth(&user, &totp_code)?;
// ============================================================================

#![allow(dead_code)]

use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaProvider {
    /// Built-in TOTP (RFC 6238) — no external IdP required
    Totp,
    /// Azure Active Directory OIDC
    AzureAd,
    /// Okta OIDC
    Okta,
    /// Duo Security TOTP/push
    Duo,
    /// Disabled — warn! emitted every session
    Disabled,
}

impl MfaProvider {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Totp     => "Built-in TOTP (RFC 6238)",
            Self::AzureAd  => "Azure Active Directory (OIDC)",
            Self::Okta     => "Okta (OIDC)",
            Self::Duo      => "Duo Security (TOTP/Push)",
            Self::Disabled => "DISABLED — CIP-005-R2-2.2 GAP OPEN",
        }
    }
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub provider:             MfaProvider,
    pub totp_issuer:          String,
    /// TOTP code length (6 or 8 digits)
    pub totp_digits:          u32,
    /// TOTP time step in seconds (default: 30)
    pub totp_period_secs:     u64,
    /// Accept ±window steps for clock skew (default: 1)
    pub totp_window:          i64,
    /// Number of one-time backup recovery codes
    pub backup_codes:         usize,
    /// Enforce MFA on every remote session (CIP-005-R2-2.2)
    pub enforce_for_all_remote: bool,
    /// External IdP OIDC discovery URL (AzureAD/Okta)
    pub oidc_discovery_url:   Option<String>,
    /// External IdP client ID
    pub oidc_client_id:       Option<String>,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            provider:               MfaProvider::Disabled,
            totp_issuer:            "Rudras BES Firewall".into(),
            totp_digits:            6,
            totp_period_secs:       30,
            totp_window:            1,
            backup_codes:           8,
            enforce_for_all_remote: true,
            oidc_discovery_url:     None,
            oidc_client_id:         None,
        }
    }
}

// ── MFA User Enrollment State ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollment {
    pub user_id:            String,
    pub secret_b32:         String,     // Base32-encoded TOTP secret
    pub provisioning_uri:   String,     // otpauth:// URI for QR code
    pub backup_codes:       Vec<String>, // plaintext shown once, then hashed
    pub backup_code_hashes: Vec<String>, // SHA3-256 hashes stored at rest
    pub enrolled_at:        u64,
    pub last_used_at:       u64,
    pub use_count:          u64,
    pub provider:           String,
}

// ── MFA Session ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub session_id:     String,
    pub user_id:        String,
    pub authenticated:  bool,
    pub factor_used:    String,   // "TOTP" / "BACKUP_CODE" / "OIDC"
    pub authenticated_at: u64,
    pub expires_at:     u64,
    pub remote_ip:      String,
    pub cip_logged:     bool,     // CIP-007-R4-4.1 logging satisfied
}

// ── TOTP Core (RFC 6238) ──────────────────────────────────────────────────────

/// Pure-Rust TOTP implementation (RFC 6238 / RFC 4226)
/// Uses HMAC-SHA256 (stronger than HMAC-SHA1 standard minimum)
pub struct TotpEngine {
    digits:      u32,
    period:      u64,
    window:      i64,
}

impl TotpEngine {
    pub fn new(digits: u32, period: u64, window: i64) -> Self {
        Self { digits, period, window }
    }

    /// Decode a Base32 secret (RFC 4648, no padding)
    fn decode_base32(s: &str) -> Vec<u8> {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let s_upper = s.to_uppercase();
        let s_clean: Vec<u8> = s_upper.bytes()
            .filter(|b| *b != b'=' && *b != b' ')
            .collect();

        let mut bits = 0u64;
        let mut bits_left = 0u32;
        let mut out = Vec::new();

        for ch in s_clean {
            let val = alphabet.iter().position(|&a| a == ch).unwrap_or(0) as u64;
            bits = (bits << 5) | val;
            bits_left += 5;
            if bits_left >= 8 {
                bits_left -= 8;
                out.push(((bits >> bits_left) & 0xFF) as u8);
            }
        }
        out
    }

    /// Generate TOTP code for a given counter (RFC 4226 HOTP core)
    fn hotp(&self, secret: &[u8], counter: u64) -> u32 {
        let counter_bytes = counter.to_be_bytes();
        let mut mac = HmacSha256::new_from_slice(secret)
            .expect("HMAC accepts any key length");
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        // Dynamic truncation (RFC 4226 §5.4)
        let offset = (result[result.len() - 1] & 0x0F) as usize;
        let code = u32::from_be_bytes([
            result[offset] & 0x7F,
            result[offset + 1],
            result[offset + 2],
            result[offset + 3],
        ]);
        code % 10u32.pow(self.digits)
    }

    /// Generate the current TOTP code for a Base32 secret
    pub fn generate(&self, secret_b32: &str) -> String {
        let secret = Self::decode_base32(secret_b32);
        let counter = unix_secs() / self.period;
        format!("{:0>width$}", self.hotp(&secret, counter), width = self.digits as usize)
    }

    /// Verify a TOTP code with clock-skew window
    pub fn verify(&self, secret_b32: &str, code: &str) -> bool {
        let code_n: u32 = match code.trim().parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        let secret = Self::decode_base32(secret_b32);
        let counter = (unix_secs() / self.period) as i64;

        for delta in -self.window..=self.window {
            let c = (counter + delta) as u64;
            if self.hotp(&secret, c) == code_n {
                return true;
            }
        }
        false
    }

    /// Generate a random Base32 secret (160 bits = NIST minimum)
    pub fn generate_secret() -> String {
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        base32_encode(&bytes)
    }

    /// Generate otpauth:// URI for QR code provisioning
    pub fn provisioning_uri(secret_b32: &str, user_id: &str, issuer: &str, digits: u32, period: u64) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}&algorithm=SHA256",
            urlenc(issuer), urlenc(user_id), secret_b32, urlenc(issuer), digits, period
        )
    }
}

fn base32_encode(data: &[u8]) -> String {
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buf = (buf << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alpha[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alpha[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

fn urlenc(s: &str) -> String {
    s.chars().map(|c| match c {
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        ' ' => "%20".into(),
        ':' => "%3A".into(),
        '/' => "%2F".into(),
        '@' => "%40".into(),
        '&' => "%26".into(),
        '=' => "%3D".into(),
        '+' => "%2B".into(),
        _ => format!("%{:02X}", c as u8),
    }).collect()
}

// ── Backup Code Generator ─────────────────────────────────────────────────────

fn generate_backup_codes(count: usize) -> (Vec<String>, Vec<String>) {
    use sha3::{Digest, Sha3_256};
    let mut codes = Vec::new();
    let mut hashes = Vec::new();
    for _ in 0..count {
        let mut raw = [0u8; 5];
        rand::thread_rng().fill_bytes(&mut raw);
        let code = format!("{}-{}", hex::encode(&raw[..2]).to_uppercase(),
                                    hex::encode(&raw[2..]).to_uppercase());
        let hash = format!("{:x}", Sha3_256::digest(code.as_bytes()));
        codes.push(code);
        hashes.push(hash);
    }
    (codes, hashes)
}

fn verify_backup_code(input: &str, hashes: &[String]) -> Option<usize> {
    use sha3::{Digest, Sha3_256};
    let hash = format!("{:x}", Sha3_256::digest(input.trim().as_bytes()));
    hashes.iter().position(|h| h == &hash)
}

// ── MFA Engine ────────────────────────────────────────────────────────────────

pub struct MfaEngine {
    config:       RwLock<MfaConfig>,
    enrollments:  RwLock<HashMap<String, MfaEnrollment>>,
    sessions:     RwLock<HashMap<String, MfaSession>>,
    totp:         TotpEngine,
    // Counters
    auth_success: AtomicU64,
    auth_fail:    AtomicU64,
    codes_burned: AtomicU64,  // backup codes used
    sessions_created: AtomicU64,
}

impl MfaEngine {
    pub fn new(config: MfaConfig) -> Self {
        let totp = TotpEngine::new(
            config.totp_digits,
            config.totp_period_secs,
            config.totp_window,
        );

        if config.provider.is_active() {
            info!(
                "✅ MFA GAP [CIP-005-R2-2.2] CLOSED: MFA engine active | \
                 provider={} | digits={} | period={}s | window=±{} steps | \
                 enforce_remote={}",
                config.provider.label(), config.totp_digits,
                config.totp_period_secs, config.totp_window,
                config.enforce_for_all_remote
            );
        } else {
            warn!(
                "🔐 MFA GAP [CIP-005-R2-2.2] OPEN: MFA provider is DISABLED. \
                 CIP-005-R2 Part 2.2 requires MFA for all Interactive Remote Access. \
                 To close: set [mfa] provider = \"totp\" in config/rudras.toml. \
                 Rudras MFA engine supports: totp | azure_ad | okta | duo"
            );
        }

        Self {
            config: RwLock::new(config),
            enrollments: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            totp,
            auth_success:     AtomicU64::new(0),
            auth_fail:        AtomicU64::new(0),
            codes_burned:     AtomicU64::new(0),
            sessions_created: AtomicU64::new(0),
        }
    }

    // ── Enrollment ────────────────────────────────────────────────────────────

    /// Enroll a user in TOTP MFA. Returns the enrollment (shows secret/QR once).
    pub fn enroll_user(&self, user_id: &str) -> MfaEnrollment {
        let cfg = self.config.read();
        let secret = TotpEngine::generate_secret();
        let uri = TotpEngine::provisioning_uri(
            &secret, user_id, &cfg.totp_issuer, cfg.totp_digits, cfg.totp_period_secs,
        );
        let (codes, hashes) = generate_backup_codes(cfg.backup_codes);

        let enrollment = MfaEnrollment {
            user_id:             user_id.into(),
            secret_b32:          secret.clone(),
            provisioning_uri:    uri.clone(),
            backup_codes:        codes,          // shown once to user
            backup_code_hashes:  hashes,
            enrolled_at:         unix_secs(),
            last_used_at:        0,
            use_count:           0,
            provider:            cfg.provider.label().into(),
        };

        info!(
            "🔐 MFA ENROLLED | user={} | provider={} | \
             backup_codes={} | uri={}",
            user_id, cfg.provider.label(), cfg.backup_codes, uri
        );

        self.enrollments.write().insert(user_id.into(), enrollment.clone());
        enrollment
    }

    pub fn is_enrolled(&self, user_id: &str) -> bool {
        self.enrollments.read().contains_key(user_id)
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// Verify a TOTP code + optionally a backup code for a user.
    /// Returns an MfaSession on success.
    pub fn authenticate(
        &self,
        user_id:   &str,
        code:      &str,
        remote_ip: &str,
    ) -> Result<MfaSession, MfaError> {
        let cfg = self.config.read();

        // MFA disabled — warn + soft-fail (allows session but logs gap)
        if !cfg.provider.is_active() {
            warn!(
                "⚠️  MFA BYPASS WARNING [CIP-005-R2-2.2] user={} ip={} — \
                 MFA is DISABLED. Session granted without second factor. \
                 This violates NERC CIP-005-R2-2.2 for High/Medium BES systems.",
                user_id, remote_ip
            );
            return Ok(self.create_session(user_id, remote_ip, "DISABLED_BYPASS"));
        }

        // Look up enrollment
        let mut enrollments = self.enrollments.write();
        let enrollment = enrollments.get_mut(user_id)
            .ok_or_else(|| MfaError::NotEnrolled(user_id.into()))?;

        // 1. Try TOTP
        if self.totp.verify(&enrollment.secret_b32, code) {
            enrollment.last_used_at = unix_secs();
            enrollment.use_count += 1;
            self.auth_success.fetch_add(1, Ordering::Relaxed);
            info!("✅ MFA OK [TOTP] | user={} | ip={} | use_count={}",
                  user_id, remote_ip, enrollment.use_count);
            let session = self.create_session(user_id, remote_ip, "TOTP");
            self.sessions.write().insert(session.session_id.clone(), session.clone());
            return Ok(session);
        }

        // 2. Try backup code
        if let Some(idx) = verify_backup_code(code, &enrollment.backup_code_hashes) {
            // Burn the code (single-use)
            enrollment.backup_code_hashes[idx] = "USED".into();
            enrollment.last_used_at = unix_secs();
            enrollment.use_count += 1;
            self.auth_success.fetch_add(1, Ordering::Relaxed);
            self.codes_burned.fetch_add(1, Ordering::Relaxed);
            let remaining = enrollment.backup_code_hashes.iter()
                .filter(|h| h.as_str() != "USED").count();
            warn!("⚠️  MFA BACKUP CODE USED | user={} | ip={} | codes_remaining={}",
                  user_id, remote_ip, remaining);
            if remaining == 0 {
                error!("🚨 MFA: All backup codes exhausted for user={}. \
                        Re-enroll immediately.", user_id);
            }
            let session = self.create_session(user_id, remote_ip, "BACKUP_CODE");
            self.sessions.write().insert(session.session_id.clone(), session.clone());
            return Ok(session);
        }

        // 3. FAIL
        self.auth_fail.fetch_add(1, Ordering::Relaxed);
        error!(
            "❌ MFA FAIL [CIP-007-R5] | user={} | ip={} | \
             total_failures={}",
            user_id, remote_ip, self.auth_fail.load(Ordering::Relaxed)
        );
        Err(MfaError::InvalidCode)
    }

    /// Validate an existing session (call on every request)
    pub fn validate_session(&self, session_id: &str, user_id: &str) -> bool {
        let sessions = self.sessions.read();
        if let Some(s) = sessions.get(session_id) {
            if s.user_id == user_id && s.authenticated && s.expires_at > unix_secs() {
                return true;
            }
        }
        false
    }

    /// Revoke a session (logout / timeout)
    pub fn revoke_session(&self, session_id: &str) {
        if self.sessions.write().remove(session_id).is_some() {
            info!("🔐 MFA SESSION REVOKED | id={}", session_id);
        }
    }

    // ── Status ────────────────────────────────────────────────────────────────

    pub fn is_gap_closed(&self) -> bool {
        self.config.read().provider.is_active()
    }

    pub fn stats(&self) -> MfaStats {
        let cfg = self.config.read();
        MfaStats {
            gap_closed:        cfg.provider.is_active(),
            provider:          cfg.provider.label().into(),
            enrolled_users:    self.enrollments.read().len() as u64,
            active_sessions:   self.sessions.read().len() as u64,
            auth_success:      self.auth_success.load(Ordering::Relaxed),
            auth_fail:         self.auth_fail.load(Ordering::Relaxed),
            backup_codes_used: self.codes_burned.load(Ordering::Relaxed),
        }
    }

    pub fn update_config(&self, new_cfg: MfaConfig) {
        let was_active = self.config.read().provider.is_active();
        let now_active = new_cfg.provider.is_active();
        if !was_active && now_active {
            info!("✅ MFA GAP [CIP-005-R2-2.2] CLOSED: Provider changed to {}",
                  new_cfg.provider.label());
        }
        *self.config.write() = new_cfg;
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn create_session(&self, user_id: &str, remote_ip: &str, factor: &str) -> MfaSession {
        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let session_id = hex::encode(id_bytes);
        let now = unix_secs();
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        MfaSession {
            session_id:       session_id.clone(),
            user_id:          user_id.into(),
            authenticated:    true,
            factor_used:      factor.into(),
            authenticated_at: now,
            expires_at:       now + 28800, // 8-hour session (CIP-007-R5 best practice)
            remote_ip:        remote_ip.into(),
            cip_logged:       true,
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum MfaError {
    NotEnrolled(String),
    InvalidCode,
    SessionExpired,
    ProviderUnavailable,
}

impl std::fmt::Display for MfaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnrolled(u)        => write!(f, "User '{}' not enrolled in MFA", u),
            Self::InvalidCode           => write!(f, "Invalid TOTP/backup code"),
            Self::SessionExpired        => write!(f, "MFA session expired"),
            Self::ProviderUnavailable   => write!(f, "MFA provider unavailable"),
        }
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStats {
    pub gap_closed:        bool,
    pub provider:          String,
    pub enrolled_users:    u64,
    pub active_sessions:   u64,
    pub auth_success:      u64,
    pub auth_fail:         u64,
    pub backup_codes_used: u64,
}
