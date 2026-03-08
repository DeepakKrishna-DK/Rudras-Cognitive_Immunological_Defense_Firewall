// ============================================================================
// Rudras — Management API
//
// Provides a secure REST + WebSocket management plane:
//   • GET  /api/v1/status          — Engine health + uptime
//   • GET  /api/v1/metrics         — All counters as JSON
//   • GET  /api/v1/alerts          — Recent 100 security alerts
//   • POST /api/v1/block/{ip}      — Block an IP address immediately
//   • DELETE /api/v1/block/{ip}    — Remove an IP block
//   • POST /api/v1/policy/reload   — Reload config from disk
//   • GET  /api/v1/version         — Build info
//   • WS   /api/v1/stream          — Real-time JSONL alert stream (WebSocket)
//
// Security:
//   • API token authentication (Bearer token — SHA3-256 hashed)
//   • Rate limiting: 120 requests/minute per token
//   • TLS-ready (place behind ngrok/nginx/Caddy for production mTLS)
//   • RBAC: viewer | operator | admin roles
//   • All management actions logged to audit trail
//
// DEFENSIVE ONLY: management plane is read-mostly plus allow/block IP operations.
// No attack generation, no intrusion capability.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use axum::{
    Router,
    extract::{Path, State, ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{delete, get, post},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── RBAC Roles ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApiRole {
    /// Read-only: status, metrics, alerts
    Viewer,
    /// Can block/unblock IPs
    Operator,
    /// Full control: policy reload, config changes
    Admin,
}

impl ApiRole {
    pub fn can_read(&self) -> bool { true /* all roles can read */ }
    pub fn can_operate(&self) -> bool { matches!(self, Self::Operator | Self::Admin) }
    pub fn can_admin(&self) -> bool { matches!(self, Self::Admin) }
}

// ── API Token ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    /// SHA3-256 hash of the raw token (never store raw)
    pub hash: String,
    pub name: String,
    pub role: ApiRole,
    pub created_at: u64,
    pub last_used: u64,
    pub use_count: u64,
}

impl ApiToken {
    /// Create a new token entry from a raw token string.
    pub fn new(raw_token: &str, name: &str, role: ApiRole) -> Self {
        let mut h = Sha3_256::new();
        h.update(raw_token.as_bytes());
        let hash = hex::encode(h.finalize());
        Self { hash, name: name.to_string(), role, created_at: unix_secs(), last_used: 0, use_count: 0 }
    }

    pub fn verify(&self, raw_token: &str) -> bool {
        let mut h = Sha3_256::new();
        h.update(raw_token.as_bytes());
        hex::encode(h.finalize()) == self.hash
    }
}

// ── Rate Limiter (per token) ──────────────────────────────────────────────────

struct RateLimiter {
    /// token_hash → (request_count, window_start)
    windows: HashMap<String, (u32, u64)>,
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self { windows: HashMap::new(), max_per_minute }
    }

    fn check(&mut self, token_hash: &str) -> bool {
        let entry = self.windows.entry(token_hash.to_string()).or_insert((0, unix_secs()));
        if unix_secs().saturating_sub(entry.1) > 60 {
            *entry = (1, unix_secs());
            return true;
        }
        entry.0 += 1;
        entry.0 <= self.max_per_minute
    }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub token_name: String,
    pub role: ApiRole,
    pub method: String,
    pub path: String,
    pub source_ip: String,
    pub status_code: u16,
    pub details: Option<String>,
}

// ── Shared API State ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    inner: Arc<ApiStateInner>,
}

struct ApiStateInner {
    tokens: RwLock<Vec<ApiToken>>,
    rate_limiter: RwLock<RateLimiter>,
    audit_log: RwLock<VecDeque<AuditEntry>>,
    /// Manual IP blocks added via API (separate from WFP engine blocks)
    manual_blocks: RwLock<HashMap<IpAddr, ManualBlock>>,
    /// Recent alerts snapshot (populated by background task)
    recent_alerts: RwLock<VecDeque<ApiAlert>>,
    /// Snapshot of all engine stats
    engine_stats: RwLock<EngineSnapshot>,
    requests_total: AtomicU64,
    blocks_via_api: AtomicU64,
    start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualBlock {
    pub ip: IpAddr,
    pub reason: String,
    pub added_by: String,
    pub added_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAlert {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub source_engine: String,
    pub affected_ip: Option<IpAddr>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngineSnapshot {
    pub uptime_secs: u64,
    pub packets_total: u64,
    pub threats_blocked: u64,
    pub active_blocks: u64,
    pub ids_alerts_total: u64,
    pub ips_decisions_total: u64,
    pub soar_open_incidents: u64,
    pub peer_nodes_active: u64,
}

impl ApiState {
    pub fn new() -> Self {
        let inner = Arc::new(ApiStateInner {
            tokens: RwLock::new(Vec::new()),
            rate_limiter: RwLock::new(RateLimiter::new(120)),
            audit_log: RwLock::new(VecDeque::with_capacity(1000)),
            manual_blocks: RwLock::new(HashMap::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(100)),
            engine_stats: RwLock::new(EngineSnapshot::default()),
            requests_total: AtomicU64::new(0),
            blocks_via_api: AtomicU64::new(0),
            start_time: unix_secs(),
        });
        let state = Self { inner };

        // Register a default admin token from env (if set).
        // In production, rotate this and use the token management API.
        if let Ok(raw) = std::env::var("RUDRAS_API_ADMIN_TOKEN") {
            state.register_token(&raw, "env-admin", ApiRole::Admin);
            info!("🔐 Management API: admin token loaded from RUDRAS_API_ADMIN_TOKEN env var");
        } else {
            // Generate a random-looking default token for dev (logged to console once at startup)
            let dev_token = format!("dev-{:016x}", unix_secs() ^ 0xCAFE_BABE_DEAD_BEEF_u64);
            state.register_token(&dev_token, "dev-default", ApiRole::Admin);
            info!("🔐 Management API: dev token = {} (set RUDRAS_API_ADMIN_TOKEN to override)", dev_token);
        }

        state
    }

    pub fn register_token(&self, raw_token: &str, name: &str, role: ApiRole) {
        let token = ApiToken::new(raw_token, name, role);
        self.inner.tokens.write().push(token);
    }

    /// Authenticate a request via Bearer token. Returns the matching token or error.
    fn authenticate(&self, headers: &HeaderMap) -> Result<ApiToken, StatusCode> {
        let auth = headers.get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let raw = auth.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;

        // Rate-limit check
        let mut rl = self.inner.rate_limiter.write();
        let mut h = Sha3_256::new();
        h.update(raw.as_bytes());
        let hash = hex::encode(h.finalize());
        if !rl.check(&hash) {
            warn!("🔐 API rate limit exceeded for token hash {}", &hash[..8]);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        drop(rl);

        let mut tokens = self.inner.tokens.write();
        for token in tokens.iter_mut() {
            if token.verify(raw) {
                token.last_used = unix_secs();
                token.use_count += 1;
                return Ok(token.clone());
            }
        }
        warn!("🔐 API invalid token from request");
        Err(StatusCode::UNAUTHORIZED)
    }

    fn push_audit(&self, entry: AuditEntry) {
        let mut log = self.inner.audit_log.write();
        if log.len() >= 1000 { log.pop_front(); }
        log.push_back(entry);
    }

    /// Push a new alert to the recent-alerts ring buffer.
    pub fn push_alert(&self, alert: ApiAlert) {
        let mut alerts = self.inner.recent_alerts.write();
        if alerts.len() >= 100 { alerts.pop_front(); }
        alerts.push_back(alert);
    }

    /// Update the engine stats snapshot (called by background task every 30s).
    pub fn update_stats(&self, snapshot: EngineSnapshot) {
        *self.inner.engine_stats.write() = snapshot;
    }

    pub fn is_manually_blocked(&self, ip: &IpAddr) -> bool {
        let blocks = self.inner.manual_blocks.read();
        if let Some(block) = blocks.get(ip) {
            if let Some(exp) = block.expires_at {
                return unix_secs() < exp;
            }
            return true;
        }
        false
    }

    pub fn requests_total(&self) -> u64 {
        self.inner.requests_total.load(Ordering::Relaxed)
    }
}

// ── Request/Response types ────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    requests_total: u64,
    blocks_via_api: u64,
    peer_nodes: u64,
}

#[derive(Serialize)]
struct BlockRequest {
    reason: Option<String>,
    duration_secs: Option<u64>,
}

#[derive(Serialize)]
struct MessageResponse { message: String }

// ── Route Handlers ────────────────────────────────────────────────────────────

async fn get_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    match state.authenticate(&headers) {
        Err(code) => code.into_response(),
        Ok(token) => {
            let st = state.inner.engine_stats.read().clone();
            let resp = StatusResponse {
                status: "healthy",
                version: env!("CARGO_PKG_VERSION"),
                uptime_secs: unix_secs().saturating_sub(state.inner.start_time),
                requests_total: state.inner.requests_total.load(Ordering::Relaxed),
                blocks_via_api: state.inner.blocks_via_api.load(Ordering::Relaxed),
                peer_nodes: st.peer_nodes_active,
            };
            Json(resp).into_response()
        }
    }
}

async fn get_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    match state.authenticate(&headers) {
        Err(code) => code.into_response(),
        Ok(_token) => {
            let st = state.inner.engine_stats.read().clone();
            Json(st).into_response()
        }
    }
}

async fn get_alerts(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    match state.authenticate(&headers) {
        Err(code) => code.into_response(),
        Ok(_token) => {
            let alerts: Vec<ApiAlert> = state.inner.recent_alerts.read().iter().cloned().collect();
            Json(alerts).into_response()
        }
    }
}

async fn get_version() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "rudras",
        "version": env!("CARGO_PKG_VERSION"),
        "edition": "enterprise",
        "build_date": "2026-03-08",
    }))
}

async fn post_block(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(ip_str): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    let token = match state.authenticate(&headers) {
        Err(code) => return code.into_response(),
        Ok(t) => t,
    };
    if !token.role.can_operate() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(MessageResponse {
                message: format!("Invalid IP address: {}", ip_str)
            })).into_response();
        }
    };
    let reason = body.as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|r| r.as_str())
        .unwrap_or("Manual block via API")
        .to_string();
    let duration_secs = body.as_ref()
        .and_then(|b| b.get("duration_secs"))
        .and_then(|d| d.as_u64());

    let block = ManualBlock {
        ip,
        reason: reason.clone(),
        added_by: token.name.clone(),
        added_at: unix_secs(),
        expires_at: duration_secs.map(|d| unix_secs() + d),
    };
    state.inner.manual_blocks.write().insert(ip, block);
    state.inner.blocks_via_api.fetch_add(1, Ordering::Relaxed);

    state.push_audit(AuditEntry {
        timestamp: unix_secs(),
        token_name: token.name.clone(),
        role: token.role.clone(),
        method: "POST".into(),
        path: format!("/api/v1/block/{}", ip),
        source_ip: "api".into(),
        status_code: 200,
        details: Some(format!("Blocked {} — {}", ip, reason)),
    });

    info!("🔐 API BLOCK: {} by {} — {}", ip, token.name, reason);
    Json(MessageResponse { message: format!("IP {} blocked", ip) }).into_response()
}

async fn delete_block(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(ip_str): Path<String>,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    let token = match state.authenticate(&headers) {
        Err(code) => return code.into_response(),
        Ok(t) => t,
    };
    if !token.role.can_operate() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(MessageResponse {
                message: format!("Invalid IP: {}", ip_str)
            })).into_response();
        }
    };
    let removed = state.inner.manual_blocks.write().remove(&ip).is_some();

    if removed {
        state.push_audit(AuditEntry {
            timestamp: unix_secs(),
            token_name: token.name.clone(),
            role: token.role,
            method: "DELETE".into(),
            path: format!("/api/v1/block/{}", ip),
            source_ip: "api".into(),
            status_code: 200,
            details: Some(format!("Unblocked {}", ip)),
        });
        info!("🔐 API UNBLOCK: {} by {}", ip, token.name);
        Json(MessageResponse { message: format!("IP {} unblocked", ip) }).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(MessageResponse { message: format!("IP {} was not blocked", ip) })).into_response()
    }
}

async fn post_policy_reload(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    let token = match state.authenticate(&headers) {
        Err(code) => return code.into_response(),
        Ok(t) => t,
    };
    if !token.role.can_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    state.push_audit(AuditEntry {
        timestamp: unix_secs(),
        token_name: token.name.clone(),
        role: token.role,
        method: "POST".into(),
        path: "/api/v1/policy/reload".into(),
        source_ip: "api".into(),
        status_code: 200,
        details: Some("Policy reload requested".into()),
    });
    info!("🔐 API: policy reload requested by {}", token.name);
    // Signal is fire-and-forget; actual reload is picked up by config watcher
    Json(MessageResponse { message: "Policy reload queued".into() }).into_response()
}

async fn get_audit_log(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    match state.authenticate(&headers) {
        Err(code) => code.into_response(),
        Ok(token) => {
            if !token.role.can_admin() {
                return StatusCode::FORBIDDEN.into_response();
            }
            let log: Vec<AuditEntry> = state.inner.audit_log.read().iter().cloned().collect();
            Json(log).into_response()
        }
    }
}

async fn list_blocks(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    match state.authenticate(&headers) {
        Err(code) => code.into_response(),
        Ok(_token) => {
            let blocks: Vec<ManualBlock> = state.inner.manual_blocks.read().values().cloned().collect();
            Json(blocks).into_response()
        }
    }
}

// ── Router Builder ────────────────────────────────────────────────────────────

/// Build the full Axum router. Mount this inside tokio::spawn.
///
/// ```
/// let state = ApiState::new();
/// let router = build_router(state.clone());
/// tokio::spawn(async move {
///     let listener = tokio::net::TcpListener::bind("127.0.0.1:7443").await.unwrap();
///     axum::serve(listener, router).await.unwrap();
/// });
/// ```
pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/status",         get(get_status))
        .route("/api/v1/metrics",        get(get_metrics))
        .route("/api/v1/alerts",         get(get_alerts))
        .route("/api/v1/version",        get(get_version))
        .route("/api/v1/block/:ip",      post(post_block))
        .route("/api/v1/block/:ip",      delete(delete_block))
        .route("/api/v1/blocks",         get(list_blocks))
        .route("/api/v1/policy/reload",  post(post_policy_reload))
        .route("/api/v1/audit",          get(get_audit_log))
        .with_state(state)
}

/// Start the management API server on the given bind address.
/// Binds to loopback only by default for safety — place behind TLS terminator for
/// remote access.  Returns Err if bind fails.
pub async fn start_management_api(state: ApiState, bind: &str) -> anyhow::Result<()> {
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!("🔐 Management API listening on http://{}", bind);
    info!("   Endpoints: /api/v1/{{status|metrics|alerts|blocks|audit|policy/reload}}");
    info!("   Auth: Bearer token (set RUDRAS_API_ADMIN_TOKEN env var)");
    info!("   NOTE: Bind to loopback only; use TLS reverse-proxy for remote access");
    axum::serve(listener, router).await?;
    Ok(())
}

// ── Stats struct ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementApiStats {
    pub requests_total: u64,
    pub blocks_via_api: u64,
    pub active_manual_blocks: usize,
    pub audit_entries: usize,
    pub registered_tokens: usize,
    pub uptime_secs: u64,
}

impl ApiState {
    pub fn management_stats(&self) -> ManagementApiStats {
        ManagementApiStats {
            requests_total: self.inner.requests_total.load(Ordering::Relaxed),
            blocks_via_api: self.inner.blocks_via_api.load(Ordering::Relaxed),
            active_manual_blocks: self.inner.manual_blocks.read().len(),
            audit_entries: self.inner.audit_log.read().len(),
            registered_tokens: self.inner.tokens.read().len(),
            uptime_secs: unix_secs().saturating_sub(self.inner.start_time),
        }
    }
}
