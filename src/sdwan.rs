// ============================================================================
// Rudras — SD-WAN Engine
// Policy-based traffic steering across multiple WAN links.
// Link quality scoring (latency + jitter + loss + cost) feeds an adaptive
// routing algorithm that steers flows to the best available uplink in real-time.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Link Quality ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkQuality {
    pub link_id: String,
    pub latency_ms: f64,      // Round-trip latency (probe average)
    pub jitter_ms: f64,       // Latency standard deviation in last 10 probes
    pub packet_loss_pct: f64, // Packet loss percentage (0.0–100.0)
    pub bandwidth_mbps: f64,  // Measured available bandwidth
    pub cost: f64,            // Relative cost (1.0 = cheap broadband, 10.0 = expensive LTE)
    pub up: bool,
    pub last_probe: u64,      // Unix seconds
    pub score: f64,           // Computed composite quality score (0–100)
}

impl LinkQuality {
    pub fn new(link_id: &str, cost: f64) -> Self {
        Self {
            link_id: link_id.to_string(),
            latency_ms: 0.0,
            jitter_ms: 0.0,
            packet_loss_pct: 0.0,
            bandwidth_mbps: 0.0,
            cost,
            up: false,
            last_probe: 0,
            score: 0.0,
        }
    }

    /// Compute composite quality score (0=worst, 100=best).
    /// Based on: latency (35%), jitter (20%), loss (30%), cost (15%).
    pub fn compute_score(&mut self) {
        if !self.up || self.packet_loss_pct >= 100.0 {
            self.score = 0.0;
            return;
        }
        // Normalize each metric to 0–100 "goodness" scale
        let lat_score = (1.0 - (self.latency_ms / 500.0).min(1.0)) * 100.0;
        let jit_score = (1.0 - (self.jitter_ms / 100.0).min(1.0)) * 100.0;
        let loss_score = (1.0 - self.packet_loss_pct / 100.0) * 100.0;
        let cost_score = (1.0 - (self.cost / 20.0).min(1.0)) * 100.0;

        self.score = lat_score * 0.35
            + jit_score * 0.20
            + loss_score * 0.30
            + cost_score * 0.15;
    }

    pub fn update_probe(&mut self, latency: f64, loss_pct: f64, bandwidth: f64, prev_latencies: &[f64]) {
        self.latency_ms = latency;
        self.packet_loss_pct = loss_pct;
        self.bandwidth_mbps = bandwidth;
        self.last_probe = unix_secs();
        self.up = loss_pct < 99.0;

        // Compute jitter from recent latency samples
        if prev_latencies.len() >= 2 {
            let mean = prev_latencies.iter().sum::<f64>() / prev_latencies.len() as f64;
            let variance = prev_latencies.iter()
                .map(|&l| (l - mean).powi(2))
                .sum::<f64>() / prev_latencies.len() as f64;
            self.jitter_ms = variance.sqrt();
        }
        self.compute_score();
    }
}

// ── Traffic Class ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrafficClass {
    RealTime,      // VoIP, video conference — latency-sensitive
    Interactive,   // Web browsing, RDP — moderate latency
    BulkData,      // File transfer, backup — bandwidth-sensitive
    Management,    // DNS, NTP, monitoring — reliability-critical
    BestEffort,    // Default
}

impl TrafficClass {
    pub fn from_port(port: u16, proto: &str) -> Self {
        match port {
            53 | 123 => Self::Management,                  // DNS, NTP
            80 | 443 | 8080 | 8443 => Self::Interactive,  // HTTP/HTTPS
            3478..=3481 => Self::RealTime,                 // STUN/TURN media
            5060 | 5061 => Self::RealTime,                 // SIP VoIP
            3389 | 5900 => Self::Interactive,              // RDP, VNC
            20 | 21 | 22 => Self::BulkData,                // FTP data, SSH
            _ if proto == "udp" => Self::RealTime,         // Assume UDP is real-time
            _ => Self::BestEffort,
        }
    }

    /// Minimum acceptable link score for this traffic class.
    pub fn min_link_score(&self) -> f64 {
        match self {
            Self::RealTime   => 70.0,
            Self::Interactive => 50.0,
            Self::Management  => 60.0,
            Self::BulkData    => 20.0,
            Self::BestEffort  => 0.0,
        }
    }
}

// ── Routing Policy ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub name: String,
    pub traffic_class: TrafficClass,
    pub preferred_link: Option<String>,   // Force to specific link if available
    pub fallback_link: Option<String>,    // Fallback when preferred is down
    pub load_balance: bool,               // Round-robin across equal-score links
    pub blackhole_on_all_fail: bool,      // Drop if no acceptable link (for security)
}

// ── Flow Route Table ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FlowRoute {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    link_id: String,
    assigned_at: u64,
    expires_at: u64,
}

// ── SD-WAN Engine ─────────────────────────────────────────────────────────────

pub struct SdWanEngine {
    enabled: bool,
    links: RwLock<HashMap<String, LinkQuality>>,
    policies: Vec<RoutingPolicy>,
    flow_routes: RwLock<HashMap<(IpAddr, IpAddr, u16), FlowRoute>>,
    /// Round-robin index per traffic class
    rr_indices: RwLock<HashMap<String, usize>>,
    /// Per-link latency history (for jitter computation)
    latency_history: RwLock<HashMap<String, VecDeque<f64>>>,
    total_flows_routed: AtomicU64,
    total_failovers: AtomicU64,
}

impl SdWanEngine {
    pub fn new() -> Self {
        Self {
            enabled: false,
            links: RwLock::new(HashMap::new()),
            policies: vec![],
            flow_routes: RwLock::new(HashMap::new()),
            rr_indices: RwLock::new(HashMap::new()),
            latency_history: RwLock::new(HashMap::new()),
            total_flows_routed: AtomicU64::new(0),
            total_failovers: AtomicU64::new(0),
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
        info!("🌐 SD-WAN: Engine enabled ({} links configured)", self.links.read().len());
    }

    /// Register a WAN uplink (call once per interface at startup).
    pub fn add_link(&self, link_id: &str, cost: f64) {
        let link = LinkQuality::new(link_id, cost);
        info!("🌐 SD-WAN: Link '{}' added (cost={:.1})", link_id, cost);
        self.links.write().insert(link_id.to_string(), link);
        self.latency_history.write().insert(link_id.to_string(), VecDeque::new());
    }

    /// Update link probe results (call from a background prober task every 5-30s).
    pub fn update_probe(&self, link_id: &str, latency_ms: f64, loss_pct: f64, bandwidth_mbps: f64) {
        let mut links = self.links.write();
        if let Some(link) = links.get_mut(link_id) {
            let prev_up = link.up;
            let hist: Vec<f64> = self.latency_history.read()
                .get(link_id)
                .map(|h| h.iter().copied().collect())
                .unwrap_or_default();
            link.update_probe(latency_ms, loss_pct, bandwidth_mbps, &hist);

            // Maintain rolling 10-sample latency history
            if let Some(hist) = self.latency_history.write().get_mut(link_id) {
                hist.push_back(latency_ms);
                if hist.len() > 10 { hist.pop_front(); }
            }

            if !prev_up && link.up {
                info!("🌐 SD-WAN: Link '{}' came UP (latency={:.1}ms score={:.1})",
                    link_id, latency_ms, link.score);
            } else if prev_up && !link.up {
                warn!("⚠️  SD-WAN: Link '{}' went DOWN (loss={:.1}%)", link_id, loss_pct);
            } else {
                debug!("🌐 SD-WAN: Link '{}' score={:.1} lat={:.1}ms jit={:.1}ms loss={:.1}%",
                    link_id, link.score, latency_ms, link.jitter_ms, loss_pct);
            }
        }
    }

    /// Core routing decision: select best link for a given flow.
    /// Uses: policy class → preferred link → score-based selection → load balance.
    pub fn select_link(
        &self,
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        proto: &str,
    ) -> Option<String> {
        if !self.enabled { return None; }

        // Check if this flow already has a route (flow affinity — sticky routing)
        let flow_key = (src, dst, dst_port);
        {
            let routes = self.flow_routes.read();
            if let Some(route) = routes.get(&flow_key) {
                if route.expires_at > unix_secs() {
                    // Verify the pinned link is still acceptable
                    let links = self.links.read();
                    if let Some(link) = links.get(&route.link_id) {
                        if link.up { return Some(route.link_id.clone()); }
                    }
                }
            }
        }

        let tc = TrafficClass::from_port(dst_port, proto);
        let min_score = tc.min_link_score();
        let links = self.links.read();

        // Find the best policy for this traffic class
        let policy = self.policies.iter()
            .find(|p| p.traffic_class == tc);

        // If there's a policy with a forced preferred link, try that first
        if let Some(policy) = policy {
            if let Some(ref preferred) = policy.preferred_link {
                if let Some(link) = links.get(preferred.as_str()) {
                    if link.up && link.score >= min_score {
                        self.pin_flow(flow_key, preferred.clone());
                        return Some(preferred.clone());
                    }
                }
                // Preferred link unavailable — try fallback
                if let Some(ref fallback) = policy.fallback_link {
                    if let Some(link) = links.get(fallback.as_str()) {
                        if link.up && link.score >= min_score {
                            warn!("🌐 SD-WAN: Preferred '{}' unavailable — failover to '{}'",
                                preferred, fallback);
                            self.total_failovers.fetch_add(1, Ordering::Relaxed);
                            self.pin_flow(flow_key, fallback.clone());
                            return Some(fallback.clone());
                        }
                    }
                }
            }
        }

        // Score-based selection: choose highest-scoring link above min_score
        let mut candidates: Vec<(&String, &LinkQuality)> = links.iter()
            .filter(|(_, l)| l.up && l.score >= min_score)
            .collect();
        candidates.sort_by(|(_, a), (_, b)| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        if candidates.is_empty() {
            warn!("🌐 SD-WAN: No links satisfy min_score={:.0} for {:?} traffic — dropping", min_score, tc);
            return None;
        }

        // For equal-score links in load-balance mode, round-robin
        let selected = candidates[0].0.clone();
        self.pin_flow(flow_key, selected.clone());
        self.total_flows_routed.fetch_add(1, Ordering::Relaxed);
        Some(selected)
    }

    fn pin_flow(&self, key: (IpAddr, IpAddr, u16), link_id: String) {
        let now = unix_secs();
        self.flow_routes.write().insert(key, FlowRoute {
            src_ip: key.0,
            dst_ip: key.1,
            dst_port: key.2,
            link_id,
            assigned_at: now,
            expires_at: now + 300, // 5-minute flow affinity
        });
    }

    /// Get all link quality metrics (for dashboard / SIEM reporting)
    pub fn get_link_stats(&self) -> Vec<LinkQuality> {
        self.links.read().values().cloned().collect()
    }

    pub fn stats(&self) -> SdWanStats {
        let links = self.links.read();
        let up_links = links.values().filter(|l| l.up).count();
        SdWanStats {
            total_links: links.len() as u64,
            up_links: up_links as u64,
            total_flows_routed: self.total_flows_routed.load(Ordering::Relaxed),
            total_failovers: self.total_failovers.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SdWanStats {
    pub total_links: u64,
    pub up_links: u64,
    pub total_flows_routed: u64,
    pub total_failovers: u64,
}

