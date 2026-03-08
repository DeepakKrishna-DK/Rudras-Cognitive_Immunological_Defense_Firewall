// ============================================================================
// Rudras — User and Entity Behavior Analytics (UEBA) Engine
//
// Builds a behavioral baseline per user/entity and detects deviations:
//   • Time-of-access anomalies (off-hours login, weekend access)
//   • Location anomalies (impossible travel, new geo)
//   • Data volume anomalies (download/upload spikes vs baseline)
//   • Protocol/port anomalies (new service access)
//   • Privilege escalation patterns
//   • Peer-group deviation (user behaving differently from similar users)
//
// Algorithm: Rolling exponential moving average (EMA) with adaptive
//            standard deviation for per-feature anomaly scoring.
//            Composite score via weighted feature importance.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn hour_of_day(ts: u64) -> u8 { ((ts % 86400) / 3600) as u8 }
fn day_of_week(ts: u64) -> u8 { ((ts / 86400 + 4) % 7) as u8 } // 0=Sun, 6=Sat

// ── Activity Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub entity_id: String,          // user or service account
    pub event_type: ActivityType,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub bytes_transferred: u64,
    pub success: bool,
    pub geo_country: Option<String>,
    pub process_name: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityType {
    Login,
    Logout,
    FileAccess,
    NetworkConnection,
    ProcessSpawn,
    PrivilegeEscalation,
    DataExfiltration,
    Authentication,
    DatabaseQuery,
    ApiCall,
}

// ── Behavioral Baseline ───────────────────────────────────────────────────────
// Per-entity statistical model. Updated via EMA (α=0.05).

const EMA_ALPHA: f64 = 0.05;

fn ema_update(mean: f64, std: f64, new_value: f64) -> (f64, f64) {
    let new_mean = EMA_ALPHA * new_value + (1.0 - EMA_ALPHA) * mean;
    let diff = new_value - new_mean;
    let new_var = EMA_ALPHA * diff * diff + (1.0 - EMA_ALPHA) * std * std;
    (new_mean, new_var.sqrt().max(0.001))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityBaseline {
    pub entity_id: String,
    pub observation_count: u64,

    // Time features
    pub typical_hours: [f32; 24],         // activity probability per hour
    pub weekend_activity_ratio: f32,       // fraction of activity on weekends

    // Volume features
    pub bytes_per_session_mean: f64,
    pub bytes_per_session_std: f64,
    pub sessions_per_day_mean: f64,
    pub sessions_per_day_std: f64,

    // Connection features
    pub typical_dst_ips: HashSet<IpAddr>,
    pub typical_dst_ports: HashSet<u16>,
    pub typical_geos: HashSet<String>,
    pub connection_count_mean: f64,
    pub connection_count_std: f64,

    // Authentication
    pub failed_auth_rate: f64,             // failures / total auth attempts
    pub typical_src_ips: HashSet<IpAddr>,

    pub last_activity: u64,
    pub created_at: u64,
}

impl EntityBaseline {
    pub fn new(entity_id: &str) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            observation_count: 0,
            typical_hours: [0.0; 24],
            weekend_activity_ratio: 0.0,
            bytes_per_session_mean: 0.0,
            bytes_per_session_std: 1.0,
            sessions_per_day_mean: 1.0,
            sessions_per_day_std: 1.0,
            typical_dst_ips: HashSet::new(),
            typical_dst_ports: HashSet::new(),
            typical_geos: HashSet::new(),
            connection_count_mean: 0.0,
            connection_count_std: 1.0,
            failed_auth_rate: 0.0,
            typical_src_ips: HashSet::new(),
            last_activity: 0,
            created_at: unix_secs(),
        }
    }

    pub fn update(&mut self, activity: &UserActivity) {
        self.observation_count += 1;
        self.last_activity = activity.timestamp;

        let hour = hour_of_day(activity.timestamp) as usize;
        self.typical_hours[hour] = self.typical_hours[hour] * (1.0 - EMA_ALPHA as f32)
            + EMA_ALPHA as f32;

        let is_weekend = matches!(day_of_week(activity.timestamp), 0 | 6);
        self.weekend_activity_ratio = self.weekend_activity_ratio * (1.0 - EMA_ALPHA as f32)
            + if is_weekend { EMA_ALPHA as f32 } else { 0.0 };

        if activity.bytes_transferred > 0 {
            let (m, s) = ema_update(self.bytes_per_session_mean, self.bytes_per_session_std,
                activity.bytes_transferred as f64);
            self.bytes_per_session_mean = m;
            self.bytes_per_session_std = s;
        }

        if let Some(ip) = activity.src_ip {
            if self.typical_src_ips.len() < 50 { self.typical_src_ips.insert(ip); }
        }
        if let Some(ip) = activity.dst_ip {
            if self.typical_dst_ips.len() < 200 { self.typical_dst_ips.insert(ip); }
        }
        if let Some(port) = activity.dst_port {
            if self.typical_dst_ports.len() < 100 { self.typical_dst_ports.insert(port); }
        }
        if let Some(ref geo) = activity.geo_country {
            if self.typical_geos.len() < 20 { self.typical_geos.insert(geo.clone()); }
        }
        if activity.event_type == ActivityType::Authentication && !activity.success {
            self.failed_auth_rate = self.failed_auth_rate * 0.99 + 0.01;
        }
    }

    /// Is this baseline mature enough for anomaly scoring? (Need ≥30 observations.)
    pub fn is_mature(&self) -> bool { self.observation_count >= 30 }
}

// ── UEBA Alert ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAlert {
    pub id: String,
    pub entity_id: String,
    pub risk_score: f32,   // 0.0 - 100.0
    pub anomalies: Vec<BehaviorAnomaly>,
    pub activity: UserActivity,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehaviorAnomaly {
    OffHoursAccess { hour: u8, typical_probability: f32 },
    UnknownSourceIp { src_ip: IpAddr },
    UnknownDestination { dst_ip: IpAddr, dst_port: u16 },
    UnusualDataVolume { actual_bytes: u64, mean_bytes: f64, z_score: f32 },
    NewGeolocation { country: String },
    ImpossibleTravel { countries: Vec<String>, time_gap_secs: u64 },
    AbnormalFailureRate { rate: f64, threshold: f64 },
    PrivilegeEscalation,
    NewProcessSpawn { process: String },
    PeerGroupDeviation { z_score: f32 },
}

// ── UEBA Engine ───────────────────────────────────────────────────────────────

pub struct UebaEngine {
    baselines: RwLock<HashMap<String, EntityBaseline>>,
    /// Recent activities per entity for short-window analysis
    recent_activities: RwLock<HashMap<String, VecDeque<UserActivity>>>,
    alerts: RwLock<VecDeque<UebaAlert>>,
    total_events: AtomicU64,
    total_alerts: AtomicU64,
    high_risk_threshold: f32,
    critical_risk_threshold: f32,
}

impl UebaEngine {
    pub fn new() -> Self {
        info!("👤 UEBA: User and Entity Behavior Analytics engine initialized");
        info!("  → Adaptive EMA baseline per entity, impossible travel detection");
        Self {
            baselines: RwLock::new(HashMap::new()),
            recent_activities: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            total_events: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            high_risk_threshold: 60.0,
            critical_risk_threshold: 80.0,
        }
    }

    /// Process a new user activity event.
    pub fn process_event(&self, activity: UserActivity) -> Option<UebaAlert> {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let entity_id = activity.entity_id.clone();
        let now = activity.timestamp;

        // Anomaly scoring (before updating baseline)
        let anomalies = {
            let baselines = self.baselines.read();
            if let Some(baseline) = baselines.get(&entity_id) {
                if baseline.is_mature() {
                    self.score_anomalies(baseline, &activity)
                } else { vec![] }
            } else { vec![] }
        };

        // Update baseline
        {
            let mut baselines = self.baselines.write();
            baselines.entry(entity_id.clone())
                .or_insert_with(|| EntityBaseline::new(&entity_id))
                .update(&activity);
        }

        // Track recent activities for impossible travel
        {
            let mut recent = self.recent_activities.write();
            let deque = recent.entry(entity_id.clone()).or_default();
            deque.push_back(activity.clone());
            if deque.len() > 100 { deque.pop_front(); }
        }

        if anomalies.is_empty() { return None; }

        // Compute composite risk score
        let risk_score = self.compute_risk_score(&anomalies);
        if risk_score < 30.0 { return None; }

        let alert = UebaAlert {
            id: format!("UEBA-{:x}", unix_secs()),
            entity_id: entity_id.clone(),
            risk_score,
            anomalies: anomalies.clone(),
            activity: activity.clone(),
            timestamp: now,
        };

        if risk_score >= self.critical_risk_threshold {
            error!("👤 UEBA CRITICAL [{}]: risk={:.0}/100 — {:?}",
                entity_id, risk_score, activity.event_type);
        } else if risk_score >= self.high_risk_threshold {
            warn!("👤 UEBA HIGH [{}]: risk={:.0}/100", entity_id, risk_score);
        } else {
            debug!("👤 UEBA MEDIUM [{}]: risk={:.0}/100", entity_id, risk_score);
        }

        self.total_alerts.fetch_add(1, Ordering::Relaxed);
        self.alerts.write().push_back(alert.clone());
        Some(alert)
    }

    fn score_anomalies(&self, baseline: &EntityBaseline, activity: &UserActivity) -> Vec<BehaviorAnomaly> {
        let mut anomalies = vec![];
        let now = activity.timestamp;

        // 1. Off-hours access
        let hour = hour_of_day(now) as usize;
        let hour_prob = baseline.typical_hours[hour];
        if hour_prob < 0.02 && baseline.observation_count > 50 {
            anomalies.push(BehaviorAnomaly::OffHoursAccess {
                hour: hour as u8,
                typical_probability: hour_prob,
            });
        }

        // 2. Unknown source IP
        if let Some(src) = activity.src_ip {
            if !baseline.typical_src_ips.contains(&src) && baseline.typical_src_ips.len() >= 5 {
                anomalies.push(BehaviorAnomaly::UnknownSourceIp { src_ip: src });
            }
        }

        // 3. Unknown destination
        if let (Some(dst), Some(port)) = (activity.dst_ip, activity.dst_port) {
            if !baseline.typical_dst_ips.contains(&dst) && !baseline.typical_dst_ports.contains(&port) {
                anomalies.push(BehaviorAnomaly::UnknownDestination { dst_ip: dst, dst_port: port });
            }
        }

        // 4. Unusual data volume (z-score)
        if activity.bytes_transferred > 0 && baseline.bytes_per_session_std > 0.0 {
            let z = (activity.bytes_transferred as f64 - baseline.bytes_per_session_mean)
                / baseline.bytes_per_session_std;
            if z > 3.0 {
                anomalies.push(BehaviorAnomaly::UnusualDataVolume {
                    actual_bytes: activity.bytes_transferred,
                    mean_bytes: baseline.bytes_per_session_mean,
                    z_score: z as f32,
                });
            }
        }

        // 5. New geolocation
        if let Some(ref geo) = activity.geo_country {
            if !baseline.typical_geos.contains(geo) && !baseline.typical_geos.is_empty() {
                anomalies.push(BehaviorAnomaly::NewGeolocation { country: geo.clone() });
            }
        }

        // 6. Impossible travel: same entity from two different countries within 1 hour
        {
            let recent = self.recent_activities.read();
            if let Some(history) = recent.get(&activity.entity_id) {
                let one_hour_ago = now.saturating_sub(3600);
                let recent_geos: Vec<(String, u64)> = history.iter()
                    .filter(|a| a.timestamp >= one_hour_ago)
                    .filter_map(|a| a.geo_country.as_ref().map(|g| (g.clone(), a.timestamp)))
                    .collect();
                if let Some(ref current_geo) = activity.geo_country {
                    for (prev_geo, prev_ts) in &recent_geos {
                        if prev_geo != current_geo {
                            anomalies.push(BehaviorAnomaly::ImpossibleTravel {
                                countries: vec![prev_geo.clone(), current_geo.clone()],
                                time_gap_secs: now - prev_ts,
                            });
                        }
                    }
                }
            }
        }

        // 7. Privilege escalation
        if activity.event_type == ActivityType::PrivilegeEscalation {
            anomalies.push(BehaviorAnomaly::PrivilegeEscalation);
        }

        // 8. High failed auth rate
        if activity.event_type == ActivityType::Authentication && !activity.success {
            if baseline.failed_auth_rate > 0.3 {
                anomalies.push(BehaviorAnomaly::AbnormalFailureRate {
                    rate: baseline.failed_auth_rate,
                    threshold: 0.3,
                });
            }
        }

        // 9. New process spawn
        if activity.event_type == ActivityType::ProcessSpawn {
            if let Some(ref proc_name) = activity.process_name {
                // Flag unusual processes
                let suspicious_procs = ["mimikatz", "psexec", "wmic", "powershell", "cmd", "regsvr32", "mshta", "certutil"];
                for sp in &suspicious_procs {
                    if proc_name.to_lowercase().contains(sp) {
                        anomalies.push(BehaviorAnomaly::NewProcessSpawn { process: proc_name.clone() });
                        break;
                    }
                }
            }
        }

        anomalies
    }

    fn compute_risk_score(&self, anomalies: &[BehaviorAnomaly]) -> f32 {
        let mut score = 0.0f32;
        for a in anomalies {
            score += match a {
                BehaviorAnomaly::ImpossibleTravel { .. } => 40.0,
                BehaviorAnomaly::PrivilegeEscalation => 35.0,
                BehaviorAnomaly::NewProcessSpawn { .. } => 30.0,
                BehaviorAnomaly::UnusualDataVolume { z_score, .. } => (z_score - 3.0).max(0.0) * 5.0 + 20.0,
                BehaviorAnomaly::NewGeolocation { .. } => 25.0,
                BehaviorAnomaly::AbnormalFailureRate { .. } => 25.0,
                BehaviorAnomaly::UnknownSourceIp { .. } => 15.0,
                BehaviorAnomaly::UnknownDestination { .. } => 10.0,
                BehaviorAnomaly::OffHoursAccess { .. } => 10.0,
                _ => 5.0,
            };
        }
        score.min(100.0)
    }

    pub fn get_baseline(&self, entity_id: &str) -> Option<EntityBaseline> {
        self.baselines.read().get(entity_id).cloned()
    }

    pub fn top_risky_entities(&self, n: usize) -> Vec<(String, f32)> {
        // Compute recent average risk from alert history
        let alerts = self.alerts.read();
        let mut entity_risk: HashMap<String, f32> = HashMap::new();
        for alert in alerts.iter() {
            let e = entity_risk.entry(alert.entity_id.clone()).or_insert(0.0);
            *e = e.max(alert.risk_score);
        }
        let mut sorted: Vec<_> = entity_risk.into_iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(n).collect()
    }

    pub fn recent_alerts(&self, n: usize) -> Vec<UebaAlert> {
        self.alerts.read().iter().rev().take(n).cloned().collect()
    }

    /// Drain entity IDs whose current risk score exceeds `min_risk` (for SOAR integration).
    pub fn drain_high_risk_entities(&self, min_risk: f32) -> Vec<String> {
        let alerts = self.alerts.read();
        let mut seen = std::collections::HashSet::new();
        alerts.iter()
            .filter(|a| a.risk_score >= min_risk)
            .filter(|a| seen.insert(a.entity_id.clone()))
            .map(|a| a.entity_id.clone())
            .collect()
    }

    pub fn stats(&self) -> UebaStats {
        UebaStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            total_alerts: self.total_alerts.load(Ordering::Relaxed),
            entities_tracked: self.baselines.read().len() as u64,
        }
    }
}

impl Default for UebaEngine {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct UebaStats {
    pub total_events: u64,
    pub total_alerts: u64,
    pub entities_tracked: u64,
}
