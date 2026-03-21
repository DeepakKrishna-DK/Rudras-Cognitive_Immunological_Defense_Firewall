// ============================================================================
// Rudras — Global Defensive Posture Engine (Threat Levels / DEFCON)
//
// Represents the dynamic "firewall levels" concept.
// The firewall operates at Level 5 (Normal) by default, and dynamically
// escalates its operational strictness up to Level 1 (Lockdown) when
// severe attacks, breaches, or anomalies are detected.
//
// Each transition shifts the entire architecture's working model:
//   - Level 5: Normal Zero-Trust validation, pass standard traffic.
//   - Level 4: Guarded. Increases rate limiting, enforces strict protocol checks.
//   - Level 3: Elevated. Blocks Tor, aggressive IP blacklisting, geo-fencing.
//   - Level 2: Critical. Quarantines non-admin users, isolates critical subnets.
//   - Level 1: Lockdown. Panic mode. Drops all traffic except emergency out-of-band IPs.
// ============================================================================

#![allow(dead_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Firewall Threat Level (DEFCON-style) ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ThreatLevel {
    /// Level 1: Extreme emergency. Active ransomware encryption, core breach.
    /// Action: Total lockdown. All interfaces dropped. Only local console or OOB management allowed.
    Lockdown = 1,

    /// Level 2: Critical active attack (Lateral movement, massive DDoS).
    /// Action: Non-admin VPNs terminated, strict internal isolation, deep packet DROP.
    Critical = 2,

    /// Level 3: High risk (Targeted scanning, repeated brute force, known C2 beaconing).
    /// Action: Tor/VPN blocking, Geo-IP fencing enforcing, strict protocol verification.
    Elevated = 3,

    /// Level 4: Guarded (Anomalous traffic spikes, minor port scanning).
    /// Action: Aggressive rate limiting, session throttling, extended logging.
    Guarded = 4,

    /// Level 5: Normal operations.
    /// Action: Standard Zero-Trust, signature blocking, normal IPS behavior.
    Normal = 5,
}

impl ThreatLevel {
    pub fn name(&self) -> &'static str {
        match self {
            ThreatLevel::Lockdown => "LEVEL 1: LOCKDOWN",
            ThreatLevel::Critical => "LEVEL 2: CRITICAL",
            ThreatLevel::Elevated => "LEVEL 3: ELEVATED",
            ThreatLevel::Guarded  => "LEVEL 4: GUARDED",
            ThreatLevel::Normal   => "LEVEL 5: NORMAL",
        }
    }

    pub fn to_u8(&self) -> u8 { *self as u8 }
    
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => ThreatLevel::Lockdown,
            2 => ThreatLevel::Critical,
            3 => ThreatLevel::Elevated,
            4 => ThreatLevel::Guarded,
            _ => ThreatLevel::Normal,
        }
    }
}

// ── State Trackers ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLog {
    pub previous_level: ThreatLevel,
    pub new_level: ThreatLevel,
    pub reason: String,
    pub timestamp: u64,
}

pub struct PostureEngine {
    current_level: AtomicU8,
    last_escalation: RwLock<u64>,
    escalation_logs: RwLock<Vec<EscalationLog>>,
    
    // Attack metrics for auto-escalation
    recent_critical_alerts: AtomicU8,
    dos_spike_detected: std::sync::atomic::AtomicBool,
}

impl PostureEngine {
    pub fn new() -> Self {
        info!("🛡️ Defensive Posture Engine initialized — System starting at LEVEL 5: NORMAL");
        Self {
            current_level: AtomicU8::new(ThreatLevel::Normal.to_u8()),
            last_escalation: RwLock::new(unix_secs()),
            escalation_logs: RwLock::new(Vec::new()),
            recent_critical_alerts: AtomicU8::new(0),
            dos_spike_detected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn current_level(&self) -> ThreatLevel {
        ThreatLevel::from_u8(self.current_level.load(Ordering::Relaxed))
    }

    /// Manually or Programmatically escalate or de-escalate the firewall threat level.
    pub fn set_level(&self, new_level: ThreatLevel, reason: &str) {
        let old_val = self.current_level.swap(new_level.to_u8(), Ordering::SeqCst);
        let old_level = ThreatLevel::from_u8(old_val);

        if old_level == new_level { return; }

        let log = EscalationLog {
            previous_level: old_level,
            new_level,
            reason: reason.to_string(),
            timestamp: unix_secs(),
        };

        if new_level < old_level {
            // Lower number = higher threat
            error!("🚨 SYSTEM THREAT LEVEL ESCALATED: {} -> {} | Reason: {}", 
                   old_level.name(), new_level.name(), reason);
        } else {
            info!("🟩 SYSTEM THREAT LEVEL DE-ESCALATED: {} -> {} | Reason: {}", 
                  old_level.name(), new_level.name(), reason);
        }

        self.escalation_logs.write().push(log);
        *self.last_escalation.write() = unix_secs();

        // Trigger immediate core architecture shifts based on new level
        self.apply_architecture_shift(new_level);
    }

    /// Analyzes an incoming severe attack and decides if the system should auto-escalate.
    /// This creates the "unique working model" that responds dynamically to an attack.
    pub fn register_attack_event(&self, severity: &str, attack_type: &str, is_insider: bool) {
        let current = self.current_level();

        // If we are already at Lockdown, nothing more to escalate automatically
        if current == ThreatLevel::Lockdown { return; }

        if severity == "CRITICAL" || severity == "HIGH" {
            let count = self.recent_critical_alerts.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Rules of Escalation
            if is_insider && attack_type.contains("Ransomware") {
                // Instant Level 1 Lockdown for internal ransomware propagation
                self.set_level(ThreatLevel::Lockdown, "Internal Ransomware propagation detected (Zero-Day / Lateral Movement). Initiating Total Lockdown.");
            } else if attack_type.contains("DoS") || attack_type.contains("Flood") {
                self.dos_spike_detected.store(true, Ordering::Relaxed);
                if current > ThreatLevel::Elevated {
                    self.set_level(ThreatLevel::Elevated, "Massive DoS Flood detected. Shifting to Level 3 (Elevated) for aggressive volume dropping.");
                }
            } else if count >= 3 {
                // 3 Critical alerts in rapid succession -> jump to Level 2
                if current > ThreatLevel::Critical {
                    self.set_level(ThreatLevel::Critical, "Multiple CRITICAL threat events detected globally. Shifting to Level 2 (Critical) isolation mode.");
                }
            } else if count >= 1 {
                // First critical alert -> Guarded
                if current == ThreatLevel::Normal {
                    self.set_level(ThreatLevel::Guarded, "Initial severe threat detected. Shifting to Level 4 (Guarded) for strict rate limiting.");
                }
            }
        }
    }

    /// Internal method to trigger firewall sub-system behavioral shifts natively.
    fn apply_architecture_shift(&self, level: ThreatLevel) {
        match level {
            ThreatLevel::Lockdown => {
                error!("🛑 ARCHITECTURE SHIFT: LEVEL 1 LOCKDOWN ACTIVE");
                error!("   -> ALL Non-Management traffic DROPPED at WFP/eBPF kernel layer.");
                error!("   -> BGP sinkholing initiated. VPNs Hard-Terminated.");
                error!("   -> NERC CIP / E-ISAC Emergency Report generated automatically.");
                // Note: The main loop will read this level and apply WFP/eBPF blocks natively.
            },
            ThreatLevel::Critical => {
                warn!("⚠️ ARCHITECTURE SHIFT: LEVEL 2 CRITICAL ACTIVE");
                warn!("   -> Aggressive zero-trust enforced. Non-Admin users quarantined.");
                warn!("   -> Geo-IP fencing: Strict domestic-only traffic permitted.");
                warn!("   -> Subnet Isolation: OT/ICS systems completely air-gapped from IT LAN.");
            },
            ThreatLevel::Elevated => {
                warn!("🟠 ARCHITECTURE SHIFT: LEVEL 3 ELEVATED ACTIVE");
                warn!("   -> Tor / Anonymous Proxies forcibly dropped.");
                warn!("   -> Machine Learning heuristic confidence threshold lowered (more aggressive blocking).");
                warn!("   -> UDP traffic globally throttled except DNS/NTP.");
            },
            ThreatLevel::Guarded => {
                info!("🟡 ARCHITECTURE SHIFT: LEVEL 4 GUARDED ACTIVE");
                info!("   -> TCP SYN limits reduced by 50% (aggressive rate limiting).");
                info!("   -> TLS inspection (DPI) depth increased to full payload capture for anomalous flows.");
            },
            ThreatLevel::Normal => {
                info!("🟢 ARCHITECTURE SHIFT: LEVEL 5 NORMAL ACTIVE");
                info!("   -> Hardware offload restored.");
                info!("   -> Machine Learning heuristics returned to standard confidence baseline.");
            }
        }
    }

    /// Periodic decay — if we haven't seen attacks in 1 hour, slowly step down the threat level.
    pub fn tick_decay(&self) {
        let now = unix_secs();
        let last = *self.last_escalation.read();
        let current = self.current_level();

        // Decay from Level 4, 3, 2 back to 5.
        // We never automatically decay from Level 1 (Lockdown) — that requires human intervention!
        if current != ThreatLevel::Normal && current != ThreatLevel::Lockdown {
            if now.saturating_sub(last) > 3600 { // 1 hour
                self.recent_critical_alerts.store(0, Ordering::Relaxed);
                self.dos_spike_detected.store(false, Ordering::Relaxed);

                let next_down = ThreatLevel::from_u8(current.to_u8() + 1);
                self.set_level(next_down, "1 hour elapsed without severe events. Auto-decaying posture.");
            }
        }
    }
}
