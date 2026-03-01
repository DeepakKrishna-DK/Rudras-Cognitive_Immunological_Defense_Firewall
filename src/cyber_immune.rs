// ============================================================================
// Rudras — CyberImmune System
// Bio-inspired adaptive defence: threat detection + antibody evolution.
// Learns from previously seen attacks and generates new blocking rules.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ── Response Action ────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    Allow,
    Monitor,
    Block,
    Quarantine,
    Evolve,
    Alert,
}

// ── Threat Assessment ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    pub is_threat: bool,
    pub severity: f64, // 0.0 – 1.0
    pub threat_type: String,
    pub src_ip: String,
    pub dst_port: u16,
    pub signature: Vec<u8>,
}

// ── Defense Result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DefenseResult {
    Blocked,
    Monitored,
    Evolved,
    NoAction,
}

// ── Antibody (learned rule) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Antibody {
    pattern: Vec<u8>,
    confidence: f64,
    generation: u32,
    hits: u64,
    created_at: u64,
}

// ── Immune Stats ─────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct CyberImmuneStats {
    pub total_threats_seen: u64,
    pub total_threats_blocked: u64,
    pub unique_threats_in_memory: u64,
    pub active_antibodies: u64,
    pub evolution_generation: u64,
    pub current_threshold: f64,
}

// ── CyberImmune System ────────────────────────────────────────────────────────

pub struct CyberImmuneSystem {
    antibodies: RwLock<Vec<Antibody>>,
    threat_memory: RwLock<HashMap<String, ThreatAssessment>>,
    threats_detected: AtomicU64,
    threats_blocked: AtomicU64,
    antibodies_gen: AtomicU64,
    generation: AtomicU64,
    adaptive_threshold: RwLock<f64>,
}

impl CyberImmuneSystem {
    pub fn new() -> Self {
        Self {
            antibodies: RwLock::new(Vec::new()),
            threat_memory: RwLock::new(HashMap::new()),
            threats_detected: AtomicU64::new(0),
            threats_blocked: AtomicU64::new(0),
            antibodies_gen: AtomicU64::new(0),
            generation: AtomicU64::new(1),
            adaptive_threshold: RwLock::new(0.65),
        }
    }

    /// Assess incoming traffic for threat status
    pub fn detect_threat(
        &self,
        src_ip: &str,
        dst_port: u16,
        protocol: &str,
        payload: &[u8],
    ) -> ThreatAssessment {
        // Check threat memory (repeat offender)
        {
            let mem = self.threat_memory.read();
            if let Some(prev) = mem.get(src_ip) {
                if prev.severity > 0.7 {
                    return ThreatAssessment {
                        is_threat: true,
                        severity: (prev.severity * 1.1).min(1.0),
                        threat_type: format!("Repeat: {}", prev.threat_type),
                        src_ip: src_ip.to_string(),
                        dst_port,
                        signature: payload[..payload.len().min(16)].to_vec(),
                    };
                }
            }
        }

        // Check antibody library (evolved rules)
        {
            let abs = self.antibodies.read();
            for ab in abs.iter() {
                if payload.len() >= ab.pattern.len()
                    && payload
                        .windows(ab.pattern.len())
                        .any(|w| w == ab.pattern.as_slice())
                {
                    self.threats_detected.fetch_add(1, Ordering::Relaxed);
                    return ThreatAssessment {
                        is_threat: true,
                        severity: ab.confidence,
                        threat_type: "AntibodyMatch".to_string(),
                        src_ip: src_ip.to_string(),
                        dst_port,
                        signature: ab.pattern.clone(),
                    };
                }
            }
        }

        // Basic heuristic: unusually large payload on surprising port
        let severity = if payload.len() > 8000 && dst_port < 1024 {
            0.6
        } else if dst_port == 4444 || dst_port == 31337 {
            0.85
        } else {
            0.0
        };

        if severity > 0.5 {
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
        }

        ThreatAssessment {
            is_threat: severity > 0.5,
            severity,
            threat_type: if severity > 0.8 {
                "BackdoorPort".to_string()
            } else if severity > 0.5 {
                "Anomaly".to_string()
            } else {
                "Clean".to_string()
            },
            src_ip: src_ip.to_string(),
            dst_port,
            signature: payload[..payload.len().min(16)].to_vec(),
        }
    }

    /// Execute defence and evolve antibodies
    pub fn execute_defense(&self, assessment: &ThreatAssessment) -> DefenseResult {
        if !assessment.is_threat {
            return DefenseResult::NoAction;
        }

        // Store in threat memory
        {
            let mut mem = self.threat_memory.write();
            mem.insert(assessment.src_ip.clone(), assessment.clone());
        }

        // Evolve antibody from this threat signature
        if assessment.signature.len() >= 4 {
            self.evolve_antibody(&assessment.signature, assessment.severity);
        }

        if assessment.severity >= 0.7 {
            self.threats_blocked.fetch_add(1, Ordering::Relaxed);
            DefenseResult::Blocked
        } else {
            DefenseResult::Monitored
        }
    }

    fn evolve_antibody(&self, pattern: &[u8], confidence: f64) {
        let gen = self.generation.load(Ordering::Relaxed) as u32;
        let mut abs = self.antibodies.write();
        // Deduplicate
        if abs.iter().any(|a| a.pattern == pattern) {
            return;
        }
        // Cap antibody count
        if abs.len() >= 10_000 {
            abs.sort_by(|a, b| a.hits.cmp(&b.hits));
            abs.truncate(9_000);
        }
        abs.push(Antibody {
            pattern: pattern.to_vec(),
            confidence,
            generation: gen,
            hits: 1,
            created_at: unix_now(),
        });
        self.antibodies_gen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> CyberImmuneStats {
        CyberImmuneStats {
            total_threats_seen: self.threats_detected.load(Ordering::Relaxed),
            total_threats_blocked: self.threats_blocked.load(Ordering::Relaxed),
            unique_threats_in_memory: self.threat_memory.read().len() as u64,
            active_antibodies: self.antibodies.read().len() as u64,
            evolution_generation: self.generation.load(Ordering::Relaxed),
            current_threshold: *self.adaptive_threshold.read(),
        }
    }

    /// Periodic evolution: prune weak antibodies, increment generation,
    /// and adaptively tighten threshold if threat rate is high.
    pub fn evolve_defenses(&self) {
        let gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let n_threats = self.threats_detected.load(Ordering::Relaxed);
        let n_blocked = self.threats_blocked.load(Ordering::Relaxed);

        // Prune antibodies with 0 hits, keep strongest
        {
            let mut abs = self.antibodies.write();
            if abs.len() > 8_000 {
                abs.sort_by(|a, b| b.hits.cmp(&a.hits));
                abs.truncate(8_000);
            }
        }

        // Adaptive threshold: if blocking rate < 50% of detections → tighten
        {
            let mut thr = self.adaptive_threshold.write();
            if n_threats > 10 {
                let block_ratio = n_blocked as f64 / n_threats as f64;
                if block_ratio < 0.5 {
                    *thr = (*thr - 0.01).max(0.50);
                } else {
                    *thr = (*thr + 0.005).min(0.90);
                }
            }
        }

        info!(
            "🧬 CyberImmune evolution Gen#{} | antibodies={} | threshold={:.3}",
            gen,
            self.antibodies.read().len(),
            self.adaptive_threshold.read()
        );

        // Export highly successful antibodies to Global Threat Knowledge
        self.save_antibodies_to_disk();
    }

    /// Save proven antibodies to disk for global threat persistence
    pub fn save_antibodies_to_disk(&self) {
        let abs = self.antibodies.read();
        // Export only antibodies with proven success (> 10 hits)
        let effective: Vec<&Antibody> = abs.iter().filter(|a| a.hits > 10).collect();
        if effective.is_empty() {
            return;
        }

        let _ = fs::create_dir_all("data/immune");
        if let Ok(json) = serde_json::to_string_pretty(&effective) {
            if let Ok(mut file) = File::create("data/immune/global_antibodies.json") {
                let _ = file.write_all(json.as_bytes());
                info!(
                    "💾 Global Threat Knowledge: Saved {} highly effective antibodies to disk",
                    effective.len()
                );
            }
        }
    }

    /// Load existing antibodies from disk into memory
    pub fn load_antibodies_from_disk(&self) {
        if let Ok(mut file) = File::open("data/immune/global_antibodies.json") {
            let mut json = String::new();
            if file.read_to_string(&mut json).is_ok() {
                if let Ok(loaded) = serde_json::from_str::<Vec<Antibody>>(&json) {
                    let mut abs = self.antibodies.write();
                    for loaded_ab in loaded {
                        if !abs.iter().any(|a| a.pattern == loaded_ab.pattern) {
                            abs.push(loaded_ab);
                        }
                    }
                    info!(
                        "📥 Global Threat Knowledge: Loaded {} antibodies from disk",
                        abs.len()
                    );
                }
            }
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
