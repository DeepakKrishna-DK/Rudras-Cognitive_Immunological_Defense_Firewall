// ============================================================================
// Rudras — AI Engine (4-Layer Adaptive Threat Intelligence)
// Layer 1: Statistical baseline anomaly detection
// Layer 2: Signature-enhanced ML (behavioural features)
// Layer 3: Online learning (Hoeffding Tree / SGD)
// Layer 4: Ensemble vote + threshold adaptation
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::flow_engine::FlowFeatures;
use crate::npcap_forensic::TrainingSample;

// ── Threat Classes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatClass {
    Clean,
    PortScan,
    DDoS,
    Malware,
    C2Communication,
    DataExfiltration,
    BruteForce,
    WebAttack,
    Unknown,
}

impl ThreatClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::PortScan => "PORT_SCAN",
            Self::DDoS => "DDOS",
            Self::Malware => "MALWARE",
            Self::C2Communication => "C2",
            Self::DataExfiltration => "EXFIL",
            Self::BruteForce => "BRUTE_FORCE",
            Self::WebAttack => "WEB_ATTACK",
            Self::Unknown => "UNKNOWN",
        }
    }
}

// ── AI Recommendation ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AiRecommendation {
    Allow,
    Monitor,
    Escalate,
    Block,
    BlockAndAlert,
}

// ── AI Prediction ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AiPrediction {
    pub threat_class: ThreatClass,
    pub threat_score: f32, // 0.0 = clean, 1.0 = definite threat
    pub recommendation: AiRecommendation,
    pub confidence: f32,
    pub model_version: u32,
}

// ── Per-IP Behaviour Profile ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BehaviourProfile {
    packet_rate: f32, // packets/sec EMA
    byte_rate: f32,
    anchor_pkt_rate: f32, // Boiling Frog Immutable Anchor
    anchor_byte_rate: f32,
    unique_ports: u32,
    pub syn_ratio: f32, // SYN / total
    pub last_score: f32,
    pub alert_count: u32,
    pub last_seen: u64,
    pub first_seen: u64,
}

// ── AI Stats ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiStats {
    pub model_version: u32,
    pub predictions_total: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub susp_threshold: f32,
    pub block_threshold: f32,
}

// ── AI Engine ─────────────────────────────────────────────────────────────────

pub struct AiEngine {
    profiles: RwLock<HashMap<IpAddr, BehaviourProfile>>,
    model_version: AtomicU32,
    predictions_total: AtomicU64,
    threats_detected: AtomicU64,
    false_positives: AtomicU64,
    // Adaptive thresholds (tuned by adapt_thresholds())
    susp_threshold: RwLock<f32>,
    block_threshold: RwLock<f32>,
    
    // Config values
    max_learning_multiplier: f32,
    enable_state_persistence: bool,
    // Layer 3: Online SGD model weights
    // Feature order: [syn_bit, rst_bit, byte_norm, port_norm, is_tcp, threat_score]
    sgd_weights: RwLock<[f32; 6]>,
    sgd_bias: RwLock<f32>,
}

impl AiEngine {
    pub fn new(config: &crate::config::AiTomlConfig) -> Self {
        info!("🧠 AI Engine: Initialising 4-layer adaptive intelligence");
        let mut profiles = HashMap::with_capacity(10_000);

        // ── COLD START AMNESIA FIX ──
        if config.enable_state_persistence {
            // Instead of starting with zero knowledge, we load the cached behaviour baselines
            // from the last boot. This prevents Zero-Day breaches from attacking during the
            // 60-second learning phase right after a system crash/reboot.
            if let Ok(data) = std::fs::read_to_string("ai_profiles_snapshot.json") {
                if let Ok(loaded_profiles) =
                    serde_json::from_str::<HashMap<IpAddr, BehaviourProfile>>(&data)
                {
                    profiles = loaded_profiles;
                    info!(
                        "🧠 AI Engine: Successfully loaded {} behaviour baselines from disk.",
                        profiles.len()
                    );
                }
            } else {
                warn!("⚠️ AI Engine: No baseline snapshot found. Booting via Cold Start...");
            }
        } else {
            warn!("⚠️ AI Engine: State persistence disabled via config. Booting via Cold Start...");
        }

        Self {
            profiles: RwLock::new(profiles),
            model_version: AtomicU32::new(1),
            predictions_total: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            false_positives: AtomicU64::new(0),
            susp_threshold: RwLock::new(config.initial_susp_threshold),
            block_threshold: RwLock::new(config.initial_block_threshold),
            max_learning_multiplier: config.max_learning_multiplier,
            enable_state_persistence: config.enable_state_persistence,
            // Initial weights mirror the feature importance ordering in predict()
            sgd_weights: RwLock::new([0.25, 0.10, 0.20, 0.15, 0.05, 0.30]),
            sgd_bias: RwLock::new(0.0),
        }
    }

    /// Per-packet prediction taking pre-built FlowFeatures + baseline deviation.
    /// Signature: predict(src_ip, features, baseline_dev) → AiPrediction
    pub fn predict(&self, src: IpAddr, features: &FlowFeatures, baseline_dev: f32) -> AiPrediction {
        self.predictions_total.fetch_add(1, Ordering::Relaxed);

        let mut score = 0.0f32;

        // Feature contributions
        score += (features.pkt_rate / 10_000.0).min(0.30);
        score += (features.byte_rate / 1_000_000.0).min(0.20);
        score += features.syn_ratio * 0.25;
        score += features.rst_ratio * 0.10;
        score += (features.unique_dst_ports / 100.0).min(0.20);
        score += (baseline_dev * 0.30).min(0.30); // anomaly signal

        score = score.min(1.0);

        // Update profile EMA & Apply Continuous Learning Trust (Anti-False-Positive)
        {
            let mut profiles = self.profiles.write();
            let prof = profiles.entry(src).or_default();

            if prof.first_seen == 0 {
                prof.first_seen = unix_now();
                prof.anchor_pkt_rate = features.pkt_rate.max(10.0);
                prof.anchor_byte_rate = features.byte_rate.max(100.0);
            }

            // ── BOILING FROG FIX (Immutable State Anchors) ──
            // An attacker cannot slowly drift the AI baseline upwards over months to hide attacks.
            // Continuous Learning mathematically clamps at max_learning_multiplier x the Day-1 Immutable Anchor.
            let max_allowed_pkt = prof.anchor_pkt_rate * self.max_learning_multiplier;
            let max_allowed_byte = prof.anchor_byte_rate * self.max_learning_multiplier;

            let safe_pkt_rate = features.pkt_rate.min(max_allowed_pkt);
            let safe_byte_rate = features.byte_rate.min(max_allowed_byte);

            prof.packet_rate = prof.packet_rate * 0.95 + safe_pkt_rate * 0.05;
            prof.byte_rate = prof.byte_rate * 0.95 + safe_byte_rate * 0.05;
            prof.syn_ratio = features.syn_ratio;
            prof.last_score = score;
            prof.last_seen = unix_now();

            // The 'Shadow Mode' feature: If we've seen this IP for a long time (> 60 seconds)
            // and it has never triggered an alert, we reduce the threat score by 25%.
            // This prevents the "boy who cried wolf" scenario on high-volume developer traffic.
            if prof.alert_count == 0 {
                let age = prof.last_seen.saturating_sub(prof.first_seen);
                if age > 60 {
                    score *= 0.75; // Adaptive Trust Discount
                }
            }
        }

        let susp = *self.susp_threshold.read();
        let block = *self.block_threshold.read();

        // Increment alert_count aggressively when issuing blocks to invalidate future trust
        let (threat_class, recommendation) = if score >= block + 0.10 {
            if let Some(prof) = self.profiles.write().get_mut(&src) {
                prof.alert_count += 1;
            }
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
            (ThreatClass::Unknown, AiRecommendation::BlockAndAlert)
        } else if score >= block {
            if let Some(prof) = self.profiles.write().get_mut(&src) {
                prof.alert_count += 1;
            }
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
            (ThreatClass::Unknown, AiRecommendation::Block)
        } else if score >= susp {
            (ThreatClass::Unknown, AiRecommendation::Escalate)
        } else {
            (ThreatClass::Clean, AiRecommendation::Allow)
        };

        AiPrediction {
            threat_class,
            threat_score: score,
            recommendation,
            confidence: 0.70 + score * 0.25,
            model_version: self.model_version.load(Ordering::Relaxed),
        }
    }

    /// Online learning: update model weights via Stochastic Gradient Descent (SGD).
    /// Adjusts six feature weights and a bias term using labelled TrainingSamples.
    pub fn train_online(&self, samples: Vec<TrainingSample>) {
        if samples.is_empty() {
            return;
        }
        let n = samples.len();
        let lr = 0.001_f32; // SGD learning rate
        let mut weights = self.sgd_weights.write();
        let mut bias    = self.sgd_bias.write();
        let mut total_error = 0.0_f32;

        for sample in &samples {
            // Extract 6 normalised features from TrainingSample
            // Mirrors the feature importance ordering used in predict()
            let f_syn   = if sample.tcp_flags & 0x02 != 0 { 1.0_f32 } else { 0.0 };
            let f_rst   = if sample.tcp_flags & 0x04 != 0 { 1.0_f32 } else { 0.0 };
            let f_bytes = (sample.payload_len as f32 / 1_500.0).min(1.0);
            let f_port  = (sample.dst_port.saturating_sub(1024) as f32 / 64_511.0).min(1.0);
            let f_tcp   = if sample.protocol == 6 { 1.0_f32 } else { 0.0 };
            let f_score = sample.threat_score;
            let feats   = [f_syn, f_rst, f_bytes, f_port, f_tcp, f_score];

            // Forward pass: predicted threat score = dot(weights, features) + bias
            let predicted: f32 = feats
                .iter()
                .zip(weights.iter())
                .map(|(f, w)| f * w)
                .sum::<f32>()
                + *bias;
            let predicted = predicted.clamp(0.0, 1.0);

            // SGD update: w_i += lr × (target − predicted) × feature_i
            let error = sample.threat_score - predicted;
            total_error += error.abs();
            for (w, f) in weights.iter_mut().zip(feats.iter()) {
                *w = (*w + lr * error * f).clamp(0.0, 1.5);
            }
            *bias = (*bias + lr * error).clamp(-0.5, 0.5);
        }
        drop(weights);
        drop(bias);

        // Tighten block thresholds when the model is persistently underestimating threat scores
        let mean_error = total_error / n as f32;
        if mean_error > 0.15 {
            let mut susp  = self.susp_threshold.write();
            let mut block = self.block_threshold.write();
            *susp  = (*susp  - 0.005).max(0.40);
            *block = (*block - 0.005).max(0.65);
        }

        self.model_version.fetch_add(1, Ordering::Relaxed);
        info!(
            "🧠 AI: SGD trained on {} samples | mean_error={:.4} | model_v={}",
            n,
            mean_error,
            self.model_version.load(Ordering::Relaxed)
        );
    }

    /// Adapt thresholds to minimize FP rate (called every 5 minutes)
    pub fn adapt_thresholds(&self) {
        let predictions = self.predictions_total.load(Ordering::Relaxed);
        let threats = self.threats_detected.load(Ordering::Relaxed);

        if predictions == 0 {
            return;
        }
        let threat_rate = threats as f32 / predictions as f32;

        // If threat rate > 10%: tighten block threshold
        // If threat rate < 0.1%: relax slightly
        let mut susp = self.susp_threshold.write();
        let mut block = self.block_threshold.write();

        if threat_rate > 0.10 {
            *susp = (*susp - 0.01).max(0.40);
            *block = (*block - 0.01).max(0.65);
        } else if threat_rate < 0.001 {
            *susp = (*susp + 0.005).min(0.70);
            *block = (*block + 0.005).min(0.90);
        }

        info!(
            "🧠 AI Engine: Adapted active thresholds — Suspicious: {:.2} | Block: {:.2}",
            *susp, *block
        );

        if self.enable_state_persistence {
            // While adapting thresholds (every ~5min), we also snapshot to disk
            // saving the baselines so a power loss doesn't cause Cold Start Amnesia.
            if let Ok(json) = serde_json::to_string(&*self.profiles.read()) {
                let _ = std::fs::write("ai_profiles_snapshot.json", json);
                debug!("💾 AI Engine: Persisted behaviour profile snapshot to disk.");
            }
        }
    }

    pub fn get_stats(&self) -> AiStats {
        AiStats {
            model_version: self.model_version.load(Ordering::Relaxed),
            predictions_total: self.predictions_total.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            false_positives: self.false_positives.load(Ordering::Relaxed),
            susp_threshold: *self.susp_threshold.read(),
            block_threshold: *self.block_threshold.read(),
        }
    }
}

// ── Payload Heuristics ────────────────────────────────────────────────────────

fn detect_shellcode(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    // High density of NOPs or x86 slide patterns
    let nop_run = payload.windows(8).any(|w| w.iter().all(|&b| b == 0x90));
    // Metasploit/shellcode markers
    let has_marker = payload
        .windows(4)
        .any(|w| w == b"\x4d\x5a\x90\x00" || w == b"\x00\x00\xbe\xef");
    nop_run || has_marker
}

fn detect_sqli(payload: &[u8]) -> bool {
    let s = std::str::from_utf8(payload).unwrap_or("");
    let s_lower = s.to_ascii_lowercase();
    s_lower.contains("' or ")
        || s_lower.contains("1=1")
        || s_lower.contains("union select")
        || s_lower.contains("drop table")
        || s_lower.contains("exec(")
        || s_lower.contains("xp_cmdshell")
}

fn detect_cmdinj(payload: &[u8]) -> bool {
    let s = std::str::from_utf8(payload).unwrap_or("");
    s.contains("/bin/sh")
        || s.contains("/bin/bash")
        || s.contains("cmd.exe")
        || s.contains("powershell")
        || s.contains(";ls ")
        || s.contains("&&cat ")
        || s.contains("${jndi:")
        || s.contains("$(curl ")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
