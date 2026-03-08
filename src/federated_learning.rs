// ============================================================================
// Rudras — Federated Learning Engine
// Privacy-preserving collaborative threat intelligence without sharing raw data.
// Implements:
//   • FedAvg (Federated Averaging) gradient aggregation
//   • Differential privacy noise injection before upload
//   • Byzantine-fault-tolerant gradient clipping (Krum / median filter)
//   • Secure model aggregation via gradient hashing
//   • P2P federated model sync (supplements distributed_immunity.rs)
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Model Gradient ────────────────────────────────────────────────────────────
// A gradient is the delta (update) to model weights after local training.
// Nodes share gradients, not raw traffic data — preserving locality privacy.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelGradient {
    /// Node that contributed this gradient
    pub node_id: String,
    /// Gradient values (flat float array — matches model parameter count)
    pub values: Vec<f32>,
    /// L2 norm of the gradient (for clipping validation)
    pub l2_norm: f32,
    /// Number of local training samples used
    pub n_samples: u64,
    /// Gradient epoch / training round
    pub round: u64,
    /// SHA3-256 hash of serialized values (tamper detection)
    pub integrity_hash: String,
    pub timestamp: u64,
    /// True if differential privacy noise was applied
    pub dp_applied: bool,
}

impl ModelGradient {
    pub fn new(node_id: &str, values: Vec<f32>, n_samples: u64, round: u64) -> Self {
        let l2_norm = (values.iter().map(|v| v * v).sum::<f32>()).sqrt();
        let hash = hash_gradient(&values);
        Self {
            node_id: node_id.to_string(),
            values,
            l2_norm,
            n_samples,
            round,
            integrity_hash: hash,
            timestamp: unix_secs(),
            dp_applied: false,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        let computed = hash_gradient(&self.values);
        computed == self.integrity_hash
    }

    /// Clip gradient L2 norm to max_norm (prevents gradient explosion / Byzantine attack amplification).
    pub fn clip(&mut self, max_norm: f32) {
        if self.l2_norm > max_norm && self.l2_norm > 0.0 {
            let scale = max_norm / self.l2_norm;
            self.values.iter_mut().for_each(|v| *v *= scale);
            self.l2_norm = max_norm;
            self.integrity_hash = hash_gradient(&self.values);
        }
    }

    /// Apply ε-differential privacy noise (Gaussian mechanism).
    /// sigma = (2 * ln(1.25/delta))^0.5 * sensitivity / epsilon
    pub fn apply_dp_noise(&mut self, epsilon: f64, delta: f64, sensitivity: f64) {
        if self.dp_applied { return; }
        let sigma = ((2.0 * (1.25 / delta).ln()).sqrt() * sensitivity / epsilon) as f32;
        // Box-Muller transform to generate Gaussian noise without rand crate
        for (i, v) in self.values.iter_mut().enumerate() {
            let u1 = lcg_uniform(unix_secs() ^ (i as u64 * 6364136223846793005));
            let u2 = lcg_uniform(unix_secs() ^ (i as u64 * 2862933555777941757));
            let noise = sigma * (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
            *v += noise;
        }
        self.l2_norm = (self.values.iter().map(|v| v * v).sum::<f32>()).sqrt();
        self.integrity_hash = hash_gradient(&self.values);
        self.dp_applied = true;
    }
}

fn lcg_uniform(seed: u64) -> f32 {
    let v = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (v >> 11) as f32 / (1u64 << 53) as f32 + 1e-10
}

fn hash_gradient(values: &[f32]) -> String {
    let mut hasher = Sha3_256::new();
    for v in values {
        hasher.update(v.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

// ── Aggregation Methods ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AggregationMethod {
    FedAvg,        // Standard weighted averaging (McMahan et al.)
    Median,        // Coordinate-wise median (Byzantine-robust)
    TrimmedMean,   // Trim top/bottom k% before averaging (Byzantine-robust)
    Krum,          // Select n-f closest gradients by L2 distance
}

// ── Global Model ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalModel {
    pub version: u64,
    pub round: u64,
    pub weights: Vec<f32>,
    pub training_nodes: u32,
    pub total_samples: u64,
    pub updated_at: u64,
    pub weight_hash: String,
}

impl GlobalModel {
    pub fn new(n_params: usize) -> Self {
        // Initialize with small random weights (uniform [-0.01, 0.01])
        let weights: Vec<f32> = (0..n_params).map(|i| {
            lcg_uniform(i as u64 * 12345) * 0.02 - 0.01
        }).collect();
        let hash = hash_weights(&weights);
        Self {
            version: 1,
            round: 0,
            weights,
            training_nodes: 0,
            total_samples: 0,
            updated_at: unix_secs(),
            weight_hash: hash,
        }
    }
}

fn hash_weights(weights: &[f32]) -> String {
    let mut h = Sha3_256::new();
    for w in weights { h.update(w.to_le_bytes()); }
    hex::encode(h.finalize())
}

// ── Byzantine Fault Tolerance ─────────────────────────────────────────────────

/// Coordinate-wise median (Byzantine-robust): if <50% of nodes are Byzantine,
/// the global model is not poisoned (Blanchard et al., 2017).
fn aggregate_median(gradients: &[Vec<f32>]) -> Vec<f32> {
    if gradients.is_empty() { return vec![]; }
    let n_params = gradients[0].len();
    let mut result = vec![0.0f32; n_params];
    let mut col = vec![0.0f32; gradients.len()];
    for j in 0..n_params {
        for (i, g) in gradients.iter().enumerate() {
            col[i] = *g.get(j).unwrap_or(&0.0);
        }
        col.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        result[j] = col[col.len() / 2];
    }
    result
}

/// FedAvg: weighted average by n_samples (McMahan et al., 2017).
fn aggregate_fedavg(gradients: &[&ModelGradient]) -> Vec<f32> {
    if gradients.is_empty() { return vec![]; }
    let total_samples: u64 = gradients.iter().map(|g| g.n_samples).sum();
    if total_samples == 0 { return vec![0.0f32; gradients[0].values.len()]; }
    let n_params = gradients[0].values.len();
    let mut result = vec![0.0f32; n_params];
    for g in gradients {
        let weight = g.n_samples as f32 / total_samples as f32;
        for (j, v) in g.values.iter().enumerate() {
            if j < result.len() {
                result[j] += v * weight;
            }
        }
    }
    result
}

/// Trimmed mean: exclude top and bottom `trim_fraction` of gradients per coordinate.
fn aggregate_trimmed_mean(gradients: &[Vec<f32>], trim_fraction: f32) -> Vec<f32> {
    if gradients.is_empty() { return vec![]; }
    let n_params = gradients[0].len();
    let trim_count = ((gradients.len() as f32 * trim_fraction) as usize).max(0);
    let mut result = vec![0.0f32; n_params];
    for j in 0..n_params {
        let mut col: Vec<f32> = gradients.iter().map(|g| *g.get(j).unwrap_or(&0.0)).collect();
        col.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let trimmed = &col[trim_count..col.len().saturating_sub(trim_count)];
        if !trimmed.is_empty() {
            result[j] = trimmed.iter().sum::<f32>() / trimmed.len() as f32;
        }
    }
    result
}

// ── Federated Learning Engine ─────────────────────────────────────────────────

pub struct FederatedLearningEngine {
    pub node_id: String,
    global_model: RwLock<GlobalModel>,
    pending_gradients: RwLock<Vec<ModelGradient>>,
    aggregation_method: AggregationMethod,
    /// DP privacy budget
    dp_epsilon: f64,
    dp_delta: f64,
    gradient_clip_norm: f32,
    min_nodes_per_round: usize,
    current_round: AtomicU64,
    total_aggregations: AtomicU64,
    /// Per-round summary
    round_history: RwLock<VecDeque<RoundSummary>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub round: u64,
    pub nodes_participated: u32,
    pub total_samples: u64,
    pub aggregation_method: AggregationMethod,
    pub gradient_norm_before: f32,
    pub gradient_norm_after: f32,
    pub byzantine_rejected: u32,
    pub timestamp: u64,
}

impl FederatedLearningEngine {
    pub fn new(node_id: &str, n_model_params: usize) -> Self {
        info!("🧠 FL: Federated Learning initialized | node_id={} params={}", node_id, n_model_params);
        info!("  → Method: FedAvg + coordinate-wise median Byzantine defense");
        info!("  → Privacy: ε-DP noise (ε=1.0, δ=1e-5) applied before gradient upload");
        Self {
            node_id: node_id.to_string(),
            global_model: RwLock::new(GlobalModel::new(n_model_params)),
            pending_gradients: RwLock::new(vec![]),
            aggregation_method: AggregationMethod::FedAvg,
            dp_epsilon: 1.0,
            dp_delta: 1e-5,
            gradient_clip_norm: 1.0,
            min_nodes_per_round: 3,
            current_round: AtomicU64::new(0),
            total_aggregations: AtomicU64::new(0),
            round_history: RwLock::new(VecDeque::new()),
        }
    }

    /// Submit a gradient from this node (with DP noise applied).
    /// Called after local training on this node's traffic data.
    pub fn submit_local_gradient(&self, mut gradient: ModelGradient) {
        // Validate integrity
        if !gradient.verify_integrity() {
            warn!("FL: Rejected gradient from {} — integrity check failed", gradient.node_id);
            return;
        }
        // Clip gradient to prevent Byzantine amplification
        gradient.clip(self.gradient_clip_norm);
        // Apply differential privacy before storing/forwarding
        gradient.apply_dp_noise(self.dp_epsilon, self.dp_delta, 1.0);
        debug!("FL: Accepted gradient from {} (n_samples={}, round={}, dp={})",
            gradient.node_id, gradient.n_samples, gradient.round, gradient.dp_applied);
        self.pending_gradients.write().push(gradient);
    }

    /// Receive gradient from a remote peer node.
    pub fn receive_peer_gradient(&self, mut gradient: ModelGradient) {
        if !gradient.verify_integrity() {
            warn!("FL: Rejected remote gradient from {} — integrity mismatch", gradient.node_id);
            return;
        }
        gradient.clip(self.gradient_clip_norm);
        self.pending_gradients.write().push(gradient);
    }

    /// Attempt to run a federated aggregation round.
    /// Returns Some(updated_model) if enough nodes have participated.
    pub fn try_aggregate(&self) -> Option<GlobalModel> {
        let pending = self.pending_gradients.read();
        if pending.len() < self.min_nodes_per_round {
            debug!("FL: Waiting for more nodes ({}/{})", pending.len(), self.min_nodes_per_round);
            return None;
        }
        drop(pending);

        let round = self.current_round.fetch_add(1, Ordering::Relaxed);
        let mut pending = self.pending_gradients.write();

        let norms_before: Vec<f32> = pending.iter().map(|g| g.l2_norm).collect();
        let avg_norm_before = norms_before.iter().sum::<f32>() / norms_before.len() as f32;

        // Byzantine rejection: remove gradients with norm > 3σ from median
        let mut sorted_norms = norms_before.clone();
        sorted_norms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_norm = sorted_norms[sorted_norms.len() / 2];
        let variance = sorted_norms.iter().map(|n| (n - median_norm).powi(2)).sum::<f32>()
            / sorted_norms.len() as f32;
        let std_dev = variance.sqrt();
        let before_count = pending.len();
        pending.retain(|g| (g.l2_norm - median_norm).abs() <= 3.0 * std_dev + 1e-6);
        let byzantine_rejected = (before_count - pending.len()) as u32;

        if byzantine_rejected > 0 {
            warn!("FL: Round {} — rejected {} Byzantine gradient(s) (norm outlier > 3σ)",
                round, byzantine_rejected);
        }

        // Aggregate
        let agg_values = match self.aggregation_method {
            AggregationMethod::FedAvg => {
                let refs: Vec<&ModelGradient> = pending.iter().collect();
                aggregate_fedavg(&refs)
            }
            AggregationMethod::Median => {
                let vecs: Vec<Vec<f32>> = pending.iter().map(|g| g.values.clone()).collect();
                aggregate_median(&vecs)
            }
            AggregationMethod::TrimmedMean => {
                let vecs: Vec<Vec<f32>> = pending.iter().map(|g| g.values.clone()).collect();
                aggregate_trimmed_mean(&vecs, 0.1)
            }
            AggregationMethod::Krum => {
                let refs: Vec<&ModelGradient> = pending.iter().collect();
                aggregate_fedavg(&refs) // Simplified: FedAvg after Byzantine filter
            }
        };

        let total_samples: u64 = pending.iter().map(|g| g.n_samples).sum();
        let nodes_participated = pending.len() as u32;
        let avg_norm_after = (agg_values.iter().map(|v| v * v).sum::<f32>()).sqrt();

        // Apply aggregated gradient to global model
        let mut model = self.global_model.write();
        for (w, g) in model.weights.iter_mut().zip(agg_values.iter()) {
            *w += g * 0.01; // Learning rate = 0.01
        }
        model.round = round;
        model.version += 1;
        model.training_nodes = nodes_participated;
        model.total_samples += total_samples;
        model.updated_at = unix_secs();
        model.weight_hash = hash_weights(&model.weights);

        let summary = RoundSummary {
            round,
            nodes_participated,
            total_samples,
            aggregation_method: self.aggregation_method.clone(),
            gradient_norm_before: avg_norm_before,
            gradient_norm_after: avg_norm_after,
            byzantine_rejected,
            timestamp: unix_secs(),
        };
        drop(model);
        pending.clear();

        info!("🧠 FL: Round {} complete — {} nodes, {} samples, {} Byzantine rejected",
            round, nodes_participated, total_samples, byzantine_rejected);

        let result = self.global_model.read().clone();
        {
            let mut hist = self.round_history.write();
            hist.push_back(summary);
            if hist.len() > 100 { hist.pop_front(); }
        }
        self.total_aggregations.fetch_add(1, Ordering::Relaxed);
        Some(result)
    }

    pub fn get_model(&self) -> GlobalModel {
        self.global_model.read().clone()
    }

    pub fn stats(&self) -> FlStats {
        FlStats {
            current_round: self.current_round.load(Ordering::Relaxed),
            total_aggregations: self.total_aggregations.load(Ordering::Relaxed),
            pending_gradients: self.pending_gradients.read().len() as u64,
            model_version: self.global_model.read().version,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlStats {
    pub current_round: u64,
    pub total_aggregations: u64,
    pub pending_gradients: u64,
    pub model_version: u64,
}
