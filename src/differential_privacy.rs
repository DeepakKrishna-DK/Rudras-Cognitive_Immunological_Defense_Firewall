#![allow(dead_code, unused_imports, unused_variables)]

//! Differential Privacy — standalone Laplace and Gaussian noise mechanisms with a
//! global privacy budget tracker.  Used by `federated_learning`, `ueba_engine`, and
//! `sbom_engine` when publishing aggregate statistics.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Seeded PRNG — no external `rand` dep required
// (Linear Congruential Generator, period 2^64)
// ─────────────────────────────────────────────────────────────────────────────

struct Lcg64 {
    state: u64,
}

impl Lcg64 {
    fn new(seed: u64) -> Self {
        Lcg64 { state: seed ^ 0x6E37_4985_32A5_B7C3 }
    }

    /// Returns the next pseudo-random u64.
    fn next_u64(&mut self) -> u64 {
        // Knuth multiplicative constants for LCG.
        self.state = self.state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    /// Returns a value in [0.0, 1.0).
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Box-Muller: returns a standard normal sample N(0,1).
    fn next_gaussian(&mut self) -> f64 {
        loop {
            // Avoid log(0) by ensuring u1 > 0.
            let u1 = self.next_f64();
            let u2 = self.next_f64();
            if u1 > 1e-15 {
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                return z;
            }
        }
    }

    /// Returns a sample from Laplace(0, 1) via the inverse-CDF method.
    fn next_laplace(&mut self) -> f64 {
        let u = self.next_f64() - 0.5; // u in (-0.5, 0.5)
        -u.signum() * (1.0 - 2.0 * u.abs()).ln()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Privacy budget tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks cumulative privacy budget consumption according to basic composition.
///
/// Under basic composition, spending (ε₁, δ₁) and (ε₂, δ₂) costs (ε₁+ε₂, δ₁+δ₂).
#[derive(Debug)]
pub struct PrivacyBudgetTracker {
    /// Accumulated ε × 10⁶ stored as integer to avoid floating-point drift.
    epsilon_spent_micro: AtomicI64,
    /// Accumulated δ × 10¹² stored as integer.
    delta_spent_pico: AtomicI64,
    pub max_epsilon: f64,
    pub max_delta: f64,
    pub query_count: AtomicU64,
}

impl PrivacyBudgetTracker {
    pub fn new(max_epsilon: f64, max_delta: f64) -> Self {
        PrivacyBudgetTracker {
            epsilon_spent_micro: AtomicI64::new(0),
            delta_spent_pico: AtomicI64::new(0),
            max_epsilon,
            max_delta,
            query_count: AtomicU64::new(0),
        }
    }

    /// Returns snapshot of current budget consumption.
    pub fn epsilon_spent(&self) -> f64 {
        self.epsilon_spent_micro.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn delta_spent(&self) -> f64 {
        self.delta_spent_pico.load(Ordering::Relaxed) as f64 / 1_000_000_000_000.0
    }

    /// Returns `true` if the requested (ε, δ) would fit within the remaining budget.
    pub fn check(&self, epsilon: f64, delta: f64) -> bool {
        self.epsilon_spent() + epsilon <= self.max_epsilon
            && self.delta_spent() + delta <= self.max_delta
    }

    /// Consume budget for one query.  Returns `false` and logs a warning if over-budget.
    pub fn consume(&self, epsilon: f64, delta: f64) -> bool {
        if !self.check(epsilon, delta) {
            warn!(
                epsilon_spent = %self.epsilon_spent(),
                delta_spent = %self.delta_spent(),
                requested_epsilon = %epsilon,
                max_epsilon = %self.max_epsilon,
                "PrivacyBudgetTracker: budget exhausted, query denied"
            );
            return false;
        }
        let eps_micro = (epsilon * 1_000_000.0) as i64;
        let delta_pico = (delta * 1_000_000_000_000.0) as i64;
        self.epsilon_spent_micro.fetch_add(eps_micro, Ordering::Relaxed);
        self.delta_spent_pico.fetch_add(delta_pico, Ordering::Relaxed);
        self.query_count.fetch_add(1, Ordering::Relaxed);
        debug!(
            epsilon = %epsilon,
            epsilon_total = %self.epsilon_spent(),
            "PrivacyBudgetTracker: budget consumed"
        );
        true
    }

    pub fn remaining_epsilon(&self) -> f64 {
        (self.max_epsilon - self.epsilon_spent()).max(0.0)
    }

    pub fn remaining_delta(&self) -> f64 {
        (self.max_delta - self.delta_spent()).max(0.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Laplace mechanism
// ─────────────────────────────────────────────────────────────────────────────

/// Adds calibrated Laplace noise to achieve (ε, 0)-DP.
///
/// Scale b = sensitivity / ε.
pub struct LaplaceMechanism {
    /// Tracks global budget when `Some`; unchecked if `None`.
    budget: Option<Arc<PrivacyBudgetTracker>>,
    rng: std::cell::RefCell<Lcg64>,
}

impl LaplaceMechanism {
    pub fn new(seed: u64, budget: Option<Arc<PrivacyBudgetTracker>>) -> Self {
        LaplaceMechanism {
            budget,
            rng: std::cell::RefCell::new(Lcg64::new(seed)),
        }
    }

    /// Returns `value + Laplace(0, sensitivity/epsilon)`.
    /// Returns `None` if the privacy budget is exhausted.
    pub fn add_noise(&self, value: f64, sensitivity: f64, epsilon: f64) -> Option<f64> {
        if epsilon <= 0.0 || sensitivity <= 0.0 {
            return None;
        }
        if let Some(ref b) = self.budget {
            if !b.consume(epsilon, 0.0) {
                return None;
            }
        }
        let scale = sensitivity / epsilon;
        let noise = self.rng.borrow_mut().next_laplace() * scale;
        Some(value + noise)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gaussian mechanism
// ─────────────────────────────────────────────────────────────────────────────

/// Adds calibrated Gaussian noise to achieve (ε, δ)-DP.
///
/// Standard deviation σ = sensitivity × √(2 ln(1.25/δ)) / ε.
pub struct GaussianMechanism {
    budget: Option<Arc<PrivacyBudgetTracker>>,
    rng: std::cell::RefCell<Lcg64>,
}

impl GaussianMechanism {
    pub fn new(seed: u64, budget: Option<Arc<PrivacyBudgetTracker>>) -> Self {
        GaussianMechanism {
            budget,
            rng: std::cell::RefCell::new(Lcg64::new(seed)),
        }
    }

    /// Returns `value + N(0, σ²)` where σ is calibrated for (ε, δ)-DP.
    /// Returns `None` if the privacy budget is exhausted.
    pub fn add_noise(&self, value: f64, sensitivity: f64, epsilon: f64, delta: f64) -> Option<f64> {
        if epsilon <= 0.0 || delta <= 0.0 || delta >= 1.0 || sensitivity <= 0.0 {
            return None;
        }
        if let Some(ref b) = self.budget {
            if !b.consume(epsilon, delta) {
                return None;
            }
        }
        let sigma = sensitivity * (2.0 * (1.25 / delta).ln()).sqrt() / epsilon;
        let noise = self.rng.borrow_mut().next_gaussian() * sigma;
        Some(value + noise)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Differentially private histogram
// ─────────────────────────────────────────────────────────────────────────────

/// Releases a differentially private histogram by adding Laplace noise to each bin.
///
/// Calibrated for L1 sensitivity = 1 (each individual contributes at most 1 to one bin).
/// Releases non-negative counts by clamping noise-added values to ≥ 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpHistogram {
    pub epsilon: f64,
    pub bin_labels: Vec<String>,
    pub noisy_counts: Vec<f64>,
    pub true_count: u64,
}

impl DpHistogram {
    /// Build a DP histogram from `counts`.  L1 sensitivity = 1 per bin.
    /// `epsilon` is split evenly across the bins (parallel composition —
    /// since bins are disjoint, the true per-query ε = `epsilon`).
    pub fn release(
        counts: &[(String, u64)],
        epsilon: f64,
        seed: u64,
        budget: Option<Arc<PrivacyBudgetTracker>>,
    ) -> Option<Self> {
        if counts.is_empty() || epsilon <= 0.0 {
            return None;
        }
        // Under parallel composition each bin query costs ε (not ε/n).
        if let Some(ref b) = budget {
            if !b.consume(epsilon, 0.0) {
                return None;
            }
        }
        let mut rng = Lcg64::new(seed);
        let scale = 1.0 / epsilon; // sensitivity=1 → scale = 1/ε
        let true_count: u64 = counts.iter().map(|(_, c)| c).sum();
        let noisy_counts: Vec<f64> = counts
            .iter()
            .map(|(_, c)| {
                let noise = rng.next_laplace() * scale;
                ((*c as f64) + noise).max(0.0)
            })
            .collect();
        let bin_labels = counts.iter().map(|(l, _)| l.clone()).collect();

        Some(DpHistogram {
            epsilon,
            bin_labels,
            noisy_counts,
            true_count,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exponential mechanism
// ─────────────────────────────────────────────────────────────────────────────

/// Exponential mechanism for selecting among discrete candidates.
///
/// Each candidate has a utility score `u_i`.  The mechanism samples candidate `i`
/// with probability proportional to exp(ε × u_i / (2 × sensitivity)).
pub struct ExponentialMechanism {
    rng: std::cell::RefCell<Lcg64>,
}

impl ExponentialMechanism {
    pub fn new(seed: u64) -> Self {
        ExponentialMechanism {
            rng: std::cell::RefCell::new(Lcg64::new(seed)),
        }
    }

    /// Returns the index of the selected candidate.
    pub fn select(&self, utilities: &[f64], sensitivity: f64, epsilon: f64) -> Option<usize> {
        if utilities.is_empty() || epsilon <= 0.0 || sensitivity <= 0.0 {
            return None;
        }
        let scale = epsilon / (2.0 * sensitivity);
        // Softmax-style weighted selection.
        let weights: Vec<f64> = utilities.iter().map(|u| (scale * u).exp()).collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return None;
        }
        let threshold = self.rng.borrow_mut().next_f64() * total;
        let mut cum = 0.0;
        for (i, &w) in weights.iter().enumerate() {
            cum += w;
            if cum >= threshold {
                return Some(i);
            }
        }
        Some(utilities.len() - 1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level DP engine (convenience wrapper)
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience engine bundling all DP primitives with a shared budget tracker.
pub struct DifferentialPrivacyEngine {
    pub budget: Arc<PrivacyBudgetTracker>,
    pub laplace: LaplaceMechanism,
    pub gaussian: GaussianMechanism,
    pub exponential: ExponentialMechanism,
}

impl DifferentialPrivacyEngine {
    /// `max_epsilon` and `max_delta` define the total privacy budget for this engine instance.
    pub fn new(max_epsilon: f64, max_delta: f64) -> Self {
        let budget = Arc::new(PrivacyBudgetTracker::new(max_epsilon, max_delta));
        DifferentialPrivacyEngine {
            laplace: LaplaceMechanism::new(0xD1FF_0001_AAAA_BBBB_u64, Some(Arc::clone(&budget))),
            gaussian: GaussianMechanism::new(0xD1FF_0002_CCCC_DDDD_u64, Some(Arc::clone(&budget))),
            exponential: ExponentialMechanism::new(0xD1FF_0003_EEEE_FFFF_u64),
            budget,
        }
    }

    /// Laplace noise addition with budget tracking.
    pub fn laplace_noise(&self, value: f64, sensitivity: f64, epsilon: f64) -> Option<f64> {
        self.laplace.add_noise(value, sensitivity, epsilon)
    }

    /// Gaussian noise addition with budget tracking.
    pub fn gaussian_noise(&self, value: f64, sensitivity: f64, epsilon: f64, delta: f64) -> Option<f64> {
        self.gaussian.add_noise(value, sensitivity, epsilon, delta)
    }

    /// DP histogram release — parallel composition (budget charged once for full ε).
    pub fn histogram(
        &self,
        counts: &[(String, u64)],
        epsilon: f64,
        seed: u64,
    ) -> Option<DpHistogram> {
        DpHistogram::release(counts, epsilon, seed, Some(Arc::clone(&self.budget)))
    }

    pub fn budget_status(&self) -> BudgetStatus {
        BudgetStatus {
            epsilon_spent: self.budget.epsilon_spent(),
            delta_spent: self.budget.delta_spent(),
            epsilon_remaining: self.budget.remaining_epsilon(),
            delta_remaining: self.budget.remaining_delta(),
            query_count: self.budget.query_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub epsilon_spent: f64,
    pub delta_spent: f64,
    pub epsilon_remaining: f64,
    pub delta_remaining: f64,
    pub query_count: u64,
}


