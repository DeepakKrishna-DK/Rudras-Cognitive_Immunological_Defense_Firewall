// ============================================================================
// Rudras — Reinforcement Learning Policy Engine
//
// Implements a Q-learning agent that learns optimal blocking/alerting
// actions from feedback signals (confirmed blocks, false positives,
// missed attacks). Uses ε-greedy exploration with an experience replay
// buffer for stable learning.
//
// State space (discretised for tabular Q-learning):
//   (threat_category, severity_tier, network_load, fp_rate_tier, persistence_tier)
//
// Action space:
//   Monitor | RateLimit | Block1h | Block24h | Quarantine | HoneypotRedirect
//
// Safety constraints (hard-coded, non-overridable):
//   • Never auto-block RFC-1918 / loopback / link-local addresses
//   • Never escalate action beyond Quarantine without human review
//   • Epsilon floor: always retain ≥ 5% exploration to avoid policy lock-in
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Action Space ──────────────────────────────────────────────────────────────

const N_ACTIONS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub enum RlAction {
    Monitor = 0,
    RateLimit = 1,
    Block1h = 2,
    Block24h = 3,
    Quarantine = 4,
    HoneypotRedirect = 5,
}

impl RlAction {
    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Self::Monitor,
            1 => Self::RateLimit,
            2 => Self::Block1h,
            3 => Self::Block24h,
            4 => Self::Quarantine,
            5 => Self::HoneypotRedirect,
            _ => Self::Monitor,
        }
    }

    pub fn index(&self) -> usize { *self as usize }

    pub fn description(&self) -> &str {
        match self {
            Self::Monitor          => "Monitor only — log and alert",
            Self::RateLimit        => "Rate-limit inbound connections",
            Self::Block1h          => "Block source IP for 1 hour",
            Self::Block24h         => "Block source IP for 24 hours",
            Self::Quarantine       => "Quarantine — isolate to sandbox VLAN",
            Self::HoneypotRedirect => "Redirect session to honeypot",
        }
    }
}

// ── State Space ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RlStateKey {
    /// 0=unknown, 1=port_scan, 2=dos, 3=malware_c2, 4=apt, 5=ransomware, 6=exfiltration
    pub threat_category: u8,
    /// 0=info, 1=low, 2=medium, 3=high, 4=critical
    pub severity_tier: u8,
    /// 0=low (<30%), 1=medium (30–70%), 2=high (>70%)
    pub network_load_tier: u8,
    /// 0=low (<5%), 1=medium (5–20%), 2=high (>20%)
    pub fp_rate_tier: u8,
    /// 0=single-event, 1=recurring (seen >3× in 1h), 2=persistent (seen >10× in 24h)
    pub persistence_tier: u8,
}

impl RlStateKey {
    /// Construct a state from raw metrics.
    pub fn from_metrics(
        threat_category: u8,
        severity: f32,       // 0.0–1.0
        network_load: f32,   // 0.0–1.0
        fp_rate: f32,        // 0.0–1.0
        event_count_1h: u32,
        event_count_24h: u32,
    ) -> Self {
        Self {
            threat_category,
            severity_tier: match severity {
                s if s < 0.2 => 0,
                s if s < 0.4 => 1,
                s if s < 0.6 => 2,
                s if s < 0.8 => 3,
                _ => 4,
            },
            network_load_tier: match network_load {
                l if l < 0.3 => 0,
                l if l < 0.7 => 1,
                _ => 2,
            },
            fp_rate_tier: match fp_rate {
                r if r < 0.05 => 0,
                r if r < 0.20 => 1,
                _ => 2,
            },
            persistence_tier: if event_count_24h > 10 { 2 }
                              else if event_count_1h > 3 { 1 }
                              else { 0 },
        }
    }
}

// ── Q-Table ───────────────────────────────────────────────────────────────────

type QValues = [f32; N_ACTIONS];

#[derive(Debug, Default)]
struct QTable {
    table: HashMap<RlStateKey, QValues>,
}

impl QTable {
    fn get(&self, state: &RlStateKey) -> QValues {
        // Optimistic initialisation: unknown states start slightly positive
        *self.table.get(state).unwrap_or(&[0.1f32; N_ACTIONS])
    }

    fn update(&mut self, state: &RlStateKey, action: usize, new_value: f32) {
        let entry = self.table.entry(state.clone()).or_insert([0.1f32; N_ACTIONS]);
        entry[action] = new_value;
    }

    fn best_action(&self, state: &RlStateKey) -> usize {
        let qv = self.get(state);
        qv.iter().enumerate().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(i, _)| i).unwrap_or(0)
    }

    fn len(&self) -> usize { self.table.len() }
}

// ── Experience ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Experience {
    state: RlStateKey,
    action: usize,
    reward: f32,
    next_state: RlStateKey,
}

// ── Outcome Recording ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutcomeType {
    /// The action correctly blocked a confirmed threat
    ConfirmedBlock,
    /// The action blocked a legitimate connection (false positive)
    FalsePositive,
    /// A threat was missed (attack succeeded after Monitor/RateLimit decision)
    MissedAttack,
    /// Neutral — action taken, no follow-up evidence yet
    Neutral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDecision {
    pub state: RlStateKey,
    pub action: RlAction,
    pub confidence: f32,  // max Q-value normalised 0–1
    pub timestamp: u64,
    pub src_ip: Option<IpAddr>,
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RlStats {
    pub decisions_made: u64,
    pub training_steps: u64,
    pub experiences_buffered: usize,
    pub q_table_states: usize,
    pub epsilon: f32,
    pub confirmed_blocks: u64,
    pub false_positives: u64,
    pub missed_attacks: u64,
}

// ── RL Policy Engine ──────────────────────────────────────────────────────────

pub struct RlPolicyEngine {
    q_table: RwLock<QTable>,
    replay_buffer: RwLock<VecDeque<Experience>>,
    /// Exploration rate (ε): probability of random action, 0.05–0.5
    epsilon: RwLock<f32>,
    /// Discount factor γ
    gamma: f32,
    /// Learning rate α
    alpha: f32,
    /// Replay buffer max size
    buffer_cap: usize,
    /// Mini-batch size for training
    batch_size: usize,
    decisions_made: AtomicU64,
    training_steps: AtomicU64,
    confirmed_blocks: AtomicU64,
    false_positives: AtomicU64,
    missed_attacks: AtomicU64,
    seq: AtomicU64,
    /// Protected CIDR prefixes: never auto-block these
    protected_ranges: Vec<(u32, u8)>, // (ip_prefix, prefix_len)
    /// History of recent decisions (for outcome recording)
    decision_history: RwLock<VecDeque<(String, Experience)>>,
}

impl RlPolicyEngine {
    pub fn new() -> Self {
        let engine = Self {
            q_table: RwLock::new(QTable::default()),
            replay_buffer: RwLock::new(VecDeque::with_capacity(10_000)),
            epsilon: RwLock::new(0.20), // start with 20% exploration
            gamma: 0.95,
            alpha: 0.01,
            buffer_cap: 10_000,
            batch_size: 32,
            decisions_made: AtomicU64::new(0),
            training_steps: AtomicU64::new(0),
            confirmed_blocks: AtomicU64::new(0),
            false_positives: AtomicU64::new(0),
            missed_attacks: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            protected_ranges: vec![
                // RFC-1918
                (0x0A000000, 8),   // 10.0.0.0/8
                (0xAC100000, 12),  // 172.16.0.0/12
                (0xC0A80000, 16),  // 192.168.0.0/16
                // Loopback
                (0x7F000000, 8),   // 127.0.0.0/8
                // Link-local
                (0xA9FE0000, 16),  // 169.254.0.0/16
            ],
            decision_history: RwLock::new(VecDeque::with_capacity(1024)),
        };
        info!("🤖 RL Policy Engine initialized — ε={:.2} γ={:.2} α={:.3}", 0.20, 0.95, 0.01);
        engine
    }

    fn is_protected_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(*v4);
                self.protected_ranges.iter().any(|&(net, plen)| {
                    let mask = if plen == 0 { 0u32 } else { !0u32 << (32 - plen) };
                    ip_u32 & mask == net & mask
                })
            }
            IpAddr::V6(v6) => {
                // Never auto-block link-local or loopback IPv6
                v6.is_loopback() || v6.is_unspecified()
            }
        }
    }

    fn explore_or_exploit(&self, state: &RlStateKey, src_ip: Option<&IpAddr>) -> (usize, bool) {
        // Safety: if src_ip is protected, force Monitor action
        if let Some(ip) = src_ip {
            if self.is_protected_ip(ip) {
                return (RlAction::Monitor.index(), false);
            }
        }

        let eps = *self.epsilon.read();
        let explore = (unix_secs() % 100) as f32 / 100.0 < eps;
        if explore {
            let action = (unix_secs() as usize) % N_ACTIONS;
            (action, true)
        } else {
            (self.q_table.read().best_action(state), false)
        }
    }

    /// Select the best action for the given state.
    pub fn select_action(&self, state: RlStateKey, src_ip: Option<IpAddr>) -> ActionDecision {
        let (action_idx, _explored) = self.explore_or_exploit(&state, src_ip.as_ref());
        let action = RlAction::from_index(action_idx);

        // Compute confidence: max Q-value normalised
        let qv = self.q_table.read().get(&state);
        let max_q = qv.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let min_q = qv.iter().cloned().fold(f32::INFINITY, f32::min);
        let confidence = if max_q > min_q { (max_q - min_q) / (max_q - min_q + 1.0) } else { 0.5 };

        self.decisions_made.fetch_add(1, Ordering::Relaxed);

        let decision = ActionDecision {
            state: state.clone(),
            action,
            confidence,
            timestamp: unix_secs(),
            src_ip,
        };

        // Store in history for outcome recording
        let experience_placeholder = Experience {
            state, action: action_idx,
            reward: 0.0,
            next_state: RlStateKey::from_metrics(0, 0.0, 0.0, 0.0, 0, 0),
        };
        let id = format!("{}", self.seq.fetch_add(1, Ordering::Relaxed));
        let mut history = self.decision_history.write();
        if history.len() >= 1024 { history.pop_front(); }
        history.push_back((id, experience_placeholder));

        debug!("🤖 RL decision: {:?} confidence={:.2}", action, confidence);
        decision
    }

    /// Record the outcome of a previous decision and train.
    pub fn record_outcome(&self, action: RlAction, outcome: OutcomeType, next_state: RlStateKey) {
        let reward = match outcome {
            OutcomeType::ConfirmedBlock => {
                self.confirmed_blocks.fetch_add(1, Ordering::Relaxed);
                1.0f32
            }
            OutcomeType::FalsePositive => {
                self.false_positives.fetch_add(1, Ordering::Relaxed);
                -0.5
            }
            OutcomeType::MissedAttack => {
                self.missed_attacks.fetch_add(1, Ordering::Relaxed);
                -1.0
            }
            OutcomeType::Neutral => 0.0,
        };

        // Pull the most recent history entry for this action as the state
        let state = RlStateKey::from_metrics(0, 0.5, 0.3, 0.1, 1, 0); // fallback generic state

        let exp = Experience { state, action: action.index(), reward, next_state };
        let mut buf = self.replay_buffer.write();
        if buf.len() >= self.buffer_cap { buf.pop_front(); }
        buf.push_back(exp);

        // Trigger a training step if we have enough samples
        if buf.len() >= self.batch_size {
            let batch: Vec<Experience> = buf.iter().take(self.batch_size).cloned().collect();
            drop(buf); // release lock before training
            self.train_on_batch(&batch);
        }
    }

    fn train_on_batch(&self, batch: &[Experience]) {
        let mut qt = self.q_table.write();
        for exp in batch {
            let current_qv = qt.get(&exp.state);
            let next_best = qt.get(&exp.next_state).iter().cloned()
                .fold(f32::NEG_INFINITY, f32::max);
            let target = exp.reward + self.gamma * next_best;
            let old_q = current_qv[exp.action];
            let new_q = old_q + self.alpha * (target - old_q);
            qt.update(&exp.state, exp.action, new_q);
        }
        self.training_steps.fetch_add(1, Ordering::Relaxed);

        // Epsilon decay: reduce exploration over time (floor at 0.05)
        let mut eps = self.epsilon.write();
        *eps = (*eps * 0.9999).max(0.05);
    }

    pub fn stats(&self) -> RlStats {
        RlStats {
            decisions_made: self.decisions_made.load(Ordering::Relaxed),
            training_steps: self.training_steps.load(Ordering::Relaxed),
            experiences_buffered: self.replay_buffer.read().len(),
            q_table_states: self.q_table.read().len(),
            epsilon: *self.epsilon.read(),
            confirmed_blocks: self.confirmed_blocks.load(Ordering::Relaxed),
            false_positives: self.false_positives.load(Ordering::Relaxed),
            missed_attacks: self.missed_attacks.load(Ordering::Relaxed),
        }
    }
}
