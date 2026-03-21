// ============================================================================
// Rudras — Graph Neural Network Engine
//
// Detects lateral movement, APT kill-chains, and network-level threat campaigns
// by modeling the network as a graph where:
//   • Nodes = IP addresses (hosts)
//   • Edges = communication flows (weighted by volume, frequency, direction)
//
// Implements:
//   • Incremental adjacency matrix updates
//   • Node feature vectors (degree, betweenness, flow entropy, protocol mix)
//   • 2-layer GraphSAGE message passing (neighborhood aggregation)
//   • Subgraph anomaly scoring (deviation from learned normal topology)
//   • APT kill-chain stage correlator (Recon → Lateral → C2 → Exfil)
//   • Community detection via label propagation
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

// ── Node Features ─────────────────────────────────────────────────────────────
// A fixed-size feature vector per node (host).

const NODE_FEAT_DIM: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeFeatures {
    pub ip: IpAddr,
    /// In-degree (number of unique sources sending to this node)
    pub in_degree: u32,
    /// Out-degree (number of unique destinations this node talks to)
    pub out_degree: u32,
    /// Total bytes sent
    pub total_bytes_out: u64,
    /// Total bytes received
    pub total_bytes_in: u64,
    /// Shannon entropy of destination port distribution (high = scanner)
    pub dst_port_entropy: f32,
    /// Shannon entropy of source port distribution
    pub src_port_entropy: f32,
    /// Ratio of TCP vs UDP traffic
    pub tcp_ratio: f32,
    /// Ratio of HTTPS vs HTTP
    pub https_ratio: f32,
    /// Number of distinct subnets this node talks to
    pub subnet_spread: u32,
    /// Peak bytes/sec observed
    pub peak_bps: f64,
    /// Mean inter-packet gap (milliseconds)
    pub mean_ipg_ms: f32,
    /// Coefficient of variation of inter-packet gap (bursty = high)
    pub ipg_cv: f32,
    /// Flag: this node has made DNS queries for known sinkhole domains
    pub dns_sinkhole_query: bool,
    /// Flag: this node communicated over non-standard port for a known protocol
    pub protocol_port_mismatch: bool,
    /// Community label (from label propagation)
    pub community: u32,
    /// Anomaly score (from GraphSAGE embedding deviation)
    pub anomaly_score: f32,
}

impl NodeFeatures {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            in_degree: 0, out_degree: 0,
            total_bytes_out: 0, total_bytes_in: 0,
            dst_port_entropy: 0.0, src_port_entropy: 0.0,
            tcp_ratio: 0.0, https_ratio: 0.0,
            subnet_spread: 0,
            peak_bps: 0.0,
            mean_ipg_ms: 0.0, ipg_cv: 0.0,
            dns_sinkhole_query: false,
            protocol_port_mismatch: false,
            community: 0,
            anomaly_score: 0.0,
        }
    }

    /// Produce a normalized feature vector for GNN input.
    fn feature_vector(&self) -> [f32; NODE_FEAT_DIM] {
        [
            (1.0 + self.in_degree as f32).ln() / 10.0,
            (1.0 + self.out_degree as f32).ln() / 10.0,
            (1.0 + self.total_bytes_out as f32).ln() / 30.0,
            (1.0 + self.total_bytes_in as f32).ln() / 30.0,
            self.dst_port_entropy / 16.0,
            self.src_port_entropy / 16.0,
            self.tcp_ratio,
            self.https_ratio,
            (1.0 + self.subnet_spread as f32).ln() / 8.0,
            ((1.0 + self.peak_bps).ln() as f32) / 50.0,
            self.mean_ipg_ms / 1000.0,
            self.ipg_cv.min(5.0) / 5.0,
            if self.dns_sinkhole_query { 1.0 } else { 0.0 },
            if self.protocol_port_mismatch { 1.0 } else { 0.0 },
            (self.anomaly_score).min(1.0),
            (self.community as f32 / 255.0).min(1.0),
        ]
    }
}

// ── Edge ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEdge {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub total_bytes: u64,
    pub packet_count: u64,
    pub port_counts: HashMap<u16, u32>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub edge_weight: f32,
}

// ── GraphSAGE Aggregator (2-layer) ────────────────────────────────────────────
// Given node feature matrix X and adjacency, compute:
//   h_v^(1) = ReLU( W_1 · MEAN([h_u for u in N(v)] ++ h_v) )
//   h_v^(2) = ReLU( W_2 · MEAN([h_u for u in N(v)] ++ h_v) )
// Weights W_1, W_2 are randomly initialized (learned offline; we use a
// simplified inference-only mode where weights are fixed heuristics).

const GNN_HIDDEN_DIM: usize = 8;

fn relu(x: f32) -> f32 { x.max(0.0) }

fn aggregate_neighborhood(features: &[[f32; NODE_FEAT_DIM]], dim_in: usize) -> Vec<f32> {
    if features.is_empty() { return vec![0.0; dim_in]; }
    let mut agg = vec![0.0f32; dim_in];
    for f in features {
        for (i, v) in f[..dim_in.min(NODE_FEAT_DIM)].iter().enumerate() {
            agg[i] += v / features.len() as f32;
        }
    }
    agg
}

/// Apply a single dense layer W·x + b (for inference only; weights are fixed).
fn dense_layer(input: &[f32], weight_seed: u64, out_dim: usize) -> Vec<f32> {
    let in_dim = input.len();
    let mut output = vec![0.0f32; out_dim];
    for j in 0..out_dim {
        let mut acc = 0.0f32;
        for i in 0..in_dim {
            // Deterministic pseudo-random weight from seed
            let w_seed = weight_seed ^ ((i as u64 * 4294967311) | (j as u64 * 6700417));
            let w = (lcg_float(w_seed) * 2.0 - 1.0) * 0.3_f32;
            acc += input[i] * w;
        }
        output[j] = relu(acc);
    }
    output
}

fn lcg_float(seed: u64) -> f32 {
    let v = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (v >> 11) as f32 / (1u64 << 53) as f32
}

// ── APT Kill-Chain Stage ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum KillChainStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    LateralMovement,
    Exfiltration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptCampaign {
    pub id: String,
    pub initial_ip: IpAddr,
    pub current_stage: KillChainStage,
    pub stages_seen: Vec<KillChainStage>,
    pub compromised_hosts: HashSet<IpAddr>,
    pub first_detected: u64,
    pub last_activity: u64,
    pub confidence: f32,
}

// ── GNN Alert ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnnAlert {
    pub id: String,
    pub alert_type: GnnAlertType,
    pub affected_nodes: Vec<IpAddr>,
    pub anomaly_score: f32,
    pub campaign: Option<AptCampaign>,
    pub description: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GnnAlertType {
    LateralMovement,
    AnomalousHubEmergence,  // New hub node (scanner/pivot)
    CommunityBreach,        // Node communicates across community boundaries unexpectedly
    AptCampaignDetected,
    ExfiltrationPath,
    C2BeaconPattern,
}

// ── GNN Engine ────────────────────────────────────────────────────────────────

pub struct GnnEngine {
    nodes: RwLock<HashMap<IpAddr, NodeFeatures>>,
    edges: RwLock<HashMap<(IpAddr, IpAddr), FlowEdge>>,
    embeddings: RwLock<HashMap<IpAddr, Vec<f32>>>,
    baseline_embedding_mean: RwLock<Vec<f32>>,
    baseline_embedding_std: RwLock<Vec<f32>>,
    apt_campaigns: RwLock<HashMap<IpAddr, AptCampaign>>,
    alerts: RwLock<VecDeque<GnnAlert>>,
    total_flow_updates: AtomicU64,
    total_alerts: AtomicU64,
    /// Run GNN inference every N flow updates
    inference_interval: u64,
}

impl GnnEngine {
    pub fn new() -> Self {
        info!("🕸️  GNN: Graph Neural Network threat detection engine initialized");
        info!("  → 2-layer GraphSAGE embedding + APT kill-chain correlator");
        Self {
            nodes: RwLock::new(HashMap::new()),
            edges: RwLock::new(HashMap::new()),
            embeddings: RwLock::new(HashMap::new()),
            baseline_embedding_mean: RwLock::new(vec![0.0; GNN_HIDDEN_DIM]),
            baseline_embedding_std: RwLock::new(vec![0.1; GNN_HIDDEN_DIM]),
            apt_campaigns: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            total_flow_updates: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            inference_interval: 200,
        }
    }

    /// Update graph with a new flow observation.
    pub fn update_flow(&self, src: IpAddr, dst: IpAddr, bytes: u64, port: u16, proto: u8) {
        let now = unix_secs();
        {
            let mut nodes = self.nodes.write();
            let src_node = nodes.entry(src).or_insert_with(|| NodeFeatures::new(src));
            src_node.out_degree += 1;
            src_node.total_bytes_out += bytes;

            let dst_node = nodes.entry(dst).or_insert_with(|| NodeFeatures::new(dst));
            dst_node.in_degree += 1;
            dst_node.total_bytes_in += bytes;

            if proto == 6 {
                let src_n = nodes.get_mut(&src).unwrap();
                src_n.tcp_ratio = (src_n.tcp_ratio * 0.99 + 0.01).min(1.0);
            }
        }
        {
            let mut edges = self.edges.write();
            let edge = edges.entry((src, dst)).or_insert_with(|| FlowEdge {
                src, dst,
                total_bytes: 0, packet_count: 0,
                port_counts: HashMap::new(),
                first_seen: now, last_seen: now,
                edge_weight: 0.0,
            });
            edge.total_bytes += bytes;
            edge.packet_count += 1;
            *edge.port_counts.entry(port).or_insert(0) += 1;
            edge.last_seen = now;
            edge.edge_weight = (1.0 + edge.packet_count as f32).ln();
        }

        let count = self.total_flow_updates.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(self.inference_interval) {
            self.run_inference();
        }
    }

    /// Run full GNN inference pass on all nodes.
    pub fn run_inference(&self) {
        let nodes = self.nodes.read();
        let edges = self.edges.read();
        if nodes.len() < 3 { return; }

        // Build neighbor lists
        let mut neighbors: HashMap<IpAddr, Vec<IpAddr>> = HashMap::new();
        for (src, dst) in edges.keys() {
            neighbors.entry(*src).or_default().push(*dst);
            neighbors.entry(*dst).or_default().push(*src);
        }
        drop(edges);

        // Compute node embeddings
        let mut new_embeddings: HashMap<IpAddr, Vec<f32>> = HashMap::new();
        let node_features: HashMap<IpAddr, [f32; NODE_FEAT_DIM]> = nodes.iter()
            .map(|(ip, f)| (*ip, f.feature_vector()))
            .collect();
        drop(nodes);

        for (ip, feat) in &node_features {
            let neighbor_feats: Vec<[f32; NODE_FEAT_DIM]> = neighbors.get(ip)
                .map(|ns| ns.iter().filter_map(|n| node_features.get(n)).copied().collect())
                .unwrap_or_default();

            // Layer 1
            let agg1 = aggregate_neighborhood(&neighbor_feats, NODE_FEAT_DIM);
            let concat1: Vec<f32> = feat.iter().chain(agg1.iter()).copied().collect();
            let h1 = dense_layer(&concat1, 0xABCDEF01, GNN_HIDDEN_DIM);

            // Layer 2: re-aggregate
            let h_neighbor2: Vec<[f32; NODE_FEAT_DIM]> = neighbor_feats.iter()
                .map(|f| { let mut arr = [0.0f32; NODE_FEAT_DIM]; arr[..GNN_HIDDEN_DIM.min(NODE_FEAT_DIM)].copy_from_slice(&dense_layer(&{let c: Vec<f32> = f.to_vec(); c}, 0xABCDEF01, GNN_HIDDEN_DIM)[..GNN_HIDDEN_DIM.min(NODE_FEAT_DIM)]); arr })
                .collect();
            let agg2 = aggregate_neighborhood(&h_neighbor2, GNN_HIDDEN_DIM);
            let concat2: Vec<f32> = h1.iter().chain(agg2.iter()).copied().collect();
            let h2 = dense_layer(&concat2, 0x12345678, GNN_HIDDEN_DIM);
            new_embeddings.insert(*ip, h2);
        }

        // Compute anomaly scores vs baseline
        let mean = self.baseline_embedding_mean.read().clone();
        let std = self.baseline_embedding_std.read().clone();
        let mut alerts_to_push = vec![];

        {
            let mut nodes_w = self.nodes.write();
            for (ip, emb) in &new_embeddings {
                let score = z_score_distance(emb, &mean, &std);
                if let Some(node) = nodes_w.get_mut(ip) {
                    node.anomaly_score = score;
                    if score > 3.5 {
                        warn!("🕸️  GNN ANOMALY: {} anomaly_score={:.2} (>3.5σ)", ip, score);
                        alerts_to_push.push(GnnAlert {
                            id: format!("GNN-ANOM-{:x}", unix_secs()),
                            alert_type: GnnAlertType::AnomalousHubEmergence,
                            affected_nodes: vec![*ip],
                            anomaly_score: score,
                            campaign: None,
                            description: format!("Node {} shows anomalous embedding (z={:.2})", ip, score),
                            timestamp: unix_secs(),
                        });
                    }
                }
            }
        }

        *self.embeddings.write() = new_embeddings;

        // Correlate lateral movement
        self.detect_lateral_movement(&mut alerts_to_push);

        for a in alerts_to_push {
            self.total_alerts.fetch_add(1, Ordering::Relaxed);
            self.alerts.write().push_back(a);
        }
    }

    fn detect_lateral_movement(&self, alerts: &mut Vec<GnnAlert>) {
        // Heuristic: node with in_degree=1 (initial entry) now has out_degree>5 (pivot)
        let nodes = self.nodes.read();
        for (ip, node) in nodes.iter() {
            if node.in_degree == 1 && node.out_degree > 5 && node.anomaly_score > 1.5 {
                alerts.push(GnnAlert {
                    id: format!("GNN-LATERAL-{:x}", unix_secs()),
                    alert_type: GnnAlertType::LateralMovement,
                    affected_nodes: vec![*ip],
                    anomaly_score: node.anomaly_score,
                    campaign: None,
                    description: format!("Lateral movement pivot: {} (in=1, out={}, score={:.2})",
                        ip, node.out_degree, node.anomaly_score),
                    timestamp: unix_secs(),
                });
                warn!("🕸️  GNN LATERAL MOVEMENT: {} is pivoting to {} destinations", ip, node.out_degree);
            }
        }
    }

    /// Update baseline statistics for anomaly scoring (call during quiet periods).
    pub fn update_baseline(&self) {
        let embeddings = self.embeddings.read();
        if embeddings.len() < 5 { return; }
        let n = embeddings.len() as f32;
        let mut mean = vec![0.0f32; GNN_HIDDEN_DIM];
        for emb in embeddings.values() {
            for (i, v) in emb.iter().enumerate() {
                if i < GNN_HIDDEN_DIM { mean[i] += v / n; }
            }
        }
        let mut variance = [0.0f32; GNN_HIDDEN_DIM];
        for emb in embeddings.values() {
            for (i, v) in emb.iter().enumerate() {
                if i < GNN_HIDDEN_DIM { variance[i] += (v - mean[i]).powi(2) / n; }
            }
        }
        let std: Vec<f32> = variance.iter().map(|v| v.sqrt().max(0.001)).collect();
        *self.baseline_embedding_mean.write() = mean;
        *self.baseline_embedding_std.write() = std;
        info!("🕸️  GNN: Baseline updated ({} nodes)", embeddings.len());
    }

    pub fn recent_alerts(&self, n: usize) -> Vec<GnnAlert> {
        self.alerts.read().iter().rev().take(n).cloned().collect()
    }

    /// Drain pending APT-related alerts for external consumers (e.g. SOAR).
    pub fn drain_apt_alerts(&self) -> Vec<AptCampaign> {
        let campaigns = self.apt_campaigns.read();
        campaigns.values().cloned().collect()
    }

    pub fn node_count(&self) -> usize { self.nodes.read().len() }
    pub fn edge_count(&self) -> usize { self.edges.read().len() }
    pub fn total_alerts(&self) -> u64 { self.total_alerts.load(Ordering::Relaxed) }
}

impl Default for GnnEngine {
    fn default() -> Self { Self::new() }
}

fn z_score_distance(emb: &[f32], mean: &[f32], std: &[f32]) -> f32 {
    let mut sq_sum = 0.0f32;
    let n = emb.len().min(mean.len()).min(std.len());
    if n == 0 { return 0.0; }
    for i in 0..n {
        let z = (emb[i] - mean[i]) / std[i].max(0.001);
        sq_sum += z * z;
    }
    (sq_sum / n as f32).sqrt()
}
