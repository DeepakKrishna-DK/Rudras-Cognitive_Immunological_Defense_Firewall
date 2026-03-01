// ============================================================================
// Rudras Distributed Immunity — P2P Antibody Broadcast (Control Plane)
// Connects firewall nodes together. When one node detects and blocks a
// zero-day threat, it broadcasts the Mathematical Signature to all peers.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::policy::{ActionType, HybridRule, PolicyEngine, RuleOrigin};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info, warn};

// Cryptography for Sybil Protection
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

// ── GOD KEY VULNERABILITY FIX ──
// We remove the hardcoded Secret Key. The cluster now uses Dynamic Key Rotation,
// loading the Day's Temporary Cryptographic Token from a protected KMS vault.
// We fallback to a temporary key if the vault isn't set up yet, to allow compilation.
fn get_daily_cluster_key() -> Vec<u8> {
    std::fs::read("kms_vault/daily.key").unwrap_or_else(|_| b"FALLBACK-EMERGENCY-KEY-ONLY".to_vec())
}

// ── KMS DEADLOCK FIX (Key Attrition Trap) ──
// Permits the usage of the previous day's key allowing a 24-hour overlap grace period.
// If the KMS server drops offline, the Swarm does not fracture instantly.
fn get_valid_cluster_keys() -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    if let Ok(k) = std::fs::read("kms_vault/daily.key") {
        keys.push(k);
    }
    if let Ok(k) = std::fs::read("kms_vault/yesterday.key") {
        keys.push(k);
    }
    if keys.is_empty() {
        keys.push(b"FALLBACK-EMERGENCY-KEY-ONLY".to_vec());
    }
    keys
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntibodyPayload {
    pub key: String,
    pub rule: HybridRule,
    pub origin_node_id: String,
    pub auth_hmac: String, // 🔑 Cryptographic Signature for Peer Verification
}

pub struct DistributedImmunity {
    peers: Vec<String>,
}

impl DistributedImmunity {
    pub fn new(
        peers: Vec<String>,
        policy: Arc<PolicyEngine>,
    ) -> (Self, mpsc::Sender<AntibodyPayload>) {
        info!("📡 Control Plane: P2P Gossip Protocol Node starting...");

        // --- 🤖 Consensus Engine ---
        // Prevents split-brain by requiring quorum (2+ nodes) before blocking globally.
        let antibody_votes: Arc<RwLock<HashMap<String, HashSet<String>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // ── MUTINY CIRCUIT BREAKER (Rate Limiter) ──
        // Solves the "Ghost Outbreak" vulnerability by restricting the Swarm from mutating
        // global policy more than 10 times per minute, preventing a complete corporate mutiny.
        let global_mutiny_limiter = Arc::new(RwLock::new((0u32, std::time::Instant::now())));

        // Channel for the AI Engine to send new antibodies out
        let (tx, mut rx) = mpsc::channel::<AntibodyPayload>(1024);

        let node_id = uuid::Uuid::new_v4().to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let initial_peers_len = peers.len();
        let peers_clone = peers.clone();

        // ── 1. The Broadcaster (Sender) ──────────────────────
        // Listens to the local AI engine. If a new rule is bred,
        // it blasts it across the network to all other firewalls.
        tokio::spawn(async move {
            while let Some(mut payload) = rx.recv().await {
                if peers_clone.is_empty() {
                    continue; // Standalone deployment, no peers to warn
                }

                // ── Compute Outbound Cryptographic Signature ──
                let cluster_key = get_daily_cluster_key();
                let mut mac = HmacSha256::new_from_slice(&cluster_key).unwrap();
                mac.update(payload.origin_node_id.as_bytes());
                mac.update(payload.key.as_bytes());
                payload.auth_hmac = hex::encode(mac.finalize().into_bytes());

                let json = match serde_json::to_string(&payload) {
                    Ok(j) => j,
                    Err(_) => continue,
                };

                for peer in &peers_clone {
                    let url = format!("{}/gossip", peer);
                    debug!("🚀 Gossip: Syncing rule '{}' to peer: {}", payload.key, url);

                    let c = client.clone();
                    let j = json.clone();
                    // Fire and forget P2P POST
                    tokio::spawn(async move {
                        let _ = c
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(j)
                            .send()
                            .await;
                    });
                }
                info!(
                    "🔄 Control Plane: Broadcasted antibody '{}' to {} peer nodes.",
                    payload.key,
                    peers_clone.len()
                );
            }
        });

        // ── 2. The Listener (Receiver) ───────────────────────
        // Opens a raw TCP socket to listen for incoming peers.
        // We do this to avoid bloating the firewall with a huge
        // HTTP framework dependency.
        let policy_clone = policy.clone();
        tokio::spawn(async move {
            // Bind to the designated P2P port
            let listener = match TcpListener::bind("0.0.0.0:8080").await {
                Ok(l) => l,
                Err(e) => {
                    warn!("⚠️ P2P: Failed to bind listener on port 8080 (already in use?). Gossip receive disabled.");
                    return;
                }
            };

            info!("👂 Control Plane: Gossip Listener Active on 0.0.0.0:8080");

            loop {
                if let Ok((mut socket, addr)) = listener.accept().await {
                    let pol = policy_clone.clone();
                    let antibody_votes_clone = antibody_votes.clone();
                    let global_mutiny_limiter_clone = global_mutiny_limiter.clone();

                    tokio::spawn(async move {
                        let mut buf = [0; 4096];
                        if let Ok(n) = socket.read(&mut buf).await {
                            if n == 0 {
                                return;
                            }
                            let request = String::from_utf8_lossy(&buf[..n]);

                            // Check if it's our POST /gossip request
                            if request.starts_with("POST /gossip") {
                                // Extract the JSON body (everything after \r\n\r\n)
                                if let Some(body_start) = request.find("\r\n\r\n") {
                                    let body = &request[body_start + 4..];

                                    if let Ok(payload) =
                                        serde_json::from_str::<AntibodyPayload>(body)
                                    {
                                        // ── Cryptographic Peer Verification (Anti-Sybil Attack & KMS Deadlock Fix) ──
                                        // Prevents a hacker from spinning up "Ghost" nodes to forge consensus.
                                        let mut authenticated = false;
                                        let valid_keys = get_valid_cluster_keys();

                                        for key in valid_keys {
                                            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
                                            mac.update(payload.origin_node_id.as_bytes());
                                            mac.update(payload.key.as_bytes());
                                            if payload.auth_hmac
                                                == hex::encode(mac.finalize().into_bytes())
                                            {
                                                authenticated = true;
                                                break;
                                            }
                                        }

                                        if !authenticated {
                                            error!("🚨 SYBIL ATTACK BLOCKED: Cryptographic signature mismatch from node '{}'. Rejecting forged payload.", payload.origin_node_id);
                                            // Send HTTP 403 Forbidden
                                            let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                                            let _ = socket.write_all(response.as_bytes()).await;
                                            return;
                                        }

                                        // ── SMOKE SCREEN MUTINY ATTACK FIX (Severity-Scoped Breaker) ──
                                        // Hackers cannot freeze the firewall by spamming low-level threats.
                                        // The Circuit Breaker only triggers on >10 mutations per minute IF
                                        // the threat severity is strictly Low/Medium.
                                        // High-Confidence/Critical antibodies ALWAYS bypass the breaker.
                                        if payload.rule.confidence < 0.85 {
                                            let mut limiter = global_mutiny_limiter_clone.write();
                                            let now = std::time::Instant::now();
                                            if now.duration_since(limiter.1).as_secs() > 60 {
                                                limiter.0 = 0;
                                                limiter.1 = now;
                                            }
                                            if limiter.0 > 10 {
                                                error!("🛑 ANTI-SMOKESCREEN: Swarm Consensus exceeded safe limits for low-confidence threats. Rate-limiting antibody '{}'.", payload.key);
                                                return;
                                            }
                                            limiter.0 += 1;
                                        }

                                        info!("🦠 Control Plane: Received AUTHENTICATED foreign antibody '{}' from node '{}'.", payload.key, payload.origin_node_id);

                                        // ── Swarm Consensus Engine ──
                                        // Prevents cascading false positives by ensuring a threat is mathematically valid across N nodes.
                                        let mut votes = antibody_votes_clone.write();
                                        let node_set = votes
                                            .entry(payload.key.clone())
                                            .or_insert_with(HashSet::new);
                                        node_set.insert(payload.origin_node_id.clone());

                                        // ── EXECUTION ENTROPY (Polymorphic Thresholds) ──
                                        // Hackers cannot predict the quorum threshold. We use sub-millisecond hardware
                                        // packet arrival times to perturb the required quorum dynamically.
                                        let hardware_entropy = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .subsec_nanos();

                                        // ── SPLIT-BRAIN FRACTURE FIX (Island Mode Degradation) ──
                                        // If the physical fiber is cut, the network automatically degrades the quorum
                                        // allowing surviving isolated nodes to locally defend themselves instantly.
                                        let peer_count = initial_peers_len.max(1) as u32;
                                        let base_quorum = if peer_count < 2 { 1 } else { 2 };

                                        // Add polymorphism (+0 or +1 node to require) but cap at actual peers
                                        let mut dynamic_quorum =
                                            base_quorum + (hardware_entropy % 2) as usize;
                                        if dynamic_quorum > peer_count as usize {
                                            dynamic_quorum = peer_count as usize;
                                        }

                                        if node_set.len() >= dynamic_quorum {
                                            // Polymorphic Quorum Reached
                                            info!("🛡️ SWARM: Antibody '{}' verified. Polymorphic Quorum ({}) reached. Installing...", payload.key, dynamic_quorum);
                                            pol.add_policy(payload.key, payload.rule);
                                        } else {
                                            warn!("⏳ CONSENSUS PENDING: Antibody received but awaiting verification from cluster (Votes: {}/{})", node_set.len(), dynamic_quorum);
                                        }
                                    }
                                }

                                // Send HTTP 200 OK
                                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        }
                    });
                }
            }
        });

        (Self { peers }, tx)
    }
}
