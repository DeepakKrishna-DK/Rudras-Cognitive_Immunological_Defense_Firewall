# 3.2 AI and Machine Learning Systems

---

## Abstract

Rudras v4.0 implements a nine-module AI/ML stack covering four distinct learning paradigms: behavioral baseline modeling (EMA/statistical), ensemble anomaly detection (isolation forest, autoencoder), graph-theoretic topology analysis (GNN), and reinforcement learning for adaptive threshold optimization. No module requires pre-labeled training data — all are fully unsupervised, learning from the live traffic stream. This document provides a complete technical reference for each module.

---

## 1. AI Engine — EMA Behavioral Baseline

**Source File:** `src/ai_engine.rs`  
**Paradigm:** Statistical / Time-series anomaly detection  
**Learning Type:** Unsupervised, online (learns from live traffic)

### 1.1 Design Philosophy

The AI engine is inspired by the biological immune system's concept of "self" vs. "non-self". Every host on the network has a unique behavioral fingerprint — its normal operating pattern. The AI engine captures this fingerprint on first contact and tracks deviations from it. When a host's behavior diverges significantly from its established fingerprint, a threat is presumed.

### 1.2 Feature Vector

For each source IP, the AI engine tracks the following behavioral features:

| Feature                          | Description                      | Normal Range  |
| -------------------------------- | -------------------------------- | ------------- |
| `packets_per_sec`                | Packet transmission rate         | 1–1000        |
| `bytes_per_sec`                  | Byte transmission rate           | 100B/s–10MB/s |
| `new_connections_per_sec`        | TCP SYN rate                     | 0–50          |
| `unique_dst_ports` (1min window) | Distinct destination ports       | 1–20          |
| `unique_dst_ips` (1min window)   | Distinct destination IPs         | 1–50          |
| `avg_packet_size`                | Mean packet payload size         | 40–1460 bytes |
| `syn_ack_ratio`                  | Ratio of SYN to ACK packets      | 0.0–0.5       |
| `icmp_rate`                      | ICMP packet rate                 | 0–10          |
| `dns_query_rate`                 | DNS query rate                   | 0–100/min     |
| `entropy`                        | Shannon entropy of payload bytes | 3.0–7.5       |

### 1.3 Immutable Anchor

The first observation of a new IP creates the **Immutable Anchor** — a snapshot of that IP's behavioral state. This anchor is immutable: it is set once and never changes. It represents "what this host looked like when it was first seen and presumably benign".

An attacker who gradually shifts behavior to avoid the EMA-tracking detector cannot escape the Immutable Anchor — no matter how slowly the behavior changes, it will eventually deviate far from the original anchor.

### 1.4 EMA Calculation

The Exponential Moving Average smooths the feature vector over time:

$$EMA_t = \alpha \cdot X_t + (1-\alpha) \cdot EMA_{t-1}$$

Where:

- $\alpha$ = `ema_alpha` (default 0.3) — higher values mean more weight on recent observations
- $X_t$ = current measured feature values
- $EMA_{t-1}$ = previous EMA value

### 1.5 Deviation Score Computation

The deviation score is the normalized distance between the current EMA and the immutable anchor:

$$deviation = \frac{|EMA_{current} - anchor|}{anchor + \epsilon}$$

Where $\epsilon = 10^{-9}$ prevents division by zero. The deviation is computed per-feature and the maximum across all features is taken as the summary score. A future enhancement (v4.1) will use Mahalanobis distance to account for feature correlation.

### 1.6 Graduated Response

| Score Range | Action     | Example Trigger                   |
| ----------- | ---------- | --------------------------------- |
| 0.0–0.54    | ALLOW      | Normal traffic                    |
| 0.55–0.69   | ALERT      | Slightly elevated connection rate |
| 0.70–0.79   | QUARANTINE | Port scanning behavior            |
| 0.80+       | BLOCK      | Confirmed lateral movement, scan  |

---

## 2. CyberImmune Engine

**Source File:** `src/cyber_immune.rs`  
**Paradigm:** Biological immune system metaphor  
**Learning Type:** Unsupervised, pattern reinforcement

### 2.1 The Biological Metaphor

The CyberImmune module extends the AI engine's behavioral model using a biological immunity metaphor:

- **Antigens:** Behavioral signatures of detected malicious activity (packet rate spikes, port scan patterns)
- **Antibodies:** Detection rules automatically generated from confirmed-malicious behavioral patterns
- **Memory Cells:** Long-term records of previously seen attacker signatures (even after the attacker's IP changes)
- **Vaccination:** When a new threat is confirmed, an "antibody" (rule) is auto-generated and distributed via swarm gossip to all peer nodes

### 2.2 Auto-Generated Detection Rules

When the AI engine confirms a block decision (score > 0.80), the CyberImmune module extracts the behavioral pattern that triggered it and creates an "antibody":

```
New antibody from event at 2026-03-08T10:45:23+05:30:
  pattern: {
    syn_rate_spike: > 150/sec,
    unique_dst_ports: > 500 in 1 minute,
    unique_dst_ips: > 200 in 1 minute
  }
  class: "network_reconnaissance"
  confidence: 0.92
  propagate_to_swarm: true
```

This antibody is broadcast to all peer nodes in the swarm, which can then apply it to traffic matching the same pattern even if they haven't seen the original attacker IP.

### 2.3 Immune Memory

Confirmed-malicious behavioral fingerprints are stored in a `Vec<ThreatSignature>` in memory. When a new connection arrives with behavioral characteristics matching a historical threat signature — even from a different IP — the CyberImmune module flags it with an elevated suspicion score.

This handles threat actors who:

- Rotate IP addresses (different IP, same malware behavior)
- Use botnets (many IPs, same traffic pattern)
- Resume attacks after IP block expiry

---

## 3. Advanced ML Engine

**Source File:** `src/advanced_ml.rs`  
**Paradigm:** Multi-model ensemble anomaly detection  
**Models:** Isolation Forest + Autoencoder + Statistical baseline

### 3.1 Ensemble Architecture

Rather than relying on a single ML model, `advanced_ml.rs` runs three complementary models and takes a weighted vote:

| Model                    | Anomaly Type Detected                             | False Positive Rate |
| ------------------------ | ------------------------------------------------- | ------------------- |
| **Isolation Forest**     | Point anomalies (single-packet oddities)          | Low                 |
| **Autoencoder**          | Sequential pattern anomalies (multi-packet flows) | Medium              |
| **Statistical Baseline** | Volume/rate anomalies                             | Very Low            |

### 3.2 Isolation Forest

The isolation forest algorithm partitions the feature space by randomly selecting a feature and a random split point. Anomalous points (which occupy sparse regions of feature space) are isolated in fewer partitions than normal points.

The anomaly score for a sample is:

$$score(x, n) = 2^{-\frac{E[h(x)]}{c(n)}}$$

Where $E[h(x)]$ is the average path length across trees and $c(n)$ is the average path length of an unsuccessful search in a binary search tree of $n$ nodes.

In Rudras, the Isolation Forest is retrained on a rolling window of 10,000 recent flow observations every 5 minutes.

### 3.3 Autoencoder-Based Anomaly Detection

The autoencoder is a neural network trained to reconstruct its input. Normal traffic patterns can be reconstructed accurately; anomalous patterns cannot. The reconstruction error is the anomaly score.

Architecture:

```
Input: 10-dimensional feature vector (the feature vector from Section 1.2)
Encoder: 10 → 6 → 4 (ReLU activation)
Bottleneck: 4-dimensional latent representation
Decoder: 4 → 6 → 10 (ReLU activation)
Loss: Mean Squared Error

Anomaly score = MSE(input, reconstructed)
Threshold: 99th percentile of reconstruction errors from training window
```

The autoencoder is implemented using a simple matrix multiplication stack (no external ML library dependency) to maintain the Rust no-external-runtime constraint.

### 3.4 Ensemble Voting

```
final_score = (isolation_forest_score × 0.40)
            + (autoencoder_score × 0.35)
            + (statistical_baseline_score × 0.25)

If final_score > 0.75 → escalate to comprehensive_blocker
```

The ensemble is more robust than any single model because:

- If a novel attack evades the isolation forest (fits within historical feature distribution), the autoencoder may catch it as an unusual sequential flow
- If both evade those, the statistical baseline catches volume/rate anomalies

---

## 4. Advanced Security Engine

**Source File:** `src/advanced_security.rs`  
**Paradigm:** Multi-dimensional threat correlation  
**Purpose:** Correlates signals across time and across multiple detection dimensions

### 4.1 Temporal Correlation

A single anomalous packet, in isolation, is low confidence. The advanced security engine tracks anomalous events across a sliding time window (configurable, default 5 minutes) for each source IP. If multiple independent anomaly signals arise from the same IP within the window, the correlation score escalates — this is a much higher-confidence threat indicator.

```
Correlation example:
  T+0:00  - AI deviation spike (score 0.62)   → ALERT (low confidence)
  T+1:30  - DNS query to suspicious domain     → ALERT (low confidence)
  T+3:00  - Port scan pattern detected by IDS  → ALERT (low confidence)

Correlation result at T+3:00:
  All three signals from same src IP within 5-min window
  correlation_score = 0.62 + 0.55 + 0.70 = 1.87 / 3 = 0.62  → normalized
  Escalate to: HIGH confidence QUARANTINE
```

### 4.2 Cross-Protocol Correlation

The advanced security engine also correlates anomalies across protocols from the same source IP. An IP that causes both HTTP WAF alerts and DNS-layer C2 pattern alerts is treated as dramatically higher confidence than either signal alone — because the likelihood of a legitimate user accidentally triggering anomalous behavior on two independent protocol layers simultaneously is extremely low.

---

## 5. Federated Learning Engine

**Source File:** `src/federated_learning.rs`  
**Paradigm:** Privacy-preserving distributed ML  
**Status:** Production-ready, requires swarm peer network

### 5.1 The Federated Learning Problem

Different Rudras nodes see different network traffic. Node A (at HQ) sees executive email and finance traffic. Node B (at datacenter) sees API server and database traffic. Each builds behavioral baselines specific to its traffic. Federated learning allows sharing _what each node has learned_ without sharing the raw network traffic that could expose private data.

### 5.2 How It Works

1. Each node trains a local model update on its observed traffic
2. The model update (gradient deltas, not raw traffic) is cryptographically aggregated with the Homomorphic Sharing module (`homomorphic_sharing.rs`) so no individual node's data is exposed
3. The aggregated model update is broadcast to all peer nodes
4. Each node applies the aggregated update to improve its local model

This is an implementation of the **FedAvg algorithm** (McMahan et al., 2017) with homomorphic encryption for update aggregation.

### 5.3 Privacy Guarantees

- **Differential Privacy:** Model updates include calibrated Gaussian noise (`epsilon = 1.0` privacy budget) before aggregation, ensuring individual flow patterns are not inferable from the aggregated update
- **Homomorphic Aggregation:** Updates are aggregated in encrypted form — no node sees the unencrypted updates of any other node
- **No Raw Traffic Sharing:** Only model gradients (parameter deltas) are shared, never raw packet data

---

## 6. Graph Neural Network (GNN) Engine

**Source File:** `src/gnn_engine.rs`  
**Paradigm:** Graph-theoretic anomaly detection  
**Specialization:** Lateral movement, topology attacks, infrastructure anomalies

### 6.1 Why Graphs for Network Security?

A network is fundamentally a graph: nodes are IP addresses, edges are connections. Attackers performing lateral movement create unusual graph patterns:

- A host that suddenly connects to 50 hosts it never connected to before
- A path between zones that should never exist (guest zone → database zone)
- Hub formation around a compromised host acting as pivot

These patterns are invisible to per-flow analysis but obvious in graph representation.

### 6.2 Graph Construction

Rudras maintains a live directed graph `G = (V, E)` where:

- `V` = set of observed IP addresses
- `E` = set of connections (directed from source to destination)
- Edge weight = number of bytes exchanged

Every new connection adds an edge to the graph. The graph is periodically pruned of edges older than `gnn_edge_ttl_minutes` (default 60 minutes) to focus on recent topology.

### 6.3 GNN Architecture

The GNN used in Rudras is a simplified **GraphSAGE** architecture:

1. **Node Feature Embedding:** Each node has a feature vector: `[degree, weighted_degree, zone_id, trust_score, ai_deviation]`
2. **Neighborhood Aggregation:** For each node, aggregate features of its 2-hop neighborhood via mean pooling
3. **Anomaly Scoring:** A node whose aggregated neighborhood representation deviates from its historical neighborhood representation is flagged

Nodes with high GNN anomaly scores represent hosts acting as lateral movement pivots or unexpected network hubs.

### 6.4 Lateral Movement Detection

The GNN is specifically tuned to detect lateral movement indicators:

- **Fan-out pattern:** One node suddenly connecting to many new nodes (scanner/pivot)
- **Chain traversal:** A → B → C path through zones (A is low-trust, C is high-value)
- **Beaconing hub:** Many nodes connecting to the same unusual external IP (C2 botnet pattern)

When GNN detects a high-anomaly-score node, it reports the central node IP to the comprehensive blocker with enrichment data about which connections are anomalous.

---

## 7. Encrypted Traffic Analysis (ETA) Engine

**Source File:** `src/eta_engine.rs`  
**Paradigm:** Traffic fingerprinting without decryption  
**Privacy:** No payload decryption — operates solely on TLS metadata

### 7.1 The TLS Inspection Problem

Modern enterprise traffic is 90%+ encrypted (TLS 1.3). Traditional deep packet inspection cannot inspect encrypted payloads without a TLS interception proxy (man-in-the-middle), which:

- Breaks certificate transparency
- Creates privacy and legal risk
- Is visible to sophisticated attackers

The ETA engine detects threats in encrypted traffic _without_ decrypting it.

### 7.2 TLS Metadata Features

The ETA engine extracts features from the TLS handshake and session metadata (all visible in plaintext during handshake):

| Feature                    | Source               | Example Value                          |
| -------------------------- | -------------------- | -------------------------------------- |
| TLS version                | ClientHello          | TLS 1.3 / 1.2 / 1.0 (1.0 = suspicious) |
| Cipher suite list          | ClientHello          | List of supported ciphers              |
| TLS extension list         | ClientHello          | Extensions present/absent              |
| SNI hostname               | ClientHello          | `api.example.com`                      |
| Server certificate details | Certificate message  | Issuer, subject, validity period       |
| Self-signed indicator      | Certificate          | True/False                             |
| Certificate age            | Certificate validity | New cert on known-bad IP               |
| Session resumption         | SessionTicket        | Yes/No                                 |
| Record size distribution   | TLS record layer     | Byte histogram                         |
| Inter-packet timing        | Packet timestamps    | Jitter variance                        |

### 7.3 JA3/JA4 Fingerprinting

The JA3 algorithm creates a fingerprint from the TLS ClientHello:

```
JA3 = MD5(TLSVersion + CipherSuites + Extensions + EllipticCurves + EllipticCurvePointFormats)
```

Malware families have characteristic JA3 fingerprints because their TLS library configurations are consistent. Rudras maintains a database of known-malicious JA3 fingerprints and matches incoming connections against it.

JA4 (a newer, more collision-resistant algorithm) is also supported for future-proofing.

---

## 8. Network DPI ML Engine

**Source File:** `src/network_dpi_ml.rs`  
**Paradigm:** ML-assisted protocol classification  
**Purpose:** Identifies protocols and applications from traffic patterns when headers are obfuscated

### 8.1 When Headers Lie

Sophisticated attackers tunnel malicious traffic over legitimate-looking protocols:

- C2 traffic over HTTP on port 80 (looks like web browsing)
- Data exfiltration over DNS (looks like normal DNS)
- Malware over HTTPS (encrypted, no visibility)

The network_dpi_ml engine uses ML to classify traffic based on statistical characteristics of the byte stream itself, independent of port numbers or declared protocol.

### 8.2 Feature Engineering for Flow Classification

For each flow, the following statistical features are extracted from the raw byte sequence:

- Byte value histogram (256-dimensional)
- Entropy of payload bytes
- Run-length statistics
- First-N-bytes fingerprint
- Packet length distribution
- Inter-arrival time statistics

These features are fed to a random forest classifier trained to distinguish:

- HTTP over non-standard ports
- DNS tunneling (high entropy DNS payloads)
- TLS/HTTPS over port 80
- Binary protocol misidentified as HTTP
- Tor traffic patterns

---

## 9. Reinforcement Learning Policy Engine

**Source File:** `src/rl_policy.rs`  
**Paradigm:** Reinforcement Learning  
**Purpose:** Continuous optimization of detection thresholds based on operational feedback

### 9.1 The Threshold Optimization Problem

IDS/IPS thresholds are not universal. A development network with engineers doing port scans of test servers should have different `syn_flood_threshold` values than a production trading system where any unusual connection is suspect. The RL policy engine learns the optimal thresholds for the specific deployment environment from feedback.

### 9.2 RL Problem Formulation

- **State:** Current system state: `{false_positive_rate, false_negative_rate, throughput, alert_volume, block_rate}`
- **Action:** Adjustment of one threshold parameter by +/- delta: `{ema_alpha, block_threshold, syn_flood_threshold, ...}`
- **Reward:** `reward = (true_positive_rate × 2.0) - (false_positive_rate × 3.0) - (performance_overhead × 0.5)`

The reward function heavily penalizes false positives (which disrupt legitimate traffic) while rewarding true positive detections.

### 9.3 Learning Algorithm

The RL engine uses a **Q-Learning** variant with experience replay:

- Q-table is updated after each "episode" (configurable: every 100 block decisions or every 1 hour, whichever comes first)
- Epsilon-greedy exploration: 90% exploitation (use best known thresholds), 10% exploration (try small adjustments to learn)
- Learning rate: 0.1 (conservative to prevent threshold oscillation)

### 9.4 Safety Constraints

The RL engine operates within hard safety limits:

- Thresholds can never be moved below minimum safety values (prevents disabling detection entirely)
- Thresholds can never be moved above maximum values (prevents thresholds so high tracking becomes useless)
- If false negative rate exceeds 10%, RL resets to conservative defaults regardless of learned policy (safety override)
