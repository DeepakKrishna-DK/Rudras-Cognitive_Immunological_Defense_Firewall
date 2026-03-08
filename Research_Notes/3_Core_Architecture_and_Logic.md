# Research Note 3: Core Architecture and Logic

**Document Version:** 4.0  
**Last Updated:** March 8, 2026  
**Classification:** Internal Research — Engineering Reference

---

## 1. Architecture Overview

Rudras v4.0 is a multi-layer, multi-threaded network security platform written in Rust. At its core, it is a packet processing pipeline that intercepts traffic at the OS kernel interface, analyzes it through 40+ overlapping detection subsystems, and enforces policy decisions.

```
┌─NIC / Kernel─────────────────────────────────────┐
│  Npcap (promiscuous capture)                     │
│  WFP (Windows Filtering Platform — block)        │
│  WinDivert (userspace interception)              │
│  L2 Engine (ARP / 802.1Q / VLAN)                 │
└──────┬───────────────────────────────────────────┘
       │
   ════╪════ FAST-PATH DROPS (O(1)) ══════════════
   │ TI Blocklist lookup (IP hash set)                   │
   │ WFP registered block filter (kernel bypass)         │
   │ DNS response NXDomain injection (malicious domain)  │
   ════╪════════════════════════════════════════════════
       │
   ┌─────┴──────────────────────────────────────────────┐
   │              ANALYSIS PIPELINE                     │
   │  Stateful Tracking (flow_engine, stateful)         │
   │  DPI / Single-Pass Inspection                      │
   │  IDS Signature Engine (85 rules / 71 categories)   │
   │  AI Behavioral Engine (EMA + Anomaly scoring)      │
   │  WAF (HTTP/SQL/XSS/RCE pattern matching)           │
   │  GNN Topology Analysis                             │
   │  UEBA User Behavior Deviation                      │
   │  DNS Security Engine                               │
   │  ETA (Encrypted Traffic Analysis)                  │
   │  Attribution Scoring                               │
   └─────┬──────────────────────────────────────────────┘
       │
   ┌─────┴──────────────────────────────────────────────┐
   │              ENFORCEMENT LAYER                     │
   │  IPS Active Response Engine                        │
   │  Zero Trust Access Decision Engine                 │
   │  Micro-Segmentation Zone Gate                      │
   │  SOAR Automated Playbook Execution                 │
   │  MTD (Moving Target Defense — IP shuffle)          │
   └─────┬──────────────────────────────────────────────┘
       │
   ┌─────┴──────────────────────────────────────────────┐
   │              OBSERVABILITY LAYER                   │
   │  Metrics (Prometheus format, port 9091)            │
   │  SIEM CEF Event Streaming                          │
   │  Forensics Chain (SHA3-256 hash chain)             │
   │  IST-timestamped JSON log (rolling file)           │
   │  SOC Dashboard (Next.js, port 3000)                │
   └────────────────────────────────────────────────────┘
```

---

## 2. Concurrency Model

Rudras is a multi-threaded application built on Tokio async runtime. The threading model is designed to maximize throughput while preventing data races through Rust's type system.

### Thread Categories

| Thread | Purpose | Synchronization |
|--------|---------|----------------|
| **Capture Thread(s)** | Npcap packet reception | None (dedicated) |
| **Packet Dispatch Thread** | Routes parsed packets to analysis subsystems | Lock-free channel |
| **AI/EMA Update Thread** | Computes EMA baselines every 5s | `RwLock<HashMap>` |
| **IDS Analysis Thread** | Pattern matches packet content | Shared `Arc<RuleSet>` |
| **IPS Response Thread** | Blocks/resets offending connections | `Arc<AtomicBool>` gate |
| **TI Feed Thread** | Refreshes blocklists from files/API | `RwLock<HashSet>` |
| **Metrics Server Thread** | Serves Prometheus scrapes on :9091 | `Arc<AtomicU64>` counters |
| **Process Monitor Thread** | Scans process table every 10s | `Arc<Mutex<Config>>` |
| **Swarm Gossip Thread** | Sends/receives peer intelligence | `UdpSocket` |
| **SOAR Playbook Thread** | Executes automated response plans | `mpsc::channel<Alert>` |

### Why RwLock Is Preferred Over Mutex
The `RwLock<T>` is used throughout Rudras for shared data structures that are read by many threads but written by one. Under normal operation, reads (allow/block decisions) vastly outnumber writes (learning new behavior). RwLock allows all read threads to proceed simultaneously, critical for throughput. A regular `Mutex` would serialize every read.

---

## 3. The Four Architectural Pillars (v4.0)

### Pillar A — Zero-Trust Enforcement (Layer 0 Gate)
**Module:** `zero_trust.rs`, `identity_policy.rs`, `micro_segmentation.rs`

Before any packet reaches the analysis pipeline, the Zero Trust module performs a deterministic access check evaluating:
- Device trust score (0.0–1.0)
- Identity verification (certificate/token validity)
- Session context (expected behavior deviations)
- Network zone authorization (source zone → destination zone policy)

If the check fails, the packet is dropped at the **OS kernel level** via WFP rule injection — no userspace cost.

**Zone Enforcement:** Rudras maintains 8 named security zones. Each zone has a label, allowed_ips CIDR range, and list of explicitly permitted destination zones. All other cross-zone traffic is implicitly denied:
```toml
[[zones]]
name = "db"
allowed_ips = ["10.10.30.0/24"]
allowed_destinations = ["app"]
# db zone can only be accessed from app zone. Never from guest, corporate, internet.
```

### Pillar B — AI Behavioral Baseline Engine
**Module:** `ai_engine.rs`, `cyber_immune.rs`, `advanced_ml.rs`

The AI engine builds an **Immutable Behavioral Baseline** for each IP on first packet. The baseline captures the first observed behavioral signature as a "fingerprint". An Exponential Moving Average (EMA) tracks evolving behavior. The ratio of current EMA to the immutable baseline is the **Deviation Score**.

Key threshold parameters:
- `suspicious_threshold` (default 0.55): Flag for inspection
- `quarantine_threshold` (default 0.70): Rate-limit and alert
- `block_threshold` (default 0.80): WFP block + IPS RST inject

The EMA uses a configurable alpha (`ema_alpha`, default 0.3) so recent behavior is weighted heavily but historical behavior is not forgotten.

### Pillar C — Distributed Swarm Immunity
**Module:** `distributed_immunity.rs`

When any Rudras node confirms a malicious IP, it broadcasts a **gossip message** to all configured peer nodes using UDP. Peer nodes receive the message, add the IP to their local blocklist, and re-broadcast to their peers. Within milliseconds, a newly discovered malicious IP is blocked on all nodes in the swarm — even if the other nodes have never seen that IP.

Gossip message format (JSON over UDP):
```json
{"type": "ThreatIntel", "src_node": "node-01", "malicious_ip": "185.220.101.5", "confidence": 0.97, "timestamp": "2026-03-08T10:30:00+05:30"}
```

### Pillar D — Adaptive Threat Response (Dynamic Mode Profiles)
**Module:** `mode_profiles.rs`, `ips_engine.rs`

| Threat Level | Trigger | Automatic Response |
|-------------|---------|-------------------|
| Normal | Block rate < 5/min | All modules active, conservative thresholds |
| Elevated | Block rate 5–50/min | Alert sensitivity increased, DPI prioritized |
| Critical | Block rate > 50/min | DPI suspended for low-priority flows, aggressive AI thresholds, anti-evasion mode |

---

## 4. Complete Module Catalog (67 Source Files)

### Category 1: Core Infrastructure
| Module | File | Purpose |
|--------|------|---------| 
| Main Entry | `main.rs` | Orchestrates all module initialization, tokio runtime setup, IST logging |
| Configuration | `config.rs` | Deserializes `rudras.toml`, validates all fields, hot-reload support |
| Policy Engine | `policy.rs` | Rule evaluation, access decision matrix |
| Packet Capture | `capture.rs` | Npcap/PCAP packet capture loop |
| Flow Tracking | `flow_engine.rs` | Stateful per-flow context (5-tuple), flow lifecycle management |
| Stateful Analysis | `stateful.rs` | TCP state machine, SYN cookie tracking |
| Metrics | `metrics.rs` | Prometheus counters/histograms + auth server on :9091 |
| Mode Profiles | `mode_profiles.rs` | Threat level transitions, module sensitivity tuning |

### Category 2: Network Enforcement Stack
| Module | File | Purpose |
|--------|------|---------| 
| WFP Engine | `wfp_engine.rs` | Windows Filtering Platform kernel-level block/allow rules |
| WinDivert Engine | `windivert_engine.rs` | Userspace packet interception + modification |
| Npcap Forensic | `npcap_forensic.rs` | Promiscuous mode capture for forensic evidence recording |
| L2 Engine | `l2_engine.rs` | ARP spoofing detection, 802.1Q VLAN enforcement, MAC analysis |
| DPI Engine | `dpi.rs` | Deep packet inspection, protocol dissection, payload analysis |

### Category 3: Detection Engines
| Module | File | Purpose |
|--------|------|---------| 
| IDS Engine | `ids_engine.rs` | Signature-based detection (85 rules, 71 categories, 70+ attack types) |
| IPS Engine | `ips_engine.rs` | Active response: TCP RST injection, WFP blocking, quarantine |
| Comprehensive Blocker | `comprehensive_blocker.rs` | Aggregated block decision across all detection signals |
| Framework Alignment | `framework_alignment.rs` | Maps detections to MITRE ATT&CK, NIST, ISO 27001 |

### Category 4: AI/ML Subsystem
| Module | File | Purpose |
|--------|------|---------| 
| AI Engine | `ai_engine.rs` | EMA-based behavioral baseline, immutable anchor |
| CyberImmune | `cyber_immune.rs` | Biological immune metaphor, antibody propagation |
| Advanced ML | `advanced_ml.rs` | Multi-model ensemble: isolation forest, autoencoder, hybrid |
| Advanced Security | `advanced_security.rs` | Multi-factor behavioral analysis, threat correlation |
| Federated Learning | `federated_learning.rs` | Privacy-preserving model aggregation across swarm nodes |
| GNN Engine | `gnn_engine.rs` | Graph Neural Network for topology-aware lateral movement detection |
| ETA Engine | `eta_engine.rs` | Encrypted Traffic Analysis without decryption via TLS metadata |
| Network DPI ML | `network_dpi_ml.rs` | ML-assisted protocol classification on raw DPI output |
| RL Policy | `rl_policy.rs` | Reinforcement Learning for dynamic threshold optimization |

### Category 5: Threat Intelligence
| Module | File | Purpose |
|--------|------|---------| 
| Threat Intelligence | `threat_intelligence.rs` | IOC feed management: 24,358 IPs, 1.25M domains, 84,501 malware sigs |
| DNS Security | `dns_security.rs` | DNS-layer blocking: C2 domains, DGA detection, DNS tunneling |
| Threat Hunt | `threat_hunt.rs` | Proactive hypothesis-driven threat hunting across flow data |
| Threat Rules Engine | `threat_rules_engine.rs` | Composite rule evaluation combining TI + behavioral + signature signals |

### Category 6: Enterprise Security
| Module | File | Purpose |
|--------|------|---------| 
| Zero Trust | `zero_trust.rs` | Device trust scoring, continuous verification, zone enforcement |
| Identity Policy | `identity_policy.rs` | Identity-aware policy with certificate/token validation |
| Micro-Segmentation | `micro_segmentation.rs` | 8-zone network segmentation with explicit allow policy |
| Endpoint Security | `endpoint_security.rs` | Host-based posture assessment, patch age, vulnerability scanning |
| Attribution Scoring | `attribution_scoring.rs` | TTP/technique-based attacker attribution scoring |
| SIEM Integration | `siem_integration.rs` | CEF log format, Syslog export, Splunk/Elastic webhook |
| Distributed Immunity | `distributed_immunity.rs` | Swarm gossip protocol for peer intelligence sharing |
| Gateway Mode | `gateway_mode.rs` | Edge gateway configuration and BGP-aware policy |
| SD-WAN | `sdwan.rs` | SD-WAN traffic prioritization and QoS integration |
| Cloud Native | `cloud_native.rs` | Kubernetes API server protection, container escape detection, cloud IMDS |
| Single Pass | `single_pass.rs` | Unified L2–L7 inspection in one packet traversal |

### Category 7: Research-Grade Modules (v4.0)
| Module | File | Purpose |
|--------|------|---------| 
| UEBA Engine | `ueba_engine.rs` | User and Entity Behavior Analytics, insider threat detection |
| SOAR Engine | `soar_engine.rs` | Security Orchestration, Automation and Response playbooks |
| Deception | `deception.rs` | Honeypot/canary token infrastructure |
| Adaptive Honeypot | `adaptive_honeypot.rs` | Dynamic honeypot that mimics real services |
| OT Protocols | `ot_protocols.rs` | Modbus/DNP3/EtherNet-IP ICS protocol security |
| Post-Quantum | `post_quantum.rs` | NIST FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA) |
| Formal Verification | `formal_verification.rs` | TLA+-based policy consistency verification |
| TPM Attestation | `tpm_attestation.rs` | Hardware root-of-trust, PCR measurement verification |
| MTD Engine | `mtd_engine.rs` | Moving Target Defense — IP rotation, port shuffling |
| Homomorphic Sharing | `homomorphic_sharing.rs` | Encrypted threat intel sharing without plaintext exposure |
| Email Security | `email_security.rs` | SMTP/DKIM/SPF/DMARC verification, phishing detection |
| RASP Engine | `rasp_engine.rs` | Runtime Application Self-Protection hooks |
| Secure Channel | `secure_channel.rs` | mTLS channel management, certificate lifecycle |
| SBOM Engine | `sbom_engine.rs` | Software Bill of Materials validation |
| Supply Chain Verifier | `supply_chain_verifier.rs` | Cryptographic package signing verification |
| eBPF/XDP | `ebpf_xdp.rs` | Linux eBPF/XDP kernel bypass (in-development) |
| P4 Offload | `p4_offload.rs` | Programmable switch P4 dataplane offload |
| Compliance Engine | `compliance_engine.rs` | GDPR/HIPAA/PCI-DSS automated compliance reporting |
| QUIC Inspector | `quic_inspector.rs` | QUIC/HTTP3 deep inspection |
| Forensics Chain | `forensics_chain.rs` | SHA3-256 immutable audit log chain |
| Differential Privacy | `differential_privacy.rs` | Privacy-preserving telemetry aggregation |
| Management API | `management_api.rs` | REST API for configuration, status, incident management |
| LLM Explainability | `llm_explainability.rs` | LLM-generated natural language threat explanations |
| Policy Verifier | `policy_verifier.rs` | Automated policy conflict detection and resolution |

### Category 8: Security Support
| Module | File | Purpose |
|--------|------|---------| 
| Process Monitor | `process_monitor.rs` | Windows process table scanning for tampering tools |
| Memory Safe Pool | `memory_safe_pool.rs` | Pre-allocated packet buffers, zero GC overhead |
| Hardware Acceleration | `hardware_accel.rs` | CPU feature detection, SIMD-accelerated hashing |

---

## 5. Data Flow: Packet Lifecycle

```
1. CAPTURE: NIC receives raw Ethernet frame
   └─ Npcap/pcap binds at data-link layer
   └─ Packet copied to userspace buffer (zero-copy where possible)

2. L2 SECURITY: l2_engine parses Ethernet header
   └─ ARP spoofing check (gratuitous ARP vs. known MAC table)
   └─ 802.1Q VLAN tag enforcement

3. FAST-PATH DROPS (sub-microsecond):
   └─ IP checked against TI blocklist (RwLock<HashSet<IpAddr>>)
   └─ WFP kernel filter pre-checks matching IP/port rules
   └─ If blocked: drop packet, increment metric, log to SIEM. STOP.

4. STATEFUL FLOW TRACKING:
   └─ flow_engine creates or updates FlowRecord keyed by 5-tuple
   └─ stateful.rs maintains TCP state machine (SYN/SYN-ACK/ACK/FIN/RST)
   └─ SYN flood detection: count half-open connections, rate-limit at threshold

5. SINGLE-PASS INSPECTION (dpi.rs + single_pass.rs):
   └─ Protocol identification: TCP/UDP/ICMP/QUIC/DNS/HTTP/TLS
   └─ WAF patterns: SQL injection, XSS, RCE, path traversal, SSRF
   └─ DLP patterns: credit card, API key, PII detection in outbound payloads

6. AI BEHAVIORAL ANALYSIS:
   └─ ai_engine: update EMA for src IP, compute deviation score
   └─ cyber_immune: compare against immutable anchor
   └─ advanced_ml: multi-model ensemble scoring (if enabled)
   └─ ueba_engine: user pattern deviation (if identity known)

7. IDS SIGNATURE MATCHING:
   └─ ids_engine: match packet against 85 rules across 71 categories
   └─ Generates alert events with severity, category, MITRE technique
   └─ Feeds alert into SOAR playbook queue

8. COMPREHENSIVE BLOCK DECISION:
   └─ comprehensive_blocker aggregates all signals: TI + IDS + AI + DNS
   └─ Weighted scoring produces final action: ALLOW / ALERT / QUARANTINE / BLOCK

9. IPS ENFORCEMENT (if BLOCK/QUARANTINE):
   └─ ips_engine injects TCP RST to both ends of connection
   └─ WFP rule registered to block subsequent packets from src IP
   └─ Swarm gossip broadcast to peers
   └─ SOAR playbook triggered (if severity >= HIGH)

10. OBSERVABILITY:
    └─ metrics: increment relevant counters (packets_total, blocks_total, alerts_total)
    └─ siem_integration: emit CEF event to syslog endpoint
    └─ forensics_chain: append event to SHA3-256 chained audit log
    └─ tracing: emit structured JSON log with IST timestamp
```

---

## 6. Configuration Architecture

The primary configuration file is `config/rudras.toml`. It is divided into sections mapping directly to module configurations:

```toml
[ai]          # ai_engine.rs, advanced_ml.rs, cyber_immune.rs parameters
[ids]         # ids_engine.rs rule categories, signatures
[ips]         # ips_engine.rs response thresholds
[threat_intel]# threat_intelligence.rs feed paths, refresh intervals
[dns]         # dns_security.rs blocklist paths, DGA detection
[zero_trust]  # zero_trust.rs trust score thresholds, posture requirements
[[zones]]     # micro_segmentation.rs zone definitions
[metrics]     # metrics.rs port, auth token validity duration
[logging]     # log path, rotation policy, IST timezone display
[capture]     # capture.rs interface, promiscuous mode, buffer sizes
[swarm]       # distributed_immunity.rs peer node addresses
[soar]        # soar_engine.rs playbook definitions
[compliance]  # compliance_engine.rs regulated framework targets
```

All configuration is hot-reloadable. The `config.rs` module fires a reload event that each subscribed module receives via a tokio watch channel.
