# 🔥 Rudras — Cognitive Immunological Defense Firewall
### The Boss of Firewalls.

<div align="center">

[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Status](https://img.shields.io/badge/status-in%20development%20(alpha)-informational.svg)]()
[![Version](https://img.shields.io/badge/Version-3.0%20Alpha-blueviolet.svg)]()

**A next-generation, self-healing firewall that thinks like an immune system.**

*Last Updated: March 2026*

</div>

---
![RudraS Logo](https://github.com/DeepakKrishna-DK/Rudras_/blob/main/main.jpeg)
---

## 📑 Table of Contents
1. [🏛️ The History of Firewalls](#️-the-history-of-firewalls)
2. [💡 Why I Built Rudras](#-why-i-built-rudras)
3. [🛡️ What is Rudras?](#️-what-is-rudras)
4. [🧠 The Philosophy — From Wall to Nervous System](#-the-philosophy--from-wall-to-nervous-system)
5. [⚙️ Core Enterprise Capabilities (v3.0)](#️-core-capabilities-v3.0)
6. [🗏️ Dual-Mode Architecture & Deployment](#️-dual-mode-architecture)
7. [🧬 The CyberImmune System](#-the-cyberimmune-system)
8. [🎯 Threat Intelligence & IOC Feeds](#-threat-intelligence--ioc-feeds)
9. [⚖️ Ethical & Legal Defaults](#️-ethical--legal-defaults)
10. [🔧 Build Requirements](#-build-requirements)
11. [🧪 Testing & Validation](#-testing--validation)
12. [📊 Real-World Performance](#-real-world-performance)
13. [🚀 Firewall Trends — How Rudras Stays Ahead](#-firewall-trends--how-rudras-stays-ahead)
14. [📅 Development Journey](#-development-journey)
15. [📚 Engineering Research & Secrets](#-engineering-research--secrets)
16. [🔭 Future Vision & Platforms](#-future-vision--platforms)
17. [📋 Changelog](#-changelog)
18. [🗂️ Version Control & Repository Status](#️-version-control--repository-status)

---

## 🏛️ The History of Firewalls

To understand why Rudras exists, you need to understand where firewalls came from — and how they've consistently failed to keep up with the threat landscape.

**Generation 1 — Packet Filters (1988)**
Born out of the Morris Worm of 1988, the first major internet worm. These early systems operated at the network layer and compared packets against a static list of rules (Source IP, Port). Fast, simple, but trivially bypassed.

**Generation 2 — Stateful Inspection (1994)**
Check Point FireWall-1 introduced stateful inspection — tracking the state of active connections instead of treating each packet independently. A quantum leap forward, but still blind to payload contents.

**Generation 3 — Application Layer Gateways & Proxies (Late 1990s)**
Firewalls evolved to understand application-level semantics (HTTP, FTP) and intercept traffic at Layer 7. This era gave rise to Unified Threat Management (UTM) appliances.

**Generation 4 — Next-Generation Firewalls (2000s–2010s)**
NGFWs brought Deep Packet Inspection, User Identity Awareness, and SSL/TLS decryption. But there was still a fundamental flaw: all of these systems operated on static rules. A zero-day attack simply slipped right through. The system was strictly reactive.

**Generation 5 — AI-Driven & Zero Trust Firewalls (2020s)**
The Zero Trust paradigm emerged as the perimeter dissolved into cloud infra and mobile laptops. Commercial products bolted AI on as an afterthought, rather than building it as the foundational layer.

This is exactly the gap that Rudras was designed to fill.

---

## 💡 Why I Built Rudras

> *"The best security system isn't a wall. It's an immune system."*

After studying firewalls during academic and personal research, I arrived at a singular conclusion: every major firewall architecture is fundamentally passive. Attackers use zero-day exploits, slowly exfiltrate data to avoid limits, and mimic legitimate patterns. A rule-based system cannot reliably stop what it has never seen.

I became fascinated by the human immune system. It detects foreign bodies through pattern recognition, remembers past threats, evolves its defenses naturally, and distributes immunity unconditionally. I asked: *Why doesn't a firewall work this way?*

### ⚡ Why Rust?
A firewall sits in the hot-path of every network packet. It must have microsecond decision latency and be completely memory-safe. Writing a security-critical engine in C/C++ guarantees buffer overflows eventually. Writing it in Java/Go introduces garbage collector pausing during 100-Gbps attacks. Rust was the only language that met all requirements cleanly.

---

## 🛡️ What is Rudras?

Rudras (named after the ancient concept of the storm deity — fierce, adaptive, and unstoppable) is a **Cognitive Immunological Defense Firewall** built entirely in Rust.

It is a living, self-adapting security system that:
- 👁️ Observes every packet flowing through the network interface in real time.
- 🔬 Analyzes behavioral patterns, threat signatures, and contextual intent.
- ⚡ Responds with graduated defense actions (monitor → rate-limit → quarantine → block).
- 🧬 Evolves its own defense rules using a genetic algorithm.
- 🧠 Remembers every threat it has ever encountered.
- 🌐 Shares that intelligence with peer nodes across the network.

Every attack makes Rudras smarter. Every session makes it more accurate.

---

## 🧠 The Philosophy — From Wall to Nervous System

Traditional firewalls act like bouncers reading a static list.

**Traditional:** `Packet → Rule Match (1000+ static rules) → Block / Allow`

Rudras thinks like a nervous system:

**Rudras:**
`Packet → Identity Resolution → Behavioral Context Analysis → Intent Classification → Adaptive Response → Memory Update → Distributed Intelligence Broadcast`

Rudras doesn't ask *"Is this on the target blocklist?"* It asks *"Does this behavior belong here, and what is its macroscopic intent?"*

---

## ⚙️ Core Capabilities (v3.0)

Rudras natively integrates modules that typically require half a dozen separate commercial appliances:

| Module | Status | What It Does |
|--------|--------|--------------|
| 🧬 **CyberImmune Engine** | ✅ Active | Self-healing ML with **Adaptive Trust** and **Immutable State Anchors** stopping Boiling-Frog data poisoning. |
| 🛡️ **Zero-Trust Anti-Tamper** | ✅ Active | Detects unauthorized sniffers (Wireshark, IDA Pro, Ghidra) in **warn-only** mode by default — no forcible termination unless explicitly opted in. |
| 🔐 **ZKDPI & Hybrid Vault** | ✅ Active | Generates SHA-256 process hashes. An **Adaptive RSA Dropper** prevents Crypto-DoS while maintaining Asymmetric Decryption vaults. |
| 🔥 **Core WAF Engine** | ✅ Active | Deep Packet Inspection stops Log4j, SQLi, and Remote Code Execution (RCE) natively. |
| 🌐 **Swarm Consensus** | ✅ Active | Distributed protocols safely degrade to local **Island Mode** during physical infrastructure failures. |
| 🦠 **Active C2 Defense** | ✅ Active | Blocks Cobalt Strike & Meterpreter beacons dynamically based on stager signatures. |
| 🔌 **Protocol Anti-Evasion** | ✅ Active | Shuts down Nmap Null scans, XMAS scans, and SYN-FIN evasion packets at Layer 0. |
| 🎯 **IOC-Based Threat Blocking** | ✅ Active | Replaces blunt country blocks with **precision IOC blocking** — specific malicious IPs and domains from 6 live feeds updated every 60 min. |
| 🌍 **Malicious Domain Blocking** | ✅ Active | DNS-layer blocking checks every query against ThreatFox C2 domains and URLhaus delivery hosts before any connection opens. |
| 🏰 **CIP Whitelisting** | ✅ Active | **Critical Infrastructure Protection** dynamically prevents blocking essential services unless malware is proven mathematically. |
| 🔗 **Layer 2 Security** | ✅ Active | Analyzes MAC anomalies to stop ARP Spoofing and Cache Poisoning at the Data Link layer. |
| 📊 **SIEM Integration** | ✅ Active | Splunk HEC and ELK Stack integrations use native **Structured JSON Logging** for instant index ingestion without regex parsers. |
| 🧩 **Ransomware Sandbox** | ✅ Active | Analyzes SMB payload entropy dynamically to kill encryption attempts at Layer 7 (Shannon entropy > 7.85/8.0 = instant block). |
| 🪤 **Deception Network** | ✅ Active | Honeypot ports (FTP, MySQL) snare attackers and harvest zero-day payloads for the AI. |
| 🏙️ **Micro-Segmentation** | ✅ Active | 8 strict security zones designed with intra-VLAN lateral movement detection limiters. |

---

## 🗏️ Dual-Mode Architecture

A firewall protecting an endpoint laptop requires vastly different behaviors than one protecting a database cluster. Rudras operates across two distinct strategic deployments:

### 💻 1. Client (Endpoint) Mode
- **Focus**: Outbound connections (60% outbound monitoring).
- **Targets**: C2 callbacks, Malware stagers, Data Exfiltration.
- **Behavior**: Quiet, adaptive thresholds tailored to avoid interrupting normal developer and user traffic.

### 🖥️ 2. Server (Gateway) Mode
- **Focus**: Inbound connections (80% inbound monitoring).
- **Targets**: Port scanning, Brute Force, Exploit propagation.
- **Behavior**: Highly aggressive. Strict Micro-segmentation. Instantly escalates any traffic arriving on an undocumented port to deep inspection.

### 🖱️ Interactive Mode Selection (v3.0)
When launched with no `--mode` flag, Rudras **prompts the user interactively** rather than silently defaulting to Client:

```
╔═══════════════════════════════════════════════════════════════════╗
║              RUDRAS — SELECT DEPLOYMENT MODE                     ║
╠═══════════════════════════════════════════════════════════════════╣
║  1  CLIENT  — Endpoint/workstation (outbound C2 & exfil focus)   ║
║  2  SERVER  — Gateway/perimeter    (inbound attack focus)         ║
║  3  AUTO    — Auto-detect from open ports                         ║
╠═══════════════════════════════════════════════════════════════════╣
║  Tip: skip this prompt with --mode client / --mode server         ║
╚═══════════════════════════════════════════════════════════════════╝
```

- **Skip prompt (CLI):** `rudras.exe --mode client` or `rudras.exe --mode server`
- **Skip prompt (config):** Set `deployment = "client"` in `[mode]` section of `config/rudras.toml`

### 🎛️ TOML Configuration Matrix (Hot Reloadable)
Rudras abstracts backend logic into `config/rudras.toml` to allow SOC Administrators to tune the engine without recompiling.

- **`[mode]` block:** Set `deployment = "client"` or `"server"` to skip the interactive prompt.
- **`[ai]` block:** Manipulate the AI Engine's `initial_susp_threshold` and `max_learning_multiplier` dynamically.
- **`[ips]` block:** Manage WFP quarantine thresholds, rate-limits, and whitelist bypass arrays.
- **`[zero_trust]` block:** Connect Active Directory, Samba, or OAuth servers to enforce Identity-Aware Policies.
- **`[blocking]` block:** Three ethically-sensitive opt-in flags — all `false` by default:
  - `process_monitor_kill_mode` — warn-only by default; set `true` only with legal counsel approval.
  - `promiscuous_capture` — host traffic only by default; set `true` only when you own the full network segment.
  - `block_anonymization_networks` — Tor/I2P not blocked by default; enable only when required by policy.

---

## 🎯 Threat Intelligence & IOC Feeds

v3.0 replaces blunt country-level GeoIP blocking with **precision IOC-based blocking** from 6 live threat feeds, updated automatically every 60 minutes:

| Feed | Source | Blocks | Confidence |
|------|--------|--------|------------|
| **Feodo Tracker** | abuse.ch | Botnet C2 IPs | 0.95 |
| **SSL Blacklist** | abuse.ch | Malware SSL IPs | 0.90 |
| **CINS Score** | cinsscore.com | Scanner/attacker IPs | 0.85 |
| **Emerging Threats** | emergingthreats.net | Compromised host IPs | 0.88 |
| **ThreatFox IOCs** | abuse.ch | C2 IPs + C2 domains | 0.92 |
| **URLhaus hostfile** | abuse.ch | Malware delivery domains | 0.90 |

**🔍 Why precision over geography?**
Country-level blocking catches ~1.4 billion legitimate users while determined attackers simply route through VPNs. IOC-based blocking targets only verified malicious actors — specific IPs and domains confirmed by independent threat researchers — with zero collateral damage.

**🌐 DNS-layer enforcement:** Every DNS query (UDP/TCP port 53) is checked against the live domain blocklist in real time. Malicious domains are dropped before the client opens any connection.

**💾 Disk persistence:** IOC lists are saved to `data/intel/` on every sync and reloaded on startup — zero-latency blocking even without internet access.

---

## ⚖️ Ethical & Legal Defaults

Rudras ships with conservative, legally safe defaults. All behaviours that could create legal risk require **explicit administrator opt-in** in `config/rudras.toml`:

| Setting | Default | Risk if Changed Without Legal Review |
|---------|---------|---------------------------------------|
| `process_monitor_kill_mode` | `false` (warn only) | Forcibly terminating user processes may violate CFAA (US), CMA (UK), EU Directive 2013/40/EU |
| `promiscuous_capture` | `false` (host traffic only) | Capturing other parties' traffic may violate ECPA Wiretap Act (US), RIPA (UK), GDPR (EU) |
| `block_anonymization_networks` | `false` (Tor/I2P allowed) | Blocking Tor is illegal in some jurisdictions; discriminates against journalists and researchers |

---

## 🔧 Build Requirements

| Tool | Required | Purpose |
|------|----------|---------|
| **Rust + Cargo** | ✅ Yes | Compiles the engine |
| **MSVC Build Tools 2022** | ✅ Yes | Windows C++ linker (Desktop C++ + Windows SDK) |
| **Npcap Driver** | ✅ Yes | Runtime packet capture |
| **Npcap SDK** | ✅ Yes | Build-time capture headers (`NPCAP_SDK_PATH` env var) |
| **Git** | ✅ Yes | Version control |
| **Python 3.x** | ⚠️ Optional | VM test scripts only |

```powershell
# One-line setup on a fresh machine (run as Administrator)
winget install Rustlang.Rustup -e
winget install Microsoft.VisualStudio.2022.BuildTools -e
rustup target add x86_64-pc-windows-msvc
rustup component add clippy rustfmt

# Build release binary
cargo build --release
# Output: target\release\rudras.exe  (~4.9 MB)
```

---

## 🧬 The CyberImmune System

This is the heart of Rudras — the feature that makes it unlike any other open-source firewall. The CyberImmune System operates in five distinct biological phases:

### 🔬 Phase 1 — Detection (T-Cell Activation)
Every packet evaluates specific behavioral heuristics: Port anomaly scoring, flow payload repetition patterns, threat reputation, and byte-rate volatility.

### 🧠 Phase 2 — Recognition (Immune Memory Lookup)
Rudras cross-references its in-memory dictionary of every threat signature previously seen. New signatures are cataloged instantly up to 10,000 distinct parallel tracks.

### 💉 Phase 3 — Response (Antibody Deployment)
Graduated proportional severity clamping to prevent false positives:

| Score | Action |
|-------|--------|
| `< 0.5` | ✅ Allow / Monitor |
| `0.5 – 0.7` | ⚠️ Monitor → Rate Limit (10 packets/sec throttling) |
| `0.7 – 0.9` | 🔶 High → 1-Hour WFP Kernel Quarantine Block |
| `> 0.9` | 🔴 Critical → Permanent Identity Ban |

### 🧪 Phase 4 — Evolution (Genetic Algorithm)
Every 10,000 packets:
- Takes critical threats and spawns 3 mutated computational rules ("Antibodies").
- Evaluates statistical fitness using Effectiveness vs Efficiency weighting.
- Survivors (Fitness > 0.7) are written permanently as local blocking logic.

### 🔄 Phase 5 — Adaptation (Continuous Calibration)
- Block rate > 50% → Threshold tightens (system becomes more aggressive)
- Block rate < 10% → Threshold relaxes (reduces false positives)

---

## 🧪 Testing & Validation

Rigorous execution tests prove Rudras' efficacy at blocking simulated intrusion events:

| Test Suite | Duration | Focus | Outcome |
|------------|----------|-------|---------|
| Basic Functionality | ~30 seconds | Packet capture, interface detection | All PASSED ✅ |
| CyberImmune Escalation | ~2 minutes | Threat detection, quarantine staging | All PASSED ✅ |
| Advanced Stress Test | ~5 minutes | 100,000 packets, memory bounds check | All PASSED ✅ |
| Enhanced Inspection | ~3 minutes | DPI SQLi blocking, DDoS detection | All PASSED ✅ |

> The genetic algorithm was validated over a **1-hour 45-minute** continuous stress session processing **1,440,000 packets** with zero false positives across standard background traffic.

---

## 📊 Real-World Performance

Observed physical metrics operating locally on a Windows 10/11 testing framework via Npcap:

| Metric | Value |
|--------|-------|
| ⚡ Packet Decision Latency | `< 1 ms` |
| 🌐 Network Throughput | `1–5 Gbps` (Physical Hardware Limit) |
| 💾 Memory Footprint | `50–100 MB` |
| 🖥️ CPU Usage (Idle) | `3–8%` |
| 🔍 Threat Lookup Speed | `O(1) Array Index` |

---

## 🚀 Firewall Trends — How Rudras Stays Ahead

| 2026–2030 Trend | Rudras Response |
|-----------------|-----------------|
| 🤖 AI-Driven Threat Prevention | ✅ CyberImmune genetic evolution — self-writing zero-day rules |
| 🔐 Zero Trust Architecture | ✅ Posture verification enforcing identity policies over passwords |
| 📈 Behavioral Analytics | ✅ Immutable state anchors matching anomaly heuristics |
| 🔒 Encrypted Traffic Inspection | ✅ Zero-Knowledge Deep Packet Inspection hashing |
| ⚙️ Automated Response | ✅ Fully autonomous — zero SOC human intervention required directly |
| 🌐 Threat Intelligence Sharing | ✅ Distributed P2P telemetry instantly synchronizes local networks |
| ☁️ SASE Alignment | ✅ Distributed control planes scale beyond single offices |

---

## 📅 Development Journey

Rudras was built systematically in structured phases, each verifying a crucial pillar of security.

- **🔩 Phase 1 — Foundation:** High-performance PCAP interception logic, core policy parsing, and geo-layer 3 blocking.
- **🧠 Phase 2 — Intelligence Layer:** Automated API caching of ThreatIntel lists, integration into SIEM JSON streamers, and Device Posture Zero-Trust configuration matrices.
- **🧬 Phase 3 — CyberImmune System:** The ML architecture. Graduated responses scaling automatically based on statistical drift deviations, preventing false positives, and saving rules to disk.
- **🌐 Phase 4 — Distributed Immunity:** Expanding the logic across a theoretical Swarm using peer-to-peer Gossip to sync Quorum rules.
- **⚖️ Phase 5 — Ethics & Precision (v3.0):** Full ethical/legal audit. Country blocking replaced with 6-feed IOC precision blocking. DNS-layer malicious domain enforcement added. All legally-sensitive behaviours made explicit opt-in. Interactive deployment mode prompt added.

---

## 📚 Engineering Research & Secrets

Rudras operates with complete transparency regarding its architectural decisions, yet fiercely protects its internal bypass mechanisms designed to prevent "cockpit-lockouts."

The `Research_Notes/` directory in the repository contains the official manifesto of the system:

- 📄 **`1_Vision_and_Purpose.md`** — Outlines the failure of static firewalls and the necessity for zero-day immunity.
- 📄 **`2_The_Problem_and_Solution.md`** — Maps physical hardware constraints (DoS Cryptography) to software solutions natively.
- 📄 **`3_Core_Architecture_and_Logic.md`** — The exact structural flow from Layer 0 WFP dropping up to the distributed Swarm Gossip.
- 📄 **`4_Usage_and_Maintenance_Guide.md`** — Administrator guide for Hot-Reloadable TOML overrides.
- 📄 **`5_Team_Engineering_Pipeline.md`** — The developer guide detailing the internal packet pipeline loop, concurrency locks (`RwLock`), and mode divergences between Server and Client states.

### 🤫 Classified Security Mechanisms (`Research_Notes/secrets/`)
To prevent reverse-engineering of the biological algorithms, absolute execution overrides are stored strictly within the private `/secrets/` subdirectory.

- 🔒 **`1_Proprietary_Algorithms.md`** — Details the `Immutable State Anchor` (Boiling Frog clamp limits) and the `Hardware Entropy` modulo logic.
- 🔒 **`2_Anti_Tamper_Mechanisms.md`** — Contains the `Dual-Clock Drift Verification` and the hardcoded literal string that enables the physical God-Key system bypass.
- 🔒 **`3_Cryptographic_Implementations.md`** — Maps the `Adaptive RSA Dropper` connection limits and the 24-hour overlap grace period code preventing KMS core deadlocks.

---

## 🔭 Future Vision & Platforms

Rudras v3.0 establishes the strongest possible foundation for an autonomous firewall. The next frontier involves extending its native reach.

### 🌍 Current Supported Base:
- 🪟 **Windows 10 / Windows 11 Enterprise** via `Npcap` and `WinDivert` ring-layer interceptors.

### 📜 Coming Soon...

To truly secure the world, Rudras must exist natively across all infrastructure backbones:

| Platform | Technology | Target Throughput |
|----------|-----------|-------------------|
| 🐧 **Linux (Servers & Clouds)** | Direct `eBPF` + `XDP` integrations | Up to 100 Gbps |
| 🍎 **macOS** | Apple Network Extensions | Endpoint-scale |
| 📱 **iOS & Android** | Lightweight mobile packet-filter nodes | Mobile-scale |
| 🔐 **Post-Quantum Cryptography** | Lattice-based NIST PQC standards | All platforms |

---

## 🗂️ Version Control & Repository Status

**Repository:** [github.com/DeepakKrishna-DK/Rudras](https://github.com/DeepakKrishna-DK/Rudras)  
**Branch:** `main`  
**License:** Proprietary — All Rights Reserved

### 📦 Clone & Setup
```powershell
git clone https://github.com/DeepakKrishna-DK/Rudras.git
cd Rudras
```
### 🔐 What Is NOT in the Repo (by design)

---

## 🤝 Philosophy & Ethics

Security built on trust requires building it trustworthily.

- 🔏 No traffic is stored at rest (unless explicitly logged during a critical attack incident).
- 🚫 No arbitrary user profiling — identity awareness is strictly access control.
- 📖 Open documentation — we document precisely how Rudras solves mathematical flaws in older firewalls to advance the field forward globally.

---

<div align="center">

*Rudras represents unyielding defense, uncompromising speed, and unparalleled architectural resilience.*

> **"The immune system does not build walls. It learns, remembers, and evolves. So does Rudras."**

</div>