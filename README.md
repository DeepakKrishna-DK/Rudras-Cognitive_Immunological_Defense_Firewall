# 🔥 Rudras — Cognitive Immunological Defense Firewall

**The Boss of Firewalls:** A next-generation, self-healing firewall that thinks like an immune system, completely built in Rust.

[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
[![Status](https://img.shields.io/badge/Status-beta-blueviolet.svg)](https://github.com/DeepakKrishna-DK/Rudras_)
[![Version](https://img.shields.io/badge/Version-4.1-blueviolet.svg)](https://github.com/DeepakKrishna-DK/Rudras_)
[![Modules](https://img.shields.io/badge/Security%20Modules-45%2B-blue.svg)](https://github.com/DeepakKrishna-DK/Rudras_)
[![Documentation](https://img.shields.io/badge/Documentation-mdBook-1E293B.svg?logo=markdown)](https://github.com/DeepakKrishna-DK/Rudras_)
[![Resources](https://img.shields.io/badge/Resources-45%2B-blue.svg)](#-supplementary-documents-videos-and-drive-resources)

![RudraS Logo](https://github.com/DeepakKrishna-DK/Rudras_/raw/main/main.jpeg)

*Every attack makes Rudras smarter. Every session makes it more accurate.*

---

## 📖 Official Documentation

The entirety of Rudras’ architecture, philosophy, usage guides, operations, and threat model mechanisms have been structured into our official **[mdBook Documentation Hub](https://github.com/DeepakKrishna-DK/Rudras-Cognitive_Immunological_Defense_Firewall/blob/main/Rudras_%20The%20Firewall%20in%20Practice.pdf)**.

---

## 📑 Table of Contents

1. [🏛️ The History of Firewalls](#️-the-history-of-firewalls)  
2. [💡 Why I Built Rudras](#-why-i-built-rudras)  
3. [🛡️ What is Rudras?](#️-what-is-rudras)  
4. [🧠 The Philosophy — From Wall to Nervous System](#-the-philosophy--from-wall-to-nervous-system)  
5. [⚙️ Core Enterprise Capabilities (v3.0–4.1)](#️-core-enterprise-capabilities-v30–41)  
6. [🗏️ Dual-Mode Architecture & Deployment](#️-dual-mode-architecture--deployment)  
7. [🧬 The CyberImmune System](#-the-cyberimmune-system)  
8. [🎯 Threat Intelligence & IOC Feeds](#-threat-intelligence--ioc-feeds)  
9. [⚖️ Ethical & Legal Defaults](#️-ethical--legal-defaults)  
10. [📖 Official Documentation (mdBook Hub)](#-official-documentation)  
11. [📂 Supplementary Documents, Videos, and Drive Resources](#-supplementary-documents-videos-and-drive-resources)  
12. [🔧 Build Requirements](#-build-requirements)  
13. [🧪 Testing & Validation](#-testing--validation)  
14. [📊 Real-World Performance](#-real-world-performance)  
15. [🚀 Firewall Trends — How Rudras Stays Ahead](#-firewall-trends--how-rudras-stays-ahead)  
16. [📅 Development Journey](#-development-journey)  
17. [🔭 Future Vision & Platforms](#-future-vision--platforms)  
18. [🤝 Philosophy & Ethics](#-philosophy--ethics)  
19. [🔒 License & Legal Notice](#-license--legal-notice)  

***

## 🏛️ The History of Firewalls

To understand why Rudras exists, you need to understand where firewalls came from — and how they have consistently failed to keep up with the threat landscape.

**Generation 1 — Packet Filters (1988)**  
Born out of the Morris Worm of 1988. These early systems operated at the network layer and compared packets against a static list of rules (source IP, port). Fast and simple, but trivially bypassed.

**Generation 2 — Stateful Inspection (1994)**  
Check Point FireWall‑1 popularized stateful inspection — tracking the state of active connections instead of treating each packet independently. A major jump forward, but still blind to payload contents.

**Generation 3 — Application Layer Gateways & Proxies (Late 1990s)**  
Firewalls evolved to understand application-level semantics (HTTP, FTP) and intercept traffic at Layer 7. This era gave rise to Unified Threat Management (UTM) appliances.

**Generation 4 — Next-Generation Firewalls (2000s–2010s)**  
NGFWs introduced Deep Packet Inspection, user identity, and SSL/TLS decryption. Yet they remained fundamentally static: a zero‑day exploit could slip straight through. The systems were reactive.

**Generation 5 — AI-Driven & Zero Trust Firewalls (2020s)**  
As perimeters dissolved into cloud and mobile, Zero Trust became the guiding paradigm. Many commercial products bolted AI on as an afterthought, rather than designing AI and immunity as the foundation.

👉 **This gap — a truly cognitive, immune‑style firewall — is exactly what Rudras was designed to fill.**

***

## 💡 Why I Built Rudras

> *“The best security system isn’t a wall. It’s an immune system.”*

After deep academic and personal research into firewall architectures, I reached a conclusion: traditional firewalls are fundamentally passive. Attackers use zero‑day exploits, low‑and‑slow exfiltration, and pattern mimicry to bypass static rules. A rule-based system cannot reliably stop what it has never seen.

The human immune system, by contrast, detects foreign bodies through pattern recognition, remembers past threats, evolves its defenses naturally, and distributes immunity across the organism.

Rudras is my answer to a question:  
**Why doesn’t a firewall behave like an immune system?**

### ⚡ Why Rust?

A firewall lives directly in the **hot path** of every packet. It must deliver microsecond‑scale decisions and be uncompromisingly memory‑safe.

- C/C++: practically guarantees buffer overflows and memory corruption over time.  
- Managed runtimes (Java/Go): introduce GC pauses exactly when a 100‑Gbps attack hits.  

**Rust** was the only language that provided:

- Compile‑time memory safety (no GC).  
- Zero‑cost abstractions.  
- High‑performance async I/O for parallel packet inspection.

***

## 🛡️ What is Rudras?

Rudras (named after the ancient storm deity — fierce, adaptive, unstoppable) is a **Cognitive Immunological Defense Firewall**, fully implemented in Rust.

It is a living, self‑adapting system that:

- 👁️ Observes every packet flowing through the network interface in real time.  
- 🔬 Analyzes behavioral patterns, threat signatures, and contextual intent.  
- ⚡ Responds with graduated defense actions (monitor → rate‑limit → quarantine → block).  
- 🧬 Evolves its own defense rules using a genetic algorithm.  
- 🧠 Remembers every threat it has ever encountered.  
- 🌐 Shares that intelligence securely with peer nodes across the network.  
- 📊 Exposes a modern **Next.js SOC Dashboard** for real‑time visibility.

**Every attack makes Rudras smarter. Every session makes it more accurate.**

***

## 🧠 The Philosophy — From Wall to Nervous System

Traditional firewalls behave like bouncers reading a static list.

**Traditional:**  
`Packet → Rule Match (1000+ static rules) → Block / Allow`

Rudras is architected as a **network nervous system**:

**Rudras:**  
`Packet → Identity Resolution → Behavioral Context Analysis → Intent Classification → Adaptive Response → Memory Update → Distributed Intelligence Broadcast`

Rudras does not ask *“Is this IP on the blocklist?”*  
It asks: **“Does this behavior belong here, and what is its macroscopic intent?”**

***

## ⚙️ Core Enterprise Capabilities (v3.0–4.1)

Rudras natively integrates modules that usually require several separate commercial appliances.

| Module | Status | What It Does |
|--------|--------|--------------|
| 🧬 **CyberImmune Engine** | ✅ Active | Self‑healing ML with **Adaptive Trust** and **Immutable State Anchors**, resisting “boiling‑frog” data poisoning. |
| 🛡️ **Zero-Trust Anti-Tamper** | ✅ Active | Detects unauthorized sniffers and debuggers (Wireshark, IDA Pro, Ghidra) in **warn‑only** mode by default; no forced termination unless explicitly opted‑in. |
| 🔐 **ZKDPI & Hybrid Vault** | ✅ Active | Zero‑Knowledge Deep Packet Inspection with SHA‑256 process hashing and an **Adaptive RSA Dropper** to prevent Crypto‑DoS while preserving asymmetric vault operations. |
| 🔥 **Core WAF Engine** | ✅ Active | Deep packet inspection to block Log4Shell (Log4j), SQLi, and RCE attempts natively. |
| 🌐 **Swarm Consensus** | ✅ Active | Distributed defense protocols that gracefully degrade into local **Island Mode** during infrastructure failures. |
| 🦠 **Active C2 Defense** | ✅ Active | Dynamically blocks Cobalt Strike, Meterpreter, and other beacon patterns via stager signature and behavior analysis. |
| 🔌 **Protocol Anti-Evasion** | ✅ Active | Shuts down Nmap NULL scans, XMAS scans, and SYN‑FIN evasions at the earliest packet stage. |
| 🎯 **IOC-Based Threat Blocking** | ✅ Active | Replaces blunt GeoIP denies with **precision IOC blocking** — specific malicious IPs and domains from 6 live feeds, refreshed every 60 minutes. |
| 🌍 **Malicious Domain Blocking** | ✅ Active | DNS‑layer filtering, checking every query against ThreatFox C2 domains and URLhaus malware hosts before any TCP handshake. |
| 🏰 **CIP Whitelisting** | ✅ Active | **Critical Infrastructure Protection** prevents accidental blocking of essential services unless malicious behavior is mathematically proven. |
| 🔗 **Layer 2 Security** | ✅ Active | Detects MAC anomalies, ARP spoofing, and cache poisoning at the data link layer. |
| 📊 **SIEM Integration** | ✅ Active | Splunk HEC and ELK integrations using structured JSON logs (no brittle regex parsing). |
| 🧩 **Ransomware Sandbox** | ✅ Active | Monitors SMB payload entropy; if Shannon entropy exceeds configurable thresholds (e.g., 7.85/8.0), traffic is quarantined as likely encryption activity. |
| 🪤 **Deception Network** | ✅ Active | Honeypot ports (e.g., FTP, MySQL) lure attackers and harvest zero‑day payloads for AI analysis. |
| 🏙️ **Micro-Segmentation** | ✅ Active | 8 hardened security zones with intra‑VLAN lateral movement detection. |
| 🧠 **IDS/IPS Taxonomy** | ✅ Active | 85+ rules across 70+ threat categories, mapping to OWASP and MITRE ATT&CK. |
| 🧮 **Compliance Mapping** | ✅ Partial | Controls mapped against CIS v8, NIST CSF 2.0, NERC CIP, and ISO 27001 domains. |

***

## 🗏️ Dual-Mode Architecture & Deployment

A firewall protecting a developer laptop has very different requirements from one guarding a production database cluster. Rudras supports two primary deployment modes and an auto‑detection path.

### 💻 1. Client (Endpoint) Mode

- **Focus:** Outbound connections (≈60% outbound monitoring).  
- **Targets:** C2 callbacks, malware stagers, silent data exfiltration.  
- **Behavior:** Quiet, adaptive thresholds tuned to avoid interrupting normal user and developer workflows.

### 🖥️ 2. Server (Gateway) Mode

- **Focus:** Inbound connections (≈80% inbound monitoring).  
- **Targets:** Port scans, brute‑force attempts, exploit propagation, lateral movement.  
- **Behavior:** Aggressive filtering, strict micro‑segmentation, deep inspection for any traffic on undocumented ports.

### 🧠 3. AUTO Mode

- **Focus:** Automatic classification of the host role.  
- **Behavior:** Uses open‑port and service fingerprinting to infer whether the host behaves more like an endpoint or gateway, then applies appropriate weights and thresholds.

### 🖱️ Interactive Mode Selection (v3.0+)

When launched without a `--mode` flag, Rudras presents an interactive selector:

```text
╔═══════════════════════════════════════════════════════════════════╗
║              RUDRAS — SELECT DEPLOYMENT MODE                      ║
╠═══════════════════════════════════════════════════════════════════╣
║  1  CLIENT  — Endpoint/workstation (outbound C2 & exfil focus)    ║
║  2  SERVER  — Gateway/perimeter    (inbound attack focus)         ║
║  3  AUTO    — Auto-detect from open ports                         ║
╠═══════════════════════════════════════════════════════════════════╣
║  Tip: skip this prompt with --mode client / --mode server         ║
╚═══════════════════════════════════════════════════════════════════╝
```

- **Skip prompt (CLI):**  
  `rudras.exe --mode client`  
  `rudras.exe --mode server`  
  `rudras.exe --mode auto`

- **Skip prompt (config):**  
  Set `deployment = "client" | "server" | "auto"` in the `[mode]` block of `config/rudras.toml`.

### 🎛️ Hot‑Reloadable TOML Configuration

All operational tuning is centralized in `config/rudras.toml`:

- **`[mode]`** – `deployment = "client" | "server" | "auto"`  
- **`[ai]`** – `initial_susp_threshold`, `max_learning_multiplier`, drift calibration.  
- **`[ips]`** – WFP quarantine thresholds, rate‑limits, whitelists.  
- **`[zero_trust]`** – connectors for AD, Samba, OAuth for identity‑aware policies.  
- **`[blocking]`** – ethically sensitive flags (all `false` by default):  
  - `process_monitor_kill_mode`  
  - `promiscuous_capture`  
  - `block_anonymization_networks`  

Configuration changes can be hot‑reloaded without recompiling.

***

## 🧬 The CyberImmune System

This is the core mechanism that makes Rudras fundamentally different.

The **CyberImmune System** operates in five biological‑inspired phases:

### 🔬 Phase 1 — Detection (T‑Cell Activation)

Each packet/flow is evaluated using heuristics including:

- Port anomaly scoring.  
- Flow payload repetition and timing patterns.  
- Threat reputation lookups.  
- Byte‑rate volatility and entropy.

### 🧠 Phase 2 — Recognition (Immune Memory Lookup)

- An in‑memory dictionary tracks previously seen malicious signatures and behaviors.  
- New signatures are indexed instantly, supporting up to **10,000** concurrent tracks.

### 💉 Phase 3 — Response (Antibody Deployment)

Graduated response levels to limit false positives:

| Score | Action |
|-------|--------|
| `< 0.5` | ✅ Allow / monitor |
| `0.5 – 0.7` | ⚠️ Monitor and rate‑limit (e.g., 10 packets/sec) |
| `0.7 – 0.9` | 🔶 High: 1‑hour WFP kernel quarantine block |
| `> 0.9` | 🔴 Critical: permanent identity/indicator ban |

### 🧪 Phase 4 — Evolution (Genetic Algorithm)

Every 10,000 packets:

- Critical threats are used as seeds for **3 mutated detection rules**.  
- Each mutation is scored by a fitness function balancing **effectiveness** and **efficiency**.  
- Mutations with fitness > 0.7 are persisted as new, local blocking logic.

### 🔄 Phase 5 — Adaptation (Continuous Calibration)

- **Block rate > 50%** → system tightens thresholds (more aggressive).  
- **Block rate < 10%** → thresholds relax (fewer false positives).  

This continuous feedback loop keeps Rudras aligned with real‑world conditions.

***

## 🎯 Threat Intelligence & IOC Feeds

Rudras v3.0+ replaces naive country‑level GeoIP blocking with **precision IOC‑based blocking** from six live feeds, refreshed every 60 minutes:

| Feed | Source | Focus | Confidence |
|------|--------|-------|-----------|
| **Feodo Tracker** | abuse.ch | Botnet C2 IPs | 0.95 |
| **SSL Blacklist** | abuse.ch | Malware SSL endpoints | 0.90 |
| **CINS Score** | cinsscore.com | Scanner/attacker IPs | 0.85 |
| **Emerging Threats** | emergingthreats.net | Compromised hosts | 0.88 |
| **ThreatFox IOCs** | abuse.ch | C2 IPs and domains | 0.92 |
| **URLhaus hostfile** | abuse.ch | Malware delivery domains | 0.90 |

### 🌐 DNS‑Layer Enforcement

- All DNS queries (UDP/TCP 53) are checked against the live domain blocklist.  
- Malicious domains are dropped before connections are initiated.

### 💾 Persistence

- IOC lists are stored under `data/intel/` after each sync.  
- On startup, Rudras reloads these from disk for **instant blocking** even when offline.

***

## ⚖️ Ethical & Legal Defaults

Rudras ships with **conservative, legally‑aware defaults**. Any behavior that might create legal or ethical risk is **opt‑in only**, configured in `config/rudras.toml`.

| Setting | Default | Potential Risk if Enabled Without Review |
|---------|---------|-------------------------------------------|
| `process_monitor_kill_mode` | `false` (warn only) | Forced process termination may trigger legal exposure under CFAA (US), CMA (UK), or EU Directive 2013/40/EU. |
| `promiscuous_capture` | `false` (host traffic only) | Capturing third‑party traffic may conflict with ECPA/Wiretap Act (US), RIPA (UK), or GDPR (EU). |
| `block_anonymization_networks` | `false` (Tor/I2P allowed) | Blanket blocking of Tor/I2P may impact journalists, researchers, and may violate local policies. |

Administrators are strongly advised to consult legal and compliance teams before enabling any of these flags.

***

## 📂 Supplementary Documents, Videos, and Drive Resources

Additional materials supporting Rudras (papers, manuals, videos, screenshots, and research artifacts) are available via GitHub and Google Drive.

- **Google Drive companion folder (supplementary docs, videos, screenshots, slides):**  
  [Project-Rudras](https://drive.google.com/drive/folders/1TscWyB0lL0uBLBLADoedSXEgF79iIs2s?usp=sharing) 

These resources include:

- Detailed project manual and design document.  
- Execution screenshots and SOC dashboard previews.  
- Demo videos and walk‑through recordings.  
- Related reference documents and research outputs.

***

## 🔧 Build Requirements

| Tool | Required | Purpose |
|------|----------|---------|
| **Rust + Cargo** | ✅ Yes | Compile the Rudras engine. |
| **MSVC Build Tools 2022** | ✅ Yes | Windows C++ toolchain and Windows SDK (for Rust on Windows). |
| **Npcap Driver** | ✅ Yes | Runtime packet capture (WinPcap‑compatible). |
| **Npcap SDK** | ✅ Yes | Build‑time PCAP headers (`NPCAP_SDK_PATH` env var). |
| **WinDivert** | ✅ Yes | Kernel‑level interception and filtering for Windows. |
| **Git** | ✅ Yes | Version control and dependency retrieval. |
| **Python 3.x** | ⚠️ Optional | VM test harnesses and synthetic traffic scripts. |
| **Node.js + npm** | ⚠️ Optional | Next.js SOC Dashboard frontend. |

***

## 🧪 Testing & Validation

Rudras is validated with multi‑stage test suites:

| Test Suite | Duration | Focus | Outcome |
|------------|----------|-------|---------|
| Basic Functionality | ~30 s | Packet capture, interface detection | All PASSED ✅ |
| CyberImmune Escalation | ~2 min | Threat scoring and quarantine staging | All PASSED ✅ |
| Advanced Stress Test | ~5 min | 100,000 packets, memory bounds checking | All PASSED ✅ |
| Enhanced Inspection | ~3 min | DPI SQLi blocking, DDoS detection | All PASSED ✅ |

The genetic algorithm was further validated over a **1 hour 45 minute** continuous session processing **~1,440,000 packets**, with **zero false positives** on baseline background traffic.

***

## 📊 Real-World Performance

Measured on Windows 10/11 test rigs with Npcap:

| Metric | Observed Value |
|--------|----------------|
| ⚡ Packet Decision Latency | `< 1 ms` |
| 🌐 Throughput | ~1–5 Gbps (limited by physical NIC) |
| 💾 Memory Footprint | ~50–100 MB |
| 🖥️ CPU Usage (Idle) | ~3–8% |
| 🔍 Threat Lookup | `O(1)` array index performance |

***

## 🚀 Firewall Trends — How Rudras Stays Ahead

| 2026–2030 Trend | Rudras Response |
|-----------------|-----------------|
| 🤖 AI-Driven Threat Prevention | ✅ CyberImmune genetic evolution engine with self‑writing zero‑day rules. |
| 🔐 Zero Trust Architecture | ✅ Device posture and identity‑aware controls embedded directly into packet path. |
| 📈 Behavioral Analytics | ✅ Immutable state anchors and anomaly heuristics for user and entity behavior. |
| 🔒 Encrypted Traffic Inspection | ✅ Zero‑Knowledge DPI and hashing, minimizing exposure while retaining signals. |
| ⚙️ Automated Response | ✅ Autonomous escalation path (monitor → rate‑limit → quarantine → block). |
| 🌐 Threat Intelligence Sharing | ✅ P2P telemetry and Quorum rule sharing for distributed immunity. |
| ☁️ SASE / SSE Alignment | ✅ Design aligned with distributed control planes beyond single‑office perimeters. |

***

## 📅 Development Journey

Rudras has been built in deliberate phases:

1. **Phase 1 — Foundation**  
   High‑performance PCAP interception, core policy parsing, basic geo‑layer blocking.

2. **Phase 2 — Intelligence Layer**  
   Threat‑intel API caching, SIEM JSON streaming, zero‑trust posture configuration.

3. **Phase 3 — CyberImmune System**  
   ML engine, graduated response scaling, drift control, on‑disk rule persistence.

4. **Phase 4 — Distributed Immunity**  
   Gossip protocols and Swarm logic for sharing learned protections across nodes.

5. **Phase 5 — Ethics & Precision (v3.0+)**  
   Legal/ethical review, replacement of country blocks with precision IOC feeds, DNS‑layer domain enforcement, and explicit opt‑in for sensitive behaviors.  

6. **Phase 6 — SOC Experience & Docs (4.x)**  
   Next.js SOC dashboard, mdBook documentation hub, and refined Windows deployment story.

***

## 🔭 Future Vision & Platforms

Rudras v4.1 establishes a solid, production‑grade foundation. Next steps:

### 🌍 Current Supported Base

- 🪟 **Windows 10 / 11 Enterprise**  
  via Npcap + WinDivert and WFP interception.

### 🧭 Roadmap Targets

| Platform | Technology | Target Throughput |
|----------|------------|-------------------|
| 🐧 Linux (servers, clouds) | eBPF + XDP | Up to 100 Gbps |
| 🍎 macOS | Network Extensions | Endpoint‑scale |
| 📱 iOS & Android | Lightweight packet‑filter nodes | Mobile‑scale |
| 🔐 Post‑Quantum Cryptography | NIST PQC lattice‑based suites | All platforms |

***

## 🤝 Philosophy & Ethics

Security must be built in a way that **earns** trust:

- 🔏 No long‑term storage of traffic content by default; logging is focused, minimal, and operator‑controlled.  
- 🚫 No arbitrary user profiling; identity is used strictly for **access control**, not surveillance.  
- 📖 Open, precise documentation of how Rudras addresses weaknesses in legacy firewalls, to advance global security practice.

> **“The immune system does not build walls. It learns, remembers, and evolves. So does Rudras.”**

***

## 🔒 License & Legal Notice

**License:** Proprietary — All Rights Reserved.  
See [LICENSE](https://github.com/DeepakKrishna-DK/Rudras-Cognitive_Immunological_Defense_Firewall/blob/main/License) for detailed usage, redistribution, and disclosure terms.

Rudras must be deployed only on networks and systems you **own or are explicitly authorized to defend**. Misuse against third‑party infrastructure without permission may violate laws in multiple jurisdictions.
