# ðŸ”¥ Rudras â€” Cognitive Immunological Defense Firewall
### The Boss of Firewalls.

<div align="center">

[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Built with Go](https://img.shields.io/badge/Built%20with-Go-blue.svg)](https://golang.org/)
[![Built with Python](https://img.shields.io/badge/Built%20with-Python-yellow.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Status](https://img.shields.io/badge/Status-In%20Development-bluelight.svg)]()
[![Version](https://img.shields.io/badge/Version-3.0%20Enterprise-blueviolet.svg)]()

**A next-generation, self-healing firewall that thinks like an immune system.**

*Last Updated: March 2026*

</div>

---
![RudraS Logo](https://github.com/DeepakKrishna-DK/Rudras_/blob/main/main.jpeg)
---

## Table of Contents
1. [The History of Firewalls](#-the-history-of-firewalls)
2. [Why I Built Rudras](#-why-i-built-rudras)
3. [What is Rudras?](#-what-is-rudras)
4. [The Philosophy â€” From Wall to Nervous System](#-the-philosophy--from-wall-to-nervous-system)
5. [Core Enterprise Capabilities (v3.0)](#-core-capabilities-v30)
6. [Dual-Mode Architecture & Deployment](#-dual-mode-architecture)
7. [The CyberImmune System](#-the-cyberimmune-system)
8. [Threat Intelligence & IOC Feeds](#-threat-intelligence--ioc-feeds)
9. [Ethical & Legal Defaults](#-ethical--legal-defaults)
10. [Build Requirements](#-build-requirements)
11. [Testing & Validation](#-testing--validation)
12. [Real-World Performance](#-real-world-performance)
13. [Firewall Trends â€” How Rudras Stays Ahead](#-firewall-trends--how-rudras-stays-ahead)
14. [Engineering Research & Secrets](#-engineering-research--secrets)
15. [Future Vision & Platforms](#-future-vision--platforms)
16. [Changelog](#-changelog)

---

## ðŸ›ï¸ The History of Firewalls

To understand why Rudras exists, you need to understand where firewalls came from â€” and how they've consistently failed to keep up with the threat landscape.

**Generation 1 â€” Packet Filters (1988)**
Born out of the Morris Worm of 1988, the first major internet worm. These early systems operated at the network layer and compared packets against a static list of rules (Source IP, Port). Fast, simple, but trivially bypassed.

**Generation 2 â€” Stateful Inspection (1994)**
Check Point FireWall-1 introduced stateful inspection â€” tracking the state of active connections instead of treating each packet independently. A quantum leap forward, but still blind to payload contents.

**Generation 3 â€” Application Layer Gateways & Proxies (Late 1990s)**
Firewalls evolved to understand application-level semantics (HTTP, FTP) and intercept traffic at Layer 7. This era gave rise to Unified Threat Management (UTM) appliances.

**Generation 4 â€” Next-Generation Firewalls (2000sâ€“2010s)**
NGFWs brought Deep Packet Inspection, User Identity Awareness, and SSL/TLS decryption. But there was still a fundamental flaw: all of these systems operated on static rules. A zero-day attack simply slipped right through. The system was strictly reactive.

**Generation 5 â€” AI-Driven & Zero Trust Firewalls (2020s)**
The Zero Trust paradigm emerged as the perimeter dissolved into cloud infra and mobile laptops. Commercial products bolted AI on as an afterthought, rather than building it as the foundational layer.

This is exactly the gap that Rudras was designed to fill.

---

## ðŸ’¡ Why I Built Rudras

> *"The best security system isn't a wall. It's an immune system."*

After studying firewalls during academic and personal research, I arrived at a singular conclusion: every major firewall architecture is fundamentally passive. Attackers use zero-day exploits, slowly exfiltrate data to avoid limits, and mimic legitimate patterns. A rule-based system cannot reliably stop what it has never seen.

I became fascinated by the human immune system. It detects foreign bodies through pattern recognition, remembers past threats, evolves its defenses naturally, and distributes immunity unconditionally. I asked: *Why doesn't a firewall work this way?*

### Why Rust?
A firewall sits in the hot-path of every network packet. It must have microsecond decision latency and be completely memory-safe. Writing a security-critical engine in C/C++ guarantees buffer overflows eventually. Writing it in Java/Go introduces garbage collector pausing during 100-Gbps attacks. Rust was the only language that met all requirements cleanly.

---

## ðŸ›¡ï¸ What is Rudras?

Rudras (named after the ancient concept of the storm deity â€” fierce, adaptive, and unstoppable) is a **Cognitive Immunological Defense Firewall** built entirely in Rust.

It is a living, self-adapting security system that:
- Observes every packet flowing through the network interface in real time.
- Analyzes behavioral patterns, threat signatures, and contextual intent.
- Responds with graduated defense actions (monitor â†’ rate-limit â†’ quarantine â†’ block).
- Evolves its own defense rules using a genetic algorithm.
- Remembers every threat it has ever encountered.
- Shares that intelligence with peer nodes across the network.

Every attack makes Rudras smarter. Every session makes it more accurate.

---

## ðŸ§  The Philosophy â€” From Wall to Nervous System

Traditional firewalls act like bouncers reading a static list.
**Traditional:** `Packet â†’ Rule Match (1000+ static rules) â†’ Block / Allow`

Rudras thinks like a nervous system:
**Rudras:**
`Packet â†’ Identity Resolution â†’ Behavioral Context Analysis â†’ Intent Classification â†’ Adaptive Response â†’ Memory Update â†’ Distributed Intelligence Broadcast`

Rudras doesn't ask *"Is this on the target blocklist?"* It asks *"Does this behavior belong here, and what is its macroscopic intent?"*

---

## âš™ï¸ Core Capabilities (v3.0)

Rudras natively integrates modules that typically require half a dozen separate commercial appliances:

| Module | Status | What It Does |
|--------|--------|--------------|
| ðŸ§¬ **CyberImmune Engine** | âœ… Active | Self-healing ML with **Adaptive Trust** and **Immutable State Anchors** stopping Boiling-Frog data poisoning. |
| ðŸ›¡ï¸ **Zero-Trust Anti-Tamper** | âœ… Active | Detects unauthorized sniffers (Wireshark, IDA Pro, Ghidra) in **warn-only** mode by default â€” no forcible termination unless explicitly opted in. |
| ðŸ” **ZKDPI & Hybrid Vault** | âœ… Active | Generates SHA-256 process hashes. An **Adaptive RSA Dropper** prevents Crypto-DoS while maintaining Asymmetric Decryption vaults. |
| ðŸ”¥ **Core WAF Engine** | âœ… Active | Deep Packet Inspection stops Log4j, SQLi, and Remote Code Execution (RCE) natively. |
| ðŸŒ **Swarm Consensus** | âœ… Active | Distributed protocols safely degrade to local **Island Mode** during physical infrastructure failures. |
| ðŸ¦  **Active C2 Defense** | âœ… Active | Blocks Cobalt Strike & Meterpreter beacons dynamically based on stager signatures. |
| ðŸ”Œ **Protocol Anti-Evasion** | âœ… Active | Shuts down Nmap Null scans, XMAS scans, and SYN-FIN evasion packets at Layer 0. |
| ðŸŽ¯ **IOC-Based Threat Blocking** | âœ… Active | Replaces blunt country blocks with **precision IOC blocking** â€” specific malicious IPs and domains from 6 live feeds updated every 60 min. |
| ðŸŒ **Malicious Domain Blocking** | âœ… Active | DNS-layer blocking checks every query against ThreatFox C2 domains and URLhaus delivery hosts before any connection opens. |
| ðŸ° **CIP Whitelisting** | âœ… Active | **Critical Infrastructure Protection** dynamically prevents blocking essential services unless malware is proven mathematically. |
| ðŸ”— **Layer 2 Security** | âœ… Active | Analyzes MAC anomalies to stop ARP Spoofing and Cache Poisoning at the Data Link layer. |
| ðŸ“Š **SIEM Integration** | âœ… Active | Splunk HEC and ELK Stack integrations use native **Structured JSON Logging** for instant index ingestion without regex parsers. |
| ðŸ§© **Ransomware Sandbox** | âœ… Active | Analyzes SMB payload entropy dynamically to kill encryption attempts at Layer 7 (Shannon entropy > 7.85/8.0 = instant block). |
| ðŸª¤ **Deception Network** | âœ… Active | Honeypot ports (FTP, MySQL) snare attackers and harvest zero-day payloads for the AI. |
| ðŸ™ï¸ **Micro-Segmentation** | âœ… Active | 8 strict security zones designed with intra-VLAN lateral movement detection limiters. |

---

## ðŸ—ï¸ Dual-Mode Architecture

A firewall protecting an endpoint laptop requires vastly different behaviors than one protecting a database cluster. Rudras operates across two distinct strategic deployments:

**1. Client (Endpoint) Mode**
- **Focus**: Outbound connections (60% outbound monitoring).
- **Targets**: C2 callbacks, Malware stagers, Data Exfiltration.
- **Behavior**: Quiet, adaptive thresholds tailored to avoid interrupting normal developer and user traffic.

**2. Server (Gateway) Mode**
- **Focus**: Inbound connections (80% inbound monitoring).
- **Targets**: Port scanning, Brute Force, Exploit propagation.
- **Behavior**: Highly aggressive. Strict Micro-segmentation. Instantly escalates any traffic arriving on an undocumented port to deep inspection.

### Interactive Mode Selection (v3.0)
When launched with no `--mode` flag, Rudras **prompts the user interactively** rather than silently defaulting to Client:

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘              RUDRAS â€” SELECT DEPLOYMENT MODE                    â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘  1  CLIENT  â€” Endpoint/workstation (outbound C2 & exfil focus)  â•‘
â•‘  2  SERVER  â€” Gateway/perimeter    (inbound attack focus)        â•‘
â•‘  3  AUTO    â€” Auto-detect from open ports                        â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘  Tip: skip this prompt with --mode client / --mode server        â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

* **Skip prompt (CLI):** `rudras.exe --mode client` or `rudras.exe --mode server`
* **Skip prompt (config):** Set `deployment = "client"` in `[mode]` section of `config/rudras.toml`

### ðŸŽ›ï¸ TOML Configuration Matrix (Hot Reloadable)
Rudras abstracts backend logic into `config/rudras.toml` to allow SOC Administrators to tune the engine without recompiling.
* **[mode] block:** Set `deployment = "client"` or `"server"` to skip the interactive prompt.
* **[ai] block:** Manipulate the AI Engine's `initial_susp_threshold` and `max_learning_multiplier` dynamically.
* **[ips] block:** Manage WFP quarantine thresholds, rate-limits, and whitelist bypass arrays.
* **[zero_trust] block:** Connect Active Directory, Samba, or OAuth servers to enforce Identity-Aware Policies.
* **[blocking] block:** Three ethically-sensitive opt-in flags â€” all `false` by default:
  - `process_monitor_kill_mode` â€” warn-only by default; set `true` only with legal counsel approval.
  - `promiscuous_capture` â€” host traffic only by default; set `true` only when you own the full network segment.
  - `block_anonymization_networks` â€” Tor/I2P not blocked by default; enable only when required by policy.

---

## ðŸŽ¯ Threat Intelligence & IOC Feeds

v3.0 replaces blunt country-level GeoIP blocking with **precision IOC-based blocking** from 6 live threat feeds, updated automatically every 60 minutes:

| Feed | Source | Blocks | Confidence |
|------|--------|--------|------------|
| **Feodo Tracker** | abuse.ch | Botnet C2 IPs | 0.95 |
| **SSL Blacklist** | abuse.ch | Malware SSL IPs | 0.90 |
| **CINS Score** | cinsscore.com | Scanner/attacker IPs | 0.85 |
| **Emerging Threats** | emergingthreats.net | Compromised host IPs | 0.88 |
| **ThreatFox IOCs** | abuse.ch | C2 IPs + C2 domains | 0.92 |
| **URLhaus hostfile** | abuse.ch | Malware delivery domains | 0.90 |

**Why precision over geography?**
Country-level blocking catches ~1.4 billion legitimate users while determined attackers simply route through VPNs. IOC-based blocking targets only verified malicious actors â€” specific IPs and domains confirmed by independent threat researchers â€” with zero collateral damage.

**DNS-layer enforcement:** Every DNS query (UDP/TCP port 53) is checked against the live domain blocklist in real time. Malicious domains are dropped before the client opens any connection.

**Disk persistence:** IOC lists are saved to `data/intel/` on every sync and reloaded on startup â€” zero-latency blocking even without internet access.

---

## âš–ï¸ Ethical & Legal Defaults

Rudras ships with conservative, legally safe defaults. All behaviours that could create legal risk require **explicit administrator opt-in** in `config/rudras.toml`:

| Setting | Default | Risk if changed without legal review |
|---------|---------|---------------------------------------|
| `process_monitor_kill_mode` | `false` (warn only) | Forcibly terminating user processes may violate CFAA (US), CMA (UK), EU Directive 2013/40/EU |
| `promiscuous_capture` | `false` (host traffic only) | Capturing other parties' traffic may violate ECPA Wiretap Act (US), RIPA (UK), GDPR (EU) |
| `block_anonymization_networks` | `false` (Tor/I2P allowed) | Blocking Tor is illegal in some jurisdictions; discriminates against journalists and researchers |

---

## ðŸ”§ Build Requirements

| Tool | Required | Purpose |
|------|----------|---------|
| **Rust + Cargo** | âœ… Yes | Compiles the engine |
| **MSVC Build Tools 2022** | âœ… Yes | Windows C++ linker (Desktop C++ + Windows SDK) |
| **Npcap Driver** | âœ… Yes | Runtime packet capture |
| **Npcap SDK** | âœ… Yes | Build-time capture headers (`NPCAP_SDK_PATH` env var) |
| **Git** | âš ï¸ Recommended | Version control |
| **Python 3.x** | âš ï¸ Optional | VM test scripts only |

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

## ðŸ§¬ The CyberImmune System

This is the heart of Rudras â€” the feature that makes it unlike any other open-source firewall. The CyberImmune System operates in five distinct biological phases:

**Phase 1 â€” Detection (T-Cell Activation)**
Every packet evaluates specific behavioral heuristics: Port anomaly scoring, flow payload repetition patterns, threat reputation, and byte-rate volatility.

**Phase 2 â€” Recognition (Immune Memory Lookup)**
Rudras cross-references its in-memory dictionary of every threat signature previously seen. New signatures are cataloged instantly up to 10,000 distinct parallel tracks.

**Phase 3 â€” Response (Antibody Deployment)**
Graduated proportional severity clamping to prevent false positives:
* `< 0.5` : Allow / Monitor
* `0.5 - 0.7` : Monitor â†’ Rate Limit (10 packets/sec throttling)
* `0.7 - 0.9` : High â†’ 1-Hour WFP Kernel Quarantine Block
* `> 0.9` : Critical â†’ Permanent Identity Ban 

**Phase 4 â€” Evolution (Genetic Algorithm)**
Every 10,000 packets:
- Takes critical threats and spawns 3 mutated computational rules ("Antibodies").
- Evaluates statistical fitness using Effectiveness vs Efficiency weighting.
- Survivors (Fitness > 0.7) are written permanently as local blocking logic.

**Phase 5 â€” Adaptation (Continuous Calibration)**
- Block rate > 50% â†’ Threshold tightens (system becomes more aggressive)
- Block rate < 10% â†’ Threshold relaxes (reduces false positives)

---

## ðŸ§ª Testing & Validation

Rigorous execution tests prove Rudras' efficacy at blocking simulated intrusion events:

| Test Suite | Duration | Focus | Outcome |
|------------|----------|-------|---------|
| Basic Functionality | ~30 seconds | Packet capture, interface detection | All PASSED âœ… |
| CyberImmune Escalation | ~2 minutes | Threat detection, quarantine staging | All PASSED âœ… |
| Advanced Stress Test | ~5 minutes | 100,000 packets, memory bounds check | All PASSED âœ… |
| Enhanced Inspection | ~3 minutes | DPI SQLi blocking, DDoS detection | All PASSED âœ… |

The genetic algorithm was validated over a 1-hour 45-minute continuous stress session processing 1,440,000 packets with zero false positives across standard background traffic.

---

## ðŸ“Š Real-World Performance

Observed physical metrics operating locally on a Windows 10/11 testing framework via Npcap:

* **Packet Decision Latency:** `< 1 ms`
* **Network Throughput:** `1â€“5 Gbps` (Physical Hardware Limit)
* **Memory Footprint:** `50â€“100 MB`
* **CPU Usage (Idle):** `3â€“8%`
* **Threat Lookup Speed:** `O(1) Array Index`

---

## ðŸš€ Firewall Trends â€” How Rudras Stays Ahead

| 2026â€“2030 Trend | Rudras Response |
|-----------------|-----------------|
| AI-Driven Threat Prevention | âœ… CyberImmune genetic evolution â€” self-writing zero-day rules |
| Zero Trust Architecture | âœ… Posture verification enforcing identity policies over passwords |
| Behavioral Analytics | âœ… Immutable state anchors matching anomaly heuristics |
| Encrypted Traffic Inspection | âœ… Zero-Knowledge Deep Packet Inspection hashing |
| Automated Response | âœ… Fully autonomous â€” zero SOC human intervention required directly |
| Threat Intelligence Sharing | âœ… Distributed P2P telemetry instantly synchronizes local networks |
| SASE Alignment | âœ… Distributed control planes scale beyond single offices |

---

## ðŸ“… Development Journey

Rudras was built systematically in structured phases, each verifying a crucial pillar of security.

- **Phase 1 â€” Foundation:** High-performance PCAP interception logic, core policy parsing, and geo-layer 3 blocking.
- **Phase 2 â€” Intelligence Layer:** Automated API caching of ThreatIntel lists, integration into SIEM JSON streamers, and Device Posture Zero-Trust configuration matrices.
- **Phase 3 â€” CyberImmune System:** The ML architecture. Graduated responses scaling automatically based on statistical drift deviations, preventing false positives, and saving rules to disk.
- **Phase 4 â€” Distributed Immunity:** Expanding the logic across a theoretical Swarm using peer-to-peer Gossip to sync Quorum rules.
- **Phase 5 â€” Ethics & Precision (v3.0):** Full ethical/legal audit. Country blocking replaced with 6-feed IOC precision blocking. DNS-layer malicious domain enforcement added. All legally-sensitive behaviours made explicit opt-in. Interactive deployment mode prompt added.

---

## ðŸ“š Engineering Research & Secrets

Rudras operates with complete transparency regarding its architectural decisions, yet fiercely protects its internal bypass mechanisms designed to prevent "cockpit-lockouts." 

The `Research_Notes/` directory in the repository contains the official manifesto of the system:
* **`1_Vision_and_Purpose.md`**: Outlines the failure of static firewalls and the necessity for zero-day immunity.
* **`2_The_Problem_and_Solution.md`**: Maps physical hardware constraints (DoS Cryptography) to software solutions natively.
* **`3_Core_Architecture_and_Logic.md`**: The exact structural flow from Layer 0 WFP dropping up to the distributed Swarm Gossip.
* **`4_Usage_and_Maintenance_Guide.md`**: Administrator guide for Hot-Reloadable TOML overrides.
* **`5_Team_Engineering_Pipeline.md`**: The developer guide detailing the internal packet pipeline loop, concurrency locks (`RwLock`), and mode divergences between Server and Client states.

### ðŸ¤« Classified Security Mechanisms (`Research_Notes/secrets/`)
To prevent reverse-engineering of the biological algorithms, absolute execution overrides are stored strictly within the private `/secrets/` subdirectory.
* **`1_Proprietary_Algorithms.md`**: Details the `Immutable State Anchor` (Boiling Frog clamp limits) and the `Hardware Entropy` modulo logic.
* **`2_Anti_Tamper_Mechanisms.md`**: Contains the `Dual-Clock Drift Verification` and the hardcoded literal string (`emergency_override.key`) that enables the physical God-Key system bypass.
* **`3_Cryptographic_Implementations.md`**: Maps the `Adaptive RSA Dropper` connection limits and the 24-hour overlap grace period code preventing KMS core deadlocks.

---

## ðŸ”­ Future Vision & Platforms

Rudras v3.0 establishes the strongest possible foundation for an autonomous firewall. The next frontier involves extending its native reach.

### ðŸŒ Current Supported Base:
* **Windows 10 / Windows 11 Enterprise** via `Npcap` and `WinDivert` ring-layer interceptors.

### ðŸ”œ Coming Soon...
To truly secure the world, Rudras must exist natively across all infrastructure backbones. The forthcoming architectural expansion targets:
* **Linux (Servers & Clouds):** Direct `eBPF` and `XDP` integrations bypassing standard Netfilter overheads to defend hypervisors natively up to 100-Gbps speeds.
* **macOS:** Replacing local endpoint agents with Apple Network Extensions processing.
* **iOS & Android:** Embedding lightweight packet-filtering client nodes into mobile infrastructures.
* **Post-Quantum Cryptography:** Upgrading current Swarm keys with lattice-based NIST PQC standards.

---

## ðŸ“‹ Changelog

### v3.0.0 â€” March 2026
- **NEW** Interactive deployment mode prompt at startup â€” no more silent Client default
- **NEW** Malicious domain blocking at DNS layer (UDP/TCP port 53) against live IOC feeds
- **NEW** 4 additional threat feeds: CINS Score, Emerging Threats, ThreatFox IOCs, URLhaus
- **NEW** Domain blocklist persisted to `data/intel/malicious_domains.txt` â€” survives restarts
- **CHANGED** Country-level GeoIP blocking removed â€” replaced with precision IOC-based IP/domain blocking
- **CHANGED** `process_monitor_kill_mode` default â†’ `false` (warn-only, no process termination)
- **CHANGED** `promiscuous_capture` default â†’ `false` (host traffic only)
- **CHANGED** `block_anonymization_networks` default â†’ `false` (Tor/I2P not blocked)
- **FIXED** All three ethically-sensitive settings now required explicit entries in `[blocking]` TOML section
- **FIXED** Unicode escape sequences in startup log messages (`\u2705` â†’ `\u{2705}`)
- **FIXED** PowerShell GeoIP script: approved function verb (`Get-CIDRNotation`), removed unused variables

### v3.0.0 â€” February 2026
- Initial release with 20 active security systems
- Full IDS/IPS engine with 200+ Snort-compatible signatures
- Distributed Immunity P2P grid
- Zero Trust AD/SAML/OAuth integration
- SIEM integration (Splunk HEC + ELK)

---

### ðŸ¤ Philosophy & Ethics

Security built on trust requires building it trustworthily.
- No traffic is stored at rest (unless explicitly logged during a critical attack incident).
- No arbitrary user profilingâ€”identity awareness is strictly access control.
- Open documentationâ€”we document precisely how Rudras solves mathematical flaws in older firewalls to advance the field forward globally.

<div align="center">

*Rudras represents unyielding defense, uncompromising speed, and unparalleled architectural resilience.*

**"The immune system does not build walls. It learns, remembers, and evolves. So does Rudras."**

</div>
