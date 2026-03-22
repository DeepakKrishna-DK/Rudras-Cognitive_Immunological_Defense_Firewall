# 4. Research-Grade Modules

---

## Abstract

Rudras v4.0 adds 30+ research-grade modules that implement capabilities typically found only in multi-million-dollar enterprise security platforms or academic research prototypes. This document covers the design, purpose, and operational behavior of all research-grade modules. Each module represents a frontier security capability backed by peer-reviewed academic research and implemented in production-quality Rust.

---

## 1. UEBA Engine (User and Entity Behavior Analytics)

**Module:** `Ueba Engine Module`  
**Academic Basis:** Behavioral analytics, insider threat detection  
**Primary Use Case:** Insider threats, privilege misuse, account compromise

### 1.1 Problem Statement

An attacker with stolen credentials, or a malicious insider, can perfectly authenticate. They have valid usernames, passwords, and certificates. Traditional perimeter controls see them as legitimate. UEBA detects anomalies in _how_ they behave after authentication, not just whether they authenticated successfully.

### 1.2 User Behavioral Baseline

For each authenticated user identity, UEBA tracks:

- **Access time distribution:** What hours does this user typically access systems?
- **Resource access patterns:** Which servers, shares, databases, APIs does this user typically access?
- **Data volume:** How much data does this user typically download/upload per session?
- **Geographic consistency:** Is this login from a typical location?
- **Peer group comparison:** Does this user behave like other users in their role?

### 1.3 Anomaly Indicators

| Indicator               | Example                                                                      | Severity |
| ----------------------- | ---------------------------------------------------------------------------- | -------- |
| Off-hours access        | Finance user accessing payroll DB at 2 AM                                    | High     |
| Geographic anomaly      | User account accessed simultaneously from two continents                     | Critical |
| Unusual resource access | Developer accessing HR database for first time                               | Medium   |
| Data volume spike       | User downloading 50× their daily average in 30 minutes                       | High     |
| New external transfer   | Sending large files to personal cloud storage for first time                 | High     |
| Privilege misuse        | Admin using service account credentials for interactive access               | High     |
| Peer deviation          | Sales rep accessing R&D files while all other sales reps have no such access | Medium   |

### 1.4 Insider Threat Scenarios

UEBA specifically enables detection of:

- **Disgruntled employee:** Normal login, but downloading all data from sensitive project before resignation
- **Account takeover:** Attacker with stolen credentials behaves differently from legitimate user
- **Credential sharing:** Two people using one account (login from different IPs simultaneously)
- **Gradual privilege escalation:** Employee slowly expanding their access over months to avoid detection

---

## 2. SOAR Engine (Security Orchestration, Automation and Response)

**Module:** `Soar Engine Module`  
**Academic Basis:** Workflow automation, decision trees, incident response  
**Primary Use Case:** Automated response to security events, reducing MTTR

### 2.1 What SOAR Does

When a security event occurs, a human analyst must investigate: gather context, correlate evidence, make a decision, take action. This process takes minutes to hours. SOAR automates these workflows — executing pre-defined playbooks within seconds of detection.

### 2.2 Playbook Architecture

A SOAR playbook is a directed acyclic graph of actions:

```toml
[[soar.playbooks]]
name = "C2_ISOLATION"
trigger = { event = "ids_alert", rule_id = "c2_callback_confirmed" }

steps = [
  { action = "block_ip", params = { ip = "$src_ip", duration_secs = 86400 } },
  { action = "isolate_host", params = { host = "$src_ip", zone = "quarantine" } },
  { action = "notify_siem", params = { severity = "critical", message = "C2 callback isolated: $src_ip" } },
  { action = "snapshot_flows", params = { src_ip = "$src_ip", window_mins = 60 } },
  { action = "notify_analyst", params = { email = "soc@company.com", priority = "P1" } }
]
```

### 2.3 Available Playbook Actions

| Action               | Description                                                         |
| -------------------- | ------------------------------------------------------------------- |
| `block_ip`           | Add IP to WFP block list with TTL                                   |
| `isolate_host`       | Move host to quarantine zone                                        |
| `rate_limit_ip`      | Apply bandwidth cap to host                                         |
| `notify_siem`        | Send SIEM event                                                     |
| `notify_analyst`     | Send alert via email/webhook                                        |
| `snapshot_flows`     | Save flow telemetry for forensic analysis                           |
| `trigger_hunt`       | Execute a threat hunt query                                         |
| `revoke_tokens`      | Invalidate identity tokens for user (if IAM integration configured) |
| `disable_account`    | Disable AD/LDAP account (if directory integration configured)       |
| `collect_forensics`  | Trigger npcap forensic capture on host                              |
| `update_ti`          | Add IOC to local threat intel feed                                  |
| `propagate_to_swarm` | Broadcast IOC to peer nodes                                         |

### 2.4 Human-in-the-Loop Mode

For irreversible actions (disable_account, permanent block), SOAR can be configured to require analyst approval within a timeout window:

```toml
{ action = "disable_account",
  params = { username = "$user", timeout_mins = 15, fallback = "rate_limit_only" } }
# If analyst doesn't approve within 15 min, falls back to rate_limit_only
```

---

## 3. Deception and Adaptive Honeypot

**Modules:** `Deception Module`, `Adaptive Honeypot Module`  
**Academic Basis:** Active deception, honeypot theory, attacker fingerprinting

### 3.1 Deception Strategy

Security deception creates false targets to attract attackers and observe their behavior:

- **Honey IPs:** IP addresses in the internal range that no legitimate service runs on. Any connection attempt is definitively malicious (no false positives possible)
- **Canary tokens:** Fake credentials, API keys, or documents that trigger alerts when accessed
- **Decoy services:** Fake SSH, RDP, SMB servers that log everything but serve no real function

### 3.2 Adaptive Honeypot

Standard honeypots serve the same generic service regardless of context. The adaptive honeypot in Rudras observes the attacker's initial probes and adapts to present a more believable target:

1. Attacker port-scans and finds port 3306 open
2. Adaptive honeypot detects this is likely a MySQL probe
3. Honeypot adapts to serve MySQL connection banner
4. Attacker sends SQL queries — honeypot logs all queries, responds with plausible fake data
5. Attacker believes they found a real database and continues — all activity logged for forensic analysis

This dramatically extends attacker observation time compared to generic honeypots that immediately appear suspicious.

### 3.3 Canary Token Alert

Canary tokens are fake sensitive assets (credentials, documents, certificates) that:

- Look real enough to be used if stolen
- Immediately alert when accessed
- Provide proof of breach with exact timing

Example canary tokens placed by Rudras:

```
AWS access key: AKIAFAKECANARYTOKEN01 (generates alert if used with AWS API)
SSH private key: stored in fake home directory (generates alert if connected anywhere)
Fake API endpoint: /api/v1/internal/admin (logs all requests, generates critical alert)
```

---

## 4. OT/ICS Protocol Security

**Module:** `Ot Protocols Module`  
**Academic Basis:** Industrial control system security, SCADA protection  
**Protocols:** Modbus TCP, DNP3, EtherNet/IP (CIP)

### 4.1 Why ICS Security Is Different

Industrial control systems (ICS) and Operational Technology (OT) networks control physical processes:

- Power generation and distribution
- Water treatment and distribution
- Oil and gas pipelines
- Manufacturing automation

A software bug in a corporate database loses data. A cyberattack on a SCADA system can cause physical damage, environmental disasters, or endanger lives. Stuxnet (2010), TRITON/TRISIS (2017), and Industroyer/Crashoverride (2016) demonstrated real-world attacks with physical consequences.

### 4.2 Modbus TCP Security

Modbus is a widely used ICS protocol (designed in 1979, with no authentication). Security enforcement:

| Function Code                 | Allowed           | Monitoring                     |
| ----------------------------- | ----------------- | ------------------------------ |
| 01 (Read Coils)               | Yes               | Log                            |
| 02 (Read Inputs)              | Yes               | Log                            |
| 03 (Read Holding Registers)   | Yes               | Log                            |
| 04 (Read Input Registers)     | Yes               | Log                            |
| 05 (Write Single Coil)        | Restricted        | Alert + whitelist check        |
| 06 (Write Single Register)    | Restricted        | Alert + whitelist check        |
| 15 (Write Multiple Coils)     | Restricted        | CRITICAL alert if not from HMI |
| 16 (Write Multiple Registers) | Restricted        | CRITICAL alert if not from HMI |
| 43 (Read Device ID)           | Source-restricted | Info                           |

Write operations are restricted to known engineering workstations (HMI whitelist). Any write command from an unrecognized source IP generates a CRITICAL alert.

### 4.3 CIP Whitelisting

EtherNet/IP and the CIP protocol are used in Rockwell PLC and Allen-Bradley automation systems. Rudras implements CIP service whitelisting:

- Allowed services (Read/Write Tag, Get Attributes) from known HMI IPs
- Denied: any CIP service from external IPs, any Write from unknown source
- Detected: CIP scan patterns (rapid Read operations across many tag names)

---

## 5. Post-Quantum Cryptography

**Module:** `Post Quantum Module`  
**Standards:** NIST FIPS 203, 204, 205 (finalized August 2024)  
**Purpose:** Quantum-resistant key exchange and digital signatures for Rudras's own communications

### 5.1 The Quantum Threat

Shor's algorithm, running on a sufficiently powerful quantum computer, can break RSA and ECC (Elliptic Curve Cryptography) in polynomial time. Current consensus: quantum computers capable of breaking 2048-bit RSA could exist within 10–15 years. Data encrypted today with RSA can be collected now and decrypted later ("harvest now, decrypt later" attacks).

### 5.2 NIST Post-Quantum Standards (2024)

NIST finalized three post-quantum cryptography standards in August 2024:

| Standard | Algorithm                            | Purpose                         | Key Size   |
| -------- | ------------------------------------ | ------------------------------- | ---------- |
| FIPS 203 | ML-KEM (formerly CRYSTALS-Kyber)     | Key Encapsulation               | 800 bytes  |
| FIPS 204 | ML-DSA (formerly CRYSTALS-Dilithium) | Digital Signatures              | 1312 bytes |
| FIPS 205 | SLH-DSA (formerly SPHINCS+)          | Stateless Hash-Based Signatures | 32 bytes   |

### 5.3 Rudras Application

Post-quantum cryptography is applied to:

- **Swarm gossip authentication:** Gossip messages between Rudras nodes are signed with ML-DSA to prevent injection of fake threat intelligence from a compromised peer
- **Config file signatures:** `sign_config.ps1` uses ML-DSA for config file integrity (replacing SHA256-HMAC in future version)
- **Secure channel establishment:** The `Secure Channel Module` module supports ML-KEM for key exchange in addition to classical ECDHE
- **Forensics chain:** Forensic audit log entries can be signed with SLH-DSA for long-term quantum-resistant integrity proof

---

## 6. Formal Policy Verification

**Module:** `Formal Verification Module`  
**Academic Basis:** Formal methods, model checking, TLA+ specification  
**Purpose:** Mathematically prove firewall policy is correct before deployment

### 6.1 The Policy Correctness Problem

Firewall policies written by humans contain errors:

- **Shadowed rules:** A specific-case rule that should match first is shadowed by a general rule earlier in the priority order
- **Unreachable rules:** Rules that can never match because earlier rules cover all their cases
- **Conflicting rules:** Two rules that should both match give contradictory verdicts
- **Policy gaps:** Combinations of src/dst/port/identity with no matching rule (default allow or deny unclear)

In production, these errors cause security incidents or service outages. The formal verification module catches them before deployment.

### 6.2 Verification Approach

The `Formal Verification Module` module converts the Rudras policy into a logical model and checks properties:

1. **Rule conflict detection:** Does any pair of rules produce contradictory verdicts for the same traffic?
2. **Completeness checking:** Is there any traffic class with no matching rule (policy gap)?
3. **Reachability analysis:** Is every rule reachable (can any traffic trigger it)?
4. **Zone policy consistency:** Do zone policies form a consistent, acyclic authorization graph?
5. **Privilege escalation path analysis:** Can any combination of legitimate policy rules provide an unauthorized path between a low-trust zone and a high-value zone?

### 6.3 Formal Specification Language

Policy is internally represented in a subset of TLA+ (Temporal Logic of Actions) for the verification engine:

```
PolicyRule == [
  priority: Nat,
  src_zone: Zone,
  dst_zone: Zone,
  action: Action,
  condition: BoolExpr
]

PolicyCorrect ==
  ∀ r1, r2 ∈ Policy:
    ¬(r1.condition ∧ r2.condition ∧ r1.action ≠ r2.action)
    -- No two rules match same traffic with different actions
```

---

## 7. TPM Attestation

**Module:** `Tpm Attestation Module`  
**Standard:** TCG TPM 2.0, TPM Remote Attestation  
**Purpose:** Hardware root-of-trust for device identity verification

### 7.1 TPM Overview

A Trusted Platform Module (TPM) is a dedicated security chip (or firmware implementation via Intel PTT/AMD fTPM) that:

- Stores cryptographic keys that cannot be extracted from the chip
- Measures the boot process and stores measurements in PCR (Platform Configuration Registers)
- Provides hardware-attested evidence of system state

### 7.2 Remote Attestation Protocol

When a device with a TPM connects to a Zero Trust protected resource:

1. **Challenge:** Rudras sends a random nonce to the device
2. **Quote:** The device's TPM signs the nonce + current PCR values with the TPM's private attestation key
3. **Verify:** Rudras verifies the signature against the device's public endorsement key (registered in directory)
4. **Evaluate:** PCR values are compared against expected good-state measurements
5. **Decision:** If PCR values match known-good state and signature validates → device is trusted. If PCR values differ (malware modified boot) → device trust score degraded or denied.

### 7.3 What TPM Attestation Catches

- **Bootkit/rootkit infection:** Malicious code loaded before TPM measurements completes → different PCR values
- **Compromised UEFI firmware:** UEFI modification changes PCR0 measurement
- **Secure Boot violation:** Boot attempted with unsigned or revoked bootloader
- **Policy-violating software running at boot:** Unauthorized security-disabled configuration

---

## 8. Moving Target Defense (MTD)

**Module:** `Mtd Engine Module`  
**Academic Basis:** Moving target defense, proactive cyber defense  
**Purpose:** Make the network harder to attack by continuously changing its observable surface

### 8.1 The Reconnaissance Problem

Every attack begins with reconnaissance: discovering IPs, open ports, and services. If these assets are static and predictable, the attacker can plan methodically. MTD makes reconnaissance expensive by constantly changing what the attacker observes.

### 8.2 MTD Techniques Implemented

**IP Address Rotation:**

- Changes virtual IP addresses of sensitive services on a schedule (e.g., every 30 minutes)
- Old IPs continue working for a transition window, then become honeypots
- Attacker who scanned and found the service IP finds it gone on the next scan

**Port Shuffling:**

- Non-standard service ports are rotated among allowed ranges
- Only authenticated clients receive the current port mapping (via secure channel)
- A port scanner finds the service on one port today, a different port tomorrow

**Decoy Service Injection:**

- MTD creates decoy listening ports that log all connections
- These decoys are interspersed with real services
- Any connection to a decoy is definitively malicious

### 8.3 MTD vs. Security Through Obscurity

MTD is distinct from security through obscurity:

- Security through obscurity relies on secret knowledge staying secret (brittle)
- MTD continuously changes state so the attack surface at any given moment is only valid briefly
- Even if an attacker discovers the current configuration, it will change before they can act

---

## 9. Homomorphic Threat Intel Sharing

**Module:** `Homomorphic Sharing Module`  
**Academic Basis:** Homomorphic encryption, privacy-preserving computation  
**Purpose:** Share threat intelligence between organizations without exposing private network data

### 9.1 The Privacy-Security Tension

Organizations want to share threat intelligence (attacker IPs, malware hashes, C2 domains) to collectively defend. But sharing requires revealing private network information (what malicious activity you observed implies something about your network topology and traffic).

Homomorphic encryption allows computation on encrypted data — threat intel can be aggregated and matched against encrypted network logs without either party learning each other's private data.

### 9.2 Application in Rudras

The homomorphic sharing module enables:

- **Federated Learning aggregation:** Aggregate ML model updates from all swarm peers without any peer seeing another's raw updates (covered in Research Note 7)
- **Private set intersection:** Two organizations can discover shared attacker IPs without learning what other IPs are in each other's sets
- **Encrypted gossip aggregation:** Multiple peer observations of the same malicious IP can be combined into a confidence-weighted consensus without each peer revealing their raw observations

### 9.3 Cryptographic Implementation

Uses a partial homomorphic encryption scheme (additively homomorphic) sufficient for gradient aggregation and confidence score aggregation. The full homomorphic encryption overhead is too high for real-time network operations; selective application to the aggregation phase only keeps performance acceptable.

---

## 10. Compliance Engine

**Module:** `Compliance Engine Module`  
**Standards Supported:** GDPR, HIPAA, PCI-DSS, SOC 2, ISO 27001

### 10.1 Automated Compliance Evidence

Compliance audits require evidence that security controls are operating correctly. Collecting this evidence manually is expensive (analysts spending weeks gathering screenshots and log exports). The compliance engine automates evidence collection and report generation.

### 10.2 Compliance Mapping

Every Rudras security control is mapped to compliance framework requirements:

| Rudras Control                  | GDPR Article  | HIPAA Safeguard     | PCI-DSS Requirement |
| ------------------------------- | ------------- | ------------------- | ------------------- |
| Data encryption at rest         | Art. 32(1)(a) | § 164.312(a)(2)(iv) | Req. 3.4            |
| Access control (Zero Trust)     | Art. 32(1)(b) | § 164.312(a)(1)     | Req. 7.1            |
| Audit logging (Forensics Chain) | Art. 32(1)(b) | § 164.312(b)        | Req. 10.1           |
| Intrusion detection (IDS/IPS)   | Art. 32(1)(d) | § 164.306(a)(1)     | Req. 11.4           |
| Vulnerability management        | Art. 32(1)(d) | § 164.308(a)(8)     | Req. 11.3           |
| Network segmentation            | Art. 32(1)(b) | § 164.312(a)(1)     | Req. 1.2            |

### 10.3 Report Generation

The compliance engine generates reports in:

- PDF (formatted compliance report with evidence tables)
- JSON (machine-readable for GRC platform import)
- CSV (for auditor review in Excel)

Reports include: control description, mapping to framework requirement, evidence of operation (log counts, configuration excerpts, metrics values), assessment period, and a pass/fail determination.

---

## 11. eBPF/XDP (Linux Kernel Acceleration)

**Module:** `Ebpf Xdp Module`  
**Status:** In development (Linux port)  
**Academic Basis:** Linux kernel extended Berkeley Packet Filter, eXpress Data Path

### 11.1 Overview

eBPF/XDP allows Rudras to run security logic directly in the Linux kernel (or even in the NIC firmware with XDP offload), achieving near-line-rate packet processing with sub-microsecond decision latency — beyond what userspace can achieve.

On Linux deployments, the WFP/WinDivert enforcement layer is replaced by eBPF programs:

- XDP programs run at NIC receive path for absolute minimum latency fast-path drops
- TC (Traffic Control) eBPF programs handle more complex analysis that can tolerate 10–100 μs latency

### 11.2 Development Status

As of v4.0, the `Ebpf Xdp Module` module contains the Rust control-plane interface and eBPF program loader. The actual eBPF bytecode programs (written in restricted C) are in development. Full eBPF/XDP implementation is targeted for v4.2 (Linux port milestone).

---

## 12. Other Research-Grade Modules (Summary)

### `Email Security Module`

SMTP inspection: DKIM signature validation, SPF record verification, DMARC policy enforcement, phishing domain detection (Levenshtein distance from known trusted domains), BEC (Business Email Compromise) pattern detection, attachment hash checking against malware feeds.

### `Rasp Engine Module`

Runtime Application Self-Protection hooks: monitors web applications from within for SQL injection execution attempts, deserialization exploits, SSRF to internal services. When an RASP hook fires, the offending request is blocked at the application runtime level while logging full context.

### `Secure Channel Module`

mTLS channel management for all Rudras inter-component and swarm communications: certificate lifecycle management, certificate rotation on expiry, OCSP stapling, certificate pinning for critical communication channels.

### `Sbom Engine Module`

Software Bill of Materials validation: loads SBOM manifests (SPDX, CycloneDX format), verifies installed software components match the declared manifest, detects unauthorized software installations, correlates components against CVE databases.

### `Supply Chain Verifier Module`

Cryptographic verification of software supply chain: verifies code signing certificates, package ancestry chains, build provenance attestations (SLSA framework). Detects supply chain compromises where legitimate software has been trojanized.

### `Forensics Chain Module`

SHA3-256 chained audit log providing tamper-evident evidence chain for all security events. Each log entry contains a hash of the previous entry — any modification of historical entries is immediately detectable. Required for legal-grade incident evidence.

### `Differential Privacy Module`

Applies differential privacy noise to telemetry data exported to external analytics systems. Prevents re-identification of individual users from aggregate network statistics while preserving statistical utility of the telemetry.

### `Management Api Module`

REST API for programmatic management: configuration updates, real-time status queries, incident acknowledgment, IOC submission. Secured with the same ephemeral token mechanism as the metrics server. Enables integration with SOAR orchestration platforms and CMDB systems.

### `Llm Explainability Module`

Generates natural language explanations of security alerts using a local LLM model. Instead of raw alert data like `"T1190 detected: src=185.x.x.x"`, produces: `"A web application exploit attempt was detected from IP 185.x.x.x, suggesting an attacker tried to exploit a vulnerability in your public-facing application (MITRE technique T1190). The AI behavioral analysis also detected unusual port scanning from this IP in the preceding 10 minutes, suggesting pre-attack reconnaissance. Recommend: block IP, investigate web application logs at 10:45:23 IST."` This dramatically reduces analyst fatigue and speeds up triage.

### `Policy Verifier Module`

Automated detection of policy conflicts and logical errors: finds rules that can never match (shadowed by higher-priority rules), rules that contradict each other, and policy gaps where traffic has no matching rule. Runs on every policy reload and blocks deployment of logically inconsistent policy.

### `Quic Inspector Module`

QUIC and HTTP/3 protocol analysis: header inspection of QUIC CRYPTO and STREAM frames, detection of HTTP/3 requests carrying known attack patterns, QUIC amplification attack detection.

### `P4 Offload Module` (Planned / Roadmap)

P4 programmable switch offload: generates P4 programs from Rudras policy that can be loaded onto P4-capable network hardware (Tofino ASICs, Barefoot switches) to enforce fast-path rules at terabit-per-second line rates without involving host CPU.
