# 3.6 Complete Module Index

---

## Abstract

This document is the definitive cross-reference index for all modules in the Rudras v4.0 source tree. It catalogs all 67 `src/*.rs` files with their purpose, key exported items, configuration keys, pipeline stage, and inter-module dependency relationships. Use this document as a map when:

- Identifying which module to modify for a given feature
- Understanding how a packet flows through the system
- Determining the impact radius of a change
- Onboarding new engineers to the codebase

---

## 1. Module Inventory Table

| #   | File                       | Category            | One-Line Purpose                                     | Key Exports                                          |
| --- | -------------------------- | ------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| 1   | `Main Module`                  | Entry Point         | Program entry, init orchestration, tokio runtime     | `main()`                                             |
| 2   | `Config Module`                | Configuration       | TOML config loading, validation, hot-reload          | `RudrasConfig`, `load_config()`, `ConfigWatcher`     |
| 3   | `Capture Module`               | Traffic Capture     | Npcap packet capture, ring buffer, BPF pre-filter    | `PacketCapture`, `CaptureConfig`, `RawPacket`        |
| 4   | `Flow Engine Module`           | Stateful Tracking   | TCP/UDP flow table, session reassembly               | `FlowEngine`, `FlowRecord`, `FlowKey`                |
| 5   | `Stateful Module`              | Stateful Inspection | Deep stateful packet inspection (SPI)                | `StatefulInspector`, `ConnectionState`               |
| 6   | `Dpi Module`                   | Deep Inspection     | L7 protocol dissection, WAF pattern matching         | `DpiEngine`, `L7Protocol`, `WafResult`               |
| 7   | `Ids Engine Module`            | Detection           | Signature + behavioral IDS, 85 rules                 | `IdsEngine`, `IdsRule`, `IdsAlert`                   |
| 8   | `Ips Engine Module`            | Prevention          | IPS action execution, RST injection, WFP block       | `IpsEngine`, `IpsDecision`, `IpsAction`              |
| 9   | `Threat Intelligence Module`   | Intelligence        | Blocklist management, Bloom filter lookup            | `ThreatIntelligence`, `TiHit`, `IocEntry`            |
| 10  | `Ai Engine Module`             | AI/ML               | EMA baseline anomaly detection, deviation scoring    | `AiEngine`, `BehaviorProfile`, `DeviationScore`      |
| 11  | `Advanced Ml Module`           | AI/ML               | Ensemble ML (Isolation Forest, Autoencoder, etc.)    | `AdvancedMlEngine`, `AnomalyScore`                   |
| 12  | `Advanced Security Module`     | AI/ML               | Multi-source correlation, threat scoring             | `AdvancedSecurityEngine`, `CorrelatedAlert`          |
| 13  | `Cyber Immune Module`          | AI/ML               | Biological immune metaphor detection                 | `CyberImmuneSystem`, `ImmuneResponse`                |
| 14  | `Distributed Immunity Module`  | Swarm               | Gossip protocol, inter-node intelligence sharing     | `DistributedImmunity`, `SwarmMessage`, `GossipPeer`  |
| 15  | `Policy Module`                | Policy              | Rule evaluation engine, policy composition           | `PolicyEngine`, `PolicyRule`, `PolicyDecision`       |
| 16  | `Zero Trust Module`            | Enterprise          | Zero-trust trust score, continuous verification      | `ZeroTrustEngine`, `TrustScore`, `TrustVerification` |
| 17  | `Identity Policy Module`       | Enterprise          | JWT/mTLS/Kerberos auth, RBAC                         | `IdentityPolicy`, `Identity`, `AuthResult`           |
| 18  | `Micro Segmentation Module`    | Enterprise          | Network zone enforcement, segment policy             | `MicroSegmentation`, `Zone`, `SegmentPolicy`         |
| 19  | `Endpoint Security Module`     | Enterprise          | Endpoint posture, agent comms, EDR integration       | `EndpointSecurity`, `PostureScore`, `EndpointAgent`  |
| 20  | `Attribution Scoring Module`   | Enterprise          | TTP-based threat actor attribution                   | `AttributionEngine`, `TtpMatch`, `ActorProfile`      |
| 21  | `Siem Integration Module`      | Observability       | CEF/LEEF event streaming to SIEM                     | `SiemIntegration`, `SiemEvent`, `CefRecord`          |
| 22  | `Metrics Module`               | Observability       | Prometheus metrics server, counters, auth            | `MetricsServer`, `Counters`, `AuthToken`             |
| 23  | `Wfp Engine Module`            | Enforcement         | Windows Filtering Platform kernel block rules        | `WfpEngine`, `WfpRule`, `WfpCallout`                 |
| 24  | `Windivert Engine Module`      | Enforcement         | WinDivert packet intercept, modification             | `WinDivertEngine`, `DivertedPacket`                  |
| 25  | `Npcap Forensic Module`        | Forensics           | Forensic PCAP capture, chain of custody              | `NpcapForensic`, `ForensicCapture`, `CustodyRecord`  |
| 26  | `L2 Engine Module`             | L2 Security         | ARP/MAC/VLAN enforcement, 802.11 analysis            | `L2Engine`, `ArpRecord`, `VlanPolicy`                |
| 27  | `Gateway Mode Module`          | Deployment          | Gateway/router mode, route management                | `GatewayMode`, `RouteEntry`                          |
| 28  | `Sdwan Module`                 | Deployment          | SD-WAN path selection, WAN policy                    | `SdWan`, `WanPath`, `PathMetrics`                    |
| 29  | `Cloud Native Module`          | Deployment          | K8s/Docker integration, CNI enforcement              | `CloudNative`, `ContainerPolicy`                     |
| 30  | `Mode Profiles Module`         | Deployment          | Operational mode presets (stealth, aggressive, etc.) | `ModeProfile`, `ProfileSettings`                     |
| 31  | `Single Pass Module`           | Performance         | Single-pass packet inspection pipeline               | `SinglePassPipeline`, `InspectionResult`             |
| 32  | `Hardware Accel Module`        | Performance         | DPDK/hardware offload integration                    | `HardwareAccel`, `OffloadCapability`                 |
| 33  | `Framework Alignment Module`   | Compliance          | MITRE ATT&CK, NIST, CIS mapping                      | `FrameworkAlignment`, `MitreMapping`                 |
| 34  | `Process Monitor Module`       | Endpoint            | Sysmon/WinAPI process creation monitoring            | `ProcessMonitor`, `ProcessEvent`                     |
| 35  | `Comprehensive Blocker Module` | Detection           | Multi-signal weighted block scoring                  | `ComprehensiveBlocker`, `BlockScore`                 |
| 36  | `Policy Module`                | Policy              | See #15                                              |
| 37  | `Sdwan Module`                 | See #28             |

> Note: The remaining 30+ source files in the `src/` directory are specialized research and advanced modules. They are documented in the Research-Grade Modules section and listed in Section 4 of this index.

---

## 2. Pipeline Stage Mapping

This table shows when each module is called in the 10-stage packet processing pipeline.

### Stage 0 — Pre-Filter (Capture)

Module called before the packet enters the main pipeline. Runs in the capture thread.

```
Capture Module          → BPF kernel pre-filter (drops irrelevant traffic never to enter Rust)
```

### Stage 1 — Packet Arrival (L2/L3 Parsing)

First stage in the Tokio async pipeline. Parses raw bytes into structured data.

```
L2 Engine Module        → Ethernet frame parsing, ARP check
Capture Module          → Packet dispatch to pipeline
```

### Stage 2 — Identity Verification

```
Identity Policy Module  → JWT/mTLS header extraction (HTTP/TLS flows)
Zero Trust Module       → Trust score evaluation for source identity
```

### Stage 3 — Flow Tracking

```
Flow Engine Module      → Flow lookup or creation, sequence/ack tracking
Stateful Module         → TCP state machine update, connection validation
```

### Stage 4 — Threat Intelligence Lookup

Fast O(1) Bloom filter + hash map lookup. If blocked, skip all further stages.

```
Threat Intelligence Module  → IP blocklist check
Dpi Module                  → Quick hostname extraction for DNS block check
```

### Stage 5 — Deep Packet Inspection

```
Dpi Module              → L7 protocol identification, WAF payload scan
Ids Engine Module       → Signature rule matching against payload
Gateway Mode Module     → (In gateway mode) inter-VLAN routing decision
```

### Stage 6 — Behavioral Analysis

```
Ai Engine Module        → EMA baseline update, deviation calculation
Advanced Ml Module      → (If enabled) Isolation Forest / Autoencoder scoring
Cyber Immune Module     → (If enabled) Immune system response check
```

### Stage 7 — Policy Evaluation

```
Policy Module           → Rule evaluation, allow/deny/limit decision
Micro Segmentation Module  → Zone transition validation
Zero Trust Module       → Final trust check before allowing
```

### Stage 8 — Action Execution

```
Ips Engine Module           → Select action (block, reset, alert, rate_limit)
Wfp Engine Module           → Install WFP kernel-level block rule
Windivert Engine Module     → (If WinDivert mode) Drop or modify packet
Comprehensive Blocker Module → Multi-signal block decision
```

### Stage 9 — Telemetry

```
Metrics Module              → Increment Prometheus counters
Siem Integration Module     → Emit CEF syslog event
Distributed Immunity Module → (If swarm) Gossip alert to peers
Npcap Forensic Module       → (If forensic mode active) Append to forensic PCAP
```

---

## 3. Configuration Key → Module Mapping

When updating `config/rudras.toml`, this table maps every top-level TOML section to the module that owns it.

| TOML Section/Key                      | Owning Module                         | Description                 |
| ------------------------------------- | ------------------------------------- | --------------------------- |
| `[ids]`                               | `Ids Engine Module`                       | IDS rule configuration      |
| `ids.enabled`                         | `Ids Engine Module`                       | Master IDS on/off           |
| `ids.alert_only`                      | `Ids Engine Module`                       | Detect but don't block      |
| `ids.rules_path`                      | `Ids Engine Module`                       | Custom rules directory      |
| `[ips]`                               | `Ips Engine Module`                       | IPS action thresholds       |
| `ips.enabled`                         | `Ips Engine Module`                       | Master IPS on/off           |
| `ips.block_duration_secs`             | `Ips Engine Module`                       | Duration of IP bans         |
| `ips.inject_rst`                      | `Ips Engine Module`                       | TCP RST injection           |
| `[dpi]`                               | `Dpi Module`                              | DPI/WAF configuration       |
| `dpi.waf_enabled`                     | `Dpi Module`                              | Web application firewall    |
| `dpi.patterns_path`                   | `Dpi Module`                              | Attack pattern library path |
| `[ai]`                                | `Ai Engine Module`                        | Behavioral baseline ML      |
| `ai.ema_alpha`                        | `Ai Engine Module`                        | EMA smoothing factor        |
| `ai.suspicious_threshold`             | `Ai Engine Module`                        | Deviation alert threshold   |
| `ai.block_threshold`                  | `Ai Engine Module`                        | Deviation block threshold   |
| `[threat_intel]`                      | `Threat Intelligence Module`              | TI feed config              |
| `threat_intel.global_iocs_path`       | `Threat Intelligence Module`              | IOC JSON feed               |
| `threat_intel.malicious_domains_path` | `Threat Intelligence Module`              | Domain blocklist            |
| `[zero_trust]`                        | `Zero Trust Module`                       | ZT policy                   |
| `[micro_segmentation]`                | `Micro Segmentation Module`               | Zone definitions            |
| `[identity]`                          | `Identity Policy Module`                  | Auth configuration          |
| `[siem]`                              | `Siem Integration Module`                 | SIEM endpoint               |
| `siem.endpoint`                       | `Siem Integration Module`                 | Syslog server address       |
| `siem.format`                         | `Siem Integration Module`                 | CEF/LEEF/JSON/Splunk        |
| `[metrics]`                           | `Metrics Module`                          | Metrics server config       |
| `metrics.port`                        | `Metrics Module`                          | Listen port (default 9091)  |
| `metrics.auth_token_validity_mins`    | `Metrics Module`                          | Token rotation interval     |
| `[capture]`                           | `Capture Module`                          | NIC and capture config      |
| `capture.interface`                   | `Capture Module`                          | Network interface name      |
| `capture.promiscuous`                 | `Capture Module`                          | Promiscuous mode            |
| `capture.ring_buffer_mb`              | `Capture Module`                          | Ring buffer size            |
| `[l2]`                                | `L2 Engine Module`                        | L2 security settings        |
| `[swarm]`                             | `Distributed Immunity Module`             | Peer mesh config            |
| `swarm.peers`                         | `Distributed Immunity Module`             | Peer addresses              |
| `[gateway]`                           | `Gateway Mode Module`                     | Gateway mode settings       |
| `[performance]`                       | `Single Pass Module`, `Hardware Accel Module` | Tuning                      |
| `[logging]`                           | `Main Module`                             | Log level, format, path     |

---

## 4. All 67 Source Files — Complete Listing

This section lists every file in alphabetical order with its category and purpose.

```
src/
├── Advanced Ml Module          [AI/ML]           Ensemble ML anomaly detection
├── Advanced Security Module    [AI/ML]           Multi-signal correlation engine
├── Ai Engine Module            [AI/ML]           Primary EMA behavioral baseline
├── Attribution Scoring Module  [Enterprise]      TTP-based threat actor attribution
├── Capture Module              [Capture]         Npcap capture, ring buffer, BPF filter
├── Cloud Native Module         [Deployment]      K8s/Docker/CNI enforcement
├── Comprehensive Blocker Module[Detection]       Multi-signal weighted block scoring
├── Config Module               [Configuration]   TOML loading, validation, hot-reload
├── Cyber Immune Module         [AI/ML]           Biological immune system metaphor
├── Distributed Immunity Module [Swarm]           Gossip protocol, swarm intelligence
├── Dpi Module                  [Detection]       L7 DPI, WAF, protocol dissection
├── Endpoint Security Module    [Enterprise]      Endpoint posture, EDR integration
├── Flow Engine Module          [Stateful]        Flow table, TCP/UDP session tracking
├── Framework Alignment Module  [Compliance]      MITRE/NIST/CIS framework mapping
├── Gateway Mode Module         [Deployment]      Inline gateway routing mode
├── Hardware Accel Module       [Performance]     DPDK/NIC offload integration
├── Identity Policy Module      [Enterprise]      JWT/mTLS/Kerberos identity auth
├── Ids Engine Module           [Detection]       Signature + behavioral IDS engine
├── Ips Engine Module           [Prevention]      IPS action engine, RST injection
├── L2 Engine Module            [L2 Security]     ARP/MAC/VLAN enforcement
├── Main Module                 [Entry Point]     Startup, init, runtime orchestration
├── Metrics Module              [Observability]   Prometheus metrics server
├── Micro Segmentation Module   [Enterprise]      Network zone segmentation
├── Mode Profiles Module        [Deployment]      Operational mode presets
├── Npcap Forensic Module       [Forensics]       Forensic PCAP + chain-of-custody
├── Policy Module               [Policy]          Rule evaluation, policy engine
├── Process Monitor Module      [Endpoint]        Sysmon/WinAPI process tracking
├── Sdwan Module                [Deployment]      SD-WAN path selection
├── Siem Integration Module     [Observability]   CEF/LEEF SIEM event streaming
├── Single Pass Module          [Performance]     Single-pass inspection pipeline
├── Stateful Module             [Stateful]        Deep stateful inspection (SPI)
├── Threat Intelligence Module  [Intelligence]    Blocklist management, IOC lookup
├── Wfp Engine Module           [Enforcement]     Windows Filtering Platform calls
├── Windivert Engine Module     [Enforcement]     WinDivert packet intercept/modify
├── Zero Trust Module           [Enterprise]      Zero-trust trust scoring engine
```

---

## 5. Threat Capability Matrix

This table maps real-world attacker techniques to the Rudras modules that detect and/or prevent them.

| MITRE Technique | Technique Name                  | Detecting Module(s)                             | Preventing Module(s)         |
| --------------- | ------------------------------- | ----------------------------------------------- | ---------------------------- |
| T1071.001       | Web Protocols C2                | `Ids Engine Module`, `Ai Engine Module`                 | `Ips Engine Module`, `Dpi Module`    |
| T1071.004       | DNS C2                          | `Threat Intelligence Module`                        | `Ips Engine Module`              |
| T1041           | Data Exfiltration over C2       | `Dpi Module`, `Ai Engine Module`                        | `Ips Engine Module`              |
| T1486           | Data Encrypted for Impact       | `Ids Engine Module` (ransomware rules)              | `Ips Engine Module`              |
| T1046           | Network Service Scan            | `Ids Engine Module`, `Ai Engine Module`                 | `Ips Engine Module` (rate limit) |
| T1110           | Brute Force                     | `Ids Engine Module`, `Ai Engine Module`                 | `Ips Engine Module`              |
| T1557           | ARP Spoofing/Poison             | `L2 Engine Module`                                  | `L2 Engine Module` (drop)        |
| T1210           | Exploitation of Remote Services | `Ids Engine Module`, `Dpi Module`                       | `Ips Engine Module`              |
| T1090           | Proxy/Tor                       | `Threat Intelligence Module` (exit nodes), `Dpi Module` | `Ips Engine Module`              |
| T1133           | External Remote Services        | `Zero Trust Module`, `Identity Policy Module`           | `Ips Engine Module`              |
| T1021.002       | SMB Lateral Movement            | `Ids Engine Module`, `Micro Segmentation Module`        | `Ips Engine Module`              |
| T1059           | Command & Scripting Interpreter | `Process Monitor Module`, `Endpoint Security Module`    | `Endpoint Security Module`       |
| T1055           | Process Injection               | `Process Monitor Module`                            | `Endpoint Security Module`       |
| T1499           | Endpoint Denial of Service      | `Ids Engine Module` (DOS rules)                     | `Ips Engine Module`              |
| T1189           | Drive-by Compromise             | `Dpi Module` (WAF), `Ids Engine Module`                 | `Ips Engine Module`, `Dpi Module`    |
| T1498           | Network Denial of Service       | `Ids Engine Module` (flood rules)                   | `Ips Engine Module`              |

---

## 6. Dependency Graph

This is a simplified text-based dependency graph showing which modules import from which:

```
Main Module
├── Config Module                  (Configuration — all modules depend on config)
├── Capture Module                 (Feeds raw packets to pipeline)
│   └── L2 Engine Module           (L2 parsing of captured frames)
├── Flow Engine Module             (Flow table, used by most inspection modules)
│   ├── Stateful Module            (TCP state machine)
│   └── Ids Engine Module          (Flow context for signature matching)
├── Threat Intelligence Module     (Blocklist — called early for fast path rejection)
├── Dpi Module                     (L7 inspection, WAF)
│   └── Ids Engine Module          (Matches DPI-extracted fields against rules)
├── Ai Engine Module               (Behavioral baseline)
│   ├── Advanced Ml Module         (Ensemble scoring called by ai_engine)
│   └── Advanced Security Module   (Correlation, called by ai_engine)
├── Cyber Immune Module            (Cooperates with ai_engine)
├── Ips Engine Module              (Executes decisions from ids, ai, ti, dpi)
│   ├── Wfp Engine Module          (Block via WFP kernel call)
│   └── Windivert Engine Module    (Block/modify via WinDivert)
├── Policy Module                  (Rule evaluation, overrides ips decisions)
├── Zero Trust Module              (Trust score, feeds Policy Module)
│   └── Identity Policy Module     (Auth results feed zero_trust)
├── Micro Segmentation Module      (Zone checks, parallel to policy)
├── Distributed Immunity Module    (Gossip, receives from peers, feeds ti)
├── Metrics Module                 (Receives telemetry from all modules)
├── Siem Integration Module        (Receives events from ids, ips, dpi)
├── Npcap Forensic Module          (Appends to forensic PCAP on security events)
└── Process Monitor Module         (Parallel OS-level monitoring, feeds ids)
```

---

## 7. Module Categorization by Function

### Category 1: Traffic Capture and Parsing

`Capture Module`, `L2 Engine Module`, `Flow Engine Module`, `Stateful Module`

These modules handle the physical ingestion and parsing of network traffic. They run in the earliest stages of the pipeline and are performance-critical. Any regression in these modules affects all subsequent processing.

### Category 2: Detection Engines

`Ids Engine Module`, `Dpi Module`, `Comprehensive Blocker Module`

Signature-based and rule-based detection. These modules produce alerts but do not take action (that is IPS's job). They should be tunable without recompilation via the rules files in `data/`.

### Category 3: AI and Behavioral Analytics

`Ai Engine Module`, `Advanced Ml Module`, `Advanced Security Module`, `Cyber Immune Module`

Statistical and ML-based anomaly detection. These modules learn normal behavior and flag deviations. They supplement signature detection for unknown/novel threats.

### Category 4: Threat Intelligence

`Threat Intelligence Module`

External IOC integration. The Bloom filter lookup is the fastest path to blocking — no ML needed for a known-bad IP.

### Category 5: Prevention and Enforcement

`Ips Engine Module`, `Wfp Engine Module`, `Windivert Engine Module`, `Comprehensive Blocker Module`

These modules take action on traffic. Bugs here are high-impact (could block legitimate traffic). Changes require testing across all allowed/block test cases.

### Category 6: Enterprise Security

`Zero Trust Module`, `Identity Policy Module`, `Micro Segmentation Module`, `Endpoint Security Module`, `Attribution Scoring Module`

Enterprise policy layer. These modules are optional addons for enterprise deployments with identity infrastructure. They are no-ops if not configured.

### Category 7: Observability and Forensics

`Metrics Module`, `Siem Integration Module`, `Npcap Forensic Module`

These modules are pure sinks — they consume events from other modules and have no effect on packet flow decisions. Safe to modify without security risk.

### Category 8: Deployment and Operations

`Config Module`, `Gateway Mode Module`, `Sdwan Module`, `Cloud Native Module`, `Mode Profiles Module`, `Framework Alignment Module`

Supporting modules for different deployment topologies and compliance reporting.

### Category 9: Advanced Research Modules

`Distributed Immunity Module`, `Process Monitor Module`, and all modules documented in the Research-Grade Modules section.

---

## 8. Adding a New Module — Checklist

When adding a new `Foo Engine Module` module to Rudras:

1. **Create `Foo Engine Module`** with the primary struct and `pub fn init(config: &RudrasConfig) -> FooEngine`
2. **Register in `Main Module`:**
   - `mod foo_engine;`
   - Initialize in the startup sequence
   - Call in the appropriate pipeline stage
3. **Add configuration section** to `config/rudras.toml` with `[foo]` block and `enabled = true`
4. **Add to `Config Module`:** New `FooConfig` struct, deserialize from TOML, validate fields
5. **Wire telemetry:**
   - Add Prometheus counters to `Metrics Module` for `rudras_foo_*` metrics
   - Emit SIEM events via `Siem Integration Module` for security-relevant actions
   - Log via `tracing::info!`, `tracing::warn!`, etc.
6. **Update pipeline stage** in this index (Section 2 of this document)
7. **Update Module Inventory** (Section 1 of this document)
8. **Write tests** in `tests/` or `#[cfg(test)]` block
9. **Update Documentation** — add a section to the appropriate deep-dive document (files 6-12) or create a new one

---

## 9. Version History of the Module Set

| Version | New Modules Added                                                                                                                                                                                   | Key Changes                                                         |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| v1.0    | `Capture Module`, `Flow Engine Module`, `Ids Engine Module`, `Ips Engine Module`, `Wfp Engine Module`, `Metrics Module`                                                                                                     | Initial release — basic IDS/IPS firewall                            |
| v2.0    | `Ai Engine Module`, `Threat Intelligence Module`, `Dpi Module`, `Policy Module`, `Siem Integration Module`                                                                                                              | AI-powered behavioral detection + TI feeds                          |
| v3.0    | `Zero Trust Module`, `Micro Segmentation Module`, `Identity Policy Module`, `Cyber Immune Module`, `Distributed Immunity Module`                                                                                        | Enterprise ZT + swarm intelligence                                  |
| v4.0    | `Advanced Ml Module`, `Advanced Security Module`, `Attribution Scoring Module`, `Npcap Forensic Module`, `L2 Engine Module`, `Hardware Accel Module`, `Framework Alignment Module`, `Process Monitor Module` + 20+ research modules | Full enterprise + research capabilities, IST logging, SOC dashboard |

---

_This index is the authoritative cross-reference for the Rudras v4.0 codebase. Update it whenever a new module is added or significantly refactored._
