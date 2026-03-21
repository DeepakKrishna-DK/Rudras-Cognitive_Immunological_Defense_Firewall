# 8.1 Complete Module Index

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
| 1   | `main.rs`                  | Entry Point         | Program entry, init orchestration, tokio runtime     | `main()`                                             |
| 2   | `config.rs`                | Configuration       | TOML config loading, validation, hot-reload          | `RudrasConfig`, `load_config()`, `ConfigWatcher`     |
| 3   | `capture.rs`               | Traffic Capture     | Npcap packet capture, ring buffer, BPF pre-filter    | `PacketCapture`, `CaptureConfig`, `RawPacket`        |
| 4   | `flow_engine.rs`           | Stateful Tracking   | TCP/UDP flow table, session reassembly               | `FlowEngine`, `FlowRecord`, `FlowKey`                |
| 5   | `stateful.rs`              | Stateful Inspection | Deep stateful packet inspection (SPI)                | `StatefulInspector`, `ConnectionState`               |
| 6   | `dpi.rs`                   | Deep Inspection     | L7 protocol dissection, WAF pattern matching         | `DpiEngine`, `L7Protocol`, `WafResult`               |
| 7   | `ids_engine.rs`            | Detection           | Signature + behavioral IDS, 85 rules                 | `IdsEngine`, `IdsRule`, `IdsAlert`                   |
| 8   | `ips_engine.rs`            | Prevention          | IPS action execution, RST injection, WFP block       | `IpsEngine`, `IpsDecision`, `IpsAction`              |
| 9   | `threat_intelligence.rs`   | Intelligence        | Blocklist management, Bloom filter lookup            | `ThreatIntelligence`, `TiHit`, `IocEntry`            |
| 10  | `ai_engine.rs`             | AI/ML               | EMA baseline anomaly detection, deviation scoring    | `AiEngine`, `BehaviorProfile`, `DeviationScore`      |
| 11  | `advanced_ml.rs`           | AI/ML               | Ensemble ML (Isolation Forest, Autoencoder, etc.)    | `AdvancedMlEngine`, `AnomalyScore`                   |
| 12  | `advanced_security.rs`     | AI/ML               | Multi-source correlation, threat scoring             | `AdvancedSecurityEngine`, `CorrelatedAlert`          |
| 13  | `cyber_immune.rs`          | AI/ML               | Biological immune metaphor detection                 | `CyberImmuneSystem`, `ImmuneResponse`                |
| 14  | `distributed_immunity.rs`  | Swarm               | Gossip protocol, inter-node intelligence sharing     | `DistributedImmunity`, `SwarmMessage`, `GossipPeer`  |
| 15  | `policy.rs`                | Policy              | Rule evaluation engine, policy composition           | `PolicyEngine`, `PolicyRule`, `PolicyDecision`       |
| 16  | `zero_trust.rs`            | Enterprise          | Zero-trust trust score, continuous verification      | `ZeroTrustEngine`, `TrustScore`, `TrustVerification` |
| 17  | `identity_policy.rs`       | Enterprise          | JWT/mTLS/Kerberos auth, RBAC                         | `IdentityPolicy`, `Identity`, `AuthResult`           |
| 18  | `micro_segmentation.rs`    | Enterprise          | Network zone enforcement, segment policy             | `MicroSegmentation`, `Zone`, `SegmentPolicy`         |
| 19  | `endpoint_security.rs`     | Enterprise          | Endpoint posture, agent comms, EDR integration       | `EndpointSecurity`, `PostureScore`, `EndpointAgent`  |
| 20  | `attribution_scoring.rs`   | Enterprise          | TTP-based threat actor attribution                   | `AttributionEngine`, `TtpMatch`, `ActorProfile`      |
| 21  | `siem_integration.rs`      | Observability       | CEF/LEEF event streaming to SIEM                     | `SiemIntegration`, `SiemEvent`, `CefRecord`          |
| 22  | `metrics.rs`               | Observability       | Prometheus metrics server, counters, auth            | `MetricsServer`, `Counters`, `AuthToken`             |
| 23  | `wfp_engine.rs`            | Enforcement         | Windows Filtering Platform kernel block rules        | `WfpEngine`, `WfpRule`, `WfpCallout`                 |
| 24  | `windivert_engine.rs`      | Enforcement         | WinDivert packet intercept, modification             | `WinDivertEngine`, `DivertedPacket`                  |
| 25  | `npcap_forensic.rs`        | Forensics           | Forensic PCAP capture, chain of custody              | `NpcapForensic`, `ForensicCapture`, `CustodyRecord`  |
| 26  | `l2_engine.rs`             | L2 Security         | ARP/MAC/VLAN enforcement, 802.11 analysis            | `L2Engine`, `ArpRecord`, `VlanPolicy`                |
| 27  | `gateway_mode.rs`          | Deployment          | Gateway/router mode, route management                | `GatewayMode`, `RouteEntry`                          |
| 28  | `sdwan.rs`                 | Deployment          | SD-WAN path selection, WAN policy                    | `SdWan`, `WanPath`, `PathMetrics`                    |
| 29  | `cloud_native.rs`          | Deployment          | K8s/Docker integration, CNI enforcement              | `CloudNative`, `ContainerPolicy`                     |
| 30  | `mode_profiles.rs`         | Deployment          | Operational mode presets (stealth, aggressive, etc.) | `ModeProfile`, `ProfileSettings`                     |
| 31  | `single_pass.rs`           | Performance         | Single-pass packet inspection pipeline               | `SinglePassPipeline`, `InspectionResult`             |
| 32  | `hardware_accel.rs`        | Performance         | DPDK/hardware offload integration                    | `HardwareAccel`, `OffloadCapability`                 |
| 33  | `framework_alignment.rs`   | Compliance          | MITRE ATT&CK, NIST, CIS mapping                      | `FrameworkAlignment`, `MitreMapping`                 |
| 34  | `process_monitor.rs`       | Endpoint            | Sysmon/WinAPI process creation monitoring            | `ProcessMonitor`, `ProcessEvent`                     |
| 35  | `comprehensive_blocker.rs` | Detection           | Multi-signal weighted block scoring                  | `ComprehensiveBlocker`, `BlockScore`                 |
| 36  | `policy.rs`                | Policy              | See #15                                              |
| 37  | `sdwan.rs`                 | See #28             |

> Note: The remaining 30+ source files in the `src/` directory are specialized research and advanced modules. They are documented in the Research-Grade Modules section and listed in Section 4 of this index.

---

## 2. Pipeline Stage Mapping

This table shows when each module is called in the 10-stage packet processing pipeline.

### Stage 0 — Pre-Filter (Capture)

Module called before the packet enters the main pipeline. Runs in the capture thread.

```
capture.rs          → BPF kernel pre-filter (drops irrelevant traffic never to enter Rust)
```

### Stage 1 — Packet Arrival (L2/L3 Parsing)

First stage in the Tokio async pipeline. Parses raw bytes into structured data.

```
l2_engine.rs        → Ethernet frame parsing, ARP check
capture.rs          → Packet dispatch to pipeline
```

### Stage 2 — Identity Verification

```
identity_policy.rs  → JWT/mTLS header extraction (HTTP/TLS flows)
zero_trust.rs       → Trust score evaluation for source identity
```

### Stage 3 — Flow Tracking

```
flow_engine.rs      → Flow lookup or creation, sequence/ack tracking
stateful.rs         → TCP state machine update, connection validation
```

### Stage 4 — Threat Intelligence Lookup

Fast O(1) Bloom filter + hash map lookup. If blocked, skip all further stages.

```
threat_intelligence.rs  → IP blocklist check
dpi.rs                  → Quick hostname extraction for DNS block check
```

### Stage 5 — Deep Packet Inspection

```
dpi.rs              → L7 protocol identification, WAF payload scan
ids_engine.rs       → Signature rule matching against payload
gateway_mode.rs     → (In gateway mode) inter-VLAN routing decision
```

### Stage 6 — Behavioral Analysis

```
ai_engine.rs        → EMA baseline update, deviation calculation
advanced_ml.rs      → (If enabled) Isolation Forest / Autoencoder scoring
cyber_immune.rs     → (If enabled) Immune system response check
```

### Stage 7 — Policy Evaluation

```
policy.rs           → Rule evaluation, allow/deny/limit decision
micro_segmentation.rs  → Zone transition validation
zero_trust.rs       → Final trust check before allowing
```

### Stage 8 — Action Execution

```
ips_engine.rs           → Select action (block, reset, alert, rate_limit)
wfp_engine.rs           → Install WFP kernel-level block rule
windivert_engine.rs     → (If WinDivert mode) Drop or modify packet
comprehensive_blocker.rs → Multi-signal block decision
```

### Stage 9 — Telemetry

```
metrics.rs              → Increment Prometheus counters
siem_integration.rs     → Emit CEF syslog event
distributed_immunity.rs → (If swarm) Gossip alert to peers
npcap_forensic.rs       → (If forensic mode active) Append to forensic PCAP
```

---

## 3. Configuration Key → Module Mapping

When updating `config/rudras.toml`, this table maps every top-level TOML section to the module that owns it.

| TOML Section/Key                      | Owning Module                         | Description                 |
| ------------------------------------- | ------------------------------------- | --------------------------- |
| `[ids]`                               | `ids_engine.rs`                       | IDS rule configuration      |
| `ids.enabled`                         | `ids_engine.rs`                       | Master IDS on/off           |
| `ids.alert_only`                      | `ids_engine.rs`                       | Detect but don't block      |
| `ids.rules_path`                      | `ids_engine.rs`                       | Custom rules directory      |
| `[ips]`                               | `ips_engine.rs`                       | IPS action thresholds       |
| `ips.enabled`                         | `ips_engine.rs`                       | Master IPS on/off           |
| `ips.block_duration_secs`             | `ips_engine.rs`                       | Duration of IP bans         |
| `ips.inject_rst`                      | `ips_engine.rs`                       | TCP RST injection           |
| `[dpi]`                               | `dpi.rs`                              | DPI/WAF configuration       |
| `dpi.waf_enabled`                     | `dpi.rs`                              | Web application firewall    |
| `dpi.patterns_path`                   | `dpi.rs`                              | Attack pattern library path |
| `[ai]`                                | `ai_engine.rs`                        | Behavioral baseline ML      |
| `ai.ema_alpha`                        | `ai_engine.rs`                        | EMA smoothing factor        |
| `ai.suspicious_threshold`             | `ai_engine.rs`                        | Deviation alert threshold   |
| `ai.block_threshold`                  | `ai_engine.rs`                        | Deviation block threshold   |
| `[threat_intel]`                      | `threat_intelligence.rs`              | TI feed config              |
| `threat_intel.global_iocs_path`       | `threat_intelligence.rs`              | IOC JSON feed               |
| `threat_intel.malicious_domains_path` | `threat_intelligence.rs`              | Domain blocklist            |
| `[zero_trust]`                        | `zero_trust.rs`                       | ZT policy                   |
| `[micro_segmentation]`                | `micro_segmentation.rs`               | Zone definitions            |
| `[identity]`                          | `identity_policy.rs`                  | Auth configuration          |
| `[siem]`                              | `siem_integration.rs`                 | SIEM endpoint               |
| `siem.endpoint`                       | `siem_integration.rs`                 | Syslog server address       |
| `siem.format`                         | `siem_integration.rs`                 | CEF/LEEF/JSON/Splunk        |
| `[metrics]`                           | `metrics.rs`                          | Metrics server config       |
| `metrics.port`                        | `metrics.rs`                          | Listen port (default 9091)  |
| `metrics.auth_token_validity_mins`    | `metrics.rs`                          | Token rotation interval     |
| `[capture]`                           | `capture.rs`                          | NIC and capture config      |
| `capture.interface`                   | `capture.rs`                          | Network interface name      |
| `capture.promiscuous`                 | `capture.rs`                          | Promiscuous mode            |
| `capture.ring_buffer_mb`              | `capture.rs`                          | Ring buffer size            |
| `[l2]`                                | `l2_engine.rs`                        | L2 security settings        |
| `[swarm]`                             | `distributed_immunity.rs`             | Peer mesh config            |
| `swarm.peers`                         | `distributed_immunity.rs`             | Peer addresses              |
| `[gateway]`                           | `gateway_mode.rs`                     | Gateway mode settings       |
| `[performance]`                       | `single_pass.rs`, `hardware_accel.rs` | Tuning                      |
| `[logging]`                           | `main.rs`                             | Log level, format, path     |

---

## 4. All 67 Source Files — Complete Listing

This section lists every file in alphabetical order with its category and purpose.

```
src/
├── advanced_ml.rs          [AI/ML]           Ensemble ML anomaly detection
├── advanced_security.rs    [AI/ML]           Multi-signal correlation engine
├── ai_engine.rs            [AI/ML]           Primary EMA behavioral baseline
├── attribution_scoring.rs  [Enterprise]      TTP-based threat actor attribution
├── capture.rs              [Capture]         Npcap capture, ring buffer, BPF filter
├── cloud_native.rs         [Deployment]      K8s/Docker/CNI enforcement
├── comprehensive_blocker.rs[Detection]       Multi-signal weighted block scoring
├── config.rs               [Configuration]   TOML loading, validation, hot-reload
├── cyber_immune.rs         [AI/ML]           Biological immune system metaphor
├── distributed_immunity.rs [Swarm]           Gossip protocol, swarm intelligence
├── dpi.rs                  [Detection]       L7 DPI, WAF, protocol dissection
├── endpoint_security.rs    [Enterprise]      Endpoint posture, EDR integration
├── flow_engine.rs          [Stateful]        Flow table, TCP/UDP session tracking
├── framework_alignment.rs  [Compliance]      MITRE/NIST/CIS framework mapping
├── gateway_mode.rs         [Deployment]      Inline gateway routing mode
├── hardware_accel.rs       [Performance]     DPDK/NIC offload integration
├── identity_policy.rs      [Enterprise]      JWT/mTLS/Kerberos identity auth
├── ids_engine.rs           [Detection]       Signature + behavioral IDS engine
├── ips_engine.rs           [Prevention]      IPS action engine, RST injection
├── l2_engine.rs            [L2 Security]     ARP/MAC/VLAN enforcement
├── main.rs                 [Entry Point]     Startup, init, runtime orchestration
├── metrics.rs              [Observability]   Prometheus metrics server
├── micro_segmentation.rs   [Enterprise]      Network zone segmentation
├── mode_profiles.rs        [Deployment]      Operational mode presets
├── npcap_forensic.rs       [Forensics]       Forensic PCAP + chain-of-custody
├── policy.rs               [Policy]          Rule evaluation, policy engine
├── process_monitor.rs      [Endpoint]        Sysmon/WinAPI process tracking
├── sdwan.rs                [Deployment]      SD-WAN path selection
├── siem_integration.rs     [Observability]   CEF/LEEF SIEM event streaming
├── single_pass.rs          [Performance]     Single-pass inspection pipeline
├── stateful.rs             [Stateful]        Deep stateful inspection (SPI)
├── threat_intelligence.rs  [Intelligence]    Blocklist management, IOC lookup
├── wfp_engine.rs           [Enforcement]     Windows Filtering Platform calls
├── windivert_engine.rs     [Enforcement]     WinDivert packet intercept/modify
├── zero_trust.rs           [Enterprise]      Zero-trust trust scoring engine
```

---

## 5. Threat Capability Matrix

This table maps real-world attacker techniques to the Rudras modules that detect and/or prevent them.

| MITRE Technique | Technique Name                  | Detecting Module(s)                             | Preventing Module(s)         |
| --------------- | ------------------------------- | ----------------------------------------------- | ---------------------------- |
| T1071.001       | Web Protocols C2                | `ids_engine.rs`, `ai_engine.rs`                 | `ips_engine.rs`, `dpi.rs`    |
| T1071.004       | DNS C2                          | `threat_intelligence.rs`                        | `ips_engine.rs`              |
| T1041           | Data Exfiltration over C2       | `dpi.rs`, `ai_engine.rs`                        | `ips_engine.rs`              |
| T1486           | Data Encrypted for Impact       | `ids_engine.rs` (ransomware rules)              | `ips_engine.rs`              |
| T1046           | Network Service Scan            | `ids_engine.rs`, `ai_engine.rs`                 | `ips_engine.rs` (rate limit) |
| T1110           | Brute Force                     | `ids_engine.rs`, `ai_engine.rs`                 | `ips_engine.rs`              |
| T1557           | ARP Spoofing/Poison             | `l2_engine.rs`                                  | `l2_engine.rs` (drop)        |
| T1210           | Exploitation of Remote Services | `ids_engine.rs`, `dpi.rs`                       | `ips_engine.rs`              |
| T1090           | Proxy/Tor                       | `threat_intelligence.rs` (exit nodes), `dpi.rs` | `ips_engine.rs`              |
| T1133           | External Remote Services        | `zero_trust.rs`, `identity_policy.rs`           | `ips_engine.rs`              |
| T1021.002       | SMB Lateral Movement            | `ids_engine.rs`, `micro_segmentation.rs`        | `ips_engine.rs`              |
| T1059           | Command & Scripting Interpreter | `process_monitor.rs`, `endpoint_security.rs`    | `endpoint_security.rs`       |
| T1055           | Process Injection               | `process_monitor.rs`                            | `endpoint_security.rs`       |
| T1499           | Endpoint Denial of Service      | `ids_engine.rs` (DOS rules)                     | `ips_engine.rs`              |
| T1189           | Drive-by Compromise             | `dpi.rs` (WAF), `ids_engine.rs`                 | `ips_engine.rs`, `dpi.rs`    |
| T1498           | Network Denial of Service       | `ids_engine.rs` (flood rules)                   | `ips_engine.rs`              |

---

## 6. Dependency Graph

This is a simplified text-based dependency graph showing which modules import from which:

```
main.rs
├── config.rs                  (Configuration — all modules depend on config)
├── capture.rs                 (Feeds raw packets to pipeline)
│   └── l2_engine.rs           (L2 parsing of captured frames)
├── flow_engine.rs             (Flow table, used by most inspection modules)
│   ├── stateful.rs            (TCP state machine)
│   └── ids_engine.rs          (Flow context for signature matching)
├── threat_intelligence.rs     (Blocklist — called early for fast path rejection)
├── dpi.rs                     (L7 inspection, WAF)
│   └── ids_engine.rs          (Matches DPI-extracted fields against rules)
├── ai_engine.rs               (Behavioral baseline)
│   ├── advanced_ml.rs         (Ensemble scoring called by ai_engine)
│   └── advanced_security.rs   (Correlation, called by ai_engine)
├── cyber_immune.rs            (Cooperates with ai_engine)
├── ips_engine.rs              (Executes decisions from ids, ai, ti, dpi)
│   ├── wfp_engine.rs          (Block via WFP kernel call)
│   └── windivert_engine.rs    (Block/modify via WinDivert)
├── policy.rs                  (Rule evaluation, overrides ips decisions)
├── zero_trust.rs              (Trust score, feeds policy.rs)
│   └── identity_policy.rs     (Auth results feed zero_trust)
├── micro_segmentation.rs      (Zone checks, parallel to policy)
├── distributed_immunity.rs    (Gossip, receives from peers, feeds ti)
├── metrics.rs                 (Receives telemetry from all modules)
├── siem_integration.rs        (Receives events from ids, ips, dpi)
├── npcap_forensic.rs          (Appends to forensic PCAP on security events)
└── process_monitor.rs         (Parallel OS-level monitoring, feeds ids)
```

---

## 7. Module Categorization by Function

### Category 1: Traffic Capture and Parsing

`capture.rs`, `l2_engine.rs`, `flow_engine.rs`, `stateful.rs`

These modules handle the physical ingestion and parsing of network traffic. They run in the earliest stages of the pipeline and are performance-critical. Any regression in these modules affects all subsequent processing.

### Category 2: Detection Engines

`ids_engine.rs`, `dpi.rs`, `comprehensive_blocker.rs`

Signature-based and rule-based detection. These modules produce alerts but do not take action (that is IPS's job). They should be tunable without recompilation via the rules files in `data/`.

### Category 3: AI and Behavioral Analytics

`ai_engine.rs`, `advanced_ml.rs`, `advanced_security.rs`, `cyber_immune.rs`

Statistical and ML-based anomaly detection. These modules learn normal behavior and flag deviations. They supplement signature detection for unknown/novel threats.

### Category 4: Threat Intelligence

`threat_intelligence.rs`

External IOC integration. The Bloom filter lookup is the fastest path to blocking — no ML needed for a known-bad IP.

### Category 5: Prevention and Enforcement

`ips_engine.rs`, `wfp_engine.rs`, `windivert_engine.rs`, `comprehensive_blocker.rs`

These modules take action on traffic. Bugs here are high-impact (could block legitimate traffic). Changes require testing across all allowed/block test cases.

### Category 6: Enterprise Security

`zero_trust.rs`, `identity_policy.rs`, `micro_segmentation.rs`, `endpoint_security.rs`, `attribution_scoring.rs`

Enterprise policy layer. These modules are optional addons for enterprise deployments with identity infrastructure. They are no-ops if not configured.

### Category 7: Observability and Forensics

`metrics.rs`, `siem_integration.rs`, `npcap_forensic.rs`

These modules are pure sinks — they consume events from other modules and have no effect on packet flow decisions. Safe to modify without security risk.

### Category 8: Deployment and Operations

`config.rs`, `gateway_mode.rs`, `sdwan.rs`, `cloud_native.rs`, `mode_profiles.rs`, `framework_alignment.rs`

Supporting modules for different deployment topologies and compliance reporting.

### Category 9: Advanced Research Modules

`distributed_immunity.rs`, `process_monitor.rs`, and all modules documented in the Research-Grade Modules section.

---

## 8. Adding a New Module — Checklist

When adding a new `src/foo_engine.rs` module to Rudras:

1. **Create `src/foo_engine.rs`** with the primary struct and `pub fn init(config: &RudrasConfig) -> FooEngine`
2. **Register in `src/main.rs`:**
   - `mod foo_engine;`
   - Initialize in the startup sequence
   - Call in the appropriate pipeline stage
3. **Add configuration section** to `config/rudras.toml` with `[foo]` block and `enabled = true`
4. **Add to `config.rs`:** New `FooConfig` struct, deserialize from TOML, validate fields
5. **Wire telemetry:**
   - Add Prometheus counters to `metrics.rs` for `rudras_foo_*` metrics
   - Emit SIEM events via `siem_integration.rs` for security-relevant actions
   - Log via `tracing::info!`, `tracing::warn!`, etc.
6. **Update pipeline stage** in this index (Section 2 of this document)
7. **Update Module Inventory** (Section 1 of this document)
8. **Write tests** in `tests/` or `#[cfg(test)]` block
9. **Update Documentation** — add a section to the appropriate deep-dive document (files 6-12) or create a new one

---

## 9. Version History of the Module Set

| Version | New Modules Added                                                                                                                                                                                   | Key Changes                                                         |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| v1.0    | `capture.rs`, `flow_engine.rs`, `ids_engine.rs`, `ips_engine.rs`, `wfp_engine.rs`, `metrics.rs`                                                                                                     | Initial release — basic IDS/IPS firewall                            |
| v2.0    | `ai_engine.rs`, `threat_intelligence.rs`, `dpi.rs`, `policy.rs`, `siem_integration.rs`                                                                                                              | AI-powered behavioral detection + TI feeds                          |
| v3.0    | `zero_trust.rs`, `micro_segmentation.rs`, `identity_policy.rs`, `cyber_immune.rs`, `distributed_immunity.rs`                                                                                        | Enterprise ZT + swarm intelligence                                  |
| v4.0    | `advanced_ml.rs`, `advanced_security.rs`, `attribution_scoring.rs`, `npcap_forensic.rs`, `l2_engine.rs`, `hardware_accel.rs`, `framework_alignment.rs`, `process_monitor.rs` + 20+ research modules | Full enterprise + research capabilities, IST logging, SOC dashboard |

---

_This index is the authoritative cross-reference for the Rudras v4.0 codebase. Update it whenever a new module is added or significantly refactored._
