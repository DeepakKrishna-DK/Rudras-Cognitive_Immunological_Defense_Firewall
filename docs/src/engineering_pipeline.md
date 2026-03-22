# Transparent Development Model

---

## 1. The v4.0 Packet Processing Pipeline

Every packet flowing through Rudras passes through the following 10-stage pipeline. Understanding this pipeline is essential for any engineer contributing to the codebase.

### Stage 0: NIC → Kernel Interface

**Module:** Npcap driver (external), `Capture Module`

The packet arrives at the NIC and is copied into Npcap's ring buffer in the kernel. The `Capture Module` module owns a PCAP handle opened in promiscuous mode. It sits in a tight loop calling `pcap_next_ex()` and pushing raw bytes into a Tokio `mpsc` channel for processing.

**Engineering Rule:** Never block the capture loop. Any packet processing that takes > 1ms must be offloaded to a worker thread via channel. The capture loop blocking means backpressure on the ring buffer, which means packet drops.

### Stage 1: L2 Parsing and Security

**Module:** `L2 Engine Module`

The raw bytes are parsed as an Ethernet frame. L2 engine extracts:

- Source/destination MAC addresses
- EtherType (IPv4=0x0800, IPv6=0x86DD, ARP=0x0806, VLAN=0x8100)
- If VLAN tagged: VLAN ID for zone enforcement
- If ARP: check against MAC-to-IP binding table for spoofing

**Engineering Rule:** ARP spoofing detection requires maintaining a `HashMap<IpAddr, MacAddr>` binding table. The first ARP for a new IP establishes the binding. Subsequent ARPs claiming the same IP with a different MAC generate a `CRITICAL` alert.

### Stage 2: IP/Transport Parsing

**Module:** `Flow Engine Module`, `Stateful Module`

The IP header is parsed for src IP, dst IP, protocol (TCP/UDP/ICMP/etc.). The `flow_engine` creates or updates a `FlowRecord` keyed by the 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)`.

The `stateful` module enforces TCP state machine transitions. A packet arriving in the wrong state (e.g., ACK without SYN) is flagged for TCP state anomaly analysis.

### Stage 3: Fast-Path Block Check

**Module:** `Threat Intelligence Module`, `Wfp Engine Module`

Before any expensive analysis, the source IP is checked against a `RwLock<HashSet<IpAddr>>` (in-memory blocklist). This is an O(1) hash lookup. If the IP matches, the packet is immediately dropped and a counter incremented. This stage handles the millions of already-known-bad IPs without burning CPU on analysis.

**Engineering Rule:** Never use `Mutex` for the blocklist — always `RwLock`. Reads are 1000x more frequent than writes. A `Mutex` here would serialize all packet decisions through a single lock and halve throughput.

### Stage 4: Deep Packet Inspection

**Module:** `Dpi Module`, `Single Pass Module`

The payload bytes are inspected for protocol-specific content. `Single Pass Module` ensures this is done in a single traversal through the packet bytes rather than multiple passes.

DPI inspects:

- **HTTP:** URL path, query parameters, headers, body (for WAF patterns)
- **DNS:** query type, domain name (for DNS security checks)
- **TLS:** SNI hostname, certificate fields (for ETA analysis)
- **SMTP:** MAIL FROM, RCPT TO, Subject, headers (for email security)
- **Modbus/DNP3:** Function code validation (for OT security)
- **QUIC:** QUIC header inspection for HTTP/3 traffic

### Stage 5: AI Behavioral Analysis

**Module:** `Ai Engine Module`, `Cyber Immune Module`, `Advanced Ml Module`, `Ueba Engine Module`

For each source IP, the AI engine maintains running statistics:

- `packets_per_sec`: EMA-smoothed packet rate
- `bytes_per_sec`: EMA-smoothed byte rate
- `new_connections_per_sec`: SYN rate
- `unique_dst_ports`: Distinct destination ports (port scan metric)
- `unique_dst_ips`: Distinct destination IPs (lateral movement metric)

The deviation score is computed against the immutable baseline established during the learning period.

**UEBA:** If the packet is associated with an authenticated user (via identity policy JWT claim), the UEBA engine additionally checks the user's behavioral baseline for anomalies — accessing unusual resources, unusually large downloads, unusual hours.

### Stage 6: IDS Signature Matching

**Module:** `Ids Engine Module`

The packet metadata (parsed headers, protocol, DPI results, flow statistics) is matched against the IDS rule set.

Rule set statistics:

- **85 rules** across **71 categories**
- **70+ attack types** recognized
- Categories include: port_scan, syn_flood, udp_flood, brute_force, sql_injection, xss, rce, path_traversal, dns_tunneling, c2_beacon, lateral_movement, data_exfiltration, ransomware_smb, etc.

Each rule produces an alert with:

- `severity`: low / medium / high / critical
- `category`: the attack category string
- `mitre_technique`: e.g., "T1190" (Exploit Public-Facing Application)
- `description`: human-readable description

### Stage 7: Threat Intelligence Enrichment

**Module:** `Threat Intelligence Module`, `Threat Rules Engine Module`, `Threat Hunt Module`

The source IP and queried domain are cross-referenced against:

- **24,358 known malicious IPs** from curated global IOC feeds
- **617 specifically tracked bad actor domains**
- **1,250,000 blocked domains** (DNS blocklist)
- **84,501 malware signature hashes**

The `threat_rules_engine` implements composite rules that combine TI signals with behavioral signals for higher-confidence alerts:

```
RULE: c2_callback_confirmed
  WHEN: TI score > 0.8 AND AI deviation > 0.6 AND DNS_query matches known C2 pattern
  THEN: CRITICAL alert, immediate block, SOAR playbook C2_RESPONSE triggered
```

### Stage 8: Comprehensive Block Decision

**Module:** `Comprehensive Blocker Module`

All signals are aggregated into a final action decision:

| Condition                 | Action                          |
| ------------------------- | ------------------------------- |
| TI hit (confidence > 0.9) | BLOCK immediately               |
| IDS CRITICAL alert        | BLOCK immediately               |
| AI deviation > [BLOCK_LIMIT]       | BLOCK                           |
| IDS HIGH alert            | QUARANTINE (rate-limit + alert) |
| AI deviation [SUSPICIOUS_RANGE]    | ALERT (log + increment metric)  |
| All clean                 | ALLOW                           |

The block decision honors a whitelist from the policy config — whitelisted IPs are never blocked regardless of signals (use carefully, document every entry).

### Stage 9: IPS Enforcement

**Module:** `Ips Engine Module`, `Wfp Engine Module`

If the decision is BLOCK:

1. TCP RST packet is crafted and injected to both connection endpoints (using WinDivert raw send)
2. The source IP is added to the WFP in-kernel block filter (subsequent packets dropped at kernel level, zero userspace cost)
3. The IP is added to the in-memory `blocked_ips` HashSet
4. Swarm gossip message is broadcast to peer nodes
5. A `forensics_chain` entry is appended with full event context

### Stage 10: Observability

**Module:** `Metrics Module`, `Siem Integration Module`, `Forensics Chain Module`

Every packet decision (ALLOW, ALERT, QUARANTINE, BLOCK) is recorded:

- **Metrics:** Prometheus counters incremented atomically
- **SIEM:** CEF-format event sent to syslog if configured
- **Audit chain:** SHA3-256 chained log entry appended
- **Structured log:** `tracing` JSON event with IST timestamp written to rolling file

---

## 2. Team Engineering Rules

### Rule 1: Never Block the Capture Loop

The `Capture Module` capture thread must process packets at wire speed. Any analysis taking more than ~100 microseconds must be dispatched to a worker thread. Blocking the capture thread causes ring buffer overflow and packet drops.

### Rule 2: Always Use RwLock for Shared Read-Heavy Data

```rust
// CORRECT: RwLock for data that is read often, written rarely
let blocked_ips: Arc<RwLock<HashSet<IpAddr>>> = Arc::new(RwLock::new(HashSet::new()));

// WRONG: Mutex serializes all reads even when no write is happening
let blocked_ips: Arc<Mutex<HashSet<IpAddr>>> = Arc::new(Mutex::new(HashSet::new()));
```

### Rule 3: Fail Open for Infrastructure Traffic (Fail Closed for External)

Internal health probes, load balancer heartbeats, and monitoring agents must not be accidentally blocked. The policy engine has a "fail open" mode for internal CIDR ranges. External traffic should fail closed — when in doubt about an external connection, block it.

### Rule 4: All Security Decisions Are Logged

There is no "silent drop" in Rudras. Every block, every quarantine, every alert, every RST injection — logged to the forensics chain. This is required for compliance and incident response.

### Rule 5: No `unsafe` Outside the WFP/Npcap Interface

The only acceptable `unsafe` code is in `Wfp Engine Module` (Windows Filtering Platform FFI) and `Npcap Forensic Module` (Npcap C library FFI). All other modules must be safe Rust. If you think you need `unsafe` for a performance reason, profile first — the Rust optimizer is usually able to match the `unsafe` version.

### Rule 6: Configuration Changes Must Be Backward Compatible

The `Config Module` deserialization uses `serde` with `#[serde(default)]` on all optional fields. Adding a new config field must provide a sensible default so that existing config files work without modification after upgrade.

### Rule 7: Test With Real Traffic, Not Just Unit Tests

Unit tests verify logic. Integration tests verify behavior against actual network traffic. Before merging any new detection module, run it against the capture corpus in `Testing/` directory and verify:

- No panics on malformed packets
- Correct detection of known-bad traffic (from test files)
- No false positives on benign traffic (from test files)
- Performance: < 1ms per packet at 99th percentile

---

## 3. Adding a New Detection Module

To add a new detection module to Rudras:

1. **Create the module file** in `src/`

   ```rust
   // My Detection Module
   pub struct MyDetection { /* config fields */ }

   impl MyDetection {
       pub fn new(config: &MyDetectionConfig) -> Self { ... }
       pub fn analyze(&self, packet: &ParsedPacket) -> Option<Alert> { ... }
   }
   ```

2. **Add config struct** to `Config Module`

   ```rust
   #[derive(Deserialize, Default)]
   pub struct MyDetectionConfig {
       #[serde(default = "default_enabled")]
       pub enabled: bool,
       // ... other fields
   }
   ```

3. **Add to `rudras.toml`**

   ```toml
   [my_detection]
   enabled = true
   # ... other parameters
   ```

4. **Initialize in `Main Module`**

   ```rust
   let my_detection = MyDetection::new(&config.my_detection);
   ```

5. **Wire into pipeline** — call `my_detection.analyze(packet)` in the appropriate pipeline stage (usually Stage 5 or 6)

6. **Add metrics** — add a counter in `Metrics Module` for your detection events

7. **Add to `Comprehensive Blocker Module`** — integrate your alert signal into the block decision logic

8. **Write tests** — add to `src/tests/` and ensure the Testing/ corpus passes

---

## 4. GeoIP Database Maintenance

The GeoIP database is used for geographic visualization in the SOC dashboard and for optional geo-based blocking rules.

### Update GeoIP

```powershell
.\scripts\fetch_geoip.ps1
# Downloads latest MaxMind GeoLite2 database to data/geoip/
```

### GeoIP Data Location

`data/geoip/` — contains MaxMind .mmdb files

### Using GeoIP in Rules

```toml
[geo_blocking]
enabled = false   # disabled by default (legal risk in some jurisdictions)
blocked_countries = []   # ISO 3166-1 alpha-2 country codes
# e.g., blocked_countries = ["KP", "IR"]  — use with legal approval only
```

---

## 5. Threat Intelligence Feed Maintenance

### Updating IOC Feeds

```powershell
# Fetch latest global IOC list
# (script auto-downloads from configured threat feed APIs)
.\scripts\fetch_geoip.ps1   # also handles TI feed updates

# Manual file update
# Replace data/intel/global_iocs.json with fresh feed
# Replace data/intel/malicious_domains.txt with fresh domain list
```

### Feed Statistics (current as of v4.0)

| Feed               | Count     | Source                               |
| ------------------ | --------- | ------------------------------------ |
| Malicious IPs      | 24,358    | Curated multi-source global IOC feed |
| Known bad domains  | 617       | Manual curation + OTX                |
| DNS blocklist      | 1,250,000 | Aggregated public block lists        |
| Malware signatures | 84,501    | Hash-based malware feed              |

### Verifying Feed Integrity

All feed files should be accompanied by a `.sha256` checksum file. The TI engine validates checksums on load and refuses to use a feed file with a mismatched checksum.

---

## 6. Signing the Configuration

Configuration tampering is detected via cryptographic signature:

```powershell
# Sign the current config (generates config\rudras.toml.sig)
.\scripts\sign_config.ps1

# On startup, Rudras validates the signature
# If signature mismatch detected: WARN log event and alert sent to SIEM
# If signature file missing: INFO log (first-run or unsigned deployment)
```
