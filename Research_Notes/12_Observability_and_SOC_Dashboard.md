# Research Note 12: Observability, Metrics, and SOC Dashboard

**Document Version:** 4.0  
**Last Updated:** March 8, 2026  
**Classification:** Internal Research — Engineering Reference

---

## Abstract

A security system that cannot be observed cannot be trusted. Rudras v4.0 implements four overlapping observability layers: structured IST-timestamped JSON logging, a Prometheus-format metrics server, a CEF-format SIEM event stream, and a real-time SOC (Security Operations Center) dashboard built in Next.js 14. This document covers the design and operation of each layer.

---

## 1. Structured Logging System

**Technology:** `tracing` + `tracing-subscriber` crates with ChronoLocal timer  
**Format:** JSON (file), pretty-print (console)  
**Timezone:** IST (UTC+5:30) — Indian Standard Time  
**Rotation:** Daily (one file per day)

### 1.1 Why Structured JSON Logs?

Traditional log files are lines of human-readable text: `"[2026-03-08 10:45:23] WARN: Blocked IP 185.1.2.3"`. These are easy to read but hard to query.

Structured JSON logs represent each event as a JSON object:
```json
{
  "timestamp": "2026-03-08T10:45:23.124578+05:30",
  "level": "WARN",
  "target": "rudras::ips_engine",
  "event": "ips_block",
  "src_ip": "185.220.101.5",
  "dst_ip": "10.10.20.50",
  "src_port": 49152,
  "dst_port": 443,
  "trigger": "ids_alert",
  "ids_rule_id": 47,
  "ids_category": "c2_beacon",
  "ids_severity": "critical",
  "ai_deviation": 0.85,
  "ti_confidence": 0.92,
  "block_duration_secs": 3600,
  "mitre_technique": "T1071.001"
}
```

This format enables:
- **Machine parsing:** Any log aggregation tool (Elasticsearch, Splunk, Loki) can index and query without custom parsers
- **Field-level searching:** `grep '"level":"WARN"'` or Elasticsearch query `{ "term": { "level": "WARN" } }`
- **Statistical analysis:** Extract numeric fields for charting (deviation scores, block counts over time)
- **Correlation:** Join log events by shared fields (src_ip, flow_id, session_id)

### 1.2 IST Timestamp Implementation

All Rudras logs display timestamps in Indian Standard Time (IST, UTC+5:30). This was implemented in v4.0 by replacing the default `tracing-subscriber` UTC timer with a `ChronoLocal` timer.

Implementation in `src/main.rs`:
```rust
use tracing_subscriber::fmt::time::ChronoLocal;

let ist_timer = ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f%:z".to_string());

// Console layer (pretty-printed, IST)
let console_layer = tracing_subscriber::fmt::layer()
    .pretty()
    .with_timer(ist_timer.clone());

// File layer (JSON, IST)
let file_layer = tracing_subscriber::fmt::layer()
    .json()
    .with_timer(ist_timer.clone())
    .with_writer(file_appender);
```

The `%:z` format specifier in the time format produces the `+05:30` offset suffix, making the IST timezone explicit in every log entry.

**Cargo.toml dependency:**
```toml
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "fmt", "chrono"] }
chrono = { version = "0.4", features = ["clock"] }
```

### 1.3 Log File Location and Rotation

Logs are written to `logs/Rudras.log.YYYY-MM-DD`:
```
logs/
├── Rudras.log.2026-03-06   # archived
├── Rudras.log.2026-03-07   # archived
└── Rudras.log.2026-03-08   # current
```

Rotation uses `tracing-appender::rolling::RollingFileAppender` with `Rotation::DAILY`. The file is rotated at midnight IST. Old files are preserved (no automatic deletion — implement your own archival policy).

### 1.4 Log Level Configuration

```toml
[logging]
level = "info"  # trace | debug | info | warn | error

# Module-specific level overrides:
# RUST_LOG env var also works:
# RUST_LOG="rudras=info,rudras::ai_engine=debug,rudras::capture=warn"
```

Recommended levels by deployment:
- **Production:** `info` (captures all security events without flooding disk with trace data)
- **Troubleshooting:** `debug` (shows packet parsing decisions, useful when investigating false positives)
- **Performance profiling:** `trace` (extremely verbose, only for short-duration diagnostic sessions)

### 1.5 Key Log Events Reference

| `event` Value | Level | Description |
|--------------|-------|-------------|
| `startup_complete` | INFO | All modules initialized, capture loop active |
| `module_loaded` | INFO | Individual module initialization with key stats |
| `ids_alert` | WARN | IDS rule triggered |
| `ips_block` | WARN | IP blocked by IPS |
| `ips_reset` | INFO | TCP RST injected |
| `ai_anomaly` | WARN | Behavioral deviation above threshold |
| `ti_hit` | WARN | Threat intel blocklist match |
| `dns_blocked` | INFO | DNS query blocked |
| `zone_violation` | WARN | Micro-segmentation zone policy violation |
| `tamper_attempt` | CRIT | Anti-tamper trigger |
| `swarm_received` | INFO | Gossip intel received from peer node |
| `soar_playbook_triggered` | WARN | SOAR playbook started |
| `config_reload` | INFO | Hot configuration reload completed |
| `forensic_capture_started` | INFO | Forensic PCAP capture initiated |

---

## 2. Prometheus Metrics Server

**Source File:** `src/metrics.rs`  
**Protocol:** Prometheus text format (OpenMetrics compatible)  
**Endpoint:** `http://127.0.0.1:9091/metrics`  
**Authentication:** Ephemeral token via `X-Rudras-Auth` header

### 2.1 Architecture

The metrics server is a lightweight HTTP server embedded in Rudras (not an external agent). It runs on a dedicated Tokio thread, listening on `127.0.0.1:9091` (loopback only — not accessible from the network by default).

The metrics server exposes security counters in Prometheus text exposition format:
```
# HELP rudras_packets_total Total packets processed
# TYPE rudras_packets_total counter
rudras_packets_total{direction="inbound"} 45231
rudras_packets_total{direction="outbound"} 38847

# HELP rudras_ips_blocks_total IPS block actions
# TYPE rudras_ips_blocks_total counter
rudras_ips_blocks_total{reason="ti_match"} 12
rudras_ips_blocks_total{reason="ids_critical"} 8
rudras_ips_blocks_total{reason="ai_deviation"} 3
```

### 2.2 Complete Metrics Catalog

#### Traffic Counters
| Metric | Labels | Description |
|--------|--------|-------------|
| `rudras_packets_total` | `direction` | Total packets processed |
| `rudras_bytes_total` | `direction` | Total bytes processed |
| `rudras_flows_created_total` | — | New flow table entries created |
| `rudras_capture_drops_total` | — | Ring buffer overflow drops |

#### Security Counters
| Metric | Labels | Description |
|--------|--------|-------------|
| `rudras_ids_alerts_total` | `severity`, `category` | IDS rule trigger count |
| `rudras_ips_decisions_total` | `action` | IPS decision count by action type |
| `rudras_ips_blocks_total` | `reason` | IP block actions by trigger reason |
| `rudras_ips_resets_total` | — | TCP RST injections |
| `rudras_ti_hits_total` | `list` | TI blocklist hits by list name |
| `rudras_dns_blocks_total` | `category` | DNS blocks by category |
| `rudras_zone_violations_total` | `src_zone`, `dst_zone` | Zone policy violations |
| `rudras_tamper_alerts_total` | — | Anti-tamper trigger count |
| `rudras_waf_blocks_total` | `attack_type` | WAF blocks by attack category |

#### Gauge Metrics
| Metric | Description |
|--------|-------------|
| `rudras_active_flows` | Currently tracked flows (flow table size) |
| `rudras_blocked_ips` | Currently WFP-blocked unique IPs |
| `rudras_ai_high_deviation_ips` | IPs currently above `suspicious_threshold` |
| `rudras_swarm_peers_connected` | Active swarm peer connections |
| `rudras_ti_malicious_ips_loaded` | Size of loaded malicious IP blocklist |
| `rudras_ti_blocked_domains_loaded` | Size of loaded domain blocklist |

#### Histogram Metrics
| Metric | Labels | Description |
|--------|--------|-------------|
| `rudras_ai_deviation_score` | — | Distribution of AI deviation scores |
| `rudras_packet_size_bytes` | `protocol` | Packet size distribution |
| `rudras_ids_evaluation_duration_us` | — | IDS processing time per packet (microseconds) |
| `rudras_packet_processing_duration_us` | — | Total pipeline latency per packet |

### 2.3 Authentication

The metrics endpoint requires an `X-Rudras-Auth: <token>` header. Without a valid token, the server returns `401 Unauthorized`. This prevents unauthorized access to security telemetry.

**Token lifecycle:**
1. A new random token is generated at startup
2. Token is logged in the structured log at INFO level: `event=metrics_token_rotated, token="MAINT-..."`
3. Token is valid for `auth_token_validity_mins` (default 60 minutes)
4. After expiry, a new token is generated and logged
5. The old token returns 401 until re-fetched from logs

**Retrieving the current token:**
```powershell
# Current day log
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | 
  Select-String "metrics_token|auth_token" | 
  Select-Object -Last 1  # Most recent token is last in file
```

### 2.4 Prometheus Scrape Configuration

To scrape Rudras from Prometheus:
```yaml
scrape_configs:
  - job_name: rudras
    static_configs:
      - targets: ['127.0.0.1:9091']
    params:
      # Bearer token is not standard in Prometheus for custom headers
      # Use metrics_path to include token as query param instead
    bearer_token_file: /etc/prometheus/rudras_token.txt
    # Or: bearer_token: <token>
```

Since Rudras uses a custom `X-Rudras-Auth` header (not the standard `Authorization: Bearer` header), use a Prometheus `authorization` config block:
```yaml
authorization:
  credentials_file: /etc/prometheus/rudras_token.txt
```

### 2.5 Grafana Dashboard

A pre-built Grafana dashboard JSON for Rudras metrics is planned for v4.1. Until then, key panels to build manually:
- **Packet rate over time:** `rate(rudras_packets_total[5m])`
- **Block rate over time:** `rate(rudras_ips_blocks_total[5m])`  
- **Top blocked attack categories:** `topk(10, rudras_ids_alerts_total by (category))`
- **AI deviation heatmap:** `rudras_ai_deviation_score` histogram panel
- **Active blocked IPs:** `rudras_blocked_ips` single-stat
- **Flow table fullness:** `rudras_active_flows / rudras_flow_table_max` gauge

---

## 3. SOC Dashboard (Next.js)

**Location:** `Frontend/` directory  
**Technology:** Next.js 14, TypeScript, Tailwind CSS, Framer Motion, Lucide React  
**Port:** 3000 (development), configurable for production  
**Backend:** Consumes Rudras metrics API and log files

### 3.1 Architecture

The SOC Dashboard is a React/Next.js frontend that visualizes Rudras telemetry. It communicates with Rudras via:
1. **Metrics API:** Polls `http://127.0.0.1:9091/metrics` every 2 seconds for live counter data
2. **Log file tail:** Reads the current day's log file for live event streaming
3. **Management API:** POSTs to `http://127.0.0.1:9091/admin/*` for control actions

### 3.2 Dashboard Panels

#### Panel 1: Threat Feed (AttackFeed Component)
Live streaming list of security events:
- All `ids_alert`, `ips_block`, `ti_hit`, `zone_violation` events
- Sorted by timestamp (newest first)
- Color-coded by severity (red=critical, orange=high, yellow=medium, blue=low)
- Each event expandable for full JSON context
- Shows: timestamp (IST), source IP, destination, category, severity, MITRE technique

#### Panel 2: Packet Statistics (Real-time Charts)
- `packets_per_second` — line chart, 5-minute rolling window
- `blocks_per_second` — area chart
- `ids_alerts_per_minute` by category — stacked bar chart
- `active_flows` — gauge

#### Panel 3: AI Anomaly Visualization (AIPanel Component)
- Live ranked list of TOP 10 most suspicious IPs by AI deviation score
- Deviation score visualized as a horizontal bar (higher = more dangerous)
- Click to expand: shows full behavioral feature vector, baseline vs current comparison
- Historical anomaly score trend for each IP (sparkline)

#### Panel 4: Incident Timeline (IncidentTimeline Component)
- Chronological event log with IST timestamps
- Filterable by severity, category, source IP
- "Acknowledge" button to mark events as reviewed (logs analyst action to forensics chain)
- Clustered view: multiple events from same source IP grouped as an "incident"

#### Panel 5: Blocked IP Intelligence
- Currently blocked IP list with block reason, duration, and remaining TTL
- Geographic data enriched via GeoIP: country flag, ASN, organization name
- "Unblock" button for analyst-initiated false positive clearing (requirs confirmation)

#### Panel 6: System Health Monitor
- Module status: green/yellow/red for each of 17+ core modules
- CPU and memory usage of the Rudras process
- Capture ring buffer utilization (warn at 70%, critical at 90%)
- Flow table utilization
- Swarm peer connectivity status

### 3.3 Glassmorphism UI Design

The SOC Dashboard uses a futuristic dark-theme glassmorphism aesthetic appropriate for a security operations context:
- **Background:** `main.jpeg` (futuristic/dark) with `backdrop-filter: blur()` overlay
- **Panels:** Translucent glass cards with `backdrop-filter: blur(12px)`, neon cyan border (`#0ff` / cyan)
- **Animations:** Framer Motion for panel entry animations (fade + slide from bottom)
- **Scanline effect:** CSS pseudo-element scanline for "live feed" monitor aesthetic
- **Color palette:** Cyan neon (#0ff) for live data, red for critical alerts, amber for high, green for all-clear

### 3.4 Hydration-Safe Design

React Server-Side Rendering (SSR) creates HTML on the server that must match the client-side hydration output exactly. Any element that differs between server and client (such as a timestamp that was rendered server-side at T=0 but differs when client hydrates at T=+500ms) causes a hydration error.

Rudras's SOC dashboard was carefully designed to avoid hydration errors:
- All real-time data (timestamps, live metrics) is initialized to `null` on the server and only populated client-side via `useEffect(() => { ... }, [])` hooks
- Components rendering live data are wrapped in a `ClientOnly` wrapper that returns `null` on the server
- `suppressHydrationWarning={true}` is set on elements with intentional server/client differences

---

## 4. SIEM Integration (Observability Output)

**Source File:** `src/siem_integration.rs`  
**Purpose:** Real-time security event streaming to external SIEM/SOAR platforms

### 4.1 CEF Format Events

CEF (Common Event Format) is the industry standard for security event exchange:
```
CEF:0|Vendor|Product|Version|EventClassId|Name|Severity|Extensions
```

Rudras emits CEF events for all security events:
```
CEF:0|Rudras Security|Rudras Firewall|4.0|IDS:85|Ransomware SMB Pattern|10|
  src=192.168.1.100 dst=10.10.20.50 spt=49152 dpt=445
  proto=TCP
  cs1=T1486 cs1Label=MitreTechnique
  cs2=ransomware_smb cs2Label=AttackCategory  
  cn1=0.91 cn1Label=AIDeviationScore
  cn2=0.95 cn2Label=TIConfidence
  msg=SMB high-entropy write pattern consistent with ransomware encryption
  rt=2026-03-08T10:45:23.000+05:30
  dvchost=RUDRAS-NODE-01
```

### 4.2 Syslog Transport

By default, CEF events are sent via UDP syslog to the configured SIEM endpoint. For reliability, TCP syslog is supported (with exponential backoff retry on connection loss). TLS-encrypted syslog is also supported for environments with compliance requirements for encrypted log transport.

---

## 5. Forensics Chain (Audit Trail)

**Source File:** `src/forensics_chain.rs`  
**Purpose:** Tamper-evident cryptographic audit trail for all security decisions

### 5.1 Chain Structure

The forensics chain creates an append-only linked list of security events where each entry contains a hash of the previous entry:

```json
[
  {
    "seq": 1,
    "timestamp": "2026-03-08T10:34:21.200000+05:30",
    "event_type": "startup",
    "data": { "version": "4.0", "modules_loaded": 17 },
    "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "this_hash": "a3b5c7d9e1f3152739455b6d7f890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
  },
  {
    "seq": 2,
    "timestamp": "2026-03-08T10:45:23.124578+05:30",
    "event_type": "ips_block",
    "data": { "src_ip": "185.220.101.5", "dst_ip": "10.10.20.50", "reason": "ids_critical" },
    "prev_hash": "a3b5c7d9e1f3152739455b6d7f890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
    "this_hash": "7e6d5c4b3a2918f7e6d5c4b3a291807e6d5c4b3a29180706e5d4c3b2a1908"
  }
]
```

To verify the chain integrity: recompute `SHA3-256(seq + timestamp + event_type + data + prev_hash)` for each entry and verify it equals `this_hash`. If any entry in the middle is modified, all subsequent hashes become invalid — modification is immediately detectable.

### 5.2 Legal Significance

The forensics chain provides:
- **Non-repudiation:** Proof that a specific security action (block, alert) was taken at a specific time
- **Integrity:** Cryptographic proof that the log was not tampered with after the fact
- **Completeness:** Every security decision is recorded (no "silent drops")

This makes the forensics chain appropriate as evidence in legal proceedings and compliance audits.
