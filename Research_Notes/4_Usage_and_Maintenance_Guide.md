# Research Note 4: Usage and Maintenance Guide

**Document Version:** 4.0  
**Last Updated:** March 8, 2026  
**Classification:** Internal Research — Engineering Reference

---

## 1. Quick Start

### Prerequisites
- Windows 10/11 (64-bit) or Windows Server 2019/2022
- Npcap driver installed (https://npcap.com) — required for packet capture
- Administrator privileges (required for WFP driver registration)
- Rust toolchain 1.75+ (for building from source)

### Build and Run
```powershell
# Build release binary
cd C:\Users\dk-32\OneDrive\Desktop\Project_2
cargo build --release

# Run with PowerShell start script
.\start-rudras.ps1

# Or run directly
.\target\release\rudras.exe --config config\rudras.toml
```

### Verify System Active
After launch, Rudras logs all 17+ core defense systems as active:
```
2026-03-08T10:34:21.123456+05:30 INFO  rudras: Rudras v4.0 starting...
2026-03-08T10:34:21.200000+05:30 INFO  rudras::ids_engine: IDS Engine loaded: 85 rules across 71 categories
2026-03-08T10:34:21.250000+05:30 INFO  rudras::threat_intelligence: TI Engine: 24358 malicious IPs, 617 known bad domains, 84501 malware sigs
2026-03-08T10:34:21.300000+05:30 INFO  rudras::dns_security: DNS Security: 1250000 blocked domains loaded
2026-03-08T10:34:21.350000+05:30 INFO  rudras::metrics: Metrics server listening on 127.0.0.1:9091
```

---

## 2. Configuration Reference

### Primary Config: `config/rudras.toml`

The config file is organized in sections. Each section maps to a specific Rust module.

#### Core Settings
```toml
[core]
mode = "auto"          # auto | client | server
interface = "auto"     # NIC interface name, or "auto" to detect
log_level = "info"     # trace | debug | info | warn | error
log_path = "logs/"
timezone = "IST"       # Timestamps in Indian Standard Time (UTC+5:30)
```

#### AI Engine Settings
```toml
[ai]
enabled = true
ema_alpha = 0.3                  # EMA smoothing factor (0.0-1.0). Higher = more reactive.
suspicious_threshold = 0.55       # Flag for closer inspection
quarantine_threshold = 0.70       # Rate-limit and alert
block_threshold = 0.80            # Full WFP block + IPS RST
baseline_learning_period_secs = 300  # Learn for 5 min before enforcing
```

#### IDS/IPS Settings
```toml
[ids]
enabled = true
categories = ["all"]    # or list specific: ["port_scan", "dos_flood", "c2_beacon"]
alert_severity = "medium"  # minimum alert severity: low | medium | high | critical

[ips]
enabled = true
auto_block_severity = "high"    # auto-block when IDS triggers >= this severity
block_duration_secs = 3600      # IP block TTL (0 = permanent)
syn_flood_threshold = 100       # SYN packets/sec before SYN flood declared
udp_flood_threshold = 1000      # UDP packets/sec before UDP flood declared
icmp_flood_threshold = 500      # ICMP packets/sec before flood declared
```

#### Threat Intelligence
```toml
[threat_intel]
enabled = true
malicious_ip_db = "data/intel/global_iocs.json"
malicious_domain_db = "data/intel/malicious_domains.txt"
dns_blocklist = "data/immune/"
refresh_interval_secs = 3600    # Re-read feeds every hour
otx_api_key = ""                # AlienVault OTX API key (leave empty to skip)
virustotal_api_key = ""         # VirusTotal API key (leave empty to skip)
```

#### Zero Trust / Micro-Segmentation
```toml
[zero_trust]
enabled = true
default_trust_score = 0.5
min_trust_score = 0.3           # Below this = deny all
device_posture_check = true
max_patch_age_days = 30         # Devices older than 30 days patch get degraded score
mfa_required = false            # Require MFA for elevated trust score

[[zones]]
name = "dmz"
allowed_ips = ["10.10.10.0/24"]
allowed_destinations = ["app"]

[[zones]]
name = "app"
allowed_ips = ["10.10.20.0/24"]
allowed_destinations = ["db", "corporate"]
```

#### Metrics Server
```toml
[metrics]
enabled = true
bind_addr = "127.0.0.1:9091"
auth_token_validity_mins = 60   # Ephemeral token lifespan (auto-rotated)
```

#### SIEM Integration
```toml
[siem]
enabled = false
protocol = "syslog"             # syslog | http | splunk | elastic
endpoint = "192.168.1.100:514"
format = "cef"                  # cef | leef | json
tls = false
```

---

## 3. Operational Modes

### AUTO Mode (Default)
Rudras queries the local port listener table on startup. If it finds any publicly bound server ports (80, 443, 8080, 3306, 5432, 22, etc.), it enters Server Mode. If only client/ephemeral ports are found, it enters Client Mode. This is the recommended setting for most deployments.

### CLIENT Mode
- 60% inspection focus on **outbound** traffic
- DLP scanning active on all outbound HTTP/HTTPS/FTP
- Process monitor active for endpoint-specific threats
- Conservative thresholds to minimize developer workflow false positives
- DNS security active for C2 domain queries
- Typical deployment: developer workstations, analyst laptops

### SERVER Mode
- 80% inspection focus on **inbound** traffic
- Aggressive WAF scanning on all HTTP/HTTPS service ports
- Port scan detection with low sensitivity (1 port scan = alert)
- IPS auto-blocks at MEDIUM severity (not just HIGH like client mode)
- Typical deployment: web servers, API gateways, database hosts, CI/CD servers

---

## 4. Metrics Server and SOC Dashboard

### Accessing Metrics

The metrics server requires an ephemeral authentication token for security. The token is logged at startup and rotated hourly.

**Step 1:** Find the token in the log
```powershell
# Look for the auth token in today's log
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | Select-String "auth_token\|X-Rudras-Auth\|Metrics token"
```

**Step 2:** Query the metrics endpoint
```powershell
$token = "TOKEN_FROM_LOG"
Invoke-WebRequest -Uri "http://127.0.0.1:9091/metrics" -Headers @{"X-Rudras-Auth" = $token}
```

### Key Metrics Exposed

| Metric | Type | Description |
|--------|------|-------------|
| `rudras_packets_total` | Counter | Total packets processed since startup |
| `rudras_packets_blocked_total` | Counter | Total packets blocked |
| `rudras_packets_dropped_total` | Counter | Total packets fast-path dropped |
| `rudras_ids_alerts_total` | Counter | IDS rule triggers |
| `rudras_ips_decisions_total` | Counter | IPS response decisions |
| `rudras_ips_blocks_total` | Counter | IPS block actions |
| `rudras_ips_resets_total` | Counter | IPS TCP RST injections |
| `rudras_ai_anomaly_score` | Histogram | Distribution of AI deviation scores |
| `rudras_threat_intel_hits_total` | Counter | TI blocklist hits |
| `rudras_active_flows` | Gauge | Currently tracked flows |
| `rudras_blocked_ips` | Gauge | Current WFP-blocked unique IPs |

### SOC Dashboard (Next.js)

The SOC Dashboard provides a real-time visual interface for all Rudras metrics.

**Location:** `Frontend/` directory  
**Technology:** Next.js 14, TypeScript, Tailwind CSS, Framer Motion  
**Port:** 3000 (default)

**Starting the dashboard:**
```powershell
cd Frontend
npm run dev   # development
npm run build ; npm start  # production
```

**Dashboard Panels:**
- **Threat Feed:** Live stream of IDS alerts with severity, category, source IP, MITRE technique
- **Packet Statistics:** Real-time charts for packets/sec, blocks/sec, anomaly scores
- **AI Anomaly Panel:** Top N most suspicious IPs with deviation scores
- **Incident Timeline:** Chronological event log with IST timestamps
- **Blocked IP Map:** Geographic visualization of blocked IPs (GeoIP data)
- **System Health:** Module status, uptime, memory usage, CPU utilization

---

## 5. Hot Configuration Modification

Most Rudras configuration parameters can be updated **without restarting the process**:

```powershell
# Edit the config file
notepad config\rudras.toml

# Send hot-reload signal (Windows)
# Rudras watches the config file for changes via notify crate
# Or use the management API:
$token = "YOUR_TOKEN"
Invoke-WebRequest -Method POST -Uri "http://127.0.0.1:9091/admin/reload" `
    -Headers @{"X-Rudras-Auth" = $token}
```

**What can be hot-reloaded:**
- AI thresholds (`ema_alpha`, `block_threshold`, etc.)
- IPS flood thresholds (`syn_flood_threshold`, `udp_flood_threshold`)
- Threat Intel feed paths
- Zero Trust trust score thresholds
- Log level

**What requires restart:**
- Network interface binding (`interface = `)
- Metrics server bind address
- WFP filter registration (kernel-level changes)
- Mode change (auto/client/server)

---

## 6. Anti-Tamper Maintenance Tokens

### Overview
Rudras's process monitor will flag its own maintenance activities if not authenticated. Any process matching tamper-tool signatures must provide a maintenance token.

### Generating a Token
```powershell
.\scripts\generate_maintenance_token.ps1
# Output: MAINT-2026-03-08T10:30:00-HASH-ABCDEF1234567890
```

### Token Validation
The token is a SHA3-256 HMAC signed with the installation's private key (generated during first install). The process monitor validates the token before suspending tamper detection for the requested window (default: 1 hour).

### Use Cases
- Running Wireshark for legitimate traffic analysis
- Running IDA Pro for binary analysis of malware samples
- Running Metasploit in an authorized penetration test
- Performing OS patching that modifies network drivers

---

## 7. Log Analysis and Diagnostics

### Log Location
Logs are written to `logs/Rudras.log.YYYY-MM-DD` in JSON format with IST timestamps.

### Useful Log Queries
```powershell
# How many IPS blocks in the last 24h?
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | 
  Select-String '"event":"ips_block"' | Measure-Object | Select-Object Count

# Find all blocked IPs
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | 
  Select-String '"event":"ips_block"' | 
  ForEach-Object { ($_ | ConvertFrom-Json).src_ip } | Sort-Object -Unique

# Find all IDS alerts at HIGH or CRITICAL severity
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | 
  Select-String '"severity":"(high|critical)"' |
  ForEach-Object { $_ | ConvertFrom-Json } | 
  Select-Object timestamp, category, src_ip, description

# Check AI anomaly score distribution
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') | 
  Select-String '"event":"ai_anomaly"' |
  ForEach-Object { ($_ | ConvertFrom-Json).score } | 
  Measure-Object -Average -Maximum -Minimum
```

### Common Log Events Reference

| Event | Meaning | Action |
|-------|---------|--------|
| `ids_alert` | IDS rule triggered | Review `category`, `severity`, `mitre_technique` fields |
| `ips_block` | IP blocked by IPS | Note `src_ip`, check if false positive |
| `ips_reset` | TCP RST injected into connection | Normal for aggressive connections |
| `ai_anomaly` | Behavioral deviation detected | Review `score` — > 0.8 = serious |
| `ti_hit` | TI blocklist match | `confidence` field shows feed quality |
| `dns_blocked` | Malicious domain query blocked | `domain` field shows attempted query |
| `process_alert` | Suspicious process detected | Review `process_name`, `pid` fields |
| `tamper_attempt` | Anti-tamper triggered | Immediate security review required |
| `zone_violation` | Micro-seg zone policy violated | Review `src_zone`, `dst_zone` fields |
| `swarm_received` | Gossip intel from peer node | `peer_node` field shows source |

---

## 8. Backup and Recovery

### Configuration Backup
```powershell
# Sign and backup config
.\scripts\sign_config.ps1
# Creates config\rudras.toml.sig alongside config\rudras.toml
# Signature validates config integrity on next startup
```

### State Recovery
If Rudras crashes mid-session, on restart it:
1. Re-reads the config file (validates signature if `.sig` present)
2. Re-loads all TI feeds from files (IP blocklist, domain blocklist preserved)
3. Rebuilds the WFP block rules from last-known-blocked IPs saved to `logs/blocked_ips.json`
4. Re-establishes swarm connections to peer nodes
5. **Does NOT** restore the in-memory AI behavioral baselines (these rebuild from traffic observation within ~5 minutes of normal operation)

### Forensic Evidence Preservation
The SHA3-256 chained forensic audit log in `logs/forensics_chain.json` is append-only and contains a cryptographic proof of every security decision made. Do not delete this file. Back it up regularly for legal/compliance purposes.

---

## 9. Troubleshooting

### Problem: "Npcap not found" at startup
**Cause:** Npcap driver not installed, or installed without WinPcap compatibility mode  
**Fix:** Download Npcap installer, check "WinPcap API-compatible Mode" during install, reboot

### Problem: Metrics server returns 401 Unauthorized
**Cause:** Auth token expired (rotates every hour) or incorrect token used  
**Fix:** Look for fresh token in current day's log file: `Select-String "auth_token"`

### Problem: Very high CPU usage (> 50%) during DPI
**Cause:** High-volume traffic with DPI enabled  
**Fix:** Increase `single_pass_worker_threads` in `[core]` config, or enable hardware acceleration in `[hardware]`

### Problem: "Too many open files" error
**Cause:** Flow table growing unbounded on high-traffic server  
**Fix:** Reduce `flow_table_max_entries` in `[flow_engine]` config, or set `flow_ttl_secs = 60`

### Problem: False positive blocking legitimate traffic
**Cause:** AI threshold too aggressive or TI feed false positive  
**Fix:** 
1. Check if IP appears in TI feed: `rudras.exe --check-ip 8.8.8.8`
2. Temporarily whitelist: add to `[policy]` whitelist block in config
3. Increase `block_threshold` slightly (e.g., 0.80 → 0.85)
4. Report false positive to TI feed maintainer

### Problem: DNS queries slow after enabling DNS security
**Cause:** DNS inspection overhead  
**Fix:** Enable `dns_cache_size = 50000` in `[dns]` config to cache query results
