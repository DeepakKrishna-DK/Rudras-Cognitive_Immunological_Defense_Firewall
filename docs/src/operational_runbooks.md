# 3.4 Operational Runbooks

---

## Abstract

This document covers the operational tooling for running and maintaining Rudras v4.0: the three PowerShell scripts in `scripts/`, the data directory layout and management lifecycle, and operational runbooks for common maintenance scenarios. Anyone responsible for day-to-day operation (not just development) should read this document.

---

## 1. Scripts Directory

```
scripts/
├── fetch_geoip.ps1               # Download country CIDR blocks from global RIRs
├── generate_maintenance_token.ps1 # Create hardware-bound HMAC maintenance token
└── sign_config.ps1               # SHA-256 sign rudras.toml for anti-tamper
```

All scripts are PowerShell 5.1+ compatible and must be run from the project root directory (`C:\Users\dk-32\OneDrive\Desktop\Project_2\` or wherever Rudras is installed).

---

## 2. Script: `fetch_geoip.ps1`

### 2.1 Purpose

Downloads IPv4 CIDR blocks for specified countries from all five global Regional Internet Registry (RIR) delegation files. Writes one `.cidr` file per country to `data/geoip/`. Rudras loads these files at startup to enable GeoIP-based blocking.

### 2.2 Usage

```powershell
# Block China and Russia (most common use case)
.\scripts\fetch_geoip.ps1 -Countries CN,RU

# Block multiple high-risk countries with custom output directory
.\scripts\fetch_geoip.ps1 -Countries CN,RU,KP,IR,SY -OutputDir data\geoip

# Single country
.\scripts\fetch_geoip.ps1 -Countries KP
```

**Parameters:**

| Parameter    | Required | Default      | Description                                                 |
| ------------ | -------- | ------------ | ----------------------------------------------------------- |
| `-Countries` | Yes      | —            | Comma-separated ISO 3166-1 alpha-2 codes (e.g., CN, RU, US) |
| `-OutputDir` | No       | `data\geoip` | Directory to write `.cidr` files                            |

### 2.3 Data Sources

The script queries all five global RIRs in sequence. Each RIR maintains authoritative allocation records for its region:

| RIR      | Coverage                                  | URL               |
| -------- | ----------------------------------------- | ----------------- |
| RIPE NCC | Europe, Middle East, Central Asia, Russia | `ftp.ripe.net`    |
| APNIC    | Asia-Pacific                              | `ftp.apnic.net`   |
| ARIN     | North America                             | `ftp.arin.net`    |
| LACNIC   | Latin America and Caribbean               | `ftp.lacnic.net`  |
| AFRINIC  | Africa                                    | `ftp.afrinic.net` |

Each RIR publishes a `delegated-<rir>-extended-latest` file. Format (per line):

```
registry|cc|type|start|value|date|status|...
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated|...
```

The script parses each line, filters for `type=ipv4` and matching country code, converts `start + value` (count) to CIDR notation, and writes all CIDRs for each country to `data/geoip/<cc>.cidr`.

### 2.4 Output Format

`data/geoip/cn.cidr` example:

```
# Rudras GeoIP — CN — Generated 2026-03-08 10:30 UTC
1.0.1.0/24
1.0.2.0/23
1.0.8.0/21
1.0.32.0/19
...
```

### 2.5 CIDR Conversion Math

The RIR files specify allocations as a start IP and a count (number of addresses). The script converts this to CIDR:

```
CIDR prefix length = 32 - log2(count)
```

Examples:

- Start: `1.0.1.0`, Count: `256` → Prefix: `32 - log2(256) = 32 - 8 = 24` → `1.0.1.0/24`
- Start: `1.0.2.0`, Count: `512` → Prefix: `32 - 9 = 23` → `1.0.2.0/23`
- Start: `1.0.8.0`, Count: `2048` → Prefix: `32 - 11 = 21` → `1.0.8.0/21`

This only works correctly for power-of-2 block sizes (all legitimate RIR allocations). Non-power-of-2 counts indicate suballocations and may produce incorrect CIDR notation — these are rare and acceptable for this use case.

### 2.6 How Rudras Loads GeoIP Data

At startup, `Threat Intelligence Module` reads `data/geoip/*.cidr` and builds an in-memory prefix trie. For each packet, source IP is looked up in the trie in O(32) time (worst-case 32 trie levels for IPv4). If the source IP falls in a blocked country's CIDR range, it is treated as a threat signal (contributes to the comprehensive block score).

Note: GeoIP blocking is **not** a hard block by default — it contributes to the weighted scoring system. To configure hard blocking of specific countries, set in `rudras.toml`:

```toml
[geoip]
hard_block_countries = ["KP", "SY"]  # Always block these
score_countries = ["CN", "RU", "IR"] # These add to block score but don't hard-block
```

### 2.7 Update Schedule

RIR delegation files update daily. Recommended maintenance schedule:

- **Weekly:** Run `fetch_geoip.ps1` to refresh CIDR data, then restart Rudras (or hot-reload if supported)
- **Before major events:** Run immediately if threat intelligence indicates targeted activity from specific countries
- **After Rudras restart:** Data is loaded from disk at startup — no dynamic reload needed

---

## 3. Script: `generate_maintenance_token.ps1`

### 3.1 Purpose

Rudras contains anti-tamper logic that detects when security tools (debuggers, packet analysers) are attached to the process. When a legitimate administrator needs to run such tools (e.g., Wireshark during network audit, x64dbg for crash analysis), they must pre-authorise the session with a maintenance token. Without the token, Rudras will log a `tamper_attempt` event and may terminate itself or enter lockdown mode.

### 3.2 Usage

```powershell
# Default: 60-minute maintenance window
.\scripts\generate_maintenance_token.ps1

# Custom duration and purpose (logged for audit trail)
.\scripts\generate_maintenance_token.ps1 -DurationMinutes 30 -Purpose "Network forensics audit by Alice"

# 4-hour emergency maintenance
.\scripts\generate_maintenance_token.ps1 -DurationMinutes 240 -Purpose "Emergency crash investigation"
```

**Parameters:**

| Parameter          | Required | Default                 | Description                                   |
| ------------------ | -------- | ----------------------- | --------------------------------------------- |
| `-DurationMinutes` | No       | `60`                    | How long the maintenance window is valid      |
| `-Purpose`         | No       | `"Planned maintenance"` | Free-text reason (written into token, logged) |
| `-OutputFile`      | No       | `maintenance.token`     | Where to write the token file                 |

### 3.3 HMAC-SHA256 Token Mechanism

The token is cryptographically bound to the specific machine and session using a machine-derived HMAC key. This means a token generated on Machine A **cannot** be used on Machine B, and a token from before a reboot is invalid after reboot.

**Key derivation (PowerShell side):**

```powershell
$keyMaterial = "rudras-hmac-v4:${hostname}:${bootEpoch}:${username}"
```

Where:

- `hostname` = `[System.Net.Dns]::GetHostName()` — machine hostname
- `bootEpoch` = Unix timestamp of last system boot (from WMI `Win32_OperatingSystem.LastBootUpTime`)
- `username` = `[System.Environment]::UserName` — currently running user

**Payload:**

```
UPTIME_START=<system_uptime_secs>,NTP_START=<unix_epoch_now>,DURATION=<seconds>,PURPOSE=<string>
```

Base64-encoded, then HMAC-SHA256 signed with the derived key.

**Token file format** (`maintenance.token`):

```
# Rudras HMAC-signed maintenance token
# Generated: 2026-03-08 10:30:00 UTC
# Purpose:   Network forensics audit by Alice
# Machine:   RUDRAS-NODE-01 / alice
# Duration:  60 minutes (expires approx. 11:30)
# WARNING:   This file is hardware-bound and machine-specific.
#            It CANNOT be reused on another machine.
PAYLOAD:VVBUSU1FX1NUQVJUPTM2MDAsT...
SIGNATURE:a3b5c7d9e1f31...
```

**Rust-side validation** (in `Advanced Security Module` anti-tamper module):

1. Read `maintenance.token` from working directory
2. Re-derive the same HMAC key using current hostname + boot epoch + username
3. Recompute `HMAC-SHA256(PAYLOAD)` and compare with `SIGNATURE`
4. Parse `NTP_START + DURATION` to determine expiry: `NTP_START + DURATION > now()`
5. If valid and not expired → suppress tamper alerts for the duration

### 3.4 Security Properties

- **Hardware-bound:** Key includes boot epoch — a copy of the token file on another machine fails because that machine has a different hostname/boot time
- **Session-bound in spirit:** If the machine reboots during a maintenance window, the token becomes invalid (boot epoch changes) — a new token must be generated
- **Audit-logged:** The `Purpose` field is included in the token and written to Rudras's structured log when the token is loaded and when it expires
- **Time-limited:** No indefinite maintenance windows — operator must explicitly set a duration

### 3.5 Post-Maintenance Cleanup

Always delete the token file when maintenance is complete:

```powershell
Remove-Item maintenance.token
```

Rudras checks for the token file at each anti-tamper check interval. If the file is deleted, the next check will find no valid token and resume normal tamper detection. If the token expires without deletion, Rudras will also resume automatically.

---

## 4. Script: `sign_config.ps1`

### 4.1 Purpose

Rudras verifies the integrity of `config/rudras.toml` at startup and periodically during operation. If the config file has been modified since the last signing, Rudras logs a `config_tamper_detected` event.

After **any** edit to `rudras.toml`, this script must be run to update the signature. Failure to re-sign will cause Rudras to reject the modified config and fall back to the last valid signed config.

### 4.2 Usage

```powershell
# Sign the default config (run from project root after every config change)
.\scripts\sign_config.ps1

# Sign a custom config path
.\scripts\sign_config.ps1 -ConfigPath config\server.toml
```

**Parameters:**

| Parameter     | Required | Default              | Description                     |
| ------------- | -------- | -------------------- | ------------------------------- |
| `-ConfigPath` | No       | `config\rudras.toml` | Path to the config file to sign |

### 4.3 How It Works

1. Computes `SHA-256` hash of the config file contents using `Get-FileHash`
2. Writes `sha256:<hex_hash>` to `<ConfigPath>.sig` (e.g., `config/rudras.toml.sig`)

`config/rudras.toml.sig` example:

```
sha256:a3b5c7d9e1f3152739455b6d7f890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f
```

At startup and during periodic integrity checks, Rudras:

1. Reads `rudras.toml.sig`
2. Computes `SHA-256(rudras.toml)` in memory
3. Compares — if different → `config_tamper_detected` log + SIEM CEF event

### 4.4 Workflow: Changing Configuration

Always follow this sequence when changing the Rudras config:

```powershell
# 1. Stop Rudras (or it will detect the in-flight change)
Stop-Service Rudras   # or Ctrl+C if running in a terminal

# 2. Edit the config
notepad config\rudras.toml

# 3. Re-sign the config
.\scripts\sign_config.ps1

# 4. Verify the signature was created
Get-Content config\rudras.toml.sig

# 5. Restart Rudras
.\start-rudras.ps1
```

---

## 5. Data Directory Layout and Lifecycle

```
data/
├── geoip/              ← Country CIDR blocks (managed by fetch_geoip.ps1)
│   ├── cn.cidr         ← China IPv4 ranges
│   ├── ru.cidr         ← Russia IPv4 ranges
│   └── *.cidr          ← Any other countries you've fetched
├── immune/             ← CyberImmune system data (auto-managed by Rudras)
│   └── *.immune        ← Serialised immune memory (do not edit manually)
└── intel/              ← Threat intelligence feeds (managed manually or by CI)
    ├── global_iocs.json      ← IP-based IOC database
    └── malicious_domains.txt ← Domain blocklist
```

### 5.1 `data/intel/global_iocs.json` — IOC Database Schema

This file contains a JSON object where each key is an IP address and each value is an IOC record:

```json
{
  "[MALICIOUS_IP_CLASSIFIED]": {
    "ip": "[MALICIOUS_IP_CLASSIFIED]",
    "source": "Emerging Threats (compromised)",
    "category": "Botnet",
    "confidence": 0.88,
    "first_seen": 0,
    "last_seen": 0
  },
  "118.193.59.15": {
    "ip": "118.193.59.15",
    "source": "CINS Score (cinsscore.com)",
    "category": "Scanner",
    "confidence": 0.85,
    "first_seen": 0,
    "last_seen": 0
  }
}
```

**Field definitions:**

| Field        | Type   | Description                                                               |
| ------------ | ------ | ------------------------------------------------------------------------- |
| `ip`         | string | IPv4 address (redundant with key, but useful for array-format exports)    |
| `source`     | string | Intelligence feed that reported this IP                                   |
| `category`   | string | Threat category — `Scanner`, `Botnet`, `C2`, `Tor`, `Proxy`, `Ransomware` |
| `confidence` | float  | Confidence score 0.0–1.0 (used in Bloom filter threshold and block score) |
| `first_seen` | int64  | Unix timestamp of first observation (0 = unknown)                         |
| `last_seen`  | int64  | Unix timestamp of most recent confirmation (0 = unknown)                  |

**Current sources in the feed:**

- **CINS Score (`cinsscore.com`):** Community Internet Noise Score — IPs that generate anomalous internet background noise. Confidence: 0.85
- **Emerging Threats (`emergingthreats.net`):** Known compromised hosts. Confidence: 0.88

**Updating `global_iocs.json`:**

```powershell
# Download from Emerging Threats (example — integrate with your CI pipeline)
# The actual fetch depends on your TI API subscriptions
# After updating, restart Rudras or use hot-reload:
# curl -X POST http://127.0.0.1:9091/admin/reload-ti -H "X-Rudras-Auth: <token>"
```

### 5.2 `data/intel/malicious_domains.txt` — Domain Blocklist

Plain text, one domain per line:

```
# Malicious/phishing/malware domains
ads.example-malware.com
cdn.botnetc2.ru
update.ransomware-infra.net
...
```

Lines starting with `#` are comments. Empty lines are ignored.

This file contains 1.25M+ domains aggregated from:

- Pi-hole blocklists
- DNS threat feeds (Quad9, Cisco Umbrella community)
- Domain-based IOCs from MISP instances

Rudras loads this file into a Bloom filter at startup for O(1) lookup. False positive rate is tunable via `rudras.toml`:

```toml
[threat_intel]
domain_bloom_false_positive_rate = 0.001  # 0.1% false positive rate
```

**Updating the domain blocklist:**

```powershell
# After replacing malicious_domains.txt, hot-reload without restart:
$token = (Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') |
  Select-String "metrics_token" | Select-Object -Last 1).ToString()
# Extract token value and POST to reload endpoint
```

### 5.3 `data/immune/` — CyberImmune Memory

Managed entirely by Rudras — do not edit these files manually. They contain serialised state from `Cyber Immune Module`:

- `antigens.immune` — Known threat signatures (analogous to antibodies)
- `memory_cells.immune` — Long-term pattern memory for recurring threats
- `active_responses.immune` — Currently active immune responses

These files are written periodically by Rudras and read at startup to restore immune memory across restarts. If corrupt, delete the directory — Rudras will rebuild from scratch (with a short learning period before full effectiveness).

---

## 6. Operational Runbooks

### Runbook 1: Routine Weekly Maintenance

```powershell
Set-Location C:\Users\dk-32\OneDrive\Desktop\Project_2

# 1. Refresh GeoIP data
.\scripts\fetch_geoip.ps1 -Countries CN,RU,KP,IR

# 2. Verify logs for issues in the past week
Get-ChildItem logs\ | Sort-Object LastWriteTime | Select-Object -Last 7 |
  ForEach-Object {
    $critical = (Get-Content $_.FullName | Select-String '"level":"ERROR"').Count
    Write-Host "$($_.Name): $critical errors"
  }

# 3. Check blocked IP count
(Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') |
  Select-String "ips_block").Count
```

### Runbook 2: After Config Change

```powershell
# After editing rudras.toml:
.\scripts\sign_config.ps1
# Then restart Rudras
```

### Runbook 3: Emergency Maintenance (Debugger/Analyser Needed)

```powershell
# Generate 2-hour maintenance token before attaching any tool
.\scripts\generate_maintenance_token.ps1 -DurationMinutes 120 -Purpose "Emergency crash analysis - ticket #4521"

# Confirm token was written
Get-Content maintenance.token

# ... perform maintenance (Wireshark, x64dbg, etc.) ...

# When done, delete token to re-enable tamper detection immediately
Remove-Item maintenance.token
Write-Host "Maintenance complete. Tamper detection re-enabled."
```

### Runbook 4: Adding New Threat Intelligence

```powershell
# 1. Backup current IOC file
Copy-Item data\intel\global_iocs.json data\intel\global_iocs.json.bak

# 2. Merge new IOCs (using your TI pipeline tool)
# python merge_iocs.py --new new_iocs.json --existing data\intel\global_iocs.json

# 3. Validate JSON syntax before loading
Get-Content data\intel\global_iocs.json | ConvertFrom-Json |
  Measure-Object | Select-Object Count  # Should print total IOC count

# 4. Hot-reload TI without restart (requires running Rudras + auth token)
$token = "<token-from-logs>"
Invoke-WebRequest -Uri "http://127.0.0.1:9091/admin/reload-ti" `
  -Method POST `
  -Headers @{"X-Rudras-Auth" = $token}
```

### Runbook 5: Log Analysis for Incident Investigation

```powershell
# Find all critical IDS alerts in a date range
$logFiles = Get-ChildItem logs\Rudras.log.2026-03-* | Sort-Object Name
foreach ($f in $logFiles) {
  Get-Content $f.FullName |
    ConvertFrom-Json -ErrorAction SilentlyContinue |
    Where-Object { $_.level -eq "WARN" -and $_.ids_severity -eq "critical" } |
    Select-Object timestamp, src_ip, ids_category, mitre_technique
}

# Find all events from a specific suspect IP
$suspectIp = "[MALICIOUS_IP_CLASSIFIED]"
Get-Content logs\Rudras.log.$(Get-Date -Format 'yyyy-MM-dd') |
  Select-String $suspectIp |
  ForEach-Object { $_ | ConvertFrom-Json -ErrorAction SilentlyContinue } |
  Sort-Object timestamp
```

### Runbook 6: Verifying Data Integrity After System Change

```powershell
# Verify config signature is still valid (should always match after boot)
$configHash = (Get-FileHash config\rudras.toml -Algorithm SHA256).Hash.ToLower()
$storedSig = (Get-Content config\rudras.toml.sig).Replace("sha256:", "").Trim()
if ($configHash -eq $storedSig) {
    Write-Host "Config signature VALID" -ForegroundColor Green
} else {
    Write-Host "Config signature MISMATCH - re-sign required!" -ForegroundColor Red
    .\scripts\sign_config.ps1
}
```

---

## 7. File Ownership and Do-Not-Touch Rules

| Path                               | Owner                            | Safe to Edit?                         |
| ---------------------------------- | -------------------------------- | ------------------------------------- |
| `config/rudras.toml`               | Operator                         | Yes — always re-sign after editing    |
| `config/rudras.toml.sig`           | `sign_config.ps1`                | No — auto-generated                   |
| `data/intel/global_iocs.json`      | TI Pipeline / Operator           | Yes — validate JSON before hot-reload |
| `data/intel/malicious_domains.txt` | TI Pipeline / Operator           | Yes — one domain per line             |
| `data/geoip/*.cidr`                | `fetch_geoip.ps1`                | Only via script                       |
| `data/immune/*.immune`             | Rudras (auto)                    | No — binary format, managed by Rudras |
| `logs/Rudras.log.*`                | Rudras (auto)                    | Read-only — do not delete live log    |
| `maintenance.token`                | `generate_maintenance_token.ps1` | Delete when done                      |
| `Research_Notes/secrets/`          | Proprietary                      | No access                             |
