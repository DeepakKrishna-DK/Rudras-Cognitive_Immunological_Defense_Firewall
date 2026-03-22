# 3.5 Deployment and Usage Scenarios

This document provides concrete examples of how Rudras can be configured and deployed in real-world environments. Each scenario highlights the key modules enabled, essential configuration snippets, and the expected operational flow.

---

## Scenario 1: Internet-Facing API Gateway Protection

**Goal:** Protect a public-facing API gateway (e.g., serving a mobile application) against volumetric attacks, SQL injection attempts, and automated credential stuffing.

### Key Modules Enabled
- **Single-Pass DPI / WAF:** Inspects incoming HTTP/HTTPS payloads for malicious patterns.
- **Adaptive Load Shedding:** Automatically drops deep inspection for IPs conducting SYN/UDP floods, switching to fast O(1) hash drops.
- **Threat Intelligence (TI) Lookup:** Rapidly rejects traffic from known botnets and anonymizing proxies.
- **SOAR Engine:** Executes automated playbooks upon high-severity alerts.

### Configuration Snippet (`rudras.toml`)
```toml
[mode]
deployment = "server"

[dpi]
enabled = true
inspect_ports = [80, 443, 8080]

[adaptive_shedding]
syn_flood_threshold_pps = 100
udp_flood_threshold_pps = 1000
fallback_to_hash_drops = true

[soar]
enable_auto_blocking = true
block_duration_minutes = 60
```

### Operational Flow (SOC View)
1. **Attack Initiated:** A botnet begins a high-volume credential stuffing attack.
2. **Detection:** The IDS/WAF detects excessive failed login patterns and SQLi signatures. Adaptive load shedding may kick in if volume exceeds the PPS threshold, preserving CPU.
3. **Response:** The SOAR engine automatically blocks the offending source IPs for 60 minutes.
4. **SOC Dashboard:** Analysts see a sudden spike in `ips_block` metrics and WAF violation alerts. The event is automatically forwarded to the SIEM with CEF formatting.

---

## Scenario 2: Developer Endpoint Security (Client Mode)

**Goal:** Secure a developer's corporate laptop without overwhelming them with false positives from legitimate development activities (like running local servers or compiling code).

### Key Modules Enabled
- **Process Monitor:** Detects the use of unauthorized sniffing or memory tampering tools (e.g., unauthorized Wireshark, Mimikatz).
- **DNS Security:** Monitors and blocks queries to known command-and-control (C2) domains.
- **UEBA (User and Entity Behavior Analytics):** Establishes a baseline for the developer's normal network traffic and flags anomalous exfiltration.

### Configuration Snippet (`rudras.toml`)
```toml
[mode]
deployment = "client"

[process_monitor]
enabled = true
scan_interval_sec = 10
# Alert only; do not auto-kill developer tools unless explicitly blacklisted
kill_mode = false

[dns_security]
block_c2_domains = true
```

### Operational Flow (SOC View)
1. **Event:** The developer accidentally runs a compromised npm package containing a reverse shell payload.
2. **Detection:** The payload attempts to resolve a C2 domain. The DNS Security module immediately intercepts and drops the query. Alternatively, if it uses a hardcoded IP, the UEBA engine flags the sudden outbound connection to an unknown IP as a significant behavioral deviation.
3. **Response:** The connection is blocked, and an alert is generated.
4. **SOC Dashboard:** The dashboard highlights an `Endpoint Security Alert` for the specific machine, allowing the SOC team to isolate the device and investigate the package.

---

## Scenario 3: Insider Threat & Data Exfiltration 

**Goal:** Detect and mitigate a compromised internal account attempting to steal sensitive data from a secure database zone.

### Key Modules Enabled
- **Zero Trust Micro-Segmentation:** Enforces strict boundaries between the corporate zone and the database (DB) zone.
- **Data Loss Prevention (DLP):** Scans outbound traffic for sensitive data patterns (e.g., credit card numbers, SSNs).
- **GNN Topology Analysis:** Maps normal lateral movement and detects anomalous cross-zone connections.

### Configuration Snippet (`rudras.toml`)
```toml
[zero_trust]
zones = ["corporate", "db", "app", "guest"]
strict_enforcement = true

[dlp]
enabled = true
scan_outbound = true

[ml_engine]
ueba_deviation_threshold = 0.75
```

### Operational Flow (SOC View)
1. **Event:** A compromised corporate device attempts to directly access the database zone via SSH and bulk-download tables.
2. **Detection:** 
   - *Layer 1:* Micro-segmentation policy immediately flags direct Corporate-to-DB traffic as unauthorized if no explicit exception exists.
   - *Layer 2:* If authorized, the UEBA engine detects that this user has never downloaded 5GB of data at 2 AM.
   - *Layer 3:* The DLP engine detects patterns resembling PII in the outbound stream.
3. **Response:** Rudras resets the TCP connection mid-stream and triggers a critical SIEM alert.
4. **SOC Dashboard:** A multi-layered incident is displayed showing policy violation, behavioral anomaly, and DLP trigger. A full forensic SHA3-256 log is captured for regulatory compliance reporting.
