# 2.2 Intrusion and Malware Detection

---

## Abstract

This document provides a complete technical deep-dive into Rudras's signature-based and rule-based detection infrastructure. This covers four core modules: the Intrusion Detection System (IDS), the Intrusion Prevention System (IPS), the Deep Packet Inspector (DPI/WAF), and the Comprehensive Blocker — the aggregation layer that unifies all detection signals into enforceable decisions.

---

## 1. Intrusion Detection System (IDS Engine)

**Module:** `Ids Engine Module`  
**Category:** Real-time signature-based threat detection  
**Performance:** < 0.5 ms per packet (99th percentile)

### 1.1 Rule Set Statistics

| Statistic             | Value                              |
| --------------------- | ---------------------------------- |
| Total rules           | 85                                 |
| Rule categories       | 71                                 |
| Attack types covered  | 70+                                |
| Severity levels       | 4 (low / medium / high / critical) |
| MITRE ATT&CK mappings | Yes (all HIGH/CRITICAL rules)      |

### 1.2 Attack Category Taxonomy

The IDS covers 70+ attack types organized into 12 major families:

**Family 1: Reconnaissance**

- ICMP sweep (ping sweep across subnet)
- SYN scan (half-open TCP port enumeration)
- UDP port scan
- OS fingerprinting (TTL, window size, options analysis)
- Banner grabbing (excessive connection attempts without data)
- Network topology mapping (unusual SNMP/CDP queries)

**Family 2: Denial of Service (DoS/DDoS)**

- SYN flood (`syn_rate > threshold` in rolling window)
- UDP flood (volumetric UDP to narrow port range)
- ICMP flood (ping flood)
- HTTP flood (thousands of HTTP requests from single IP)
- Slowloris (slow connection open, low-bandwidth DoS)
- DNS amplification (open resolver abuse)
- NTP amplification (Monlist/MON_GETLIST abuse)
- Smurf attack (ICMP broadcast amplification)
- Fragmentation attack (IP fragmentation exhaustion)

**Family 3: Web Application Attacks (WAF)**

- SQL Injection (UNION SELECT, OR 1=1, stacked queries, blind inference timing)
- Cross-Site Scripting (script tag injection, event handler injection, DOM manipulation)
- Remote Code Execution (shell_exec, system(), eval(), deserialization)
- Path Traversal (../../etc/passwd, %2e%2e%2f variants)
- XML External Entity (XXE) injection (DOCTYPE declarations, external entity references)
- Server-Side Request Forgery (SSRF) (localhost/internal IP in user-supplied URLs)
- HTTP Request Smuggling (Content-Length / Transfer-Encoding conflict)
- Server-Side Template Injection ({{7*7}}, Jinja2/Twig/Velocity templates)
- LDAP Injection (directory traversal via LDAP filter manipulation)
- Command Injection (;ls, &&id, $(whoami) in HTTP parameters)

**Family 4: Protocol Exploitation**

- TCP session hijacking (sequence number prediction)
- IP fragmentation overlap (teardrop attack pattern)
- ARP cache poisoning (gratuitous ARP with conflicting MAC binding)
- BGP route hijack anomaly (unexpected route advertisement change)
- OSPF route injection
- VLAN hopping (double-tagging 802.1Q frames)

**Family 5: Lateral Movement**

- SMB enumeration (\$admin share mass access attempts)
- SMB brute force (NTLM challenge-response spray)
- RDP brute force (TCP 3389 mass connection attempts)
- SSH brute force (TCP 22 mass authentication failures)
- WMI remote execution (WMI via network, suspicious command patterns)
- PsExec-style execution (port 445 + IPC$ access pattern)
- Pass-the-hash indicators (NTLM authentication to multiple hosts in short window)

**Family 6: Command & Control (C2)**

- Beacon regularity pattern (HTTP/HTTPS at mathematically regular intervals)
- DNS beacon (regular TXT/A queries to dynamic domain patterns)
- ICMP tunneling (large ICMP payloads, non-standard ICMP types)
- HTTP/HTTPS long-polling to IOC domains
- IRC C2 (connect to port 6667 + NICK/JOIN commands)
- Tor exit node communication (IP matches Tor consensus list)
- Domain Generation Algorithm (DGA) query patterns (high-entropy domain strings)

**Family 7: Data Exfiltration**

- DNS tunneling (large DNS queries, base64-encoded subdomains, unusually high query rate)
- HTTPS to unusual destinations with large upload volume
- FTP/SFTP large upload to external IP
- Outbound encrypted traffic to known exfil infrastructure
- PII pattern detection in payload (credit card, SSN, passport number patterns)
- API key leakage (AWS/GCP/Azure credential patterns in HTTP payloads)

**Family 8: Credential Attack**

- Password spray (same password to many accounts in sequence)
- Kerberoasting indicators (large Kerberos TGS requests for many SPNs)
- LDAP credential exposure
- OAuth token theft patterns

**Family 9: Malware Activity**

- Ransomware SMB behavior (rapid file open/rename/close cycles)
- Payload download stager URLs (known malware CDN patterns)
- Packed executable indicators in HTTP responses
- Abnormal process-port relationships (unlikely process making outbound connections)

**Family 10: Encrypted Traffic Threats (ETA)**

- Malformed TLS certificate chains
- Self-signed certificates to suspicious IPs
- TLS version downgrade attempts (forced SSLv3 / TLS 1.0)
- JA3 fingerprint matching (malware-specific TLS client fingerprints)

**Family 11: Cloud & Container**

- Kubernetes API server enumeration (GET /api/v1/pods from unexpected source)
- AWS IMDS access from non-standard workload
- Container escape indicators (unusual host filesystem access patterns)
- Cloud metadata SSRF (169.254.169.254 access from external request context)

**Family 12: OT/ICS Threats**

- Modbus illegal function code
- DNP3 unsolicited response manipulation
- EtherNet/IP unauthorized read/write
- SCADA HMI port access from non-engineering workstation

### 1.3 Rule Processing Algorithm

Each rule is evaluated as a boolean expression over packet/flow metadata:

```
Rule: syn_flood_detection
  CONDITION: (proto == TCP) AND (flags == SYN) AND (syn_rate(src_ip, 10s) > 100)
  SEVERITY: critical
  ACTION: alert + ips_escalate
  MITRE: T1498.001 (Network Flood)
  CATEGORY: dos_flood
```

The rule engine iterates all enabled rules against the parsed packet. Rules that match produce an `IdsAlert` struct:

```rust
pub struct IdsAlert {
    pub rule_id: u32,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub mitre_technique: Option<String>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub timestamp: DateTime<Utc>,
    pub packet_hash: [u8; 32],
}
```

### 1.4 Performance Optimization

The IDS engine uses several optimizations to stay within the < 0.5 ms per-packet budget:

1. **Rule categorization by protocol:** Rules are pre-divided by protocol. Only TCP rules are evaluated for TCP packets. This reduces the average rule evaluation count by ~60%.

2. **Fast-fail on cheap conditions first:** Rules are evaluated in cheapest-first order. If the IP protocol check fails, the rest of the rule is skipped.

3. **Statistical tracking via lock-free ring buffers:** Rate-based conditions (e.g., `syn_rate > 100/10s`) use a per-IP `AtomicU64` ring buffer with a sliding-window counter, updated with `fetch_add` for zero-contention concurrent access.

4. **Bloom filter pre-check for signature rules:** String-based payload signatures (SQL injection patterns, etc.) are indexed in a Bloom filter for O(1) probable-match pre-check before the more expensive regex evaluation.

---

## 2. Intrusion Prevention System (IPS Engine)

**Module:** `Ips Engine Module`  
**Category:** Active response enforcement  
**Latency:** < 2 ms from detection to block (WFP kernel rule registered)

### 2.1 IPS Response Actions

The IPS engine implements three response modes:

| Action                | Mechanism                              | When Used                           |
| --------------------- | -------------------------------------- | ----------------------------------- |
| **TCP RST Injection** | WinDivert raw send RST to both ends    | TCP connections to be terminated    |
| **WFP Kernel Block**  | Register WFP callout filter for src IP | All traffic from a confirmed-bad IP |
| **Rate Limiting**     | Token bucket via atomic counter        | Suspicious but not confirmed bad    |

### 2.2 IPS Decision Matrix

```
IDS CRITICAL severity  → IMMEDIATE BLOCK (RST + WFP)
IDS HIGH severity      → QUARANTINE (rate limit + 30s observation, then block if repeats)
AI deviation > [BLOCK_LIMIT]    → IMMEDIATE BLOCK
AI deviation [QUARANTINE_RANGE] → QUARANTINE
TI confidence > [AUTO_BLOCK_LIMIT]   → IMMEDIATE BLOCK
TI confidence 0.70-0.90 → ALERT + monitor
SYN flood detected     → SYN cookie mode + rate limit
UDP flood detected     → Drop excess, alert
```

### 2.3 TCP RST Injection Mechanics

When a TCP connection must be terminated:

1. **Craft RST for server:** Source=attacker_IP:attacker_port, Dest=server_IP:server_port, Seq=last_seen_seq+1, RST flag set
2. **Craft RST for client:** Source=server_IP:server_port, Dest=attacker_IP:attacker_port, Seq=last_seen_ack, RST flag set
3. Both packets sent via WinDivert raw send into the network stack
4. Both endpoints receive RST and close connections immediately

This terminates the connection cleanly from both sides without leaving half-open sockets.

### 2.4 Block Duration and Expiry

WFP block rules have a configurable TTL (`block_duration_secs`, default 3600 = 1 hour). The IPS engine maintains a `BTreeMap<Instant, IpAddr>` of expiry times. A background task checks every 60 seconds and removes expired WFP rules.

IPs that trigger the same detection repeatedly before expiry have their block duration doubled (exponential backoff block extension, up to `max_block_duration_secs`).

### 2.5 Live Stats (From March 8, 2026 Run)

```
First 5 minutes of operation:
  ips_decisions_total: 202
  ips_blocks_total: 36
  ips_resets_total: 166
  Unique IPs blocked: 12
```

This demonstrates the IPS actively responding to real malicious traffic within seconds of startup.

---

## 3. Deep Packet Inspection (DPI Engine and WAF)

**Modules:** `Dpi Module`, `Single Pass Module`

### 3.1 What DPI Does

DPI examines the _payload content_ of packets, not just headers. This enables detecting attacks that are entirely contained within application-layer data, including:

- SQL injection strings in HTTP request bodies
- Malware download URLs in HTTP responses
- C2 command patterns in DNS TXT records
- Credential theft patterns in HTTPS form submissions (via TLS metadata)

### 3.2 Protocol Support

| Protocol          | Inspection Depth                            | Notes                             |
| ----------------- | ------------------------------------------- | --------------------------------- |
| HTTP/1.1          | Full URL, headers, body                     | WAF logic here                    |
| HTTP/2            | Header frames, DATA frames                  | Decompressed with hpack           |
| HTTPS/TLS 1.2-1.3 | SNI, cipher suite, cert CN                  | No decryption — ETA metadata only |
| QUIC/HTTP3        | Header inspection                           | Quic Inspector Module                 |
| DNS               | Query/response, domain, type                | DNS security here                 |
| SMTP              | MAIL FROM/TO, Subject, MIME                 | Email security here               |
| Modbus TCP        | Function code, register access              | OT security here                  |
| DNP3              | Function code, object group                 | OT security here                  |
| FTP               | Control channel commands, data channel size | Exfil detection                   |
| SSH               | Version string (pre-auth scanning)          | Banner analysis only              |

### 3.3 WAF Pattern Library

**SQL Injection Patterns:**

- `UNION SELECT` (case-insensitive, with whitespace variants)
- `OR '1'='1'` and OR/AND boolean arithmetic patterns
- `; DROP TABLE` stacked query indicator
- `EXECUTE` / `EXEC` / `xp_cmdshell` stored procedure abuse
- `WAITFOR DELAY`, `SLEEP()` time-based blind injection indicators
- Hex-encoded variations (`0x41 0x44 ...` SQL keyword obfuscation)

**XSS Patterns:**

- `<script>` injection (and obfuscated variants: `<scr\x00ipt>`, `<SCRIPT>`)
- JavaScript event handlers (`onerror=`, `onload=`, `onclick=`, `onfocus=`)
- `javascript:` URI scheme injection
- CSS expression injection (`expression(...)`)
- DOM manipulation via `document.cookie`, `localStorage`

**Command Injection Patterns:**

- Shell metacharacters in URL params: `;`, `&&`, `||`, `` ` ``, `$()`
- Known shell commands: `cat /etc/passwd`, `ls -la`, `id`, `whoami`, `uname -a`
- PowerShell indicators: `Invoke-Expression`, `IEX`, `DownloadString`, `EncodedCommand`

**Path Traversal Patterns:**

- `../`, `..%2F`, `..\`, `%252e%252e%252f` (double-encoded)
- Absolute path prefixes: `/etc/`, `/proc/`, `C:\Windows\`
- Null byte injection: `filename.php\x00.jpg`

### 3.4 Single-Pass Architecture

`Single Pass Module` implements a unified L2-through-L7 inspection that traverses packet bytes exactly once. Traditional multi-pass inspection would:

1. Pass 1: Parse L2 header
2. Pass 2: Parse L3 header
3. Pass 3: Parse L4 header
4. Pass 4: Parse application layer
5. Pass 5: WAF pattern match
6. Pass 6: DPI signature match

Single-pass combines all of these into a single byte-array traversal with position tracking:

```
byte[0..14]   → Ethernet header (L2)
byte[14..34]  → IP header (L3)
byte[34..54]  → TCP/UDP header (L4)
byte[54..]    → Application payload (L7)

Single iterator over byte[0..packet_len] with protocol state machine
```

This eliminates redundant memory accesses and dramatically improves cache efficiency.

---

## 4. Comprehensive Blocker

**Module:** `Comprehensive Blocker Module`  
**Purpose:** Aggregation layer that combines all detection module signals into a final enforcement decision

### 4.1 Signal Aggregation Model

The comprehensive blocker receives signals from 8+ detection subsystems:

```
Input signals:
  - ti_score:        0.0-1.0  (from Threat Intelligence Module)
  - ids_severity:    0-4      (from Ids Engine Module: 0=none, 1=low, 2=med, 3=high, 4=critical)
  - ai_deviation:    0.0-1.0  (from Ai Engine Module)
  - dns_blocked:     bool     (from Dns Security Module)
  - gnn_anomaly:     0.0-1.0  (from Gnn Engine Module, topology deviation)
  - ueba_score:      0.0-1.0  (from Ueba Engine Module, user behavior deviation)
  - process_alert:   bool     (from Process Monitor Module)
  - l2_anomaly:      bool     (from L2 Engine Module: ARP spoof, VLAN violation)
```

### 4.2 Weighted Scoring Formula

The final block score is computed as a weighted sum:

```
block_score = (ti_score × 0.30)
            + (ids_normalized × 0.25)
            + (ai_deviation × 0.20)
            + (dns_blocked × 0.10)
            + (gnn_anomaly × 0.08)
            + (ueba_score × 0.05)
            + (l2_anomaly × 0.02)

Where:
  ids_normalized = ids_severity / 4.0

Action:
  block_score >= [BLOCK_LIMIT] → BLOCK
  block_score >= 0.60 → QUARANTINE
  block_score >= 0.30 → ALERT
  block_score < 0.30  → ALLOW
```

Certain conditions override the score formula (hard blocks):

- `ti_score > [AUTO_BLOCK_LIMIT]` → BLOCK regardless of score
- `ids_severity == CRITICAL` → BLOCK regardless of score
- IP is in the explict whitelist → ALLOW regardless of score

### 4.3 False Positive Mitigation

The blocker implements several strategies to reduce false positives:

1. **Confirmation window for QUARANTINE:** An IP quarantined at block_score 0.60–0.79 is observed for 30 seconds. If no additional triggers arrive, it is promoted back to ALLOW.

2. **Pattern diversity requirement for BLOCK:** A BLOCK decision based only on `ai_deviation` (without IDS or TI confirmation) requires deviation > [AUTO_BLOCK_LIMIT] (not 0.80) to account for legitimate traffic spikes.

3. **Burst allowance for known internal ranges:** The corporate internal CIDR ranges receive a 0.15 score reduction to account for expected higher traffic volumes.

4. **Feedback loop:** An analyst reviewing a block in the SOC dashboard can mark it as false positive, which temporarily increases the block threshold for that IP for 24 hours while the AI engine recalibraates its baseline.

---

## 5. Framework Alignment Module

**Module:** `Framework Alignment Module`  
**Purpose:** Maps Rudras detections to industry compliance frameworks

### 5.1 Supported Frameworks

| Framework             | Coverage                                              |
| --------------------- | ----------------------------------------------------- |
| **MITRE ATT&CK v14**  | All HIGH/CRITICAL IDS rules tagged with technique IDs |
| **NIST SP 800-53**    | Controls mapped to each detection category            |
| **ISO 27001:2022**    | Annex A controls mapped                               |
| **CIS Controls v8**   | Critical security control mappings                    |
| **OWASP Top 10 2021** | WAF rules mapped to OWASP categories                  |
| **MITRE D3FEND**      | Defensive technique category mapping                  |

### 5.2 MITRE ATT&CK Technique Coverage

| Attack Family     | MITRE Techniques Covered                            |
| ----------------- | --------------------------------------------------- |
| Reconnaissance    | T1595, T1590, T1592, T1046                          |
| Initial Access    | T1190, T1133, T1078                                 |
| Execution         | T1203, T1059, T1569                                 |
| Persistence       | T1574, T1053                                        |
| Lateral Movement  | T1021.001 (RDP), T1021.002 (SMB), T1550 (Pass-hash) |
| Collection        | T1114, T1560                                        |
| Command & Control | T1071, T1095, T1572, T1568, T1008                   |
| Exfiltration      | T1048, T1567, T1041                                 |
| Impact            | T1498, T1499, T1486 (ransomware)                    |

### 5.3 Compliance Reporting

The `Framework Alignment Module` module generates compliance event records that can be consumed by the `Compliance Engine Module` module (see Research Note 10: Research-Grade Modules) to produce automated GDPR/HIPAA/PCI-DSS compliance reports.

Every IDS alert is tagged with:

- `mitre_technique_id`: e.g., "T1190"
- `nist_control`: e.g., "SI-3"
- `iso_control`: e.g., "A.12.6.1"
- `cis_control`: e.g., "7.7"
