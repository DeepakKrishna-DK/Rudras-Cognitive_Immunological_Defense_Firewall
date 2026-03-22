# 2.4 Threat Intelligence Capabilities

---

## Abstract

Threat Intelligence (TI) is the curated knowledge of known malicious infrastructure — IP addresses, domains, file hashes, and URLs associated with threat actors. Rudras v4.0 operates the largest embedded TI corpus of any open-architecture firewall: 24,358 malicious IPs, 1,250,617 blocked domains, 84,501 malware signatures, and 617 explicitly tracked threat-actor domains. This document describes the TI subsystem architecture, data sources, blocking mechanics, and DNS-layer enforcement.

---

## 1. Threat Intelligence Engine

**Module:** `Threat Intelligence Module`  
**Dataset Sizes (v4.0):**

| Feed                          | Entries   | Update Frequency               |
| ----------------------------- | --------- | ------------------------------ |
| Malicious IP addresses        | 24,358    | On-load + configurable refresh |
| Known threat-actor domains    | 617       | On-load + configurable refresh |
| DNS blocklist (mass category) | 1,250,000 | On-load                        |
| Malware file hashes (SHA256)  | 84,501    | On-load                        |

### 1.1 Data File Locations

```
data/intel/global_iocs.json          # Malicious IP and domain IOCs
data/intel/malicious_domains.txt     # Known bad domain list
data/immune/                         # DNS block category lists
data/geoip/                          # GeoIP database for geographic enrichment
```

### 1.2 IOC Data Schema

The `global_iocs.json` file follows this schema per entry:

```json
{
  "ip": "[MALICIOUS_IP_CLASSIFIED]",
  "confidence": 0.95,
  "category": "tor_exit_node",
  "first_seen": "2025-06-15",
  "last_seen": "2026-03-01",
  "source": "OTX",
  "tags": ["tor", "exit_node", "anonymization"],
  "ttps": ["T1090.003"],
  "threat_actor": null,
  "asn": "AS204720",
  "country": "DE"
}
```

### 1.3 In-Memory Data Structures

After loading from files, TI data is stored in optimized in-memory structures:

```rust
// O(1) lookup for blocked IPs
blocked_ips: RwLock<HashSet<IpAddr>>

// O(1) lookup for blocked domains (exact match)
blocked_domains_exact: RwLock<HashSet<String>>

// Bloom filter for probable domain match (sub-1-microsecond pre-check)
domain_bloom: BloomFilter

// Full confidence and metadata (for enrichment only, not in hot path)
ioc_details: RwLock<HashMap<IpAddr, IocRecord>>

// Malware hash lookup (for DPI payload matching)
malware_hashes: RwLock<HashSet<[u8; 32]>>
```

The Bloom filter enables a two-tier domain lookup: first check the Bloom filter (O(1), zero false negatives for non-matching domains), then check the HashSet only for probable matches. This reduces memory bandwidth on the 1.25M domain list.

### 1.4 Confidence Score System

Each IOC has a confidence score (0.0–1.0):

| Score Range | Interpretation                              | Action            |
| ----------- | ------------------------------------------- | ----------------- |
| 0.90–1.00   | High confidence (multi-source confirmed)    | BLOCK immediately |
| 0.70–0.89   | Medium confidence (single reliable source)  | ALERT + monitor   |
| 0.50–0.69   | Low confidence (automated feed, unverified) | LOG only          |
| < 0.50      | Unconfirmed                                 | Ignore            |

Confidence scores are combined when the same IOC appears in multiple feeds:

```
combined_confidence = 1 - (1 - source1_confidence) × (1 - source2_confidence)
# e.g., 0.8 from OTX + 0.75 from VirusTotal = 1 - (0.2 × 0.25) = 0.95
```

### 1.5 Feed Refresh

When `restart` or a SIGHUP reload is received, the TI engine re-reads all files and updates the in-memory structures:

1. New `HashSet` built from fresh file data
2. Atomic swap: `blocked_ips.write()` replaced with new set in a single write lock acquisition
3. Old set dropped — Rust ownership ensures safe deallocation
4. Metrics updated with new counts

---

## 2. DNS Security Engine

**Module:** `Dns Security Module`  
**Role:** DNS-layer threat interception, the last line of defense before C2 connects

### 2.1 Why DNS Is Critical

90%+ of malware uses DNS as part of its operation:

- **C2 Beaconing:** Resolving the C2 server hostname before connecting
- **DNS Tunneling:** Encoding data in DNS query subdomains to exfiltrate data
- **Domain Generation Algorithm (DGA):** Generating thousands of random domains, one of which the attacker controls
- **Fast-flux DNS:** Rapidly rotating DNS A records to hide malicious infrastructure

Blocking at the DNS layer stops malware before it can establish its first connection. Even if the malware evades the IDS/WAF/AI — if it can't resolve its C2 server, it can't operate.

### 2.2 DNS Blocking Mechanisms

**Mechanism 1: Domain Blocklist Match**
DNS queries for domains in the blocklist receive an `NXDOMAIN` response injected by Rudras's DNS security engine. The malware receives "domain not found" and fails to connect.

**Mechanism 2: IP Response Substitution**
DNS queries that resolve to a known-malicious IP can optionally have the response modified to return a sinkhole IP (a controlled IP that logs all connection attempts from infected hosts). This enables detection of infected hosts without their malware connecting to the real C2.

**Mechanism 3: DGA Detection**
DGA domains follow patterns different from human-readable legitimate domains:

- Very high entropy (random character distributions)
- No meaningful substrings
- Short domain names with numbers + consonants only
- No history in domain registration databases

The DNS security engine applies an entropy classifier to query domains. Domains with entropy > 3.5 bits/character AND length < 12 characters are flagged as probable DGA and blocked.

**Mechanism 4: DNS Tunneling Detection**
DNS tunneling embeds data in subdomains:

```
YWxpY2U6cGFzc3dvcmQ=.evil-domain.com.   # base64-encoded data in subdomain
```

Detection indicators:

- Subdomain length > 50 characters
- Non-standard characters (=, /, +) in subdomain
- High Shannon entropy of subdomain component
- Unusually high query rate (tunneling generates many queries per minute)
- TXT record queries at high volume (exfiltration via TXT responses)

### 2.3 DNS Cache Poisoning Prevention

Rudras validates DNS responses against expected records:

- **DNSSEC validation:** If the domain has DNSSEC records, validate the signature chain
- **Response anomaly detection:** A DNS response claiming an unexpected IP for a well-known domain (e.g., `google.com` resolving to a private IP) generates a CRITICAL alert
- **Flood response filtering:** DNS amplification attack responses (large DNS responses to spoofed source IPs) are detected by the IDS module and rate-limited

### 2.4 Domain Category Blocklists

The 1,250,000-domain blocklist is organized into categories stored in `data/immune/`:

| Category           | Examples                  | Purpose                        |
| ------------------ | ------------------------- | ------------------------------ |
| Malware C2         | Known C2 infrastructure   | Block active malware           |
| Phishing           | Lookalike domains         | Block credential theft         |
| Tracking/Analytics | Third-party trackers      | Privacy protection             |
| P2P / Botnets      | Known P2P botnet domains  | Block distributed malware      |
| Ads / Adware       | Ad network domains        | Optional (disabled by default) |
| Adult Content      | Optional category         | Optional (disabled by default) |
| Cryptomining       | Mining pool domains       | Block resource theft           |
| Tor                | Tor onion services in DNS | Detect/block Tor usage         |

Categories can be individually enabled/disabled in `config/rudras.toml`.

---

## 3. Threat Hunt Engine

**Module:** `Threat Hunt Module`  
**Role:** Proactive, hypothesis-driven threat hunting  
**Paradigm:** Distinct from reactive detection — analyst-guided proactive search

### 3.1 What Is Threat Hunting?

Traditional IDS/IPS is **reactive**: it triggers when known attack patterns are present. Threat hunting is **proactive**: a security analyst forms a hypothesis ("I believe there may be an infected host performing slow, low-volume data exfiltration that evades rate-based detection") and then runs targeted queries against historical flow data to test the hypothesis.

The `Threat Hunt Module` module provides the data layer and query primitives for threat hunting operations.

### 3.2 Threat Hunting Queries

Available built-in hunt queries:

**Hunt 1: Beaconing Detection**
Identifies connections with mathematically regular intervals (classic C2 beacon signature):

```
HUNT: Find connections from src IP with median inter-connection time variance < 5s
      over a 30-minute observation window
→ Suspects: hosts with regular automated outbound connections
```

**Hunt 2: Low-and-Slow Port Scan**
Traditional IDS catches fast port scans. This hunt catches slow ones evading rate thresholds:

```
HUNT: Find IPs that connected to > 100 unique destination ports over the last 24h
      with < 5 connections/minute average rate
→ Suspects: patient attackers, automated reconnaissance avoiding threshold
```

**Hunt 3: Unusual Outbound Volume**

```
HUNT: Find hosts with outbound bytes > 10× their 7-day baseline
      for a sustained period > 10 minutes
→ Suspects: data exfiltration, backup exfil, compromised data store
```

**Hunt 4: Rare Process-Port Binding**

```
HUNT: Find network connections from processes that have never used
      that destination port in their historical baseline
→ Suspects: LOLBin abuse (certutil.exe making HTTPS connection), malware
```

**Hunt 5: Lateral Movement Over Time**

```
HUNT: Find IPs that connected to > 20 unique internal IPs over 6h
      where each connection touched at least one sensitive port (22,3389,445,1433)
→ Suspects: post-breach lateral movement, insider threat
```

### 3.3 Custom Hunt Queries

Analysts can define custom hunt queries in TOML format:

```toml
[[threat_hunt.custom_queries]]
name = "suspicious_rdp_outside_business_hours"
description = "RDP connections outside 9AM-7PM IST"
protocol = "tcp"
dst_port = 3389
time_window_hours = 24
condition = "hour_utc_offset < 3 OR hour_utc_offset > 14"  # 9AM-7PM IST = UTC 3:30-13:30
severity = "medium"
```

---

## 4. Threat Rules Engine

**Module:** `Threat Rules Engine Module`  
**Role:** Composite rule evaluation combining multiple detection signals

### 4.1 Composite Rules vs. Simple Rules

A simple IDS rule matches a single condition: `if SYN_rate > 100 then alert`.

A composite threat rule combines multiple conditions from multiple modules:

```
RULE: confirmed_c2_callback
  WHEN:
    - TI score > 0.7 for destination IP                    [from Threat Intelligence Module]
    - DNS query matched C2 domain pattern in last 60s      [from Dns Security Module]
    - AI deviation > 0.6 for source IP                     [from Ai Engine Module]
    - Connection is outbound on port 443 or 80             [from Flow Engine Module]
  THEN:
    - Severity: CRITICAL
    - Action: BLOCK + SOAR playbook "C2_ISOLATION"
    - MITRE technique: T1071.001
    - Alert: "High confidence C2 callback detected"
```

Composite rules dramatically reduce false positives because they require multiple independent signals to align simultaneously — the probability of all conditions being satisfied by benign traffic is extremely low.

### 4.2 Rule Priority and Ordering

Rules are evaluated in priority order (highest priority first). Once a CRITICAL or HIGH rule matches, evaluation stops for that packet (no need to compute lower-priority matches). ALLOW rules (whitelist rules) are evaluated first in the priority order to prevent expensive evaluation for known-good traffic.

### 4.3 Built-in Composite Rules

| Rule Name                    | Conditions                                                               | Severity |
| ---------------------------- | ------------------------------------------------------------------------ | -------- |
| `confirmed_c2_callback`      | TI match + DNS hit + AI deviation + outbound port 443/80                 | CRITICAL |
| `ransomware_smb_lateral`     | SMB session + high file rename rate + high entropy writes + internal src | CRITICAL |
| `credential_spray`           | Auth failure rate > N/min + multiple destination hosts                   | HIGH     |
| `dns_exfiltration_confirmed` | Long subdomain + high entropy + high DNS query rate from same host       | HIGH     |
| `supply_chain_compromise`    | SBOM mismatch + unexpected outbound connection + process anomaly         | HIGH     |
| `insider_data_theft`         | UEBA deviation > 0.8 + large outbound upload + unusual hours             | HIGH     |
| `apt_multi_stage`            | Port scan + exploit attempt + lateral movement within 30 min window      | CRITICAL |
