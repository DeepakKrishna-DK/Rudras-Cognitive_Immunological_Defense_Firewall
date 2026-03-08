# Research Note 9: Enterprise Security Modules

**Document Version:** 4.0  
**Last Updated:** March 8, 2026  
**Classification:** Internal Research — Engineering Reference

---

## Abstract

Enterprise security in Rudras v4.0 is implemented through 11 modules covering Zero Trust access control, identity-aware policy, network micro-segmentation, endpoint posture assessment, attacker attribution, SIEM integration, distributed immunity, gateway mode, SD-WAN, cloud-native protection, and single-pass performance optimization. Together these modules transform Rudras from a network firewall into a full Security Platform covering the full enterprise control surface.

---

## 1. Zero Trust Engine

**Source File:** `src/zero_trust.rs`  
**Principle:** "Never trust, always verify" — every connection requires continuous authentication and authorization

### 1.1 Core Concept

Traditional network security models assume that traffic inside the corporate perimeter is trusted. Zero Trust eliminates this assumption. Every connection — even between two internal servers in the same data center — must be explicitly authorized based on identity, device posture, and context.

Rudras implements Zero Trust at the network layer, evaluating every flow against a dynamic trust score.

### 1.2 Trust Score Composition

Each device/IP receives a composite trust score (0.0–1.0):

| Factor | Weight | Scoring |
|--------|--------|---------|
| **Device identity** | 0.30 | Valid certificate = 1.0; No certificate = 0.0 |
| **Device posture** | 0.25 | Patch age, AV status, known vulnerabilities |
| **Network context** | 0.20 | Expected zone, expected ports, expected behavior |
| **Behavioral baseline** | 0.15 | AI deviation score (inverted) |
| **Session history** | 0.10 | Prior anomalies in session history |

```
trust_score = Σ(factor_score × factor_weight)

If trust_score < min_trust_threshold (default 0.30) → DENY
If trust_score < medium_trust_threshold (default 0.55) → ALLOW with step-up auth required
If trust_score >= medium_trust_threshold → ALLOW
```

### 1.3 Device Posture Assessment

Device posture is evaluated based on:
- **OS patch age:** Devices with patches > 30 days old receive a 0.20 posture penalty
- **Known CVEs on device:** If endpoint security module detects unpatched critical CVEs, 0.30 penalty
- **AV/EDR status:** Endpoint with no active security software: 0.40 penalty
- **Disk encryption:** Unencrypted disk on a laptop accessing sensitive data: 0.15 penalty
- **Past incidents:** Device with prior high-severity incidents in last 30 days: 0.20 penalty

### 1.4 Continuous Verification

Zero Trust is not a one-time check at connection establishment. Rudras continuously re-evaluates trust scores:
- Every 60 seconds for active, high-volume flows
- Every packet for flows to high-sensitivity zones (finance, research, db)
- Immediately when any anomaly is detected for the source IP by any module

If the trust score drops below the threshold during an established session (e.g., the behavioral baseline suddenly spikes), the session is terminated and re-authenticated.

### 1.5 Policy Exceptions

Zero Trust policy supports explicit exceptions for infrastructure automation:
```toml
[[zero_trust.exceptions]]
src_cidr = "10.10.1.0/24"
dst_cidr = "10.10.30.0/24"
reason = "Kubernetes health probes"
expiry = "2026-12-31"
approved_by = "network-security-team"
# Exceptions require approval documentation and have mandatory expiry
```

---

## 2. Identity Policy Engine

**Source File:** `src/identity_policy.rs`  
**Role:** Identity-aware policy enforcement, beyond IP-based rules

### 2.1 Why Identity > IP

In cloud-native and remote-work environments, IP addresses are ephemeral. Users receive different IPs from VPN, cloud instances rotate IPs, and Kubernetes pods get new IPs on each restart. IP-based firewall rules become unmaintainable.

The identity policy engine binds network policy to **user and service identities** instead of IP addresses:
- JWT/OAuth2 tokens carry user identity in HTTP/HTTPS headers
- mTLS certificates identify service-to-service communication
- Kerberos tickets identify Windows domain users

### 2.2 Policy Structure

```toml
[[identity_policy.rules]]
identity = "user:john.smith@company.com"
allow_zones = ["corporate", "app"]
deny_zones = ["db", "finance", "research"]
max_bytes_per_day = 1073741824  # 1GB/day limit
require_mfa = false
time_restrictions = "09:00-18:00 IST"

[[identity_policy.rules]]
identity = "service:payment-processor"
allow_zones = ["app", "db"]
allow_dst_ports = [5432, 6379]  # Only PostgreSQL and Redis
require_mtls = true
```

### 2.3 Token Extraction

The identity policy engine extracts identity claims from:

| Source | Method | Fields Used |
|--------|--------|-------------|
| HTTP Authorization header | JWT decode (verify signature) | `sub` (subject), `groups`, `scope` |
| mTLS client certificate | X.509 CN/SAN extraction | Common Name, Subject Alt Name |
| Kerberos ticket | SPNEGO/Negotiate header decode | Service Principal Name |
| AWS/GCP/Azure IAM tokens | Instance metadata correlation | Role ARN, Service Account |

Tokens are verified against the configured identity provider (Keycloak, Okta, Azure AD, etc.)

---

## 3. Micro-Segmentation Engine

**Source File:** `src/micro_segmentation.rs`  
**Role:** Network segmentation at zone level, enforcing explicit inter-zone policy

### 3.1 Zone Design

Rudras v4.0 supports up to 16 named security zones. The default zone layout covers a typical enterprise:

| Zone | Default CIDR | Permitted Access From | Purpose |
|------|-------------|----------------------|---------|
| `dmz` | 10.10.10.0/24 | internet, corporate | Public-facing services |
| `app` | 10.10.20.0/24 | dmz, corporate | Application servers |
| `db` | 10.10.30.0/24 | app | Database servers |
| `finance` | 10.10.40.0/24 | corporate (restricted users) | Finance systems |
| `research` | 10.10.50.0/24 | corporate (approved users) | R&D systems |
| `corporate` | 10.10.60.0/24 | internet (VPN), management | Employee workstations |
| `guest` | 192.168.100.0/24 | internet only | Guest WiFi |
| `management` | 10.10.70.0/24 | management hosts only | Network devices, firewalls |

### 3.2 Policy Evaluation for Inter-Zone Traffic

Every packet crossing zone boundaries is evaluated:
```
1. Determine src zone from src IP CIDR lookup
2. Determine dst zone from dst IP CIDR lookup
3. Check if src_zone → dst_zone is in the allowed_destinations list
4. If not: DROP + generate ZONE_VIOLATION alert
5. If yes: continue to analysis pipeline
```

Zone violation is logged as a HIGH-severity event because cross-zone traffic that violates policy is a strong indicator of:
- Lateral movement (east-west traffic to unauthorized zone)
- Misconfigured application (worth investigating regardless)
- Compromised host attempting unauthorized access

### 3.3 Micro-Segmentation vs. VLAN

Traditional VLANs provide coarse network segmentation. Micro-segmentation provides:
- **Finer granularity:** Policy per-identity within a zone, not just per-zone
- **Dynamic policy:** Policy based on user identity, device posture, behavioral state — not just static VLAN membership
- **Software-defined:** No physical VLAN infrastructure required — enforced in software by Rudras

---

## 4. Endpoint Security Module

**Source File:** `src/endpoint_security.rs`  
**Role:** Host-based security assessment, vulnerability awareness, compliance

### 4.1 Posture Checks

The endpoint security module performs periodic posture assessments integrating with the Zero Trust trust score:

- **OS Version Check:** Detects Windows/Linux version and patch level via observed network behavior indicators and configuration data
- **Open Port Audit:** Cross-references expected service ports for this device role against actual observed open ports
- **Vulnerability Database Correlation:** If CVE-to-product mapping is configured, flags hosts running software with critical unpatched CVEs
- **Certificate Validity:** Verifies device certificates are not expired, not revoked, issued by trusted CA

### 4.2 Host Intrusion Indicators

Network-observable indicators of host compromise:
- **Anomalous process-port mapping:** `calc.exe` making HTTPS connections (LOLBin abuse)
- **Hash mismatch:** HTTP response serving a file whose SHA256 doesn't match SBOM manifest
- **Unexpected service listening:** New listening port appears on a known server (backdoor indicator)
- **Memory injection pattern:** Connecting process has DLL load indicators visible in process metadata

### 4.3 Integration with Process Monitor

The `endpoint_security.rs` module shares data with `process_monitor.rs`. The process monitor scans the Windows process table for suspicious processes; endpoint security maps those findings to network behavior context.

Example correlation:
```
process_monitor detects: "mimikatz.exe" running as PID 4892
endpoint_security correlates: PID 4892 has made 47 authentication attempts to
                               3 domain controllers in the last 2 minutes
Combined alert: "Credential dumping tool active + authentication spray detected — 
                likely pass-the-hash attack in progress"
Severity: CRITICAL
```

---

## 5. Attribution Scoring Engine

**Source File:** `src/attribution_scoring.rs`  
**Role:** Attacker attribution based on observed TTPs (Tactics, Techniques, Procedures)

### 5.1 What Is Attribution?

Attribution is the process of identifying *which threat actor group* is responsible for an attack, based on the specific techniques they use. Different APT groups have characteristic playbooks:
- **APT28 (Fancy Bear / Russia):** Spear phishing + OPSEC-conscious tooling
- **APT41 (China):** Supply chain attacks + financially motivated
- **Lazarus Group (North Korea):** Financial theft + SWIFT system targeting
- **Criminal groups (various):** Ransomware + extortion

### 5.2 TTP-Based Scoring

The attribution engine maintains a database of known TTP (MITRE ATT&CK technique) associations for major threat actor groups. When IDS/IPS detects multiple techniques from the same source in a short window, the attribution scorer computes a Bayesian posterior probability that the activity matches each known threat actor profile.

```
Observed TTPs from src IP 185.x.x.x in last 60 min:
  T1046 (Network Service Scanning)     → seen
  T1021.002 (SMB/Windows Admin Shares) → seen  
  T1071.001 (HTTP C2)                  → seen
  T1486 (Data Encrypted for Impact)    → seen

Attribution scores:
  APT28:           12% (these TTPs occasionally used)
  Ransomware gang: 87% (hallmark ransomware pre-encryption reconnaissance pattern)
  Unknown:         1%
  
Alert: "HIGH CONFIDENCE: Ransomware actor activity pattern. Isolate affected hosts 
        immediately. Activate incident response playbook IR-RANSOMWARE."
```

### 5.3 Attribution Limitations

Attribution is probabilistic, not definitive. The attribution score:
- **Should inform response urgency** (APT attribution → treat as sophisticated, persistent threat)
- **Should NOT be presented as ground truth** to law enforcement without corroborating evidence
- **False positives possible** when defenders share TTPs (e.g., red teams using the same public tools as APTs)

---

## 6. SIEM Integration Module

**Source File:** `src/siem_integration.rs`  
**Role:** Streams security events to external SIEM platforms

### 6.1 Supported Export Formats

| Format | Used By | Protocol |
|--------|---------|---------|
| **CEF (Common Event Format)** | ArcSight, LogRhythm | Syslog UDP/TCP |
| **LEEF (Log Event Extended Format)** | IBM QRadar | Syslog UDP/TCP |
| **JSON (Elastic Common Schema)** | Elasticsearch/Kibana (ELK), Splunk | HTTP webhook |
| **Splunk HEC** | Splunk Enterprise/Cloud | HTTPS POST |
| **Syslog RFC 5424** | Generic syslog aggregators | UDP/TCP port 514 |

### 6.2 Event Schema

Every security event exported to SIEM includes:

```
CEF format example:
CEF:0|Rudras Security|Rudras|4.0|IDS:1047|SQL Injection Attempt|7|
  src=192.168.1.100 dst=10.10.20.50 spt=49152 dpt=443
  cs1=T1190 cs1Label=MitreTechnique
  cs2=sql_injection cs2Label=AttackCategory
  cn1=0.87 cn1Label=AiDeviationScore
  msg=SQL UNION SELECT pattern in HTTP POST body
  rt=2026-03-08T10:45:23.000+05:30
```

### 6.3 Event Filtering and Rate Limiting

High-volume environments can generate thousands of SIEM events per minute. The SIEM integration module provides:
- **Severity filter:** Only export events >= configured minimum severity
- **Rate limiting:** Maximum events/second to the SIEM (configurable, default 100/sec)
- **Deduplication:** Identical events within a 30-second window are aggregated into a single event with an occurrence count
- **Category filter:** Selectively enable/disable export for specific IDS categories

---

## 7. Distributed Immunity (Swarm)

**Source File:** `src/distributed_immunity.rs`  
**Role:** Epidemiological threat intelligence sharing across a fleet of Rudras nodes

### 7.1 The Swarm Model

A fleet of Rudras nodes form a swarm where threat discoveries are immediately shared:

```
Node A detects new C2 IP → broadcasts gossip to peers B, C, D
Node B receives gossip → adds IP to local blocklist → re-broadcasts to peers A, C, D
Node C receives from both A and B → deduplicates → adds to blocklist → re-broadcasts
...all nodes protected within ~100ms of first detection
```

### 7.2 Gossip Protocol Specification

- **Transport:** UDP (best-effort, no acknowledgment required)
- **Port:** Configurable (default 9090)
- **Message Format:** JSON
- **Deduplication:** SHA256 of (ip + timestamp) used as message ID; duplicate message IDs ignored
- **TTL:** Each message carries a hop count. After 3 hops, message is not re-broadcast (prevents infinite loops)

### 7.3 Gossip Message Types

| Type | Payload | Action on Receipt |
|------|---------|------------------|
| `ThreatIntel` | malicious IP + confidence + TTPs | Add to local blocklist |
| `ThreatDomain` | malicious domain + category | Add to local DNS blocklist |
| `ModelUpdate` | Federated learning gradient delta | Update local ML model |
| `Antibody` | CyberImmune behavioral signature | Add to local threat signatures |
| `Revocation` | Previously reported IP now cleared | Remove from blocklist |

---

## 8. Gateway Mode

**Source File:** `src/gateway_mode.rs`  
**Role:** BGP-aware internet gateway security policy

### 8.1 Gateway Mode Features

When Rudras runs at an internet gateway/edge router:
- **BGP advertisement monitoring:** Alerts on unexpected route changes that could indicate BGP hijack
- **Geopolitical routing policy:** Optional blocklist for traffic from certain geographic regions (requires explicit configuration and legal review)
- **Transit traffic inspection:** Analyzes traffic passing through (not just to/from the gateway)
- **Ingress filtering:** BCP38 implementation — drops packets with spoofed source IPs that couldn't have originated from the claimed source network

### 8.2 BGP Security

BGP is not authenticated by default in most deployments. BGP route hijacking allows attackers to redirect internet traffic through their infrastructure. Rudras's BGP monitoring:
- Tracks expected BGP routes from each peer AS
- Alerts on new route advertisements for prefixes previously advertised by other ASes
- Integrates with RPKI (Resource Public Key Infrastructure) validation when available

---

## 9. SD-WAN Module

**Source File:** `src/sdwan.rs`  
**Role:** Integrates Rudras security enforcement with SD-WAN infrastructure

### 9.1 SD-WAN Security Policy Enforcement

In SD-WAN deployments, security policy must follow traffic regardless of which physical path it takes:
- Security policies are synchronized to all SD-WAN edge nodes in the fabric
- Traffic classification (business-critical vs. best-effort) is correlated with security risk scoring
- High-risk traffic (elevated threat score) is routed through full inspection path
- Low-risk trusted traffic (verified devices, established flows) can take faster low-inspection path

### 9.2 QoS and Security Correlation

The SD-WAN module correlates Quality of Service decisions with security state:
- If a flow triggers a MEDIUM IDS alert, its QoS priority is demoted (less bandwidth)
- If a flow is quarantined, it is rate-limited to 10% of normal bandwidth allocation
- This creates an automatic "security tax" on suspicious traffic without hard blocking

---

## 10. Cloud Native Security Module

**Source File:** `src/cloud_native.rs`  
**Role:** Security for Kubernetes, containers, and cloud infrastructure

### 10.1 Kubernetes API Protection

The Kubernetes API server is a high-value target — compromise provides full cluster control:
- **Authentication anomalies:** kubectl commands from unexpected source IPs
- **Privilege escalation indicators:** ClusterRoleBinding creation, privileged pod creation
- **Enumeration patterns:** Rapid GET requests across multiple namespace/resource combinations
- **Secrets exfiltration:** Unusual volume of Kubernetes Secret read operations

### 10.2 Container Escape Indicators

Network-observable container escape indicators:
- A process identified as a container workload making calls to `/proc/[host]` or host filesystem paths
- Docker socket access (`/var/run/docker.sock`) from within a container
- Unexpected connections from container to container runtime management API

### 10.3 Cloud Metadata SSRF

Cloud metadata services (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`) expose sensitive credentials. SSRF attacks trick cloud applications into querying these endpoints on behalf of an attacker.

Rudras detects:
- Any HTTP request containing `169.254.169.254` in the URL or headers
- Any DNS resolution attempt for `metadata.google.internal`
- Any outbound request to `metadata.azure.com/metadata/instance` from a non-application-tier host

---

## 11. Single Pass Engine

**Source File:** `src/single_pass.rs`  
**Role:** Performance optimization — eliminate redundant packet parsing

### 11.1 The Multi-Pass Problem

naïve packet inspection with multiple security modules each independently parsing the same packet bytes:
- `ids_engine.rs` parses IP+TCP headers
- `dpi.rs` parses IP+TCP+HTTP headers
- `ai_engine.rs` parses IP+TCP headers (for flow statistics)
- `dns_security.rs` parses IP+UDP+DNS headers

Each parse is a potential cache miss as the packet bytes may be evicted from CPU cache between parsers. For a firewall processing 50,000 packets/second, this represents meaningful CPU overhead.

### 11.2 Single-Pass Solution

`single_pass.rs` implements a **shared parse context** that traverses all protocol layers once and stores the results in a `ParsedPacket` struct shared across all modules:

```rust
pub struct ParsedPacket {
    // Ethernet layer
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    
    // IP layer
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub ttl: u8,
    
    // Transport layer
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: Option<TcpFlags>,
    pub payload_offset: usize,
    
    // Application layer (if identified)
    pub http_method: Option<HttpMethod>,
    pub http_url: Option<String>,
    pub dns_query: Option<String>,
    pub tls_sni: Option<String>,
    
    // Pre-computed analysis values
    pub payload_entropy: f32,
    pub payload_hash: [u8; 32],
}
```

All detection modules receive a reference to this struct rather than the raw bytes. The parsing cost is paid once; all modules benefit. Benchmark results show this reduces overall packet analysis CPU usage by ~22% at 50,000 packets/second workloads.
