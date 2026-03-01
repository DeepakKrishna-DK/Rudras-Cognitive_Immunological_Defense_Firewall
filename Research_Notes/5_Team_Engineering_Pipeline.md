# Research Note 5: Firewall Processing Pipeline & Team Guide

## 1. Introduction for Internal Engineering
This document details the exact sequence of events when a network packet hits the physical Network Interface Card (NIC) and how it flows through the Rudras backend. 
Unlike commercial firewalls that use monolithic `if/else` ladders, Rudras uses a segmented pipeline to preserve Rust's concurrency advantages (fearless parallel execution) and minimize CPU lock contention.

---

## 2. The Step-by-Step Packet Pipeline

### Step 1: NIC Interception (Layer 2 / Layer 3)
1.  **Hardware Ingress:** The packet arrives at the Wi-Fi/Ethernet port.
2.  **OS Kernel Intercept:** Before the Windows OS networking stack processes the packet, our driver (Npcap/WinDivert) intercepts it at the lowest possible software layer.
3.  **Rust Buffer Allocation:** The packet is copied into an immutable byte-slice `&[u8]`. The `capture.rs` loop decodes the raw Ethernet framing into parsed IPv4/IPv6 headers and TCP/UDP ports using the `pnet` crate.

### Step 2: The Fast-Path Drops (O(1) Checks)
Before performing any expensive Machine Learning math, we drop obvious garbage traffic immediately to save CPU cycles.
1.  **Anti-Evasion:** Check for invalid TCP states (e.g., SYN-FIN anomalous packets, NULL XMAS scans). Dropped instantly.
2.  **Bogon Filter:** Is the source IP from a spoofed loopback or multicast address that shouldn't be routable?
3.  **GeoIP Blacklist:** Is the `src_ip` originating from a sanctioned country blocklist loaded in memory?
4.  **Threat Intel Lookup:** Is the `src_ip` matching a known botnet C2 node cached from Feodo Tracker or URLhaus?

*Contextual Mode Divergence:*
*   **Server Mode:** The fast-path zeroes in on external inbound traffic, dynamically evaluating unrequested connections and instant-dropping anomalous port scans.
*   **Client Mode:** The fast-path specifically profiles outbound initialization. It prioritizes internal LAN MAC-mapping (L2 Security) to monitor for ARP spoofing within the corporate Wi-Fi.

*If the packet passes all Fast-Path checks, it advances to deep analysis.*

### Step 3: Deep Packet Inspection & WAF (Layer 7)
1.  **Payload Extraction:** If the packet contains a payload (e.g., HTTP POST data), it is evaluated by `comprehensive_blocker.rs`.
2.  **Signature Matching:** Fast Regex operations scan the raw bytes for known Exploit signatures (Log4j `${jndi:`, SQL Injection `UNION SELECT`, Remote Code Execution `cmd.exe`).
3.  **Data Loss Prevention (DLP):** For outbound packets, the payload is scanned for Cloud API Keys (AWS `AKIA...`) or unencrypted Credit Card structures to prevent insider exfiltration.

*Contextual Mode Divergence:*
*   **Server Mode:** Heavily weights `Signature Matching` against inbound payloads targeting published service ports (80 HTTP, 443 HTTPS).
*   **Client Mode:** Heavily weights `DLP Checking` on outbound traffic to prevent endpoint laptops from leaking Cloud API keys to external C2 domains.

### Step 4: The CyberImmune ML Engine (Behavioral Scoring)
Instead of looking at the packet content, this layer looks at the *metadata of the connection over time*.
1.  **Flow Analysis:** We calculate the connection's Exponential Moving Average (EMA). "Is this IP sending 100 packets a second, or 10,000?"
2.  **Baseline Application:** The `AiEngine` compares the current flow rate against the `Immutable State Anchor` created when that specific IP first connected today.
3.  **Threat Verdict generation:** 
    *   If deviation is minor: Update the behavioral profile and allow.
    *   If deviation crosses `susp_threshold` (e.g. 0.55): Engage rate-limiting API (Quality of Service throttling).
    *   If deviation crosses `block_threshold` (e.g. 0.80): Declare an active anomaly. 

### Step 5: Incident Escalation & Response
1.  **The Trigger:** An anomaly verdict is passed to `ips_engine.rs` (Intrusion Prevention System).
2.  **OS Enforcement:** The IPS Engine installs a dynamic Windows Filtering Platform (WFP) block rule directly into the kernel to sever the IP connection permanently at the OS level.
3.  **The Swarm Broadcast:** The local firewall node generates an `AntibodyPayload` containing the hostile IP signature and rule context. It transmits this payload to all other Rudras instances in the enterprise via the async P2P Gossip protocol (`distributed_immunity.rs`).
4.  **Logging Pipeline:** An asynchronous background thread formats the attack details into a flat JSON object and ships it to Splunk or Elasticsearch (`siem_integration.rs`).

---

## 3. Team Guidelines for Expanding the Engine

If you are a developer tasked with adding a completely new feature to Rudras, you must follow these architectural rules to prevent destabilization:

### Rule 1: Never Block the Capture Loop
The main loop in `capture.rs` processes thousands of packets a second. **You must never perform standard I/O (Disk Reads, API HTTP Calls, DNS lookups) directly on a per-packet basis.**
*   *Wrong:* Doing a web request to VirusTotal inside the packet handler. The firewall will lag and connection timeouts will occur globally.
*   *Right:* An asynchronous background task downloads the VirusTotal list every hour, saves it to an `Arc<RwLock<HashSet>>` in memory, and the packet loop performs an instant `O(1)` memory read against it.

### Rule 2: Respect the Mutex Cost (`RwLock`)
We use `RwLock` to share state between the packet analyzer and the AI engine. 
*   **Always use `read()` where possible.** Hundreds of packet threads can read simultaneously. 
*   **Only `write()` when absolutely necessary.** If you hold a `.write()` lock for too long, all other packet processing physically halts, causing an immediate DoS spike. Release locks as fast as humanly possible.

### Rule 3: Fail Open vs Fail Closed (The CIP Principle)
If your new module crashes or encounters a None/Err state, it must fallback gracefully based on the context.
*   If evaluating Critical Infrastructure (CIP Whitelisted IPs): **Fail Open (Allow)** to ensure hospital machines and power grids never accidentally offline themselves due to a bug in our code.
*   If evaluating an untrusted public external connection: **Fail Closed (Block/Drop)** to maintain strict Zero-Trust integrity.
