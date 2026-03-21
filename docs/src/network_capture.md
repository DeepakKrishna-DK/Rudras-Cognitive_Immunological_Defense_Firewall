# 5.1 Network Capture and Enforcement

---

## Abstract

The network capture and enforcement stack is Rudras's interface with the OS kernel and physical network hardware. This stack must operate at line-rate speeds with sub-millisecond latency — it is the first and last place a packet touches before Rudras acts on it. This document covers the five modules that form this stack: `capture.rs` (packet ingestion), `wfp_engine.rs` (Windows kernel enforcement), `windivert_engine.rs` (userspace interception), `npcap_forensic.rs` (forensic evidence capture), and `l2_engine.rs` (Layer 2 security).

---

## 1. Packet Capture Module

**Source File:** `src/capture.rs`  
**Technology:** libpcap/Npcap  
**OS Layer:** Data-link layer (below IP)

### 1.1 Why Npcap/PCAP?

Rudras captures packets at the data-link layer using Npcap (Windows) or libpcap (Linux). This approach provides:

- **Promiscuous mode:** Captures ALL traffic on the segment, not just traffic addressed to this host. Essential for gateway/IDS deployments that must see others' traffic
- **Protocol independence:** Receives raw Ethernet frames — Rudras implements its own protocol parsing rather than relying on OS networking stack's limited parsed view
- **Copy-on-write safety:** Packet bytes are copied out of the ring buffer before the capture thread releases ownership — preventing race conditions between capture and analysis threads
- **Kernel bypass option:** On supported hardware, DPDK/XDP paths bypass the OS network stack entirely for maximum performance

### 1.2 Capture Modes

| Mode                    | Description                                                      | Use Case                                         |
| ----------------------- | ---------------------------------------------------------------- | ------------------------------------------------ |
| **Promiscuous**         | Captures all frames on the segment regardless of destination MAC | IDS/IPS in gateway/inline mode                   |
| **Non-promiscuous**     | Captures only frames addressed to this host                      | Endpoint/client mode (less resource usage)       |
| **Monitor (802.11)**    | Captures all 802.11 frames including management/control          | Wi-Fi security analysis (requires supported NIC) |
| **Offline (PCAP file)** | Reads from a pre-recorded .pcap file                             | Analysis of historical captures, testing         |

### 1.3 Capture Ring Buffer

Npcap uses a kernel ring buffer to hold captured packets before userspace retrieval:

- **Buffer size:** Configurable in `[capture] ring_buffer_mb` (default 64MB)
- **Overflow behavior:** If the ring buffer fills before packets are consumed (capture thread too slow), packets are dropped
- **Monitoring:** `rudras_capture_drops_total` Prometheus counter tracks ring buffer overflow events
- **Tuning:** Increase `ring_buffer_mb` for high-traffic environments; decrease `analysis_thread_workers` latency with more worker threads

### 1.4 BPF Pre-Filter

A Berkeley Packet Filter (BPF) program can be applied at the kernel level to pre-filter packets before they reach userspace. This reduces the CPU cost of processing packets that Rudras doesn't need to inspect (e.g., filtering out known-good internal monitoring traffic before userspace sees it):

```
BPF filter: "not (src net 10.10.70.0/24 and dst net 10.10.70.0/24)"
# Exclude management-to-management internal traffic from capture
```

BPF filtering happens in kernel space — filtered-out packets never cross the kernel/userspace boundary.

### 1.5 Interface Auto-Detection

When `interface = "auto"` in config, Rudras:

1. Enumerates all network interfaces via pcap API
2. Filters to those that are UP and have IP addresses
3. Excludes loopback (`127.0.0.1`) and virtual adapters (Hyper-V, VMware virtual NICs)
4. Selects the interface with the most traffic (highest byte rate) as the primary capture target
5. Logs the selected interface at startup: `"Auto-detected capture interface: Ethernet0 (10.0.2.15)"`

---

## 2. Windows Filtering Platform (WFP) Engine

**Source File:** `src/wfp_engine.rs`  
**OS Interface:** Windows Filtering Platform (kernel-mode callout driver interface)  
**Enforcement Latency:** < 100 μs (kernel-level, no userspace round-trip)

### 2.1 What Is WFP?

Windows Filtering Platform is the Microsoft Windows kernel framework for network packet filtering. It replaced the deprecated NDIS packet filter interface in Windows Vista. WFP allows:

- Registering callout filters that are invoked for matching packets at kernel context
- Injecting, modifying, blocking, or allowing packets from kernel context
- Zero-copy packet access (in kernel memory, no userspace copy required)

WFP is the same framework used by Windows Defender Firewall, Windows Filtering services, and commercial enterprise EDR products.

### 2.2 WFP Callout Registration

Rudras registers WFP callout filters at the following WFP layers:

| WFP Layer                            | Layer GUID                       | Purpose                            |
| ------------------------------------ | -------------------------------- | ---------------------------------- |
| `FWPM_LAYER_INBOUND_NETWORK_V4`      | Network layer IPv4 inbound       | Block inbound IP traffic           |
| `FWPM_LAYER_OUTBOUND_NETWORK_V4`     | Network layer IPv4 outbound      | Block outbound IP traffic          |
| `FWPM_LAYER_INBOUND_TRANSPORT_V4`    | Transport layer TCP/UDP inbound  | Port-level blocking                |
| `FWPM_LAYER_OUTBOUND_TRANSPORT_V4`   | Transport layer TCP/UDP outbound | Port-level blocking                |
| `FWPM_LAYER_ALE_AUTH_CONNECT_V4`     | ALE connect layer                | Block new outbound TCP connections |
| `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` | ALE accept layer                 | Block new inbound TCP connections  |

### 2.3 Adding a Block Rule

When the IPS engine decides to block an IP:

1. The IP is passed to `wfp_engine.add_block_rule(ip, duration)`
2. `wfp_engine.rs` calls `FwpmFilterAdd0()` via FFI to register a kernel-mode filter matching the IP
3. The filter action is `FWP_ACTION_BLOCK`
4. All subsequent packets from/to that IP are dropped at kernel context — they never reach userspace
5. The `blocked_rules` HashMap stores `(filter_id, expiry_instant)` for TTL management

### 2.4 Rule Persistence Across Restart

WFP rules can be flagged as `FWPM_SESSION_FLAG_DYNAMIC` (cleared at process exit) or persistent (survive process restart). Rudras uses:

- **Dynamic rules** for TTL-limited blocks (the rule disappears if Rudras crashes, preventing permanent lockouts from Rudras bugs)
- **Static rules** for permanent policy rules that should survive restart (configured in `[policy]` whitelist/blacklist)

This design means a crash of Rudras does not permanently block legitimate traffic — the kernel rules expire when the process exits. The tradeoff is that blocks must be re-established on restart (handled by loading `logs/blocked_ips.json` on startup).

### 2.5 The `unsafe` Block

All WFP operations require FFI calls into Windows kernel APIs. This is the primary `unsafe` block in Rudras:

```rust
// SAFETY: WFP session and filter handles are valid (verified above),
// FwpmFilterAdd0 is called with properly initialized structures.
unsafe {
    let result = FwpmFilterAdd0(
        self.engine_handle,
        &filter,
        std::ptr::null_mut(),
        &mut filter_id,
    );
    // ...
}
```

All unsafe FFI code is contained within `wfp_engine.rs` and `npcap_forensic.rs`. No other module has unsafe code.

---

## 3. WinDivert Engine

**Source File:** `src/windivert_engine.rs`  
**Technology:** WinDivert (third-party Windows userspace network diversion tool)  
**Capability:** Intercept, modify, or drop packets in userspace

### 3.1 WinDivert vs WFP

| Feature             | WFP                  | WinDivert                 |
| ------------------- | -------------------- | ------------------------- |
| Operating context   | Kernel mode          | Userspace                 |
| Performance         | Highest (kernel)     | Very high (userspace)     |
| Packet modification | Limited              | Full (intercept + resend) |
| TCP RST injection   | Via filter inject    | Direct send               |
| Complexity          | High (kernel driver) | Lower (userspace API)     |

WinDivert is used for operations that require packet modification (TCP RST injection) and raw send. WFP is used for pure block/allow decisions where kernel-mode performance is critical.

### 3.2 TCP RST Injection (Primary Use)

The primary use of WinDivert in Rudras is TCP RST injection for IPS connection termination:

```rust
// Craft RST packet for server-side connection
let rst_to_server = craft_tcp_rst(
    attacker_ip, attacker_port,    // pretend to be the attacker
    server_ip, server_port,        // sending to the server
    server_last_seen_ack,          // use correct sequence number
);

// Craft RST packet for client-side connection
let rst_to_client = craft_tcp_rst(
    server_ip, server_port,        // pretend to be the server
    attacker_ip, attacker_port,    // sending to the attacker
    attacker_last_seen_seq + 1,    // use correct sequence number
);

// Send both RSTs via WinDivert raw inject
windivert.send(&rst_to_server, &addr_server)?;
windivert.send(&rst_to_client, &addr_client)?;
```

### 3.3 Packet Modification

WinDivert can intercept a packet, modify its contents in memory, and reinject it. This is used for:

- **DNS response modification:** Intercepting DNS responses for blocked domains and replacing the A record with `127.0.0.1` (NXDomain sinkhole)
- **HTTP redirect injection:** For quarantined internal hosts, intercepting HTTP requests and injecting a redirect to a security notification page
- **MTD IP address rewriting:** Translating between real and virtual IP addresses for Moving Target Defense

---

## 4. Npcap Forensic Capture

**Source File:** `src/npcap_forensic.rs`  
**Purpose:** Forensic-quality packet capture for incident response and legal evidence

### 4.1 Forensic vs. Analysis Capture

While `capture.rs` captures packets for analysis (real-time processing), `npcap_forensic.rs` captures packet data for forensic storage:

- **Lossless:** Unlike analysis capture that may shed packets under load, forensic capture uses a larger buffer and a dedicated thread to ensure no evidence is lost during the capture window
- **Standard format:** Writes to PCAP-NG format (IEEE 802.15.4 compliant), readable by Wireshark, tcpdump, and forensic tools
- **Evidence integrity:** SHA256 hash of each PCAP file is recorded at the time of creation; SOAR playbook can trigger collection of this hash to the forensics chain
- **Timestamped:** Packets include nanosecond-resolution timestamps in the PCAP-NG file

### 4.2 Triggered Forensic Capture

Forensic capture is typically triggered by:

1. SOAR playbook action `collect_forensics` when a CRITICAL event occurs
2. Manual trigger via management API: `POST /admin/forensics/capture`
3. Continuious background capture (optional, configurable — creates large files)

The default mode is **triggered capture**: starts 60 seconds before the triggering event (ring buffer allows rewinding) and continues for configurable duration after.

### 4.3 Evidence Chain of Custody

For captured evidence to be admissible in legal proceedings, the chain of custody must be documented:

1. PCAP file is created with timestamp and triggering event reference
2. SHA256 hash of PCAP file is computed immediately
3. Hash is appended to the `forensics_chain.json` audit log (with the chain hash)
4. Analyst who reviewed the capture is logged (via management API authentication)
5. Any subsequent file copy/export operations are logged

This documentation trail satisfies requirements for digital forensic evidence in most jurisdictions.

---

## 5. Layer 2 Security Engine

**Source File:** `src/l2_engine.rs`  
**Protocol Coverage:** Ethernet, 802.1Q VLAN, ARP, 802.11 (WiFi)

### 5.1 Why L2 Security Matters

Network security often focuses on Layer 3 and above (IP, TCP, HTTP). But attacks at Layer 2 can completely undermine Layer 3 security:

- **ARP spoofing** tricks hosts into sending traffic to the attacker rather than the real gateway (classic man-in-the-middle setup)
- **VLAN hopping** allows an attacker in one VLAN to inject frames into another VLAN, bypassing the access control intended by VLAN segmentation
- **MAC flooding** overflows switch CAM tables, causing switches to flood frames to all ports (effectively converting a switched network to a hub where all traffic is broadcast)

### 5.2 ARP Spoofing Detection

ARP is used to map IP addresses to MAC addresses. ARP has no authentication — any host can send an ARP response claiming any IP maps to any MAC. This is by design (RFC 826), but enables trivial man-in-the-middle attacks.

Rudras maintains a binding table: `HashMap<IpAddr, MacAddr>`. The first ARP for a new IP establishes the binding. Any subsequent ARP for the same IP with a **different MAC** triggers an alert:

```
ARP SPOOFING DETECTED:
  IP: 10.10.20.1 (likely the gateway)
  Previously known MAC: 00:11:22:33:44:55
  New ARP claiming MAC: AA:BB:CC:DD:EE:FF
  Source of new ARP: 10.10.20.155

Action: Alert CRITICAL, log both MACs, maintain original binding,
        flag 10.10.20.155 as ARP poisoning source → immediate block
```

### 5.3 VLAN Enforcement

In VLANs, 802.1Q frames carry a VLAN tag. Rudras enforces VLAN policy:

- Each VLAN ID is mapped to a security zone (`vlan_to_zone` mapping in config)
- Double-tagged frames (802.1Q-in-802.1Q, used in VLAN hopping attacks) are detected and blocked
- Frames claiming VLAN membership inconsistent with their source port are dropped

### 5.4 MAC Address Analysis

Beyond ARP, L2 engine performs MAC address analysis:

- **OUI lookup:** First 3 bytes of MAC identify the vendor (Intel, Cisco, Apple, etc.)
- **Randomized MAC detection:** Modern clients randomize MAC by default for privacy. Sudden MAC changes for an established host can indicate an attacker attempting to bypass MAC-based access controls
- **Unicast vs. multicast/broadcast:** Unusual burst of broadcast frames can indicate ARP flooding attack

### 5.5 802.11 WiFi Frame Inspection

When running on a WiFi interface in monitor mode:

- **Deauthentication attack detection:** An 802.11 deauthentication frame flood (forcing clients to reconnect) is a classic Evil Twin attack setup. Rudras detects broadcast deauth frames at > 5/second as an attack
- **Probe request analysis:** Client probe requests reveal the SSIDs clients are looking for, useful for identifying rogue AP setups
- **Protected Management Frame (PMF) enforcement:** If the network supports PMF (802.11w) and a client connects without it, the reduced-security connection is flagged
