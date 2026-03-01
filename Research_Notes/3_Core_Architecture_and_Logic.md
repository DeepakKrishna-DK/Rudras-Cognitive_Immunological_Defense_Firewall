# Research Note 3: Core Architecture & Modularity

## 1. Zero-Trust Enforcement (Layer 0)
Rudras fundamentally views all incoming network traffic as inherently hostile until proven innocent. This starts at the Network Interface Card (NIC).
* **Network Driver Integration:** Rudras injects into the OS Driver stack (via Windows Filtering Platform / NDI / eBPF on Linux). 
* **The Pcap/Forensic Loop:** It streams copy-on-write packet byte-arrays to the memory-safe Rust parser, analyzing protocol states (TCP SYN vs ACK sequences).
* **The WFP Kernel Dropper:** Based on the AI verdicts or static policies, it instructs the OS Kernel to silently drop or reset connections instantly.

## 2. Artificial Intelligence Engine
The ML model trains a continuous, un-interrupted `BehaviourProfile` mapping for every unique active IP address. 
* It uses Exponential Moving Average (EMA) processing to smooth bursty data.
* **Continuous Learning Trust:** Addresses high-traffic developers (e.g. Jenkins build bots) by adapting its threshold dynamically to account for massive data streams, preventing False Positives on authorized internal servers.

## 3. Distributed P2P Swarm Intelligence
A single firewall provides strong local perimeter defense, but an enterprise has multiple branch locations. 
* **The Gossip Protocol:** If firewall Node-A detects a Zero-Day malware behavior, it instantly hashes the rule signature into an `AntibodyPayload`.
* **Asynchronous Networking:** This payload is broadcast (via Tokyo's async runtime) to all other firewalls in the corporation concurrently.
* Node-B, Node-C, etc., check the consensus (Quorum) before automatically installing the block-rule. They all become immune within milliseconds of Node-A being attacked.

## 4. The Policy Modulator
At its root, all modules connect through a central, concurrent `PolicyEngine` (locking mechanisms written with high-performance `parking_lot::RwLock`). 
* This provides a static block-list (e.g., Geo-IP location blocks of hostile nations), a white-list (e.g., Critical Infrastructure Protections, private internal loopbacks), and dynamic rules inserted by the SIEM integration or AI logic.
