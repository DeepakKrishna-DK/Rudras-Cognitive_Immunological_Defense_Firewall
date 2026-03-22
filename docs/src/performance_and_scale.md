# 3.1 Performance and Scale

Rudras is designed for near-zero operational friction, built in Rust to eliminate garbage collection pauses, enforce memory safety at compile-time, and run multi-threaded async workloads at network speed.

The following benchmarks demonstrate Rudras’s structural capabilities and measured performance profiles.

---

## 1. Packets Per Second (PPS) Processing Latencies

The single-pass architecture of the Rudras DPI mitigates layer duplication. Unlike cascaded architectures, layers 2 through 7 are parsed concurrently. Under typical lab deployments running on an equivalent **8-core x86_64 system (e.g., AMD EPYC / Intel Xeon 3.0GHz)**, Rudras targets the following latency profiles:

| Pipeline Stage | Target Median Latency | Target P99 Latency | Notes |
| :--- | :--- | :--- | :--- |
| **Fast-Path Drops (L2/L3)** | < 0.1 µs | < 0.5 µs | O(1) hash drops of malformed/bogon packets |
| **Threat Intelligence (Bloom)** | < 1 µs | < 2 µs | Bloom filter execution against 1.25M+ domains |
| **Stateful Connection Track** | ~ 5 µs | ~ 12 µs | L4 state updates |
| **IDS Signature Match (Snort)**| ~ 15 µs | ~ 50 µs | Regex and Byte pattern parallel matrix evaluation |
| **DPI/L7 WAF Extraction** | < 100 µs | < 200 µs | Full payload normalization and OWASP CRS evaluation |
| **Full Stack Evaluation** | ~ 250 µs | < 800 µs | Total pipeline decision time before allow/block command |

> **Note:** These metrics represent theoretical constraints validated via the Tokio async runtime architecture and are subject to hardware variables, kernel context switches, and PCAP driver efficacy (e.g. WinDivert limits).

## 2. Hardware Resource Utilization

Rudras automatically tunes its thread pool based on the system's available cores. By default, it spawns isolated thread pools for network I/O, AI baseline crunching, and periodic management tasks.

### Memory Footprint

| Component | RAM Budget (Typical) | Scaling Dynamics |
| :--- | :--- | :--- |
| **Base Engine (Idle)** | 40-50 MB | Core Rust binaries and structures |
| **TI Bloom Filters** | ~15 MB | Holds >1.2M domain entries |
| **CyberImmune Models** | 80-150 MB | Dependent on the volume of active endpoints tracked |
| **TCP State Tables** | 100 MB per 10k flows | Dynamic, aging drops inactive states |
| **Total Peak Expected**| < 500 MB (Client) / ~2-4 GB (Server) | Configurable hard limits |

Rudras employs **adaptive capacity management**. When memory limits are reached, it initiates early LRU eviction of old state trackers and throttles non-essential SIEM reporting buffers prior to entering failure modes.

## 3. Adaptive Decryption & DPI Shedding

Handling modern volumetric attacks necessitates structural defenses against CPU starvation. 

### The DoS Cryptographic Bottleneck 

When attacked with 1,000,000 HTTPS packets per second, traditional firewalls exhaust resources on SSL decryption and DPI. If the packet count violates a pre-configured exponential moving average (`udp_flood_threshold_pps` or `syn_flood_threshold_pps`), Rudras implements an immediate protocol shed sequence for the offending IPs:

1. Modifies the handling path for the attack IPs.
2. Suspends active DPI on those flows, ceasing regex and ML anomaly parsing.
3. Downgrades the inspection to L3/L4 `allow/drop` fast-routing paths. 
4. Regains line-rate capability through inexpensive hash table checking.

This feature enables Rudras to survive volumetric assaults while successfully processing legitimate asynchronous connections in the background.

## 4. Hardware Offload Initiatives (v4.2 Roadmap)

Though Rudras achieves high gigabit throughput in userspace architectures via WinDivert and raw sockets, scaling into the Terabit landscape requires specialized networking hardware.

- **eBPF/XDP Kernel Bypass (Linux):** Offloading early-drop logic and connection counting to eBPF hooks inside the kernel network stack, avoiding expensive user-space context switches.
- **P4 Programmable Switches:** Rudras policy engines are natively capable of emitting P4 bytecodes that can be directly mapped to Tofino ASICs, ensuring 100% wire-speed micro-segmentation enforcement on physical data center switches.
