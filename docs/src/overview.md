# 1.1 Start Here Overview

Welcome to Rudras v4.0. This overview provides a brief introduction to what Rudras is, its key benefits, and how it is typically deployed.

## What is Rudras?

Rudras is a unified Cognitive Immunological Defense System (CIDS) designed to proactively detect zero-day exploits, nation-state APTs, and insider threats safely at NIC line-rate speeds. Unlike traditional firewalls that rely on static signature matching, Rudras acts as an AI-native immune system for your network—building behavioral baselines to detect anomalous traffic patterns continuously.

## Key Differentiators

*   **Behavioral Deviation Detection:** Uses AI and continuously computes metrics. Detection happens without needing an explicit signature match when traffic diverges from its baseline.
*   **Anti-Tamper & Process Verification:** Operates with zero trust of the host OS, running parallel process monitoring. It checks access against device posture, patch age, and identity.
*   **Adaptive DPI Shedding:** Automatically mitigates DoS cryptographic bottlenecks by suspending deep packet inspection on flooded IPs and leveraging fast hash-table lookups, ensuring high availability.
*   **Micro-Segmentation Enforcement:** Native integration with zero-trust networking zones restricts lateral movement across application layers and environments.
*   **Research-Backed Security:** Over 40 natively integrated defense modules backed by academic computer science research.

## Architecture Pipeline

The packet lifecycle in Rudras follows a strictly controlled pipeline:
1.  **Network Capture (L2)**: Rapid PCAP/WFP ingress.
2.  **Fast-Path Drops**: Early elimination of malformed packets.
3.  **Threat Intelligence (TI) Lookup**: O(1) matching against IOC lists.
4.  **IDS Signature Match**: Snort/Suricata compatibility layer.
5.  **DPI / WAF**: App-layer decryption and protocol parsing.
6.  **AI Behavioral Score**: Real-time traffic deviation detection.
7.  **IPS Enforcement**: Real-time decision to Block, Throttle, Reset, or Alert.

## Typical Deployment Modes

*   **Client Mode (Endpoint)**: Focused on outbound monitoring—preventing C2 callbacks, stopping exotic data exfiltration, and enforcing local zero-trust process posture.
*   **Server Mode (Gateway)**: Focused on inbound monitoring—applying aggressive L7 WAF scanning, tracking port scans, and blocking brute-force application attacks.
