# Research Note 4: Usage and Maintenance Guide

## 1. Hot Config Modification
Firewall administrators no longer need to reboot or pause active inspection.
- **Location:** The `config/rudras.toml` file dynamically dictates state.
- **Usage:** To increase or decrease AI threshold strictness depending on localized IT events, modify the `[ai]` block.
- **Integration:** To plug Rudras into corporate logging, configure `[siem]` and pass in the correct Elasticsearch HTTP URL, Index, and Token.

## 2. Process Anti-Tamper Overrides (IT Tool Execution)
Under normal operations, the `Anti-Tamper` loop will violently kill unauthorized network inspection tools (like Wireshark) because they resemble malware C2 exfiltration behaviors.
- **Maintenance Tokens:** When IT genuinely requires 60 minutes for network troubleshooting, a mathematically rigorous `maintenance.token` must be forged physically inside the Rudras execution directory.
- **Components:** The token must define an explicit `UPTIME_START`, an `NTP_START` clock signature, and a specific `DURATION` limit to allow tools without leaving the firewall permanently paralyzed.

## 3. Logs and Diagnostic Outputs
Rudras implements a rolling log architecture using raw, highly-structured JSON.
- **Target Folder:** The `/logs/` directory contains daily-rolling instances (`Rudras.log.2026-X-X`).
- **SIEM Pipeline:** It outputs `security_event=true` structs which Splunk Universal Forwarders and ELK beats natively parse without needing slow Regex extraction blocks. 

## 4. Operational Dual-Modes
Always run the deployment wrapper: `start-rudras.ps1`.
- **Client Endpoints:** When protecting a CFO's laptop handling sensitive data, deploy with Mode: Client. Outbound malware-stagers triggering callback ports will be met with immediate local blocks.
- **Server Perimeters:** When securing a public Web Application or SQL server, deploy with Mode: Server. The intrusion prevention system scales up packet-dropping behaviors aggressively to throttle incoming volumetric attacks.
