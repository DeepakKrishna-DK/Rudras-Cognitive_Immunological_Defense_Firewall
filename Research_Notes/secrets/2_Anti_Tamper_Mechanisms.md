# Secret Note 2: Anti-Tamper & Cockpit Lockout Defense
**WARNING: EXTREMELY HIGHLY CLASSIFIED. CONTAINS EMERGENCY BYPASS CODES.**

This document details the exact process control flow and the literal strings required to physically bypass the Zero-Trust execution enforcers if the firewall completely fails or turns rogue.

## 1. The Dual-Clock Drift Verification (VM Suspension Fix)
If a hacker compromises the local host OS, they will attempt to run `Wireshark` to see what Rudras isn't catching. Rudras kills `wireshark.exe`. 
The hacker will then forge a `maintenance.token` to give themselves administrative immunity. 
- **The Exploit:** Hackers usually pause/suspend the Virtual Machine (VM) to halt the OS Clock, drop the token in the folder, and resume. The firewall thinks it's a valid unexpired token.
- **The Fix:** We implemented `Dual-Clock Drift Verification`. The token requires `UPTIME_START` and `NTP_START`. When parsed, `duration_since` the hardware Uptime must exactly match the `duration_since` the wall-calendar NTP. If the VM is paused, Uptime stops but NTP calculates the lost time on resume automatically. 
- **Execution:** If `Drift > 60 seconds` — Token is instantly rejected as a forgery, and Wireshark is terminated via `SIGKILL`.

## 2. Hardware Break-Glass Override (The God Key)
If the KMS server goes down permanently, and the Dual-Clocks fail, the entire SOC team is locked out of their own firewall network. To prevent "Cockpit Lockout":
- **Execution:** Administrators must physically open a secured hypervisor console and create a file perfectly named: `emergency_override.key`
- **The Secret String:** The inside of the file must contain exactly:
  `BREAK-GLASS-RUDRAS-EMERGENCY-001`
- **Result:** The moment this file is scanned on the 3-second `ProcessMonitor` loop, it bypasses all time, AI, and quorum checks violently. It permits the execution of any IT/Sniffer tool absolutely. 
- **Risk:** This string must NEVER be disclosed to developers or external sources. If an attacker reads it, they command the Swarm.
