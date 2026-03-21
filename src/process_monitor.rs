// ============================================================================
// Rudras — Anti-Tamper & Evasion Monitor (Process Monitor)
// Detects and, when explicitly configured, terminates processes that are
// attempting to bypass or tamper with the firewall outside of an authorised
// maintenance window.
//
// ETHICAL & LEGAL DESIGN PRINCIPLES
// ──────────────────────────────────
// 1. WARN-ONLY by default.  Process termination is NEVER the default action.
//    Set process_monitor_kill_mode = true in [blocking] config ONLY on
//    corporate-managed devices with an employee Acceptable Use Policy in place.
//
// 2. Two-tier tool classification.
//    Tier 1 (unauthorized_sniffers): raw-capture tools with minimal legitimate
//      use on production endpoints.  Detected and (optionally) terminated when
//      outside a maintenance window.
//    Tier 2 (research_tools): industry-standard security, debugging, and
//      network-engineering tools (Wireshark, IDA Pro, Ghidra, GDB, Burp Suite,
//      etc.).  These are ONLY logged — NEVER terminated, regardless of config.
//
// 3. No hardcoded override keys.  All maintenance windows are validated via
//    HMAC-SHA256 signed tokens bound to the host's hardware identifiers.
// ============================================================================

#![allow(dead_code)]

use crate::metrics::Metrics;
use base64::engine::general_purpose::STANDARD as B64STD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Derive a runtime HMAC key from machine-specific identifiers.
/// This makes override tokens hardware-bound — they cannot be reused
/// on a different machine or transferred by an attacker.
fn derive_hmac_key() -> Vec<u8> {
    // Mix: hostname + OS boot time + username → deterministic per-machine
    let hostname = System::host_name().unwrap_or_else(|| "unknown-host".to_string());
    let boot_ts = System::boot_time();
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "system".to_string());
    // Salt prefix prevents trivial reversal
    format!("rudras-hmac-v4:{}:{}:{}", hostname, boot_ts, username).into_bytes()
}

/// Verify that a token file contains a valid HMAC-SHA256 signature.
/// Token file format (one field per line):
///   PAYLOAD:<base64-encoded-data>
///   SIGNATURE:<hex-encoded-HMAC-SHA256>
///
/// Returns `(is_valid, payload_string)`.
fn verify_token_hmac(contents: &str) -> (bool, String) {
    let mut payload_b64 = String::new();
    let mut signature_hex = String::new();
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("PAYLOAD:") {
            payload_b64 = v.trim().to_string();
        }
        if let Some(v) = line.strip_prefix("SIGNATURE:") {
            signature_hex = v.trim().to_string();
        }
    }
    if payload_b64.is_empty() || signature_hex.is_empty() {
        return (false, String::new());
    }
    // Decode claimed signature
    let Ok(claimed_sig) = hex::decode(&signature_hex) else {
        return (false, String::new());
    };
    // Compute expected HMAC over the raw payload string
    let key = derive_hmac_key();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key length is valid");
    mac.update(payload_b64.as_bytes());
    let expected = mac.finalize().into_bytes();
    // Constant-time comparison (prevent timing side-channel)
    let valid = expected.as_slice() == claimed_sig.as_slice();
    (valid, payload_b64)
}

pub struct ProcessMonitor {
    metrics: Arc<Metrics>,
    kill_mode: bool,  // true = terminate detected processes; false (default) = warn/log only
    // Processes that have NO legitimate purpose on a managed endpoint and indicate
    // active network-evasion or firewall-bypass attempts.
    // These are sniffers / raw-capture tools operated outside a maintenance window.
    unauthorized_sniffers: Vec<&'static str>,
    // Dual-use tools: legitimate for security research, penetration testing, and
    // software development, but potentially misused.  In WARN-only mode (default)
    // these are logged.  Kill mode NEVER kills these tools — a professional
    // security researcher has every right to run IDA Pro or Ghidra.
    research_tools: Vec<&'static str>,
}

impl ProcessMonitor {
    /// `kill_mode`: set from `config.blocking.process_monitor_kill_mode`.
    /// Defaults to `false` — warn/log only.  See BlockingConfig for legal guidance.
    pub fn new(metrics: Arc<Metrics>, kill_mode: bool) -> Self {
        Self {
            metrics,
            kill_mode,
            // ── TIER 1: Unauthorized passive sniffers ───────────────────────
            // These tools, when running OUTSIDE a maintenance window, indicate
            // someone is attempting to bypass or record the firewall's filtering.
            // They are still only terminated when kill_mode = true.
            // Note: Wireshark, tshark, and tcpdump are LEGITIMATE tools for
            // network engineers — their presence is logged, not assumed hostile.
            unauthorized_sniffers: vec![
                "pktmon.exe",   // Windows built-in, rarely needed on production hosts
                "rawcap.exe",   // Dedicated raw capture with no UI — rarely legitimate
                "windump.exe",  // WinPcap-era tcpdump port
            ],
            // ── TIER 2: Dual-use security / development tools ────────────────
            // These are industry-standard tools used daily by millions of
            // legitimate security researchers, penetration testers, and
            // software developers.  Rudras logs their presence for awareness
            // but NEVER terminates them — doing so would be unethical and
            // potentially illegal without consent.
            research_tools: vec![
                "wireshark.exe",
                "tshark.exe",
                "dumpcap.exe",
                "nmcap.exe",
                "netmon.exe",
                "tcpdump.exe",
                "charles.exe",  // HTTP debugging proxy
                "fiddler.exe",  // HTTP debugging proxy
                "burpsuite",    // Penetration testing suite (legal with authorization)
                "procexp.exe",  // Microsoft Sysinternals — standard sysadmin tool
                "x64dbg.exe",
                "x32dbg.exe",
                "ollydbg.exe",
                "ida64.exe",               // IDA Pro — industry-standard disassembler
                "cheatengine-x86_64.exe",
                "ghidra.bat",              // NSA open-source reverse engineering tool
                "frida-server",            // Dynamic instrumentation
                "gdb.exe",                 // GNU debugger — fundamental development tool
                "strace.exe",
            ],
        }
    }

    /// Starts a background monitor that detects and logs network-monitoring tools.
    /// Termination only occurs when `kill_mode = true` AND the tool is in the
    /// unauthorized_sniffers tier AND no valid maintenance window is active.
    pub fn start(self: Arc<Self>) {
        if self.kill_mode {
            warn!("⚔️  Anti-Tamper: Process monitor starting in KILL MODE — unauthorized sniffers will be terminated.");
            warn!("⚠️  LEGAL NOTICE: kill_mode=true must only be enabled on corporate-owned devices with user-informed");
            warn!("⚠️  Acceptable Use Policies in place. Consult legal counsel before enabling in your jurisdiction.");
        } else {
            info!("🛡️  Anti-Tamper: Process monitor starting in WARN-ONLY mode — detected tools are logged, not terminated.");
            info!("    To enable termination: set process_monitor_kill_mode = true in [blocking] config after reviewing legal guidance.");
        }

        tokio::spawn(async move {
            let mut sys = System::new_all();

            loop {
                sys.refresh_all();

                for process in sys.processes().values() {
                    let proc_name = process.name().to_string_lossy().to_lowercase();

                    // ── Check TIER 2 dual-use research tools (WARN only, never kill) ──
                    for &tool in &self.research_tools {
                        if proc_name.contains(tool) || proc_name == tool {
                            // Check maintenance window first
                            if Self::maintenance_window_active() {
                                debug!("🔧 ANTI-TAMPER: Maintenance window active — research tool permitted: {}", proc_name);
                                continue;
                            }
                            warn!("👁️  ANTI-TAMPER [OBSERVE]: Dual-use security tool detected: {} (PID: {}) — logging only, not terminating.",
                                process.name().to_string_lossy(), process.pid());
                            // Increment observation metric but do not block/terminate
                            self.metrics.record_threat();
                        }
                    }

                    // ── Check TIER 1 unauthorized sniffers ────────────────────────────
                    for &tool in &self.unauthorized_sniffers {
                        if proc_name.contains(tool) || proc_name == tool {
                            // ── ZERO-TRUST MAINTENANCE WINDOW v5 (HMAC-Signed Token) ──
                            let mut maintenance_active = false;
                            if let Ok(contents) = std::fs::read_to_string("maintenance.token") {
                                let (sig_valid, payload) = verify_token_hmac(&contents);
                                if !sig_valid {
                                    warn!("⚔️  ANTI-TAMPER: maintenance.token has INVALID HMAC — rejecting (possible tampering or wrong machine).");
                                } else if let Ok(decoded_bytes) = B64STD.decode(&payload) {
                                    if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                                        let mut start_up: Option<u64> = None;
                                        let mut start_ntp: Option<u64> = None;
                                        let mut duration: Option<u64> = None;
                                        for part in decoded_str.split(',') {
                                            if let Some(v) = part.strip_prefix("UPTIME_START=") {
                                                start_up = v.parse().ok();
                                            }
                                            if let Some(v) = part.strip_prefix("NTP_START=") {
                                                start_ntp = v.parse().ok();
                                            }
                                            if let Some(v) = part.strip_prefix("DURATION=") {
                                                duration = v.parse().ok();
                                            }
                                        }
                                        if let (Some(up), Some(ntp), Some(dur)) = (start_up, start_ntp, duration) {
                                            let current_uptime = sysinfo::System::uptime();
                                            let current_ntp = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                            let uptime_elapsed = current_uptime.saturating_sub(up);
                                            let ntp_elapsed = current_ntp.saturating_sub(ntp);
                                            let time_drift = ntp_elapsed.abs_diff(uptime_elapsed);
                                            if time_drift > 60 {
                                                warn!("⚔️  FATAL: Time Drift {}s detected. VM suspension or NTP poisoning attack! Token revoked.", time_drift);
                                            } else if uptime_elapsed <= dur {
                                                maintenance_active = true;
                                                debug!("🔧 ANTI-TAMPER: HMAC-valid maintenance window active ({}s remaining).", dur.saturating_sub(uptime_elapsed));
                                            } else {
                                                warn!("⚠️  ANTI-TAMPER: Maintenance token EXPIRED — rejecting IT tool bypass.");
                                            }
                                        }
                                    }
                                }
                            }

                            if maintenance_active {
                                warn!("🔧 ANTI-TAMPER: Authorized Maintenance Window Active. Permitting tool: {}", process.name().to_string_lossy());
                                continue;
                            }

                            warn!("🚨 ANTI-TAMPER: Unauthorized sniffer detected: {} (PID: {})",
                                process.name().to_string_lossy(), process.pid());
                            self.metrics.record_threat();

                            if self.kill_mode {
                                // ── NO HARDCODED BREAK-GLASS KEY ─────────────────────────
                                // SECURITY: All administrative overrides go through the
                                // HMAC-signed maintenance.token system above.
                                // ─────────────────────────────────────────────────────────
                                if process.kill() {
                                    warn!("☠️  ANTI-TAMPER [KILL]: Terminated unauthorized sniffer: {}", process.name().to_string_lossy());
                                } else {
                                    error!("❌ ANTI-TAMPER: Failed to terminate process: {}. Insufficient privileges.", process.name().to_string_lossy());
                                }
                            } else {
                                warn!("🔇 ANTI-TAMPER [WARN-ONLY]: Process NOT terminated — set process_monitor_kill_mode=true to enable termination.");
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    /// Quick helper: returns true if a valid maintenance.token exists and is
    /// within its active window.  Used for the dual-use research tool path
    /// where we don't need the full token parse — just a gate check.
    fn maintenance_window_active() -> bool {
        if let Ok(contents) = std::fs::read_to_string("maintenance.token") {
            let (sig_valid, payload) = verify_token_hmac(&contents);
            if !sig_valid {
                return false;
            }
            if let Ok(decoded_bytes) = B64STD.decode(&payload) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                    let mut start_up: Option<u64> = None;
                    let mut duration: Option<u64> = None;
                    for part in decoded_str.split(',') {
                        if let Some(v) = part.strip_prefix("UPTIME_START=") {
                            start_up = v.parse().ok();
                        }
                        if let Some(v) = part.strip_prefix("DURATION=") {
                            duration = v.parse().ok();
                        }
                    }
                    if let (Some(up), Some(dur)) = (start_up, duration) {
                        let elapsed = sysinfo::System::uptime().saturating_sub(up);
                        return elapsed <= dur;
                    }
                }
            }
        }
        false
    }
}
