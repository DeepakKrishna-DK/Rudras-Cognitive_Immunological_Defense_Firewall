// ============================================================================
// Rudras — Endpoint Security Agent
// ============================================================================
//
// PURPOSE
// ───────
// Host-based protection layer that monitors the *endpoint itself* — running
// processes, suspicious executable locations, credential-access tools, and
// process-level network behaviour.  This is the "EDR lightweight agent"
// component of a full security platform: it catches threats that bypass the
// network layer (e.g. malware already resident on the host).
//
// DESIGN PRINCIPLES
// ─────────────────
// 1. Alert-first.  This module NEVER terminates processes by default.
//    Set kill_mode = true in config ONLY on corporate-managed devices that
//    have an employee Acceptable Use Policy in place.
//
// 2. Two-tier classification (mirrors process_monitor.rs philosophy):
//    Tier 1 — Confirmed-Hostile: tools with no legitimate use in production
//             (mimikatz variants, keyloggers, SharpDump, etc.)
//    Tier 2 — Suspicious-Context: dual-use tools that are only an alert when
//             they appear on production hosts at unusual times
//             (nc/ncat, certutil -urlcache, mshta, etc.)
//
// 3. Posture score.  Every scan updates an EndpointPosture score (0.0–1.0)
//    that feeds back into the Zero Trust engine to down-score device trust
//    when hostile processes are detected.
//
// 4. No credential scanning.  This module NEVER reads memory, files, or
//    credentials from processes.  It only observes process metadata
//    (name, path, PID) from the OS.
// ============================================================================

#![allow(dead_code, unused_imports)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tracing::{debug, error, info, warn};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Alert severity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EndpointSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl EndpointSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info     => "INFO",
            Self::Low      => "LOW",
            Self::Medium   => "MEDIUM",
            Self::High     => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

// ── Alert type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointAlertType {
    /// A known hostile tool detected by process name (mimikatz, pwdump, etc.)
    KnownMaliciousTool,
    /// Dual-use tool running outside an authorised maintenance window
    SuspiciousDualUseTool,
    /// Executable running from a temp / download / AppData path
    SuspiciousExecLocation,
    /// Process spawned by an unusual parent (e.g., Word.exe → cmd.exe)
    SuspiciousParentChild,
    /// Unusual process running with SYSTEM or elevated privileges
    ElevatedPrivilegeProcess,
    /// Credential access indicator: LSASS access, SAM queries, etc.
    CredentialAccessIndicator,
    /// Process exhibiting lateral movement behaviour (PSExec, WMI, net.exe)
    LateralMovementTool,
    /// Scheduled-task or registry-run key persistence indicator
    PersistenceIndicator,
    /// Script interpreter launched unexpectedly from a non-shell parent
    UnexpectedScriptExecution,
    /// Living-Off-the-Land Binary (LOLBin) used in unexpected context
    LolBinMisuse,
}

// ── Single endpoint alert ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAlert {
    pub id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub alert_type: EndpointAlertType,
    pub severity: EndpointSeverity,
    pub detail: String,
    /// Matching MITRE ATT&CK technique ID (informational)
    pub mitre_technique: &'static str,
}

// ── Endpoint posture ──────────────────────────────────────────────────────────

/// Aggregated endpoint health score, updated on every scan.
/// Feed this into the Zero Trust engine to adjust device trust dynamically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPosture {
    /// 1.0 = fully clean, 0.0 = critically compromised
    pub score: f32,
    pub last_updated: u64,
    pub active_alert_count: u32,
    pub critical_alert_count: u32,
    pub suspicious_process_names: Vec<String>,
    pub scan_count: u64,
}

impl Default for EndpointPosture {
    fn default() -> Self {
        Self {
            score: 1.0,
            last_updated: unix_now(),
            active_alert_count: 0,
            critical_alert_count: 0,
            suspicious_process_names: Vec::new(),
            scan_count: 0,
        }
    }
}

// ── Process classification tables ─────────────────────────────────────────────

/// Tier-1: known hostile process names.  Presence alone is critical.
/// These are tools with essentially no legitimate production use.
static KNOWN_HOSTILE: &[(&str, &str, &str)] = &[
    // (name_fragment, detail, mitre_technique)
    ("mimikatz",        "Credential dumping framework — extracts NTLM/Kerberos",       "T1003"),
    ("mimilib",         "Mimikatz SSP library",                                        "T1003"),
    ("wce",             "Windows Credential Editor — credential theft",                "T1003"),
    ("pwdump",          "Password hash dumping tool",                                  "T1003"),
    ("fgdump",          "Credential harvesting tool",                                  "T1003"),
    ("cachedump",       "Domain cached credential dumper",                             "T1003"),
    ("quarks-pwdump",   "NTLM hash extractor",                                         "T1003"),
    ("sharpdump",       "Managed .NET LSASS memory dumper",                            "T1003"),
    ("nanodump",        "LSASS minidump tool",                                         "T1003"),
    ("procdump",        "Legitimate tool; only critical when targeting lsass.exe",     "T1003"),
    ("lsass",           "Never start a process named lsass — only the real OS process","T1003"),
    ("gsecdump",        "SAM/Active Directory hash extractor",                         "T1003"),
    ("metasploit",      "Exploitation framework — should never appear on production",  "T1059"),
    ("msfconsole",      "Metasploit console",                                          "T1059"),
    ("meterpreter",     "Metasploit post-exploitation agent",                          "T1059"),
    ("cobalt",          "Cobalt Strike beacon / teamserver",                           "T1071"),
    ("beacon.exe",      "Cobalt Strike payload",                                       "T1071"),
    ("empire",          "PowerShell Empire C2 framework",                              "T1059.001"),
    ("invoke-empire",   "Empire PS launcher",                                          "T1059.001"),
    ("covenant",        "Covenant C2 framework",                                       "T1071"),
    ("havoc",           "Havoc C2 framework payload",                                  "T1071"),
    ("sliver",          "Sliver C2 implant",                                           "T1071"),
    ("brute-force",     "Brute-force attack tool",                                     "T1110"),
    ("hashcat",         "Password hash cracking — unexpected on production servers",   "T1110"),
    ("john",            "John the Ripper hash cracker",                                "T1110"),
    ("hydra",           "Online brute-force tool",                                     "T1110"),
    ("medusa",          "Parallel login brute-forcer",                                 "T1110"),
    ("ncrack",          "Network auth cracker",                                        "T1110"),
    ("sqlmap",          "Automated SQL injection tool",                                "T1190"),
    ("nikto",           "Web vulnerability scanner",                                   "T1190"),
];

/// Tier-2: dual-use tools that are suspicious in production context.
static SUSPICIOUS_DUAL_USE: &[(&str, EndpointSeverity, &str, &str)] = &[
    // (name_fragment, severity, detail, mitre_technique)
    ("ncat",        EndpointSeverity::High,   "Netcat variant — common C2 pivot tool",              "T1059"),
    ("nc.exe",      EndpointSeverity::High,   "Netcat — classic backdoor / bind shell",             "T1059"),
    ("netcat",      EndpointSeverity::High,   "Netcat — classic backdoor / bind shell",             "T1059"),
    ("nmap",        EndpointSeverity::Medium, "Network scanner — unexpected on non-pentest host",    "T1046"),
    ("masscan",     EndpointSeverity::High,   "High-speed scanner — no legitimate prod use",        "T1046"),
    ("zmap",        EndpointSeverity::High,   "Internet-scale scanning tool",                       "T1046"),
    ("psexec",      EndpointSeverity::High,   "Remote execution via SMB — lateral movement indicator","T1570"),
    ("psexec64",    EndpointSeverity::High,   "64-bit PSExec variant",                              "T1570"),
    ("wmic",        EndpointSeverity::Medium, "WMI command-line — LOLBin abuse indicator",          "T1047"),
    ("mshta",       EndpointSeverity::High,   "HTA host — common Living-Off-the-Land launcher",     "T1218.005"),
    ("regsvr32",    EndpointSeverity::High,   "LOLBin — can execute COM DLLs from remote URLs",     "T1218.010"),
    ("rundll32",    EndpointSeverity::Medium, "LOLBin — DLL loader, common payload delivery",       "T1218.011"),
    ("installutil", EndpointSeverity::High,   "LOLBin — .NET bypass of AppLocker",                  "T1218.004"),
    ("certutil",    EndpointSeverity::Medium, "LOLBin — commonly used to download malware",         "T1105"),
    ("bitsadmin",   EndpointSeverity::Medium, "LOLBin — download/upload via Background Transfer",   "T1197"),
    ("schtasks",    EndpointSeverity::Medium, "Scheduled task creation — persistence indicator",    "T1053"),
    ("at.exe",      EndpointSeverity::Medium, "Legacy task scheduler — persistence indicator",      "T1053"),
    ("reg.exe",     EndpointSeverity::Medium, "Registry edit — possible run key persistence",       "T1112"),
    ("vssadmin",    EndpointSeverity::High,   "Shadow copy deletion — ransomware indicator",        "T1490"),
    ("bcdedit",     EndpointSeverity::High,   "Boot config edit — ransomware / rootkit",            "T1490"),
    ("wbadmin",     EndpointSeverity::High,   "Backup deletion — ransomware indicator",              "T1490"),
    ("esentutl",    EndpointSeverity::High,   "ESE db copy — NTDS.dit / credential extraction",    "T1003.003"),
    ("ntdsutil",    EndpointSeverity::Critical,"NTDS utility — Active Directory database extraction","T1003.003"),
    ("sekurlsa",    EndpointSeverity::Critical,"Mimikatz module — in-memory credential extraction", "T1003"),
    ("net1",        EndpointSeverity::Medium, "net1 — user/group enumeration or modification",      "T1087"),
    ("whoami",      EndpointSeverity::Low,    "Discovery — may indicate scripted recon",            "T1033"),
    ("ipconfig",    EndpointSeverity::Low,    "Network discovery — may be scripted recon",          "T1016"),
    ("arp",         EndpointSeverity::Low,    "ARP table inspection — network discovery",           "T1016"),
    ("route",       EndpointSeverity::Low,    "Routing table inspection — network discovery",       "T1016"),
];

/// Executable path fragments considered suspicious (temp / staging locations).
static SUSPICIOUS_PATHS: &[(&str, &str)] = &[
    (r"\temp\",           "Executable in TEMP — common malware staging area"),
    (r"\tmp\",            "Executable in /tmp — common malware staging area"),
    (r"\appdata\local\temp\", "AppData\\Local\\Temp — common dropper location"),
    (r"\downloads\",      "Executable running from Downloads folder"),
    (r"\recycle",         "Executable in Recycle Bin — evasion technique"),
    (r"\public\",         "C:\\Users\\Public — world-writable malware staging"),
    (r"\programdata\",    "ProgramData (non-vendor) — common payload staging"),
    (r"c:\\windows\\temp\\", "Windows temp — common malware / exploit staging"),
    (r"\perflogs\",       "PerfLogs — rarely legitimate, common evasion"),
];

// ── Endpoint Agent ──────────────────────────────────────────────────────────

pub struct EndpointAgent {
    alerts: RwLock<VecDeque<EndpointAlert>>,
    posture: RwLock<EndpointPosture>,
    alert_counter: AtomicU64,
    kill_mode: bool,
    // Track already-alerted PIDs to avoid log spam per scan cycle
    alerted_pids: RwLock<HashSet<u32>>,
}

impl EndpointAgent {
    pub fn new(kill_mode: bool) -> Self {
        if kill_mode {
            warn!("⚠️  Endpoint Security: kill_mode ENABLED — suspicious processes will be terminated");
            warn!("   Only use this on corporate-managed devices with an AUP in place.");
        } else {
            info!("🖥️  Endpoint Security: alert-only mode (kill_mode disabled)");
        }
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(1000)),
            posture: RwLock::new(EndpointPosture::default()),
            alert_counter: AtomicU64::new(1),
            kill_mode,
            alerted_pids: RwLock::new(HashSet::new()),
        }
    }

    /// Run a single endpoint scan.  Returns any new alerts generated.
    /// Designed to run every 5–30 seconds from a background task.
    pub fn scan(&self) -> Vec<EndpointAlert> {
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut new_alerts: Vec<EndpointAlert> = Vec::new();
        let alerted = self.alerted_pids.read();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name_lower = process.name().to_string_lossy().to_lowercase();
            let exe_path = process
                .exe()
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            // ── Tier 1: Known hostile tools ──────────────────────────────────
            for (fragment, detail, mitre) in KNOWN_HOSTILE {
                if name_lower.contains(fragment) {
                    // LSASS is a real Windows process — only alert if it's a
                    // second instance (real lsass runs as PID 4-700 range on boot)
                    if *fragment == "lsass" && pid_u32 < 1000 {
                        continue;
                    }
                    // procdump is only hostile when targeting lsass — we can't
                    // read command-line args safely here, so just warn Medium
                    let sev = if *fragment == "procdump" {
                        EndpointSeverity::Medium
                    } else {
                        EndpointSeverity::Critical
                    };
                    if !alerted.contains(&pid_u32) {
                        let alert = self.make_alert(
                            pid_u32,
                            &name_lower,
                            &exe_path,
                            EndpointAlertType::KnownMaliciousTool,
                            sev,
                            detail,
                            mitre,
                        );
                        new_alerts.push(alert);
                    }
                    break;
                }
            }

            // ── Tier 2: Suspicious dual-use tools ────────────────────────────
            if new_alerts.last().is_none_or(|a| a.pid != pid_u32) {
                for (fragment, sev, detail, mitre) in SUSPICIOUS_DUAL_USE {
                    if name_lower.contains(fragment) {
                        if !alerted.contains(&pid_u32) {
                            let alert = self.make_alert(
                                pid_u32,
                                &name_lower,
                                &exe_path,
                                EndpointAlertType::SuspiciousDualUseTool,
                                sev.clone(),
                                detail,
                                mitre,
                            );
                            new_alerts.push(alert);
                        }
                        break;
                    }
                }
            }

            // ── Suspicious executable path ────────────────────────────────────
            if !exe_path.is_empty() {
                for (path_fragment, detail) in SUSPICIOUS_PATHS {
                    if exe_path.contains(path_fragment) {
                        // Only alert if this isn't already a hostile/dual-use alert
                        let already_alerted =
                            new_alerts.iter().any(|a| a.pid == pid_u32);
                        if !already_alerted && !alerted.contains(&pid_u32) {
                            // Low noise: only alert non-MS/edge process names running from temp
                            let skip = ["svchost", "dllhost", "conhost", "msedge", "chrome"]
                                .iter()
                                .any(|n| name_lower.contains(n));
                            if !skip {
                                let alert = self.make_alert(
                                    pid_u32,
                                    &name_lower,
                                    &exe_path,
                                    EndpointAlertType::SuspiciousExecLocation,
                                    EndpointSeverity::Medium,
                                    detail,
                                    "T1036.005",
                                );
                                new_alerts.push(alert);
                            }
                        }
                        break;
                    }
                }
            }
        }
        drop(alerted);

        // ── Emit alerts + update state ────────────────────────────────────────
        if !new_alerts.is_empty() {
            let mut alerted_mut = self.alerted_pids.write();
            let mut alert_queue = self.alerts.write();
            for alert in &new_alerts {
                alerted_mut.insert(alert.pid);
                // Keep ring buffer bounded at 1000
                if alert_queue.len() >= 1000 {
                    alert_queue.pop_front();
                }
                alert_queue.push_back(alert.clone());

                // Log at appropriate level
                match alert.severity {
                    EndpointSeverity::Critical | EndpointSeverity::High => {
                        error!(
                            "🖥️  ENDPOINT {} [PID {}] {} | {} | MITRE:{}",
                            alert.severity.label(),
                            alert.pid,
                            alert.process_name,
                            alert.detail,
                            alert.mitre_technique
                        );
                    }
                    EndpointSeverity::Medium => {
                        warn!(
                            "🖥️  ENDPOINT {} [PID {}] {} | {}",
                            alert.severity.label(),
                            alert.pid,
                            alert.process_name,
                            alert.detail
                        );
                    }
                    EndpointSeverity::Low | EndpointSeverity::Info => {
                        debug!(
                            "🖥️  ENDPOINT {} [PID {}] {} | {}",
                            alert.severity.label(),
                            alert.pid,
                            alert.process_name,
                            alert.detail
                        );
                    }
                }

                // If kill_mode is enabled AND this is Critical tier-1 hostile tool,
                // attempt termination — only for unambiguously hostile processes.
                if self.kill_mode
                    && matches!(alert.severity, EndpointSeverity::Critical)
                    && matches!(alert.alert_type, EndpointAlertType::KnownMaliciousTool)
                {
                    warn!(
                        "🖥️  ENDPOINT: kill_mode active — requesting OS termination of PID {}",
                        alert.pid
                    );
                    // sysinfo process kill via refresh → kill; safe API
                    let mut kill_sys = System::new();
                    kill_sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                    if let Some(proc) = kill_sys.process(sysinfo::Pid::from_u32(alert.pid)) {
                        proc.kill();
                    }
                }
            }
        }

        // ── Recompute posture score ───────────────────────────────────────────
        self.update_posture(&new_alerts);

        // Purge stale alerted PIDs every 1000 scans (prevents unbounded growth)
        // by checking whether those PIDs still exist
        {
            let mut stale_pids = self.alerted_pids.write();
            let mut refresh_sys = System::new();
            refresh_sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            stale_pids.retain(|pid| {
                refresh_sys
                    .process(sysinfo::Pid::from_u32(*pid))
                    .is_some()
            });
        }

        new_alerts
    }

    fn make_alert(
        &self,
        pid: u32,
        name: &str,
        exe_path: &str,
        alert_type: EndpointAlertType,
        severity: EndpointSeverity,
        detail: &str,
        mitre_technique: &'static str,
    ) -> EndpointAlert {
        EndpointAlert {
            id: self.alert_counter.fetch_add(1, Ordering::Relaxed),
            timestamp: unix_now(),
            pid,
            process_name: name.to_string(),
            exe_path: exe_path.to_string(),
            alert_type,
            severity,
            detail: detail.to_string(),
            mitre_technique,
        }
    }

    fn update_posture(&self, new_alerts: &[EndpointAlert]) {
        let mut posture = self.posture.write();
        posture.scan_count += 1;
        posture.last_updated = unix_now();

        // Rebuild from ring buffer for accurate current score
        let alerts = self.alerts.read();
        let now = unix_now();
        // Only count alerts from the last 5 minutes as "active"
        let window = 300u64;
        let active: Vec<&EndpointAlert> = alerts
            .iter()
            .filter(|a| now.saturating_sub(a.timestamp) < window)
            .collect();

        posture.active_alert_count = active.len() as u32;
        posture.critical_alert_count = active
            .iter()
            .filter(|a| a.severity >= EndpointSeverity::High)
            .count() as u32;
        posture.suspicious_process_names = active
            .iter()
            .map(|a| a.process_name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Score algorithm: start at 1.0, deduct per active alert
        let mut score: f32 = 1.0;
        for alert in &active {
            score -= match alert.severity {
                EndpointSeverity::Critical => 0.30,
                EndpointSeverity::High     => 0.15,
                EndpointSeverity::Medium   => 0.07,
                EndpointSeverity::Low      => 0.02,
                EndpointSeverity::Info     => 0.005,
            };
        }
        posture.score = score.max(0.0);

        if posture.critical_alert_count > 0 {
            error!(
                "🖥️  ENDPOINT POSTURE: {:.0}% | {} active alerts ({} HIGH/CRITICAL) — device trust REDUCED",
                posture.score * 100.0,
                posture.active_alert_count,
                posture.critical_alert_count
            );
        } else if posture.active_alert_count > 0 {
            warn!(
                "🖥️  ENDPOINT POSTURE: {:.0}% | {} active alerts",
                posture.score * 100.0,
                posture.active_alert_count
            );
        }
    }

    /// Returns the current endpoint health posture.
    /// Call this from the Zero Trust engine to gate network access decisions.
    pub fn get_posture(&self) -> EndpointPosture {
        self.posture.read().clone()
    }

    /// Returns up to `limit` most recent endpoint alerts.
    pub fn recent_alerts(&self, limit: usize) -> Vec<EndpointAlert> {
        self.alerts
            .read()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_counter.load(Ordering::Relaxed)
    }
}
