// ============================================================================
// Rudras — Runtime Application Self-Protection (RASP) Engine
//
// Monitors protected processes for signs of compromise at runtime:
//
//   • Process Hollowing — PE image on disk vs. in-memory mismatch
//   • DLL Injection — unexpected module loads into protected processes
//   • Fileless Execution — executable pages mapped from non-file-backed memory
//   • LD_PRELOAD / AppInit_DLLs hooking — interposition library injection
//   • Unexpected Syscalls — syscalls not in the process's declared policy
//   • Memory Integrity — periodic hash of critical code sections
//   • Stack Smashing Indicators — stack canary violation simulation
//
// Platform-aware:
//   Windows: simulates VirtualQuery / ReadProcessMemory pattern
//   Linux: simulates /proc/<pid>/maps parsing
//   Both: pure-Rust implementation — no unsafe FFI required for the
//         simulation layer; for real protection, integrate with the
//         wfp_engine.rs or ebpf_xdp.rs hooks.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Syscall Policy ────────────────────────────────────────────────────────────

/// Per-process syscall allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPolicy {
    pub process_name: String,
    /// Set of allowed syscall numbers (Linux NR_* / Windows call IDs)
    pub allowed_syscalls: HashSet<u32>,
    /// Alert (but allow) on these syscalls instead of blocking
    pub alert_syscalls: HashSet<u32>,
}

impl SyscallPolicy {
    pub fn default_web_server() -> Self {
        let mut allowed = HashSet::new();
        // Accept: read, write, socket, bind, accept, connect, close, stat, open...
        for n in [0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50] {
            allowed.insert(n);
        }
        let mut alert = HashSet::new();
        // Alert on: ptrace, prctl, execve, mmap-exec, socket(AF_PACKET)
        for n in [59u32, 101, 9, 157, 158] { alert.insert(n); }
        SyscallPolicy {
            process_name: "web_server".into(),
            allowed_syscalls: allowed,
            alert_syscalls: alert,
        }
    }
}

// ── Protected Process State ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ProtectedProcess {
    pid: u32,
    process_name: String,
    exe_path: String,
    /// SHA-256 of the executable at registration time
    exe_hash_baseline: [u8; 32],
    /// Expected module (DLL/SO) set at registration time
    baseline_modules: HashSet<String>,
    policy: SyscallPolicy,
    registered_at: u64,
    last_checked: u64,
    alerts_generated: u32,
}

// ── RASP Alerts ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RaspAlertType {
    /// Executable image in memory differs from disk version
    ProcessHollowing {
        pid: u32,
        process_name: String,
        expected_hash: String,
        actual_hash: String,
    },
    /// Unexpected DLL/SO loaded into protected process address space
    DllInjection {
        pid: u32,
        process_name: String,
        injected_module: String,
    },
    /// Executable memory region not backed by any file
    FilelessExecution {
        pid: u32,
        process_name: String,
        region_addr: u64,
        region_size: u64,
    },
    /// LD_PRELOAD / AppInit_DLLs interposition detected
    LdPreloadHook {
        pid: u32,
        hook_library: String,
    },
    /// syscall not in the declared allowlist
    UnexpectedSyscall {
        pid: u32,
        process_name: String,
        syscall_number: u32,
        syscall_name: String,
    },
    /// Memory region hash changed — potential code patching
    MemoryIntegrityViolation {
        pid: u32,
        region_name: String,
        expected_hash: String,
        actual_hash: String,
    },
    /// Stack canary violation detected
    StackSmashing {
        pid: u32,
        process_name: String,
        function_hint: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaspAlert {
    pub id: String,
    pub alert_type: RaspAlertType,
    pub severity: RaspSeverity,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RaspSeverity { Medium, High, Critical }

// ── Memory Region Snapshot ────────────────────────────────────────────────────

/// Simulated memory region descriptor (equivalent to VirtualQuery / /proc/maps entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_addr: u64,
    pub size: u64,
    pub permissions: MemoryPermissions,
    /// None = anonymous / heap / stack; Some = file-backed mapping
    pub backing_file: Option<String>,
    /// SHA-256 of region contents at last snapshot
    pub content_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    pub fn rwx() -> Self { Self { read: true, write: true, execute: true } }
    pub fn rx()  -> Self { Self { read: true, write: false, execute: true } }
    pub fn rw()  -> Self { Self { read: true, write: true, execute: false } }
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RaspStats {
    pub processes_protected: usize,
    pub scans_completed: u64,
    pub alerts_total: u64,
    pub hollowing_detected: u64,
    pub injection_detected: u64,
    pub fileless_detected: u64,
    pub syscall_violations: u64,
    pub memory_integrity_violations: u64,
}

// ── RASP Engine ───────────────────────────────────────────────────────────────

pub struct RaspEngine {
    protected: RwLock<HashMap<u32, ProtectedProcess>>,
    /// Per-process memory region snapshots (pid → regions)
    memory_snapshots: RwLock<HashMap<u32, Vec<MemoryRegion>>>,
    alerts: RwLock<VecDeque<RaspAlert>>,
    scans: AtomicU64,
    alerts_total: AtomicU64,
    hollowing: AtomicU64,
    injection: AtomicU64,
    fileless: AtomicU64,
    syscall_viol: AtomicU64,
    mem_integrity: AtomicU64,
    seq: AtomicU64,
}

impl RaspEngine {
    pub fn new() -> Self {
        info!("🛡️  RASP Engine initialized — process hollowing / DLL injection / fileless / syscall monitoring");
        Self {
            protected: RwLock::new(HashMap::new()),
            memory_snapshots: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::with_capacity(256)),
            scans: AtomicU64::new(0),
            alerts_total: AtomicU64::new(0),
            hollowing: AtomicU64::new(0),
            injection: AtomicU64::new(0),
            fileless: AtomicU64::new(0),
            syscall_viol: AtomicU64::new(0),
            mem_integrity: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        }
    }

    fn next_id(&self) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("RASP-{}-{}", unix_secs(), n)
    }

    fn push_alert(&self, alert_type: RaspAlertType, severity: RaspSeverity) {
        warn!("🛡️  RASP: {:?}", alert_type);
        self.alerts_total.fetch_add(1, Ordering::Relaxed);
        let alert = RaspAlert {
            id: self.next_id(), alert_type, severity,
            timestamp: unix_secs(),
        };
        let mut q = self.alerts.write();
        if q.len() >= 256 { q.pop_front(); }
        q.push_back(alert);
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// Register a process for RASP protection.
    pub fn register_process(
        &self,
        pid: u32,
        process_name: &str,
        exe_path: &str,
        exe_bytes: &[u8],
        baseline_modules: Vec<String>,
        policy: SyscallPolicy,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(exe_bytes);
        let hash_out = hasher.finalize();
        let mut baseline_hash = [0u8; 32];
        baseline_hash.copy_from_slice(&hash_out);

        let proc = ProtectedProcess {
            pid, process_name: process_name.to_string(),
            exe_path: exe_path.to_string(),
            exe_hash_baseline: baseline_hash,
            baseline_modules: baseline_modules.into_iter().collect(),
            policy,
            registered_at: unix_secs(),
            last_checked: unix_secs(),
            alerts_generated: 0,
        };
        self.protected.write().insert(pid, proc);
        info!("🛡️  RASP: Registered process {} (pid={}) for protection", process_name, pid);
    }

    /// Deregister a process (e.g. on clean exit).
    pub fn deregister_process(&self, pid: u32) {
        self.protected.write().remove(&pid);
        self.memory_snapshots.write().remove(&pid);
    }

    // ── Checks ────────────────────────────────────────────────────────────────

    /// Check for process hollowing: compare current exe hash to baseline.
    pub fn check_hollowing(&self, pid: u32, current_exe_bytes: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(current_exe_bytes);
        let current = hasher.finalize();

        if let Some(proc) = self.protected.read().get(&pid) {
            if current.as_slice() != proc.exe_hash_baseline {
                self.hollowing.fetch_add(1, Ordering::Relaxed);
                self.push_alert(
                    RaspAlertType::ProcessHollowing {
                        pid,
                        process_name: proc.process_name.clone(),
                        expected_hash: hex::encode(proc.exe_hash_baseline),
                        actual_hash: hex::encode(current),
                    },
                    RaspSeverity::Critical,
                );
            }
        }
    }

    /// Check for unexpected module loads.
    pub fn check_loaded_modules(&self, pid: u32, current_modules: &[String]) {
        if let Some(proc) = self.protected.read().get(&pid) {
            for module in current_modules {
                if !proc.baseline_modules.contains(module) {
                    self.injection.fetch_add(1, Ordering::Relaxed);
                    self.push_alert(
                        RaspAlertType::DllInjection {
                            pid,
                            process_name: proc.process_name.clone(),
                            injected_module: module.clone(),
                        },
                        RaspSeverity::Critical,
                    );
                }
            }
        }
    }

    /// Check memory regions for anonymous executable mappings (fileless execution).
    pub fn check_memory_regions(&self, pid: u32, regions: &[MemoryRegion]) {
        self.memory_snapshots.write().insert(pid, regions.to_vec());

        let name = self.protected.read().get(&pid)
            .map(|p| p.process_name.clone())
            .unwrap_or_else(|| format!("pid:{}", pid));

        for region in regions {
            // Executable anonymous region = potential fileless shellcode
            if region.permissions.execute && region.backing_file.is_none() && region.size > 0 {
                self.fileless.fetch_add(1, Ordering::Relaxed);
                self.push_alert(
                    RaspAlertType::FilelessExecution {
                        pid,
                        process_name: name.clone(),
                        region_addr: region.base_addr,
                        region_size: region.size,
                    },
                    RaspSeverity::High,
                );
            }

            // Writable+Executable region (W^X violation) = suspicious
            if region.permissions.write && region.permissions.execute && region.size > 0 {
                warn!("🛡️  W^X violation: pid={} addr=0x{:016X}", pid, region.base_addr);
            }
        }
    }

    /// Check for LD_PRELOAD / AppInit_DLLs environment interposition.
    pub fn check_env_hooks(&self, pid: u32, env_vars: &HashMap<String, String>) {
        let suspicious_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"];
        for var in suspicious_vars {
            if let Some(val) = env_vars.get(var) {
                if !val.is_empty() {
                    self.push_alert(
                        RaspAlertType::LdPreloadHook { pid, hook_library: val.clone() },
                        RaspSeverity::High,
                    );
                }
            }
        }
    }

    /// Report a syscall — check against process policy.
    pub fn report_syscall(&self, pid: u32, syscall_number: u32) {
        let procs = self.protected.read();
        if let Some(proc) = procs.get(&pid) {
            if !proc.policy.allowed_syscalls.contains(&syscall_number)
                && !proc.policy.alert_syscalls.contains(&syscall_number) {
                self.syscall_viol.fetch_add(1, Ordering::Relaxed);
                let name = syscall_name(syscall_number);
                drop(procs);
                if let Some(proc) = self.protected.read().get(&pid) {
                    self.push_alert(
                        RaspAlertType::UnexpectedSyscall {
                            pid,
                            process_name: proc.process_name.clone(),
                            syscall_number,
                            syscall_name: name,
                        },
                        RaspSeverity::High,
                    );
                }
            }
        }
    }

    /// Memory integrity check: rehash a named region and compare to snapshot.
    pub fn check_memory_integrity(
        &self, pid: u32, region_name: &str,
        current_bytes: &[u8], expected_hash: [u8; 32],
    ) {
        let mut hasher = Sha256::new();
        hasher.update(current_bytes);
        let current = hasher.finalize();

        if current.as_slice() != expected_hash {
            self.mem_integrity.fetch_add(1, Ordering::Relaxed);
            self.push_alert(
                RaspAlertType::MemoryIntegrityViolation {
                    pid,
                    region_name: region_name.to_string(),
                    expected_hash: hex::encode(expected_hash),
                    actual_hash: hex::encode(current),
                },
                RaspSeverity::Critical,
            );
        }
    }

    /// Scan all registered processes (runs periodically in background task).
    pub fn periodic_scan(&self) {
        let count = self.protected.read().len();
        if count == 0 { return; }
        self.scans.fetch_add(1, Ordering::Relaxed);
        debug!("🛡️  RASP: Periodic scan — {} processes monitored", count);

        // In a real RASP implementation, we would:
        // 1. ReadProcessMemory / /proc/<pid>/mem to get current exe bytes
        // 2. List loaded modules from /proc/<pid>/maps or PsGetProcessMitigationPolicy
        // 3. Compare against baselines
        //
        // For the simulation layer, we only verify that the registry is intact.
        // Actual checks are triggered via check_hollowing(), check_loaded_modules(), etc.
        // which are called by the os-level hooks or the process_monitor module.
    }

    pub fn drain_alerts(&self) -> Vec<RaspAlert> {
        self.alerts.write().drain(..).collect()
    }

    pub fn stats(&self) -> RaspStats {
        RaspStats {
            processes_protected: self.protected.read().len(),
            scans_completed: self.scans.load(Ordering::Relaxed),
            alerts_total: self.alerts_total.load(Ordering::Relaxed),
            hollowing_detected: self.hollowing.load(Ordering::Relaxed),
            injection_detected: self.injection.load(Ordering::Relaxed),
            fileless_detected: self.fileless.load(Ordering::Relaxed),
            syscall_violations: self.syscall_viol.load(Ordering::Relaxed),
            memory_integrity_violations: self.mem_integrity.load(Ordering::Relaxed),
        }
    }
}

// ── Syscall Number → Name ─────────────────────────────────────────────────────

fn syscall_name(nr: u32) -> String {
    match nr {
        0  => "read",
        1  => "write",
        2  => "open",
        3  => "close",
        9  => "mmap",
        11 => "munmap",
        39 => "getpid",
        41 => "socket",
        56 => "clone",
        57 => "fork",
        59 => "execve",
        60 => "exit",
        101 => "ptrace",
        157 => "prctl",
        _  => "unknown",
    }.to_string()
}
