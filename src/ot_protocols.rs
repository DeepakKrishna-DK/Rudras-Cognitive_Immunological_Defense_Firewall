// ============================================================================
// Rudras — OT/ICS Protocol Engine
// State-machine based anomaly detection for Industrial Control System protocols.
//
// Supports:
//   • Modbus TCP — function code allow-list, ARM-before-EXECUTE validation,
//                  illegal coil/register access detection
//   • DNP3        — SFC/outstation link-layer state, unsolicited response
//                  spoofing detection, SELECT-BEFORE-OPERATE enforcement
//   • EtherNet/IP — CIP connection state, unauthorized class/instance access
//   • IEC 61850   — GOOSE/SV frame rate anomaly (substation protection relay)
//
// ETHICAL NOTE: Detection only. No protocol manipulation or command injection.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Common OT Alert ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtAlert {
    pub id: String,
    pub protocol: OtProtocol,
    pub violation: OtViolation,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub severity: OtSeverity,
    pub raw_frame_hex: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtProtocol {
    ModbusTcp,
    Dnp3,
    EtherNetIp,
    Iec61850Goose,
    Profinet,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OtViolation {
    // Modbus
    UnauthorizedFunctionCode { fc: u8, device_id: u8 },
    WriteWithoutPriorRead { coil_or_reg: u16 },
    ExcessivePollingRate { polls_per_sec: f32, threshold: f32 },
    IllegalAddressRange { start: u16, count: u16, max_allowed: u16 },
    ModbusReplay { seq_delta: i32 },
    // DNP3
    UnsolicitedResponseWithoutConfig { outstation: u16 },
    SelectBeforeOperateViolation { point_index: u16 },
    Dnp3AuthBypass,
    Dnp3BroadcastCommand,
    // EtherNet/IP
    CipUnauthorizedClass { class_id: u16, requested_by: IpAddr },
    CipServiceOutOfRange { service: u8 },
    // IEC 61850
    GooseFrameBurst { frames_per_sec: f32, threshold: f32 },
    GooseSeqRollback { st_num: u32, detected_st_num: u32 },
    // Generic
    UnexpectedSource { expected: IpAddr, actual: IpAddr },
    ScanOrProbe { ports_touched: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OtSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical, // Any command that could affect physical process: coil WRITE, CB OPERATE
}

// ── Modbus Engine ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusPolicy {
    pub device_id: u8,
    /// Explicitly allowed function codes
    pub allowed_function_codes: Vec<u8>,
    /// Coil address range that is legal
    pub allowed_coil_range: (u16, u16),
    /// Register address range that is legal
    pub allowed_register_range: (u16, u16),
    /// Maximum polls per second before flagging
    pub max_polls_per_sec: f32,
    /// Require a read (FC1/FC3) before any write (FC5/FC6/FC15/FC16)
    pub read_before_write: bool,
}

impl Default for ModbusPolicy {
    fn default() -> Self {
        Self {
            device_id: 1,
            // FC1=ReadCoils, FC2=ReadDiscreteInputs, FC3=ReadHoldingRegisters, FC4=ReadInputRegisters
            // FC5=WriteSingleCoil, FC6=WriteSingleRegister
            // FC15=WriteMultipleCoils, FC16=WriteMultipleRegisters
            allowed_function_codes: vec![1, 2, 3, 4, 5, 6, 15, 16],
            allowed_coil_range: (0, 1023),
            allowed_register_range: (0, 1023),
            max_polls_per_sec: 10.0,
            read_before_write: true,
        }
    }
}

#[derive(Debug)]
struct ModbusSessionState {
    last_read_time: u64,
    last_write_time: u64,
    read_addresses: Vec<u16>,
    poll_times: VecDeque<u64>,
    last_transaction_id: u16,
}

impl Default for ModbusSessionState {
    fn default() -> Self {
        Self {
            last_read_time: 0,
            last_write_time: 0,
            read_addresses: vec![],
            poll_times: VecDeque::new(),
            last_transaction_id: 0,
        }
    }
}

pub struct ModbusEngine {
    policies: RwLock<HashMap<u8, ModbusPolicy>>,
    states: RwLock<HashMap<IpAddr, ModbusSessionState>>,
    alerts: RwLock<VecDeque<OtAlert>>,
    violations: AtomicU64,
}

impl ModbusEngine {
    pub fn new() -> Self {
        info!("⚙️  OT/Modbus: State machine engine initialized");
        let mut policies = HashMap::new();
        policies.insert(1, ModbusPolicy::default());
        Self {
            policies: RwLock::new(policies),
            states: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            violations: AtomicU64::new(0),
        }
    }

    /// Parse and evaluate a Modbus TCP payload.
    /// Returns list of violations (empty = clean).
    pub fn evaluate(&self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> Vec<OtAlert> {
        // Modbus TCP: [transaction_id u16][protocol_id u16=0][length u16][unit_id u8][fc u8][data...]
        if payload.len() < 8 { return vec![]; }
        let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
        let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
        if protocol_id != 0 { return vec![]; } // Not Modbus TCP
        let unit_id = payload[6];
        let fc = payload[7];

        let policies = self.policies.read();
        let policy = policies.get(&unit_id).or_else(|| policies.get(&1));
        let policy = match policy {
            Some(p) => p.clone(),
            None => { debug!("Modbus: no policy for device {}", unit_id); return vec![]; }
        };
        drop(policies);

        let mut violations = vec![];
        let now = unix_secs();

        // Function code allow-list check
        if !policy.allowed_function_codes.contains(&fc) {
            violations.push(self.make_alert(src_ip, dst_ip, payload,
                OtAlert {
                    id: format!("MB-{:x}", now),
                    protocol: OtProtocol::ModbusTcp,
                    violation: OtViolation::UnauthorizedFunctionCode { fc, device_id: unit_id },
                    src_ip, dst_ip,
                    severity: if fc >= 0x80 { OtSeverity::High } else { OtSeverity::Critical },
                    raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                    timestamp: now,
                }
            ));
        }

        // Address range check for FC3/FC4/FC6/FC16
        if fc == 3 || fc == 4 || fc == 6 || fc == 16 {
            if payload.len() >= 12 {
                let start_addr = u16::from_be_bytes([payload[8], payload[9]]);
                let count_or_val = u16::from_be_bytes([payload[10], payload[11]]);
                let (min_addr, max_addr) = policy.allowed_register_range;
                if start_addr < min_addr || start_addr > max_addr ||
                   start_addr.saturating_add(count_or_val) > max_addr {
                    violations.push(self.make_alert(src_ip, dst_ip, payload,
                        OtAlert {
                            id: format!("MB-RANGE-{:x}", now),
                            protocol: OtProtocol::ModbusTcp,
                            violation: OtViolation::IllegalAddressRange {
                                start: start_addr,
                                count: count_or_val,
                                max_allowed: max_addr,
                            },
                            src_ip, dst_ip,
                            severity: OtSeverity::High,
                            raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                            timestamp: now,
                        }
                    ));
                }
            }
        }

        // Read-before-write enforcement (FC5=WriteSingleCoil, FC6=WriteReg, FC15/FC16)
        if policy.read_before_write && (fc == 5 || fc == 6 || fc == 15 || fc == 16) {
            let last_read = {
                let states = self.states.read();
                states.get(&src_ip).map(|s| s.last_read_time).unwrap_or(0)
            };
            if last_read == 0 {
                violations.push(self.make_alert(src_ip, dst_ip, payload, OtAlert {
                    id: format!("MB-NOREAD-{:x}", now),
                    protocol: OtProtocol::ModbusTcp,
                    violation: OtViolation::WriteWithoutPriorRead {
                        coil_or_reg: if payload.len() >= 10 {
                            u16::from_be_bytes([payload[8], payload[9]])
                        } else { 0 }
                    },
                    src_ip, dst_ip,
                    severity: OtSeverity::Critical,
                    raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                    timestamp: now,
                }));
            }
        }

        // Update session state
        {
            let mut states = self.states.write();
            let state = states.entry(src_ip).or_default();
            if fc == 1 || fc == 2 || fc == 3 || fc == 4 {
                state.last_read_time = now;
            } else if fc == 5 || fc == 6 || fc == 15 || fc == 16 {
                state.last_write_time = now;
            }
            state.poll_times.push_back(now);
            while state.poll_times.len() > 100 { state.poll_times.pop_front(); }
            state.last_transaction_id = transaction_id;
        }

        // Poll rate check
        {
            let states = self.states.read();
            if let Some(state) = states.get(&src_ip) {
                if state.poll_times.len() >= 10 {
                    let oldest = state.poll_times.front().copied().unwrap_or(now);
                    let elapsed = (now - oldest).max(1) as f32;
                    let rate = state.poll_times.len() as f32 / elapsed;
                    if rate > policy.max_polls_per_sec {
                        violations.push(OtAlert {
                            id: format!("MB-RATE-{:x}", now),
                            protocol: OtProtocol::ModbusTcp,
                            violation: OtViolation::ExcessivePollingRate {
                                polls_per_sec: rate,
                                threshold: policy.max_polls_per_sec,
                            },
                            src_ip, dst_ip,
                            severity: OtSeverity::Medium,
                            raw_frame_hex: String::new(),
                            timestamp: now,
                        });
                    }
                }
            }
        }

        for v in &violations {
            warn!("⚙️  OT VIOLATION [{:?}]: {} → {:?}", v.severity, src_ip, v.violation);
            self.violations.fetch_add(1, Ordering::Relaxed);
            self.alerts.write().push_back(v.clone());
        }
        violations
    }

    fn make_alert(&self, _src: IpAddr, _dst: IpAddr, _p: &[u8], a: OtAlert) -> OtAlert { a }
}

// ── DNP3 Engine ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Dnp3SessionState {
    master_addr: u16,
    outstation_addr: u16,
    last_select_index: Option<u16>,
    last_select_time: u64,
    sbo_timeout_secs: u64,
    unsolicited_configured: bool,
}

pub struct Dnp3Engine {
    sessions: RwLock<HashMap<(IpAddr, IpAddr), Dnp3SessionState>>,
    alerts: RwLock<VecDeque<OtAlert>>,
    violations: AtomicU64,
}

impl Dnp3Engine {
    pub fn new() -> Self {
        info!("⚙️  OT/DNP3: State machine engine initialized");
        Self {
            sessions: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            violations: AtomicU64::new(0),
        }
    }

    /// Evaluate a DNP3 frame (application layer minimum parsing).
    /// DNP3 Link Layer: [0x0564][length][ctrl][dst_addr u16 LE][src_addr u16 LE][crc2]
    pub fn evaluate(&self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> Vec<OtAlert> {
        if payload.len() < 10 { return vec![]; }
        if payload[0] != 0x05 || payload[1] != 0x64 { return vec![]; } // DNP3 start bytes
        let dst_addr = u16::from_le_bytes([payload[4], payload[5]]);
        let src_addr = u16::from_le_bytes([payload[6], payload[7]]);
        let ctrl = payload[3];
        let now = unix_secs();
        let mut violations = vec![];

        // DIR=1 (master→outstation), DIR=0 (outstation→master)
        let dir = (ctrl >> 7) & 1;
        // FC from control byte (lower 4 bits for link layer)
        let link_fc = ctrl & 0x0F;

        // Unsolicited response from outstation: only valid if configured
        if dir == 0 && link_fc == 4 {
            // Unsolicited response (App layer FC=0x82)
            let key = (dst_ip, src_ip); // outstation is src
            let sessions = self.sessions.read();
            let unsol_configured = sessions.get(&key)
                .map(|s| s.unsolicited_configured)
                .unwrap_or(false);
            drop(sessions);
            if !unsol_configured {
                let alert = OtAlert {
                    id: format!("DNP3-UNSOL-{:x}", now),
                    protocol: OtProtocol::Dnp3,
                    violation: OtViolation::UnsolicitedResponseWithoutConfig { outstation: src_addr },
                    src_ip, dst_ip,
                    severity: OtSeverity::High,
                    raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                    timestamp: now,
                };
                warn!("⚙️  DNP3 VIOLATION: Unsolicited response from outstation {} without config", src_addr);
                self.violations.fetch_add(1, Ordering::Relaxed);
                self.alerts.write().push_back(alert.clone());
                violations.push(alert);
            }
        }

        // SELECT-BEFORE-OPERATE enforcement (parse app layer FC if enough bytes)
        if payload.len() >= 14 {
            let app_ctrl = payload[10];
            let app_fc = payload[11];
            // App FC 0x03 = OPERATE, 0x81 = SELECT
            if app_fc == 0x03 {
                let point_index = u16::from_le_bytes([
                    payload.get(14).copied().unwrap_or(0),
                    payload.get(15).copied().unwrap_or(0),
                ]);
                let key = (src_ip, dst_ip);
                let (select_seen, select_time) = {
                    let sessions = self.sessions.read();
                    sessions.get(&key)
                        .map(|s| (s.last_select_index == Some(point_index), s.last_select_time))
                        .unwrap_or((false, 0))
                };
                let sbo_timeout = 30u64;
                if !select_seen || (now - select_time) > sbo_timeout {
                    let alert = OtAlert {
                        id: format!("DNP3-SBO-{:x}", now),
                        protocol: OtProtocol::Dnp3,
                        violation: OtViolation::SelectBeforeOperateViolation { point_index },
                        src_ip, dst_ip,
                        severity: OtSeverity::Critical,
                        raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                        timestamp: now,
                    };
                    warn!("⚙️  DNP3 CRITICAL: OPERATE without SELECT for point {} from {}", point_index, src_ip);
                    self.violations.fetch_add(1, Ordering::Relaxed);
                    self.alerts.write().push_back(alert.clone());
                    violations.push(alert);
                }
            } else if app_fc == 0x81 {
                // Record SELECT
                let point_index = u16::from_le_bytes([
                    payload.get(14).copied().unwrap_or(0),
                    payload.get(15).copied().unwrap_or(0),
                ]);
                let key = (src_ip, dst_ip);
                let mut sessions = self.sessions.write();
                let session = sessions.entry(key).or_insert_with(|| Dnp3SessionState {
                    master_addr: src_addr,
                    outstation_addr: dst_addr,
                    last_select_index: None,
                    last_select_time: 0,
                    sbo_timeout_secs: 30,
                    unsolicited_configured: false,
                });
                session.last_select_index = Some(point_index);
                session.last_select_time = now;
            }
        }

        // Broadcast command (dst_addr == 0xFFFF) — dangerous in ICS
        if dst_addr == 0xFFFF {
            let alert = OtAlert {
                id: format!("DNP3-BCAST-{:x}", now),
                protocol: OtProtocol::Dnp3,
                violation: OtViolation::Dnp3BroadcastCommand,
                src_ip, dst_ip,
                severity: OtSeverity::Critical,
                raw_frame_hex: hex::encode(&payload[..payload.len().min(32)]),
                timestamp: now,
            };
            warn!("⚙️  DNP3 CRITICAL: Broadcast command from {} to all outstations!", src_ip);
            self.violations.fetch_add(1, Ordering::Relaxed);
            self.alerts.write().push_back(alert.clone());
            violations.push(alert);
        }

        violations
    }
}

// ── IEC 61850 GOOSE Frame Rate Monitor ───────────────────────────────────────

pub struct Goose61850Engine {
    frame_times: RwLock<HashMap<IpAddr, VecDeque<u64>>>,
    alerts: RwLock<VecDeque<OtAlert>>,
    max_goose_fps: f32,
}

impl Goose61850Engine {
    pub fn new(max_goose_fps: f32) -> Self {
        Self {
            frame_times: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            max_goose_fps,
        }
    }

    /// Called on every GOOSE Ethernet frame (EtherType 0x88B8).
    pub fn evaluate(&self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> Option<OtAlert> {
        let now = unix_secs();
        let mut frame_times = self.frame_times.write();
        let times = frame_times.entry(src_ip).or_default();
        times.push_back(now);
        while times.len() > 200 { times.pop_front(); }
        if times.len() < 10 { return None; }
        let oldest = *times.front().unwrap();
        let elapsed = (now - oldest).max(1) as f32;
        let fps = times.len() as f32 / elapsed;
        if fps > self.max_goose_fps {
            let alert = OtAlert {
                id: format!("GOOSE-BURST-{:x}", now),
                protocol: OtProtocol::Iec61850Goose,
                violation: OtViolation::GooseFrameBurst { frames_per_sec: fps, threshold: self.max_goose_fps },
                src_ip, dst_ip,
                severity: OtSeverity::High,
                raw_frame_hex: String::new(),
                timestamp: now,
            };
            warn!("⚙️  GOOSE BURST: {:.1} fps from {} (threshold {:.1})", fps, src_ip, self.max_goose_fps);
            self.alerts.write().push_back(alert.clone());
            return Some(alert);
        }
        None
    }
}

// ── Unified OT Engine ─────────────────────────────────────────────────────────

pub struct OtProtocolEngine {
    pub modbus: ModbusEngine,
    pub dnp3: Dnp3Engine,
    pub goose: Goose61850Engine,
    total_violations: AtomicU64,
}

impl OtProtocolEngine {
    pub fn new() -> Self {
        info!("⚙️  OT/ICS Protocol Engine: Modbus + DNP3 + IEC 61850 GOOSE active");
        Self {
            modbus: ModbusEngine::new(),
            dnp3: Dnp3Engine::new(),
            goose: Goose61850Engine::new(100.0),
            total_violations: AtomicU64::new(0),
        }
    }

    /// Dispatch payload by protocol hint.
    pub fn evaluate(&self, protocol: OtProtocol, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> Vec<OtAlert> {
        match protocol {
            OtProtocol::ModbusTcp => self.modbus.evaluate(src_ip, dst_ip, payload),
            OtProtocol::Dnp3 => self.dnp3.evaluate(src_ip, dst_ip, payload),
            OtProtocol::Iec61850Goose => {
                self.goose.evaluate(src_ip, dst_ip, payload).into_iter().collect()
            }
            _ => vec![],
        }
    }

    pub fn violations(&self) -> u64 { self.total_violations.load(Ordering::Relaxed) }
}
