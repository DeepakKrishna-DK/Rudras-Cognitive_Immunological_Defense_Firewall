// ============================================================================
// Rudras — Security Framework Alignment Engine
// ============================================================================
//
// Maps Rudras detection categories to industry-standard security frameworks:
//
//   MITRE ATT&CK  — Adversarial tactics, techniques, and procedures (TTPs)
//                   Used by CrowdStrike, Palo Alto, Fortinet, Microsoft Defender
//
//   OWASP Top 10  — Web application security risk categories
//                   Used by WAFs, AppSec tools, DAST/SAST scanners
//
// When the IDS engine fires an alert, the framework tags are automatically
// populated so SOC analysts see structured, industry-standard context:
//
//   Alert: Possible Command & Control traffic
//   Framework: MITRE ATT&CK
//   Technique:  T1071 — Application Layer Protocol (C2)
//   Tactic:     Command-and-Control
//   Severity:   High
//
// This module is additive-only — it does NOT modify detection logic.
// It only enriches existing alerts with framework metadata.
// ============================================================================

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::ids_engine::IdsCategory;

// ── MITRE ATT&CK Tactic (Kill-Chain Stage) ───────────────────────────────────

/// Top-level MITRE ATT&CK tactic — the "why" of the technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitreTactic {
    Reconnaissance,       // TA0043 — info gathering before attack
    ResourceDevelopment,  // TA0042 — acquiring infrastructure/tools
    InitialAccess,        // TA0001 — gaining first foothold
    Execution,            // TA0002 — running malicious code
    Persistence,          // TA0003 — maintaining presence
    PrivilegeEscalation,  // TA0004 — gaining higher-level permissions
    DefenseEvasion,       // TA0005 — avoiding detection
    CredentialAccess,     // TA0006 — stealing credentials
    Discovery,            // TA0007 — mapping the environment
    LateralMovement,      // TA0008 — moving through network
    Collection,           // TA0009 — gathering data of interest
    CommandAndControl,    // TA0011 — maintaining C2 channel
    Exfiltration,         // TA0010 — stealing data
    Impact,               // TA0040 — disrupting/manipulating systems
}

impl MitreTactic {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Reconnaissance      => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess       => "TA0001",
            Self::Execution           => "TA0002",
            Self::Persistence         => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion      => "TA0005",
            Self::CredentialAccess    => "TA0006",
            Self::Discovery           => "TA0007",
            Self::LateralMovement     => "TA0008",
            Self::Collection          => "TA0009",
            Self::CommandAndControl   => "TA0011",
            Self::Exfiltration        => "TA0010",
            Self::Impact              => "TA0040",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Reconnaissance      => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess       => "Initial Access",
            Self::Execution           => "Execution",
            Self::Persistence         => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion      => "Defense Evasion",
            Self::CredentialAccess    => "Credential Access",
            Self::Discovery           => "Discovery",
            Self::LateralMovement     => "Lateral Movement",
            Self::Collection          => "Collection",
            Self::CommandAndControl   => "Command and Control",
            Self::Exfiltration        => "Exfiltration",
            Self::Impact              => "Impact",
        }
    }
}

// ── MITRE ATT&CK Technique ───────────────────────────────────────────────────

/// A specific MITRE ATT&CK technique or sub-technique with structured metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MitreTechnique {
    /// Technique identifier e.g. "T1071"
    pub id: &'static str,
    /// Sub-technique identifier e.g. "T1071.001" — None if top-level
    pub sub_id: Option<&'static str>,
    /// Human-readable name
    pub name: &'static str,
    /// Which kill-chain tactic this technique belongs to
    pub tactic: MitreTactic,
}

impl MitreTechnique {
    /// Returns the most specific applicable ID (sub-technique if present)
    pub fn effective_id(&self) -> &'static str {
        self.sub_id.unwrap_or(self.id)
    }

    pub fn display(&self) -> String {
        format!(
            "{} — {} [{}]",
            self.effective_id(),
            self.name,
            self.tactic.label()
        )
    }

    pub fn log_line(&self) -> String {
        format!(
            "MITRE ATT&CK | Tactic: {} ({}) | Technique: {} ({})",
            self.tactic.label(),
            self.tactic.id(),
            self.name,
            self.effective_id()
        )
    }
}

// ── Pre-defined MITRE techniques most relevant to a network firewall ──────────

pub mod mitre {
    use super::{MitreTactic, MitreTechnique};

    // ── Reconnaissance ────────────────────────────────────────────────────
    pub const NETWORK_SCANNING: MitreTechnique = MitreTechnique {
        id: "T1595",
        sub_id: Some("T1595.001"),
        name: "Network Scanning / Port Scan",
        tactic: MitreTactic::Reconnaissance,
    };
    pub const SERVICE_DISCOVERY: MitreTechnique = MitreTechnique {
        id: "T1046",
        sub_id: None,
        name: "Network Service Discovery",
        tactic: MitreTactic::Discovery,
    };

    // ── Execution ─────────────────────────────────────────────────────────
    pub const COMMAND_SCRIPTING: MitreTechnique = MitreTechnique {
        id: "T1059",
        sub_id: None,
        name: "Command and Scripting Interpreter",
        tactic: MitreTactic::Execution,
    };

    // ── Credential Access ─────────────────────────────────────────────────
    pub const BRUTE_FORCE: MitreTechnique = MitreTechnique {
        id: "T1110",
        sub_id: None,
        name: "Brute Force",
        tactic: MitreTactic::CredentialAccess,
    };

    // ── Command and Control ───────────────────────────────────────────────
    pub const C2_APP_LAYER: MitreTechnique = MitreTechnique {
        id: "T1071",
        sub_id: None,
        name: "Application Layer Protocol (C2)",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const DNS_C2: MitreTechnique = MitreTechnique {
        id: "T1071",
        sub_id: Some("T1071.004"),
        name: "DNS Covert C2 Channel",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const DYNAMIC_RESOLUTION_DGA: MitreTechnique = MitreTechnique {
        id: "T1568",
        sub_id: Some("T1568.002"),
        name: "Domain Generation Algorithms (DGA)",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const ENCRYPTED_CHANNEL: MitreTechnique = MitreTechnique {
        id: "T1573",
        sub_id: None,
        name: "Encrypted Channel (TLS Anomaly)",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const NON_STANDARD_PORT: MitreTechnique = MitreTechnique {
        id: "T1571",
        sub_id: None,
        name: "Non-Standard Port",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const PORT_KNOCKING: MitreTechnique = MitreTechnique {
        id: "T1205",
        sub_id: Some("T1205.001"),
        name: "Port Knocking (Traffic Signaling)",
        tactic: MitreTactic::DefenseEvasion,
    };

    // ── Exfiltration ──────────────────────────────────────────────────────
    pub const EXFIL_OVER_C2: MitreTechnique = MitreTechnique {
        id: "T1041",
        sub_id: None,
        name: "Exfiltration Over C2 Channel",
        tactic: MitreTactic::Exfiltration,
    };
    pub const EXFIL_OVER_PROTO: MitreTechnique = MitreTechnique {
        id: "T1048",
        sub_id: None,
        name: "Exfiltration Over Alternative Protocol",
        tactic: MitreTactic::Exfiltration,
    };
    pub const EXFIL_DNS: MitreTechnique = MitreTechnique {
        id: "T1048",
        sub_id: Some("T1048.003"),
        name: "Exfiltration Over DNS Tunnel",
        tactic: MitreTactic::Exfiltration,
    };

    // ── Impact ────────────────────────────────────────────────────────────
    pub const RANSOMWARE: MitreTechnique = MitreTechnique {
        id: "T1486",
        sub_id: None,
        name: "Data Encrypted for Impact (Ransomware)",
        tactic: MitreTactic::Impact,
    };
    pub const NETWORK_DOS: MitreTechnique = MitreTechnique {
        id: "T1498",
        sub_id: None,
        name: "Network Denial of Service",
        tactic: MitreTactic::Impact,
    };
    pub const DOS_REFLECTION: MitreTechnique = MitreTechnique {
        id: "T1498",
        sub_id: Some("T1498.002"),
        name: "Reflection / Amplification DoS (SYN/UDP/ICMP Flood)",
        tactic: MitreTactic::Impact,
    };

    // ── Lateral Movement ──────────────────────────────────────────────────
    pub const LATERAL_TOOL_TRANSFER: MitreTechnique = MitreTechnique {
        id: "T1570",
        sub_id: None,
        name: "Lateral Tool Transfer",
        tactic: MitreTactic::LateralMovement,
    };
    pub const REMOTE_SERVICES: MitreTechnique = MitreTechnique {
        id: "T1021",
        sub_id: None,
        name: "Remote Services (SMB/RDP/WMI pivot)",
        tactic: MitreTactic::LateralMovement,
    };

    // ── Initial Access ────────────────────────────────────────────────────
    pub const EXPLOIT_PUBLIC_FACING: MitreTechnique = MitreTechnique {
        id: "T1190",
        sub_id: None,
        name: "Exploit Public-Facing Application",
        tactic: MitreTactic::InitialAccess,
    };
    pub const MALWARE_DRIVE_BY: MitreTechnique = MitreTechnique {
        id: "T1189",
        sub_id: None,
        name: "Drive-by Compromise (Malware Download)",
        tactic: MitreTactic::InitialAccess,
    };

    // ── NEW: Malware & Botnet ─────────────────────────────────────────────
    pub const WORM_REPLICATION: MitreTechnique = MitreTechnique {
        id: "T1570",
        sub_id: None,
        name: "Worm / Lateral Tool Transfer via Self-Replication",
        tactic: MitreTactic::LateralMovement,
    };
    pub const TROJAN_CALLBACK: MitreTechnique = MitreTechnique {
        id: "T1071",
        sub_id: Some("T1071.001"),
        name: "Trojan Web Protocol Callback (RAT C2)",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const RESOURCE_HIJACKING: MitreTechnique = MitreTechnique {
        id: "T1496",
        sub_id: None,
        name: "Resource Hijacking (Cryptojacking)",
        tactic: MitreTactic::Impact,
    };
    pub const INGRESS_TOOL_TRANSFER: MitreTechnique = MitreTechnique {
        id: "T1105",
        sub_id: None,
        name: "Ingress Tool Transfer (Dropper / Downloader)",
        tactic: MitreTactic::CommandAndControl,
    };
    pub const REMOTE_ACCESS_BACKDOOR: MitreTechnique = MitreTechnique {
        id: "T1219",
        sub_id: None,
        name: "Remote Access Software (Backdoor RAT)",
        tactic: MitreTactic::CommandAndControl,
    };

    // ── NEW: DoS / Amplification ──────────────────────────────────────────
    pub const ENDPOINT_DOS: MitreTechnique = MitreTechnique {
        id: "T1499",
        sub_id: None,
        name: "Endpoint Denial of Service",
        tactic: MitreTactic::Impact,
    };
    pub const SERVICE_STOP: MitreTechnique = MitreTechnique {
        id: "T1489",
        sub_id: None,
        name: "Service Stop / Slowloris Exhaustion",
        tactic: MitreTactic::Impact,
    };

    // ── NEW: Network Spoofing / Man-in-the-Middle ─────────────────────────
    pub const ARP_CACHE_POISON: MitreTechnique = MitreTechnique {
        id: "T1557",
        sub_id: Some("T1557.002"),
        name: "ARP Cache Poisoning (MITM)",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const DNS_SPOOF: MitreTechnique = MitreTechnique {
        id: "T1557",
        sub_id: Some("T1557.003"),
        name: "DNS Spoofing / Cache Poisoning",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const NETWORK_SNIFFING: MitreTechnique = MitreTechnique {
        id: "T1040",
        sub_id: None,
        name: "Network Sniffing (Passive Capture)",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const ADVERSARY_IN_THE_MIDDLE: MitreTechnique = MitreTechnique {
        id: "T1557",
        sub_id: None,
        name: "Adversary-in-the-Middle (Session / BGP Hijacking)",
        tactic: MitreTactic::CredentialAccess,
    };

    // ── NEW: Web / WAF ────────────────────────────────────────────────────
    pub const CSRF_TECHNIQUE: MitreTechnique = MitreTechnique {
        id: "T1185",
        sub_id: None,
        name: "Browser Session Hijacking / CSRF",
        tactic: MitreTactic::Collection,
    };
    pub const SSRF_TECHNIQUE: MitreTechnique = MitreTechnique {
        id: "T1190",
        sub_id: None,
        name: "Server-Side Request Forgery (SSRF)",
        tactic: MitreTactic::InitialAccess,
    };
    pub const HTTP_SMUGGLING: MitreTechnique = MitreTechnique {
        id: "T1190",
        sub_id: None,
        name: "HTTP Request Smuggling",
        tactic: MitreTactic::InitialAccess,
    };
    pub const INSECURE_DESER: MitreTechnique = MitreTechnique {
        id: "T1190",
        sub_id: None,
        name: "Insecure Deserialization RCE",
        tactic: MitreTactic::Execution,
    };

    // ── NEW: Credential / Authentication Attacks ──────────────────────────
    pub const PASSWORD_SPRAYING: MitreTechnique = MitreTechnique {
        id: "T1110",
        sub_id: Some("T1110.003"),
        name: "Password Spraying",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const CREDENTIAL_STUFFING: MitreTechnique = MitreTechnique {
        id: "T1110",
        sub_id: Some("T1110.004"),
        name: "Credential Stuffing",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const STEAL_WEB_SESSION_COOKIE: MitreTechnique = MitreTechnique {
        id: "T1539",
        sub_id: None,
        name: "Steal Web Session Cookie / Token Hijacking",
        tactic: MitreTactic::CredentialAccess,
    };

    // ── NEW: Memory / Exploitation ────────────────────────────────────────
    pub const EXPLOIT_CLIENT_EXEC: MitreTechnique = MitreTechnique {
        id: "T1203",
        sub_id: None,
        name: "Exploitation for Client Execution (Buffer/Heap/Stack Overflow)",
        tactic: MitreTactic::Execution,
    };
    pub const PRIVILEGE_ESCALATION_EXPLOIT: MitreTechnique = MitreTechnique {
        id: "T1068",
        sub_id: None,
        name: "Exploitation for Privilege Escalation",
        tactic: MitreTactic::PrivilegeEscalation,
    };
    pub const ZERO_DAY: MitreTechnique = MitreTechnique {
        id: "T1203",
        sub_id: None,
        name: "Zero-Day Anomaly / Unknown Exploit Pattern",
        tactic: MitreTactic::Execution,
    };

    // ── NEW: APT / Persistence / Evasion ─────────────────────────────────
    pub const CREATE_SCHEDULED_TASK: MitreTechnique = MitreTechnique {
        id: "T1053",
        sub_id: None,
        name: "Scheduled Task / Job (Persistence Traffic)",
        tactic: MitreTactic::Persistence,
    };
    pub const OS_CREDENTIAL_DUMPING: MitreTechnique = MitreTechnique {
        id: "T1003",
        sub_id: None,
        name: "OS Credential Dumping (LSASS/SAM/NTDS over network)",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const LOLBINS: MitreTechnique = MitreTechnique {
        id: "T1218",
        sub_id: None,
        name: "Living-Off-the-Land Binaries (LOLBins network activity)",
        tactic: MitreTactic::DefenseEvasion,
    };
    pub const OBFUSCATED_FILES: MitreTechnique = MitreTechnique {
        id: "T1027",
        sub_id: None,
        name: "Obfuscated Files / Protocol Masquerading (Defense Evasion)",
        tactic: MitreTactic::DefenseEvasion,
    };

    // ── NEW: Cloud & API ──────────────────────────────────────────────────
    pub const CLOUD_API_ABUSE: MitreTechnique = MitreTechnique {
        id: "T1530",
        sub_id: None,
        name: "Data from Cloud Storage / API Abuse",
        tactic: MitreTactic::Collection,
    };
    pub const CLOUD_METADATA_ACCESS: MitreTechnique = MitreTechnique {
        id: "T1552",
        sub_id: Some("T1552.005"),
        name: "Cloud Instance Metadata API (IMDS Exploitation)",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const CONTAINER_ESCAPE: MitreTechnique = MitreTechnique {
        id: "T1611",
        sub_id: None,
        name: "Escape to Host (Container Breakout Signal)",
        tactic: MitreTactic::PrivilegeEscalation,
    };

    // ── NEW: Wireless ─────────────────────────────────────────────────────
    pub const EVIL_TWIN_AP: MitreTechnique = MitreTechnique {
        id: "T1557",
        sub_id: Some("T1557.004"),
        name: "Evil Twin / Rogue Access Point (Wi-Fi MITM)",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const WIFI_DEAUTH: MitreTechnique = MitreTechnique {
        id: "T1498",
        sub_id: None,
        name: "Wi-Fi Deauthentication Flood (DoS)",
        tactic: MitreTactic::Impact,
    };

    // ── NEW: Cryptographic Attacks ────────────────────────────────────────
    pub const CRYPTO_BRUTE_FORCE: MitreTechnique = MitreTechnique {
        id: "T1110",
        sub_id: Some("T1110.001"),
        name: "Brute Force — Key/Password Exhaustion",
        tactic: MitreTactic::CredentialAccess,
    };
    pub const TLS_DOWNGRADE: MitreTechnique = MitreTechnique {
        id: "T1573",
        sub_id: None,
        name: "TLS Downgrade / Protocol Downgrade Attack",
        tactic: MitreTactic::CommandAndControl,
    };
}

// ── OWASP Top 10 (2021) ──────────────────────────────────────────────────────

/// OWASP Top 10 — 2021 edition risk categories.
/// Reference: https://owasp.org/Top10/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwaspCategory {
    /// A01 — Broken Access Control
    BrokenAccessControl,
    /// A02 — Cryptographic Failures (formerly Sensitive Data Exposure)
    CryptographicFailures,
    /// A03 — Injection (SQL, OS, LDAP, NoSQL, SSTI)
    Injection,
    /// A04 — Insecure Design
    InsecureDesign,
    /// A05 — Security Misconfiguration
    SecurityMisconfiguration,
    /// A06 — Vulnerable and Outdated Components
    VulnerableComponents,
    /// A07 — Identification and Authentication Failures (Brute Force, Session)
    AuthenticationFailures,
    /// A08 — Software and Data Integrity Failures
    IntegrityFailures,
    /// A09 — Security Logging and Monitoring Failures
    LoggingFailures,
    /// A10 — Server-Side Request Forgery (SSRF)
    ServerSideRequestForgery,
}

impl OwaspCategory {
    pub fn id(&self) -> &'static str {
        match self {
            Self::BrokenAccessControl     => "A01:2021",
            Self::CryptographicFailures   => "A02:2021",
            Self::Injection               => "A03:2021",
            Self::InsecureDesign          => "A04:2021",
            Self::SecurityMisconfiguration=> "A05:2021",
            Self::VulnerableComponents    => "A06:2021",
            Self::AuthenticationFailures  => "A07:2021",
            Self::IntegrityFailures       => "A08:2021",
            Self::LoggingFailures         => "A09:2021",
            Self::ServerSideRequestForgery=> "A10:2021",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::BrokenAccessControl      => "Broken Access Control",
            Self::CryptographicFailures    => "Cryptographic Failures",
            Self::Injection                => "Injection",
            Self::InsecureDesign           => "Insecure Design",
            Self::SecurityMisconfiguration => "Security Misconfiguration",
            Self::VulnerableComponents     => "Vulnerable and Outdated Components",
            Self::AuthenticationFailures   => "Identification and Authentication Failures",
            Self::IntegrityFailures        => "Software and Data Integrity Failures",
            Self::LoggingFailures          => "Security Logging and Monitoring Failures",
            Self::ServerSideRequestForgery => "Server-Side Request Forgery (SSRF)",
        }
    }

    pub fn log_line(&self) -> String {
        format!("OWASP Top 10 | {} — {}", self.id(), self.label())
    }
}

// ── Unified Framework Tag ─────────────────────────────────────────────────────

/// A single framework classification tag attached to an IDS alert.
/// Each alert may have zero or more tags (multi-framework alerts are common).
#[derive(Debug, Clone, Serialize)]
pub enum FrameworkTag {
    Mitre(MitreTechnique),
    Owasp(OwaspCategory),
}

impl FrameworkTag {
    /// Short log-friendly string for tracing macros
    pub fn short_label(&self) -> String {
        match self {
            Self::Mitre(t)  => format!("MITRE:{}", t.effective_id()),
            Self::Owasp(c)  => format!("OWASP:{}", c.id()),
        }
    }

    /// Full structured description suitable for SIEM event fields
    pub fn full_log(&self) -> String {
        match self {
            Self::Mitre(t) => t.log_line(),
            Self::Owasp(c) => c.log_line(),
        }
    }
}

// ── Core Mapping Function ────────────────────────────────────────────────────

/// Maps an `IdsCategory` to one or more `FrameworkTag`s.
///
/// A single IDS detection may map to multiple framework entries — for example,
/// SQL Injection is both MITRE T1190 (Exploit Public-Facing App) and
/// OWASP A03 (Injection).  All applicable tags are returned.
///
/// This function is called by `IdsEngine::make_alert()` at alert-creation time
/// so every `IdsAlert` carries pre-computed framework context — no extra work
/// is needed downstream in the IPS engine, SIEM connector, or log formatter.
pub fn map_ids_category(cat: &IdsCategory) -> Vec<FrameworkTag> {
    use mitre::*;
    use FrameworkTag::{Mitre, Owasp};

    match cat {
        // ── Port / Service Discovery ──────────────────────────────────────
        IdsCategory::PortScan => vec![
            Mitre(NETWORK_SCANNING),
        ],
        IdsCategory::ServiceEnumeration => vec![
            Mitre(SERVICE_DISCOVERY),
        ],

        // ── Credential Attacks ────────────────────────────────────────────
        IdsCategory::BruteForce => vec![
            Mitre(BRUTE_FORCE),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],

        // ── Web Application Attacks ───────────────────────────────────────
        IdsCategory::SQLInjection => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::XSS => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),                // XSS is subclass of injection
        ],
        IdsCategory::CommandInjection => vec![
            Mitre(COMMAND_SCRIPTING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::DirectoryTraversal => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::ExploitAttempt => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::VulnerableComponents),
        ],

        // ── Command & Control ─────────────────────────────────────────────
        IdsCategory::C2Communication => vec![
            Mitre(C2_APP_LAYER),
        ],
        IdsCategory::DgaActivity => vec![
            Mitre(DYNAMIC_RESOLUTION_DGA),
        ],
        IdsCategory::DnsTunneling => vec![
            Mitre(DNS_C2),
            Mitre(EXFIL_DNS),
        ],
        IdsCategory::TlsAnomaly => vec![
            Mitre(ENCRYPTED_CHANNEL),
            Owasp(OwaspCategory::CryptographicFailures),
        ],

        // ── Data Exfiltration ─────────────────────────────────────────────
        IdsCategory::DataExfiltration => vec![
            Mitre(EXFIL_OVER_C2),
            Mitre(EXFIL_OVER_PROTO),
        ],

        // ── Lateral Movement ──────────────────────────────────────────────
        IdsCategory::LateralMovement => vec![
            Mitre(REMOTE_SERVICES),
            Mitre(LATERAL_TOOL_TRANSFER),
        ],

        // ── Ransomware / Impact ───────────────────────────────────────────
        IdsCategory::Ransomware => vec![
            Mitre(RANSOMWARE),
        ],

        // ── Denial of Service ─────────────────────────────────────────────
        IdsCategory::SynFlood | IdsCategory::UdpFlood | IdsCategory::IcmpFlood => vec![
            Mitre(DOS_REFLECTION),
            Mitre(NETWORK_DOS),
        ],

        // ── Malware Delivery ──────────────────────────────────────────────
        IdsCategory::MalwareDownload => vec![
            Mitre(MALWARE_DRIVE_BY),
            Owasp(OwaspCategory::VulnerableComponents),
        ],

        // ── Protocol Anomaly — may indicate evasion or non-standard port ──
        IdsCategory::ProtocolAnomaly => vec![
            Mitre(NON_STANDARD_PORT),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],

        // ── Honeypot / Policy — governance tracking ───────────────────────
        IdsCategory::Honeypot | IdsCategory::PolicyViolation => vec![
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],

        // ── Malware & Botnet ──────────────────────────────────────────────
        IdsCategory::WormPropagation => vec![
            Mitre(WORM_REPLICATION),
        ],
        IdsCategory::TrojanCommunication => vec![
            Mitre(TROJAN_CALLBACK),
        ],
        IdsCategory::SpywareExfiltration => vec![
            Mitre(EXFIL_OVER_C2),
            Mitre(EXFIL_OVER_PROTO),
        ],
        IdsCategory::BotnetTraffic => vec![
            Mitre(C2_APP_LAYER),
        ],
        IdsCategory::CryptojackingTraffic => vec![
            Mitre(RESOURCE_HIJACKING),
        ],
        IdsCategory::DropperDownload => vec![
            Mitre(INGRESS_TOOL_TRANSFER),
            Owasp(OwaspCategory::VulnerableComponents),
        ],
        IdsCategory::BackdoorAccess => vec![
            Mitre(REMOTE_ACCESS_BACKDOOR),
        ],
        IdsCategory::BankingMalwareComm => vec![
            Mitre(C2_APP_LAYER),
        ],
        IdsCategory::IotMalwarePropagation => vec![
            Mitre(WORM_REPLICATION),
            Mitre(C2_APP_LAYER),
        ],

        // ── Network / Amplification DoS ───────────────────────────────────
        IdsCategory::DnsAmplification
        | IdsCategory::NtpAmplification
        | IdsCategory::HttpFlood
        | IdsCategory::SlowlorisAttack
        | IdsCategory::PingOfDeath
        | IdsCategory::SmurfAttack
        | IdsCategory::FraggleAttack
        | IdsCategory::DDoS => vec![
            Mitre(NETWORK_DOS),
            Mitre(DOS_REFLECTION),
        ],

        // ── Spoofing & MITM ───────────────────────────────────────────────
        IdsCategory::ArpSpoofing => vec![
            Mitre(ARP_CACHE_POISON),
            Owasp(OwaspCategory::InsecureDesign),
        ],
        IdsCategory::DnsSpoofing => vec![
            Mitre(DNS_SPOOF),
        ],
        IdsCategory::IpSpoofing | IdsCategory::MacSpoofing => vec![
            Mitre(ADVERSARY_IN_THE_MIDDLE),
            Owasp(OwaspCategory::InsecureDesign),
        ],
        IdsCategory::BgpHijackingAttempt | IdsCategory::SessionHijacking => vec![
            Mitre(ADVERSARY_IN_THE_MIDDLE),
        ],
        IdsCategory::PacketSniffing => vec![
            Mitre(NETWORK_SNIFFING),
        ],
        IdsCategory::TrafficAnomaly => vec![
            Mitre(NON_STANDARD_PORT),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],

        // ── Web / WAF ─────────────────────────────────────────────────────
        IdsCategory::BlindSqlInjection => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::StoredXss | IdsCategory::ReflectedXss | IdsCategory::DomXss => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::Csrf => vec![
            Mitre(CSRF_TECHNIQUE),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::Ssrf => vec![
            Mitre(SSRF_TECHNIQUE),
            Owasp(OwaspCategory::ServerSideRequestForgery),
        ],
        IdsCategory::LdapInjection
        | IdsCategory::XpathInjection
        | IdsCategory::XmlInjection => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::RemoteFileInclusion => vec![
            Mitre(INGRESS_TOOL_TRANSFER),
            Owasp(OwaspCategory::VulnerableComponents),
        ],
        IdsCategory::LocalFileInclusion => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::InsecureDeserialization => vec![
            Mitre(INSECURE_DESER),
            Owasp(OwaspCategory::IntegrityFailures),
        ],
        IdsCategory::Clickjacking => vec![
            Mitre(CSRF_TECHNIQUE),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::HttpRequestSmuggling => vec![
            Mitre(HTTP_SMUGGLING),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],
        IdsCategory::HttpResponseSplitting => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::Injection),
        ],
        IdsCategory::OpenRedirect => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],

        // ── Authentication Attacks ────────────────────────────────────────
        IdsCategory::PasswordSpraying => vec![
            Mitre(PASSWORD_SPRAYING),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],
        IdsCategory::CredentialStuffing => vec![
            Mitre(CREDENTIAL_STUFFING),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],
        IdsCategory::SessionFixation => vec![
            Mitre(STEAL_WEB_SESSION_COOKIE),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],
        IdsCategory::TokenHijacking => vec![
            Mitre(STEAL_WEB_SESSION_COOKIE),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],
        IdsCategory::OAuthAbuse => vec![
            Mitre(STEAL_WEB_SESSION_COOKIE),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],

        // ── Memory / Exploitation ─────────────────────────────────────────
        IdsCategory::BufferOverflowAttempt
        | IdsCategory::FormatStringAttack
        | IdsCategory::UseAfterFreeAttempt => vec![
            Mitre(EXPLOIT_CLIENT_EXEC),
            Owasp(OwaspCategory::VulnerableComponents),
        ],
        IdsCategory::RceAttempt => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Mitre(EXPLOIT_CLIENT_EXEC),
            Owasp(OwaspCategory::VulnerableComponents),
        ],
        IdsCategory::PrivilegeEscalation => vec![
            Mitre(PRIVILEGE_ESCALATION_EXPLOIT),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::ZeroDayAnomaly => vec![
            Mitre(ZERO_DAY),
            Owasp(OwaspCategory::VulnerableComponents),
        ],

        // ── APT Network Indicators ────────────────────────────────────────
        IdsCategory::InitialAccessExploit => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
        ],
        IdsCategory::PersistenceIndicator => vec![
            Mitre(CREATE_SCHEDULED_TASK),
        ],
        IdsCategory::CredentialDumpTraffic => vec![
            Mitre(OS_CREDENTIAL_DUMPING),
            Owasp(OwaspCategory::AuthenticationFailures),
        ],
        IdsCategory::LivingOffLand => vec![
            Mitre(LOLBINS),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],
        IdsCategory::DefenseEvasionNetwork => vec![
            Mitre(OBFUSCATED_FILES),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],

        // ── Cloud & API ───────────────────────────────────────────────────
        IdsCategory::ApiAbuse => vec![
            Mitre(CLOUD_API_ABUSE),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
        IdsCategory::CloudCredentialTheft => vec![
            Mitre(CLOUD_METADATA_ACCESS),
            Owasp(OwaspCategory::CryptographicFailures),
        ],
        IdsCategory::MetadataExploitation => vec![
            Mitre(CLOUD_METADATA_ACCESS),
            Owasp(OwaspCategory::ServerSideRequestForgery),
        ],
        IdsCategory::ContainerEscapeSignal => vec![
            Mitre(CONTAINER_ESCAPE),
            Owasp(OwaspCategory::InsecureDesign),
        ],
        IdsCategory::KubernetesApiAttack => vec![
            Mitre(EXPLOIT_PUBLIC_FACING),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],

        // ── Wireless ──────────────────────────────────────────────────────
        IdsCategory::EvilTwinDetection | IdsCategory::RogueAccessPoint => vec![
            Mitre(EVIL_TWIN_AP),
            Owasp(OwaspCategory::InsecureDesign),
        ],
        IdsCategory::WifiDeauth => vec![
            Mitre(WIFI_DEAUTH),
        ],
        IdsCategory::WpaCrackAttempt => vec![
            Mitre(CRYPTO_BRUTE_FORCE),
            Owasp(OwaspCategory::CryptographicFailures),
        ],
        IdsCategory::BluetoothAttack => vec![
            Mitre(ADVERSARY_IN_THE_MIDDLE),
            Owasp(OwaspCategory::InsecureDesign),
        ],

        // ── Cryptographic Anomalies ───────────────────────────────────────
        IdsCategory::BruteForceDecryption => vec![
            Mitre(CRYPTO_BRUTE_FORCE),
            Owasp(OwaspCategory::CryptographicFailures),
        ],
        IdsCategory::TimingAttack => vec![
            Mitre(CRYPTO_BRUTE_FORCE),
            Owasp(OwaspCategory::CryptographicFailures),
        ],
        IdsCategory::PaddingOracleAttack => vec![
            Mitre(OBFUSCATED_FILES),
            Owasp(OwaspCategory::CryptographicFailures),
        ],
        IdsCategory::TlsDowngrade => vec![
            Mitre(TLS_DOWNGRADE),
            Owasp(OwaspCategory::CryptographicFailures),
        ],

        // ── Insider / Supply Chain ────────────────────────────────────────
        IdsCategory::InsiderDataExfiltration => vec![
            Mitre(EXFIL_OVER_PROTO),
            Owasp(OwaspCategory::LoggingFailures),
        ],
        IdsCategory::SuspiciousInternalTraffic => vec![
            Mitre(REMOTE_SERVICES),
            Owasp(OwaspCategory::SecurityMisconfiguration),
        ],
        IdsCategory::UnauthorizedExternalConn => vec![
            Mitre(NON_STANDARD_PORT),
            Owasp(OwaspCategory::BrokenAccessControl),
        ],
    }
}

// ── Log Formatter ────────────────────────────────────────────────────────────

/// Formats the framework tags for a concise single-line SIEM/log output.
///
/// Example output:
///   `[MITRE:T1071 | OWASP:A03:2021]`
pub fn format_tags_short(tags: &[FrameworkTag]) -> String {
    if tags.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = tags.iter().map(|t| t.short_label()).collect();
    format!("[{}]", parts.join(" | "))
}

/// Formats a multi-line structured framework report for verbose SIEM events.
///
/// Example output (two lines):
///   MITRE ATT&CK | Tactic: Command and Control (TA0011) | Technique: Application Layer Protocol (C2) (T1071)
///   OWASP Top 10 | A03:2021 — Injection
pub fn format_tags_verbose(tags: &[FrameworkTag]) -> Vec<String> {
    tags.iter().map(|t| t.full_log()).collect()
}

// ── Detection Matrix (reference, used in docs / audit output) ────────────────

/// One row in the detection matrix suitable for structured reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatrixRow {
    pub ids_category: String,
    pub framework: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic_or_risk: String,
}

/// Builds the full detection matrix for all IDS categories.
/// Call once on startup (e.g. for audit trail or documentation generation).
pub fn build_detection_matrix() -> Vec<DetectionMatrixRow> {
    use IdsCategory::*;

    let all_categories = [
        PortScan, ServiceEnumeration, BruteForce, ExploitAttempt,
        SQLInjection, XSS, CommandInjection, DirectoryTraversal,
        C2Communication, DgaActivity, DnsTunneling, DataExfiltration,
        LateralMovement, Ransomware, MalwareDownload, SynFlood,
        UdpFlood, IcmpFlood, TlsAnomaly, ProtocolAnomaly,
        Honeypot, PolicyViolation,
    ];

    let mut rows = Vec::new();

    for cat in &all_categories {
        let tags = map_ids_category(cat);
        if tags.is_empty() {
            rows.push(DetectionMatrixRow {
                ids_category: format!("{:?}", cat),
                framework: "—".into(),
                technique_id: "—".into(),
                technique_name: "—".into(),
                tactic_or_risk: "—".into(),
            });
        } else {
            for tag in &tags {
                let row = match tag {
                    FrameworkTag::Mitre(t) => DetectionMatrixRow {
                        ids_category: format!("{:?}", cat),
                        framework: "MITRE ATT&CK".into(),
                        technique_id: t.effective_id().into(),
                        technique_name: t.name.into(),
                        tactic_or_risk: t.tactic.label().into(),
                    },
                    FrameworkTag::Owasp(c) => DetectionMatrixRow {
                        ids_category: format!("{:?}", cat),
                        framework: "OWASP Top 10".into(),
                        technique_id: c.id().into(),
                        technique_name: c.label().into(),
                        tactic_or_risk: c.label().into(),
                    },
                };
                rows.push(row);
            }
        }
    }

    rows
}

/// Prints the detection matrix to the log on startup (INFO level).
/// Called once by main() after the IDS engine is initialized.
pub fn log_detection_matrix() {
    use tracing::info;

    info!("╔══════════════════════════════════════════════════════════════════╗");
    info!("║        RUDRAS — SECURITY FRAMEWORK ALIGNMENT MATRIX             ║");
    info!("╠══════════════════════════════════════════════════════════════════╣");
    info!("║  Framework: MITRE ATT&CK v14  +  OWASP Top 10 (2021)           ║");
    info!("╠════════════════════╦══════════════╦═════════════╦═══════════════╣");
    info!("║ IDS Category       ║ Framework    ║ Technique   ║ Tactic/Risk   ║");
    info!("╠════════════════════╬══════════════╬═════════════╬═══════════════╣");

    let matrix = build_detection_matrix();
    for row in &matrix {
        info!(
            "║ {:<19} ║ {:<12} ║ {:<11} ║ {:<13} ║",
            truncate(&row.ids_category, 19),
            truncate(&row.framework, 12),
            truncate(&row.technique_id, 11),
            truncate(&row.tactic_or_risk, 13),
        );
    }

    info!("╠══════════════════════════════════════════════════════════════════╣");
    info!("║  Total mapped detections: {:<38} ║", matrix.len());
    info!("╚══════════════════════════════════════════════════════════════════╝");
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
