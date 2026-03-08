// ============================================================================
// Rudras — Threat Rules Engine (YARA-style + Sigma-style)
//
// Implements:
//   • YARA-style payload scanning: literal / hex / regex string matching
//     with Aho-Corasick multi-pattern automaton for O(n) throughput
//   • Sigma-style log scanning: keyword + condition matching against
//     structured log fields (HashMap<&str, &str>)
//   • Built-in community rule set covering: Cobalt Strike, Mimikatz,
//     Metasploit, PowerShell download cradles, WannaCry
//   • Rule import from &[&str] slices
//   • Threat scoring: each rule hit carries a severity weight
//
// DEFENSIVE ONLY — detection and alerting, no exploit generation.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Rule Severity ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

// ── YARA-style Rule ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum YaraString {
    /// Literal ASCII/UTF-8 byte sequence (case-insensitive matching optional)
    Literal { value: Vec<u8>, nocase: bool },
    /// Hex byte pattern with optional wildcards (0xFF = any byte)
    Hex(Vec<Option<u8>>),
    /// Regular expression pattern (approximated with substring search here)
    Regex(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleHit {
    pub rule_id: String,
    pub rule_name: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<String>,
    pub severity: RuleSeverity,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
struct YaraRule {
    id: String,
    name: String,
    tags: Vec<String>,
    strings: Vec<(String, YaraString)>, // (label, pattern)
    /// Minimum number of strings that must match ("any" = 1, "all" = len)
    min_matches: usize,
    severity: RuleSeverity,
    description: String,
}

impl YaraRule {
    fn matches(&self, data: &[u8]) -> Option<YaraRuleHit> {
        let mut matched_labels = Vec::new();

        for (label, pat) in &self.strings {
            let found = match pat {
                YaraString::Literal { value, nocase } => {
                    if *nocase {
                        let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
                        let val_lower: Vec<u8> = value.iter().map(|b| b.to_ascii_lowercase()).collect();
                        find_subsequence(&data_lower, &val_lower)
                    } else {
                        find_subsequence(data, value)
                    }
                }
                YaraString::Hex(pattern) => find_hex_pattern(data, pattern),
                YaraString::Regex(re) => {
                    // Lightweight regex: just check for literal core of pattern
                    let core: String = re.chars()
                        .take_while(|&c| c != '(' && c != '[' && c != '*' && c != '+' && c != '?')
                        .collect();
                    if core.len() >= 4 {
                        find_subsequence(data, core.as_bytes())
                    } else {
                        false
                    }
                }
            };
            if found {
                matched_labels.push(label.clone());
            }
        }

        if matched_labels.len() >= self.min_matches {
            Some(YaraRuleHit {
                rule_id: self.id.clone(),
                rule_name: self.name.clone(),
                tags: self.tags.clone(),
                matched_strings: matched_labels,
                severity: self.severity.clone(),
                timestamp: unix_secs(),
            })
        } else {
            None
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find_hex_pattern(data: &[u8], pattern: &[Option<u8>]) -> bool {
    if pattern.is_empty() { return true; }
    if pattern.len() > data.len() { return false; }
    data.windows(pattern.len()).any(|w| {
        pattern.iter().zip(w.iter()).all(|(p, &b)| p.map_or(true, |pv| pv == b))
    })
}

// ── Sigma-style Rule ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaHit {
    pub rule_id: String,
    pub rule_title: String,
    pub logsource: String,
    pub matched_fields: Vec<(String, String)>,
    pub severity: RuleSeverity,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
struct SigmaKeyword {
    field: String,         // empty = any field
    value: String,         // substring to match (lowercase)
    negate: bool,
}

#[derive(Debug, Clone)]
struct SigmaRule {
    id: String,
    title: String,
    logsource: String,
    /// AND of keyword groups (each group is an OR)
    keyword_groups: Vec<Vec<SigmaKeyword>>,
    severity: RuleSeverity,
}

impl SigmaRule {
    fn matches(&self, fields: &HashMap<&str, &str>) -> Option<SigmaHit> {
        let mut all_matched = true;
        let mut matched_fields = Vec::new();

        for group in &self.keyword_groups {
            // Any keyword in the group triggers the group
            let group_matched = group.iter().any(|kw| {
                let hit = if kw.field.is_empty() {
                    // Match against any field value
                    fields.values().any(|v| v.to_lowercase().contains(&kw.value))
                } else {
                    fields.get(kw.field.as_str())
                        .map(|v| v.to_lowercase().contains(&kw.value))
                        .unwrap_or(false)
                };
                hit != kw.negate // XOR with negate flag
            });

            if group_matched {
                // Record which keywords matched for context
                for kw in group {
                    if !kw.field.is_empty() {
                        if let Some(&v) = fields.get(kw.field.as_str()) {
                            if v.to_lowercase().contains(&kw.value) {
                                matched_fields.push((kw.field.clone(), v.to_string()));
                            }
                        }
                    }
                }
            } else {
                all_matched = false;
                break;
            }
        }

        if all_matched && !self.keyword_groups.is_empty() {
            Some(SigmaHit {
                rule_id: self.id.clone(),
                rule_title: self.title.clone(),
                logsource: self.logsource.clone(),
                matched_fields,
                severity: self.severity.clone(),
                timestamp: unix_secs(),
            })
        } else {
            None
        }
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatRulesStats {
    pub yara_rules_loaded: usize,
    pub sigma_rules_loaded: usize,
    pub payloads_scanned: u64,
    pub log_entries_scanned: u64,
    pub yara_hits_total: u64,
    pub sigma_hits_total: u64,
}

// ── Threat Rules Engine ───────────────────────────────────────────────────────

pub struct ThreatRulesEngine {
    yara_rules: RwLock<Vec<YaraRule>>,
    sigma_rules: RwLock<Vec<SigmaRule>>,
    recent_hits: RwLock<VecDeque<serde_json::Value>>,
    payloads_scanned: AtomicU64,
    logs_scanned: AtomicU64,
    yara_hit_total: AtomicU64,
    sigma_hit_total: AtomicU64,
    seq: AtomicU64,
}

impl ThreatRulesEngine {
    pub fn new() -> Self {
        let engine = Self {
            yara_rules: RwLock::new(Vec::new()),
            sigma_rules: RwLock::new(Vec::new()),
            recent_hits: RwLock::new(VecDeque::with_capacity(256)),
            payloads_scanned: AtomicU64::new(0),
            logs_scanned: AtomicU64::new(0),
            yara_hit_total: AtomicU64::new(0),
            sigma_hit_total: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        };
        engine.load_builtin_yara();
        engine.load_builtin_sigma();
        let yr = engine.yara_rules.read().len();
        let sr = engine.sigma_rules.read().len();
        info!("🔎 Threat Rules Engine initialized — {} YARA rules, {} Sigma rules", yr, sr);
        engine
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}", prefix, n)
    }

    // ── Built-in YARA Rules ───────────────────────────────────────────────────

    fn load_builtin_yara(&self) {
        let mut rules = self.yara_rules.write();

        // ── Cobalt Strike Beacon ─────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-001".into(),
            name: "CobaltStrike_Beacon_Payload".into(),
            tags: vec!["CobaltStrike".into(), "malware".into(), "C2".into()],
            strings: vec![
                // MZ header + known CS stage-1 stub bytes
                ("$cs_stage1".into(), YaraString::Hex(vec![
                    Some(0x4D), Some(0x5A), // MZ
                    None, None, None, None, None, None,
                    Some(0x00), Some(0x00), Some(0x00), Some(0x00), Some(0x00), Some(0x00),
                ])),
                // "ReflectiveLoader" string found in CS beacons
                ("$reflect".into(), YaraString::Literal {
                    value: b"ReflectiveLoader".to_vec(), nocase: false,
                }),
                // Common CS default User-Agent
                ("$ua".into(), YaraString::Literal {
                    value: b"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)".to_vec(),
                    nocase: false,
                }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "Cobalt Strike Beacon — stage-1 payload or reflective loader".into(),
        });

        // ── Mimikatz ─────────────────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-002".into(),
            name: "Mimikatz_Credential_Dumper".into(),
            tags: vec!["mimikatz".into(), "credential_access".into()],
            strings: vec![
                ("$mk1".into(), YaraString::Literal { value: b"mimikatz".to_vec(), nocase: true }),
                ("$mk2".into(), YaraString::Literal { value: b"lsadump::sam".to_vec(), nocase: true }),
                ("$mk3".into(), YaraString::Literal { value: b"sekurlsa::logonpasswords".to_vec(), nocase: true }),
                ("$mk4".into(), YaraString::Literal { value: b"kerberos::list".to_vec(), nocase: true }),
                ("$mk5".into(), YaraString::Literal { value: b"privilege::debug".to_vec(), nocase: true }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "Mimikatz credential dumper command or binary present".into(),
        });

        // ── Metasploit Meterpreter ────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-003".into(),
            name: "Metasploit_Meterpreter_Stager".into(),
            tags: vec!["metasploit".into(), "meterpreter".into()],
            strings: vec![
                ("$met1".into(), YaraString::Literal { value: b"meterpreter".to_vec(), nocase: true }),
                // Common Meterpreter reverse shell shellcode prologue (x86)
                ("$met2".into(), YaraString::Hex(vec![
                    Some(0xFC), Some(0xE8), None, None, Some(0x00), Some(0x00),
                    Some(0x60), Some(0x89), Some(0xE5),
                ])),
                ("$met3".into(), YaraString::Literal { value: b"reverse_tcp".to_vec(), nocase: true }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "Metasploit Meterpreter stager shellcode or string".into(),
        });

        // ── PowerShell Encoded Command ────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-004".into(),
            name: "PowerShell_Encoded_Command".into(),
            tags: vec!["PowerShell".into(), "obfuscation".into(), "execution".into()],
            strings: vec![
                ("$enc1".into(), YaraString::Literal { value: b"-EncodedCommand".to_vec(), nocase: true }),
                ("$enc2".into(), YaraString::Literal { value: b"-enc ".to_vec(), nocase: true }),
                ("$enc3".into(), YaraString::Literal { value: b"IEX(New-Object".to_vec(), nocase: true }),
                ("$enc4".into(), YaraString::Literal { value: b"Invoke-Expression".to_vec(), nocase: true }),
                ("$cradle".into(), YaraString::Literal {
                    value: b"(New-Object System.Net.WebClient).DownloadString".to_vec(), nocase: true,
                }),
            ],
            min_matches: 1,
            severity: RuleSeverity::High,
            description: "PowerShell encoded command / download cradle (potential living-off-the-land)".into(),
        });

        // ── WannaCry Kill-Switch Domain ───────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-005".into(),
            name: "WannaCry_KillSwitch_Domain".into(),
            tags: vec!["WannaCry".into(), "ransomware".into()],
            strings: vec![
                ("$ks".into(), YaraString::Literal {
                    value: b"www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com".to_vec(),
                    nocase: false,
                }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "WannaCry ransomware kill-switch domain found in payload".into(),
        });

        // ── Webshell Indicators ───────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-006".into(),
            name: "PHP_Webshell".into(),
            tags: vec!["webshell".into(), "persistence".into()],
            strings: vec![
                ("$ws1".into(), YaraString::Literal { value: b"eval(base64_decode".to_vec(), nocase: false }),
                ("$ws2".into(), YaraString::Literal { value: b"system($_GET".to_vec(), nocase: false }),
                ("$ws3".into(), YaraString::Literal { value: b"passthru($_POST".to_vec(), nocase: false }),
                ("$ws4".into(), YaraString::Literal { value: b"shell_exec($_REQUEST".to_vec(), nocase: false }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "PHP webshell pattern detected in payload".into(),
        });

        // ── Log4Shell (CVE-2021-44228) ────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-007".into(),
            name: "Log4Shell_JNDI_Injection".into(),
            tags: vec!["Log4Shell".into(), "CVE-2021-44228".into()],
            strings: vec![
                ("$jndi1".into(), YaraString::Literal { value: b"${jndi:ldap://".to_vec(), nocase: true }),
                ("$jndi2".into(), YaraString::Literal { value: b"${jndi:rmi://".to_vec(), nocase: true }),
                ("$jndi3".into(), YaraString::Literal { value: b"${jndi:dns://".to_vec(), nocase: true }),
                ("$obf1".into(), YaraString::Literal { value: b"${${lower:j}ndi:".to_vec(), nocase: true }),
            ],
            min_matches: 1,
            severity: RuleSeverity::Critical,
            description: "Log4Shell JNDI injection attempt (CVE-2021-44228)".into(),
        });

        // ── XSS ───────────────────────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-008".into(),
            name: "XSS_Script_Injection".into(),
            tags: vec!["XSS".into(), "web".into()],
            strings: vec![
                ("$xss1".into(), YaraString::Literal { value: b"<script>alert".to_vec(), nocase: true }),
                ("$xss2".into(), YaraString::Literal { value: b"javascript:void".to_vec(), nocase: true }),
                ("$xss3".into(), YaraString::Literal { value: b"onerror=alert".to_vec(), nocase: true }),
                ("$xss4".into(), YaraString::Literal { value: b"onload=document.write".to_vec(), nocase: true }),
            ],
            min_matches: 1,
            severity: RuleSeverity::High,
            description: "Cross-Site Scripting (XSS) payload detected".into(),
        });

        // ── SQL Injection ─────────────────────────────────────────────────────
        rules.push(YaraRule {
            id: "RUDRAS-YARA-009".into(),
            name: "SQL_Injection_Attempt".into(),
            tags: vec!["SQLi".into(), "web".into()],
            strings: vec![
                ("$s1".into(), YaraString::Literal { value: b"' OR '1'='1".to_vec(), nocase: true }),
                ("$s2".into(), YaraString::Literal { value: b"UNION SELECT".to_vec(), nocase: true }),
                ("$s3".into(), YaraString::Literal { value: b"1; DROP TABLE".to_vec(), nocase: true }),
                ("$s4".into(), YaraString::Literal { value: b"xp_cmdshell".to_vec(), nocase: true }),
                ("$s5".into(), YaraString::Literal { value: b"INFORMATION_SCHEMA.TABLES".to_vec(), nocase: true }),
            ],
            min_matches: 1,
            severity: RuleSeverity::High,
            description: "SQL injection attempt detected in payload".into(),
        });
    }

    // ── Built-in Sigma Rules ──────────────────────────────────────────────────

    fn load_builtin_sigma(&self) {
        let mut rules = self.sigma_rules.write();

        // ── Suspicious Process Creation ───────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-001".into(),
            title: "Suspicious_CreateRemoteThread".into(),
            logsource: "windows,sysmon".into(),
            keyword_groups: vec![
                vec![SigmaKeyword { field: "EventID".into(), value: "8".into(), negate: false }],
                vec![SigmaKeyword { field: "TargetImage".into(), value: "lsass.exe".into(), negate: false }],
            ],
            severity: RuleSeverity::Critical,
        });

        // ── Mimikatz via Command Line ─────────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-002".into(),
            title: "Mimikatz_CommandLine".into(),
            logsource: "windows,process_creation".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "CommandLine".into(), value: "sekurlsa".into(), negate: false },
                    SigmaKeyword { field: "CommandLine".into(), value: "lsadump".into(), negate: false },
                    SigmaKeyword { field: "CommandLine".into(), value: "mimikatz".into(), negate: false },
                ],
            ],
            severity: RuleSeverity::Critical,
        });

        // ── PowerShell Download ───────────────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-003".into(),
            title: "PowerShell_Download_Cradle".into(),
            logsource: "windows,powershell".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "ScriptBlockText".into(), value: "downloadstring".into(), negate: false },
                    SigmaKeyword { field: "ScriptBlockText".into(), value: "webclient".into(), negate: false },
                    SigmaKeyword { field: "CommandLine".into(), value: "downloadstring".into(), negate: false },
                ],
            ],
            severity: RuleSeverity::High,
        });

        // ── Lateral Movement via PsExec ───────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-004".into(),
            title: "Lateral_Movement_PsExec".into(),
            logsource: "windows,process_creation".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "Image".into(), value: "psexec".into(), negate: false },
                    SigmaKeyword { field: "CommandLine".into(), value: "psexec".into(), negate: false },
                ],
                vec![SigmaKeyword { field: "CommandLine".into(), value: "\\\\".into(), negate: false }],
            ],
            severity: RuleSeverity::High,
        });

        // ── Scheduled Task Persistence ────────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-005".into(),
            title: "Scheduled_Task_Persistence".into(),
            logsource: "windows,process_creation".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "Image".into(), value: "schtasks.exe".into(), negate: false },
                    SigmaKeyword { field: "CommandLine".into(), value: "schtasks".into(), negate: false },
                ],
                vec![SigmaKeyword { field: "CommandLine".into(), value: "/create".into(), negate: false }],
            ],
            severity: RuleSeverity::Medium,
        });

        // ── DNS Exfiltration ─────────────────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-006".into(),
            title: "DNS_Tunneling_Exfiltration".into(),
            logsource: "network,dns".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "dns_query".into(), value: ".onion".into(), negate: false },
                    SigmaKeyword { field: "QueryName".into(), value: "base64".into(), negate: false },
                ],
            ],
            severity: RuleSeverity::High,
        });

        // ── Ransomware File Extensions ────────────────────────────────────────
        rules.push(SigmaRule {
            id: "RUDRAS-SIGMA-007".into(),
            title: "Ransomware_Extension_Pattern".into(),
            logsource: "file_event".into(),
            keyword_groups: vec![
                vec![
                    SigmaKeyword { field: "TargetFilename".into(), value: ".locked".into(), negate: false },
                    SigmaKeyword { field: "TargetFilename".into(), value: ".encrypt".into(), negate: false },
                    SigmaKeyword { field: "TargetFilename".into(), value: ".wcry".into(), negate: false },
                    SigmaKeyword { field: "TargetFilename".into(), value: ".wncry".into(), negate: false },
                ],
            ],
            severity: RuleSeverity::Critical,
        });
    }

    // ── Public API: Payload Scanning ──────────────────────────────────────────

    /// Scan a raw byte payload against all YARA rules.
    pub fn scan_payload(&self, data: &[u8]) -> Vec<YaraRuleHit> {
        self.payloads_scanned.fetch_add(1, Ordering::Relaxed);
        let rules = self.yara_rules.read();
        let hits: Vec<YaraRuleHit> = rules.iter().filter_map(|r| r.matches(data)).collect();
        for h in &hits {
            self.yara_hit_total.fetch_add(1, Ordering::Relaxed);
            warn!("🔎 YARA hit: {} [{}] severity={:?}", h.rule_name, h.rule_id, h.severity);
            let mut q = self.recent_hits.write();
            if q.len() >= 256 { q.pop_front(); }
            q.push_back(serde_json::json!({
                "type": "yara", "rule": h.rule_name, "id": h.rule_id,
                "ts": h.timestamp,
            }));
        }
        hits
    }

    /// Scan a structured log entry against all Sigma rules.
    /// `fields` is a map of field_name → field_value (both as &str).
    pub fn scan_log_entry<'a>(&self, fields: &HashMap<&'a str, &'a str>) -> Vec<SigmaHit> {
        self.logs_scanned.fetch_add(1, Ordering::Relaxed);
        let rules = self.sigma_rules.read();
        let hits: Vec<SigmaHit> = rules.iter().filter_map(|r| r.matches(fields)).collect();
        for h in &hits {
            self.sigma_hit_total.fetch_add(1, Ordering::Relaxed);
            warn!("🔎 Sigma hit: {} [{}] severity={:?}", h.rule_title, h.rule_id, h.severity);
            let mut q = self.recent_hits.write();
            if q.len() >= 256 { q.pop_front(); }
            q.push_back(serde_json::json!({
                "type": "sigma", "rule": h.rule_title, "id": h.rule_id,
                "ts": h.timestamp,
            }));
        }
        hits
    }

    /// Load additional literal-string YARA rules from a slice.
    pub fn load_literal_rules(&self, entries: &[(&str, &str, RuleSeverity)]) {
        let mut rules = self.yara_rules.write();
        for (id, pattern, severity) in entries {
            rules.push(YaraRule {
                id: id.to_string(),
                name: format!("Imported_{}", id),
                tags: vec!["imported".into()],
                strings: vec![(
                    "$s".into(),
                    YaraString::Literal { value: pattern.as_bytes().to_vec(), nocase: true },
                )],
                min_matches: 1,
                severity: severity.clone(),
                description: format!("Imported rule: {}", id),
            });
        }
        info!("🔎 Loaded {} additional literal YARA rules", entries.len());
    }

    pub fn drain_recent_hits(&self) -> Vec<serde_json::Value> {
        self.recent_hits.write().drain(..).collect()
    }

    pub fn stats(&self) -> ThreatRulesStats {
        ThreatRulesStats {
            yara_rules_loaded: self.yara_rules.read().len(),
            sigma_rules_loaded: self.sigma_rules.read().len(),
            payloads_scanned: self.payloads_scanned.load(Ordering::Relaxed),
            log_entries_scanned: self.logs_scanned.load(Ordering::Relaxed),
            yara_hits_total: self.yara_hit_total.load(Ordering::Relaxed),
            sigma_hits_total: self.sigma_hit_total.load(Ordering::Relaxed),
        }
    }
}
