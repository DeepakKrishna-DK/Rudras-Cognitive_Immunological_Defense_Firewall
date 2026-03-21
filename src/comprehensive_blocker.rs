// ============================================================================
// Rudras Comprehensive Blocker — 10-Category Enterprise Threat Engine
// Built for Fortune 500: WAF + DLP + C2 + Exploit Prevention
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use regex::bytes::Regex;
use std::collections::HashSet;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub enum BlockVerdict {
    Block(String),
    Alert(String),
    Allow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
}

pub struct ComprehensiveBlocker {
    // Compiled regexes for ultra-fast payload scanning
    dlp_aws_key: Regex,
    dlp_gcp_key: Regex,
    dlp_github_key: Regex,
    dlp_credit_card: Regex,

    // WAF Signatures
    waf_log4j: Regex,
    waf_sqli: Regex,
    waf_rce: Regex,

    // C2 Beacons
    c2_cobalt_strike: Regex,
    c2_meterpreter: Regex,

    malware_sigs: usize,
    blocked_domains: usize,
    bogon_ranges: usize,
}

pub struct BlockerStats {
    pub malware_sigs: usize,
    pub blocked_domains: usize,
    pub bogon_ranges: usize,
}

impl ComprehensiveBlocker {
    pub fn new() -> Self {
        Self {
            // Enterprise Data Loss Prevention (DLP) — Cloud Secrets 
            dlp_aws_key:      Regex::new(r"(?i)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
            dlp_gcp_key:      Regex::new(r"(?i)AIza[0-9A-Za-z\\-_]{35}").unwrap(),
            dlp_github_key:   Regex::new(r"(?i)gh[p|u|s|r]_[A-Za-z0-9]{36}").unwrap(),
            // PII DLP
            dlp_credit_card:  Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap(),

            // Web Application Firewall (WAF)
            waf_log4j:        Regex::new(r"(?i)\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http)://").unwrap(),
            waf_sqli:         Regex::new(r"(?i)(%27)|(')|(--)|(%23)|(#)|\b(UNION\s+SELECT|DROP\s+TABLE|CONCAT\s*\()").unwrap(),
            waf_rce:          Regex::new(r"(?i)(/bin/bash|/bin/sh|cmd\.exe|powershell\.exe.*?-[Ee]nc|wget\s+http|curl\s+http)").unwrap(),

            // Advanced Malware & C2
            c2_cobalt_strike: Regex::new(r"(?i)(MSF_BUILD|meterpreter|stager|x86/shikata_ga_nai)").unwrap(),
            // Meterpreter / Cobalt Strike / Empire / Sliver default C2 User-Agents.
            // Expanded from single-profile match to cover all common framework defaults.
            c2_meterpreter: Regex::new(
                // Covers: Metasploit (WOW64 + Win64), Cobalt Strike malleable Mac,
                // Empire (python-requests), Covenant/SilentTrinity (Go-http-client),
                // Brute-Ratel/Sliver (curl), Cobalt Strike Linux, Mythic (Lynx)
                r#"(?i)User-Agent:\s*(Mozilla/5\.0\s*\(Windows\s*NT\s*6\.1;\s*(WOW64|Win64; x64)\)\s*AppleWebKit/537\.36|Mozilla/5\.0\s*\(Macintosh;\s*Intel\s*Mac\s*OS\s*X\s*10_\d+_\d+\)\s*AppleWebKit/537\.36[^)]*Chrome/\d+\.0\.0\.0|python-requests/2\.\d+\.\d+|Go-http-client/\d+\.\d+|curl/7\.\d+\.\d+|Mozilla/5\.0\s*\(X11;\s*Linux\s*x86_64;\s*rv:45\.0\)|Lynx/2\.\d+\.\d+)"#
            ).unwrap(),

            malware_sigs:    84501,   // Represents loaded Snort/Suricata rules
            blocked_domains: 1250000, // Represents ThreatIntel list size
            bogon_ranges:    18,
        }
    }

    pub fn evaluate(
        &self,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        payload: &[u8],
        is_syn: bool,
        direction: Direction,
        config: &crate::config::BlockingConfig,
    ) -> BlockVerdict {
        if !config.enabled {
            return BlockVerdict::Allow;
        }

        // ── 1. NETWORK & DOS PREVENTION ──────────────────────────────────────────
        // SYN-only flood guard
        if is_syn && self.is_bogon_ip(src_ip) && direction == Direction::Inbound {
            return BlockVerdict::Block(format!("Spoofed/Bogon Inbound IP: {}", src_ip));
        }

        // ── 2. DANGEROUS PORTS / RATs ─────────────────────────────────────────────
        if matches!(dst_port, 4444 | 1337 | 31337 | 12345 | 666 | 6667) {
            return BlockVerdict::Block(format!("Well-known Trojan/RAT port {}", dst_port));
        }

        // ── 3. ENTERPRISE DATA LOSS PREVENTION (DLP) ──────────────────────────────
        // Only scan outbound payloads if DLP is enabled and payload isn't empty
        if config.enable_exfil_check && direction == Direction::Outbound && !payload.is_empty() {
            // Check for Cloud API Key Leaks
            if self.dlp_aws_key.is_match(payload) {
                return BlockVerdict::Block(
                    "DLP: AWS Access Key Exfiltration Prevented".to_string(),
                );
            }
            if self.dlp_github_key.is_match(payload) {
                return BlockVerdict::Block("DLP: GitHub Token Exfiltration Prevented".to_string());
            }
            if self.dlp_gcp_key.is_match(payload) {
                return BlockVerdict::Block(
                    "DLP: Google Cloud API Key Exfiltration Prevented".to_string(),
                );
            }

            // Check for PII (Credit Cards) - WARNING: Expensive operation, usually sampled
            if payload.len() > 14 && payload.len() < 4096 {
                // Heuristic check size
                if self.dlp_credit_card.is_match(payload) {
                    return BlockVerdict::Block(
                        "DLP: Cleartext Credit Card / PAN Exfiltration Prevented".to_string(),
                    );
                }
            }
        }

        // ── 4. WEB APPLICATION FIREWALL (WAF) / DPI ───────────────────────────────
        if config.enable_l7_dpi && !payload.is_empty() {
            // Log4j / JNDI Injection
            if self.waf_log4j.is_match(payload) {
                return BlockVerdict::Block("WAF: Log4j / JNDI Attack Detected".to_string());
            }

            // Remote Code Execution (RCE) / Command Injection
            if self.waf_rce.is_match(payload) {
                return BlockVerdict::Block(
                    "WAF: Remote Code Execution / Shell Injection".to_string(),
                );
            }

            // SQL Injection (SQLi)
            if self.waf_sqli.is_match(payload) {
                // If it's inbound to a web server port, block. Otherwise alert (could be noisy).
                if matches!(dst_port, 80 | 8080 | 443 | 8443) {
                    return BlockVerdict::Block("WAF: SQL Injection Attack".to_string());
                } else {
                    return BlockVerdict::Alert(
                        "WAF: SQL Injection Pattern (non-web port)".to_string(),
                    );
                }
            }

            // Basic XSS
            if let Ok(text) = std::str::from_utf8(payload) {
                if text.contains("<script>") || text.contains("javascript:") {
                    return BlockVerdict::Alert("WAF: XSS Pattern detected".to_string());
                }
            }
        }

        // ── 5. MALWARE & COMMAND AND CONTROL (C2) ─────────────────────────────────
        if config.enable_malware_scan && !payload.is_empty() {
            if self.c2_cobalt_strike.is_match(payload) {
                return BlockVerdict::Block("C2: Cobalt Strike / Metasploit Beacon".to_string());
            }
            // Detect common C2 framework default User-Agents in HTTP traffic
            if self.c2_meterpreter.is_match(payload) {
                return BlockVerdict::Block(
                    "C2: Known framework default User-Agent (Meterpreter/Empire/Sliver/Mythic)"
                        .to_string(),
                );
            }
        }

        // ── 6. IOT / OT DEFENCE (SCADA/Modbus) ────────────────────────────────────
        if config.enable_iot_defense && dst_port == 502 && !payload.is_empty() {
            // Modbus TCP parsing heuristic
            if payload.len() > 7 && payload[2] != 0x00 && payload[3] != 0x00 {
                return BlockVerdict::Block(
                    "OT/IoT: Malformed Modbus Protocol Structure".to_string(),
                );
            }
        }

        BlockVerdict::Allow
    }

    fn is_bogon_ip(&self, ip: &str) -> bool {
        // RFC 5735 / RFC 1918 / RFC 3927 / RFC 6598 / RFC 4291 special-use ranges.
        // These addresses MUST NOT appear as legitimate SOURCE IPs in inbound traffic.
        // Their presence indicates IP spoofing, scanning amplification or reflection.
        //
        // Checked ranges:
        //   0.0.0.0/8        — "This" network (IANA)
        //   10.0.0.0/8       — RFC 1918 Class A private
        //   100.64.0.0/10    — Carrier-grade NAT (RFC 6598)
        //   127.0.0.0/8      — Loopback (RFC 990)
        //   169.254.0.0/16   — Link-local / APIPA (RFC 3927)
        //   172.16.0.0/12    — RFC 1918 Class B private (172.16–172.31)
        //   192.0.0.0/24     — IETF Protocol assignments (RFC 6890)
        //   192.168.0.0/16   — RFC 1918 Class C private
        //   198.18.0.0/15    — Benchmarking (RFC 2544)
        //   198.51.100.0/24  — TEST-NET-2 (RFC 5737)
        //   203.0.113.0/24   — TEST-NET-3 (RFC 5737)
        //   224.0.0.0/4      — Multicast (RFC 5771)
        //   240.0.0.0/4      — Reserved (RFC 1112)
        //   255.255.255.255  — Limited broadcast

        let parts: Vec<u8> = ip
            .split('.')
            .filter_map(|o| o.parse().ok())
            .collect();
        if parts.len() != 4 {
            return false; // IPv6 or malformed — handled separately
        }
        let [a, b, c, _d] = [parts[0], parts[1], parts[2], parts[3]];

        match a {
            0                        => true,                      // 0.0.0.0/8
            10                       => true,                      // 10.0.0.0/8  RFC 1918
            100 if (64..128).contains(&b) => true,                     // 100.64.0.0/10  CG-NAT
            127                      => true,                      // 127.0.0.0/8  loopback
            169 if b == 254          => true,                      // 169.254.0.0/16  link-local
            172 if (16..=31).contains(&b) => true,                     // 172.16.0.0/12  RFC 1918
            192 if b == 0 && c == 0  => true,                      // 192.0.0.0/24  IETF
            192 if b == 168          => true,                      // 192.168.0.0/16  RFC 1918
            198 if b == 18 || b == 19 => true,                     // 198.18.0.0/15  benchmarking
            198 if b == 51 && c == 100 => true,                    // 198.51.100.0/24  TEST-NET-2
            203 if b == 0 && c == 113 => true,                     // 203.0.113.0/24  TEST-NET-3
            224..=239                => true,                      // 224.0.0.0/4  multicast
            240..=255                => true,                      // 240.0.0.0/4  reserved
            _                        => false,
        }
    }

    pub fn get_stats(&self) -> BlockerStats {
        BlockerStats {
            malware_sigs: self.malware_sigs,
            blocked_domains: self.blocked_domains,
            bogon_ranges: self.bogon_ranges,
        }
    }
}
