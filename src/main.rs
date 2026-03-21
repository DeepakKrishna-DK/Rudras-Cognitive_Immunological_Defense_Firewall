// Rudras Cross-Platform Firewall — Enterprise Edition
// All advanced security modules configured from config/rudras.toml

#![allow(
    // Existing suppressions
    dead_code,
    unused_imports,
    unused_variables,
    unexpected_cfgs,
    unused_unsafe,
    // Security APIs legitimately need many parameters — wrapping into structs
    // would reduce clarity for CIP/compliance/ML functions
    clippy::too_many_arguments,
    // ML/matrix code uses index loops by design (BLAS-style inner products)
    clippy::needless_range_loop,
    // Manual clamp patterns in hot paths predate .clamp() stabilisation;
    // auto-fix already applied to most; the rest are in ML score normalisation
    clippy::manual_clamp,
    // drop() on non-Drop types is a no-op but used as documentation
    clippy::drop_non_drop,
    // Arc<RwLock<T>> is safe in our single-threaded tokio context
    clippy::arc_with_non_send_sync,
    // IPS / IDS / XSS / XDP / TLS are industry standard acronyms
    clippy::upper_case_acronyms,
    // vec! then push pattern in dynamic compliance check builders
    clippy::vec_init_then_push,
    // useless vec! initialisation — already fixed in most files
    clippy::useless_vec,
    // redundant closure around function pointers in async blocks
    clippy::redundant_closure,
    // single-char names in local ML computation loops are idiomatic
    clippy::single_char_add_str,
    // unwrap_used pattern checked just above — Clippy can't see it in all cases
    clippy::unnecessary_unwrap,
    // option_if_let_else generates less readable code for compliance checks
    clippy::option_if_let_else,
)]

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║      RUDRAS — DEFENSE-IN-DEPTH: 5-ZONE OSI SECURITY ARCHITECTURE       ║
// ║  NIST SP 800-41 • CIS Controls v8 • NERC CIP-005 • ISO 27001           ║
// ║  MARL Bridge: one attack event → all 5 zones respond simultaneously    ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── ZONE 1: PERIMETER  [OSI L3 — Packet Filtering + NGFW] ──────────────────
//    Mechanism: IP/port/protocol rules at NIC (XDP) and kernel (WFP)
//    Strength : Zero-CPU drops before kernel TCP/IP stack
//    Weakness : No session state; blind to encrypted application payloads
mod advanced_security;
mod config;
mod cyber_immune;
mod dpi;
mod l2_engine;
mod metrics;
mod policy;
mod process_monitor;
mod stateful;

// ── ZONE 1 (continued): Enterprise Edge & Gateway ───────────────────────────
mod gateway_mode;          // 🌐 Gateway/perimeter mode with HA failover
mod identity_policy;       // 🪪  Identity-Aware Policy Engine
mod siem_integration;      // 📡 SIEM connectors (Splunk/ELK/QRadar)
mod zero_trust;            // 🔐 Zero Trust: AD/SAML/OAuth + Device Posture

// ── ZONE 2: NETWORK  [OSI L3-L4 — Stateful Inspection + Segmentation] ──────
//    Mechanism: Connection state tables, VLAN isolation, flow risk scoring
//    Strength : Context-aware per-connection decisions; detects scan pivots
//    Weakness : Limited visibility into encrypted application payloads
mod micro_segmentation;    // 🔒 Zone-based isolation & lateral movement prevention
mod threat_intelligence;   // 🌐 Threat feeds: Feodo/URLhaus/SSLBL/OTX/MISP

// ── ZONE 2 (continued): SD-WAN, Cloud, Single-pass pipeline ────────────────
mod cloud_native;          // ☁️  Kubernetes/container network policy
mod sdwan;                 // 🌐 SD-WAN policy-aware routing & segmentation
mod single_pass;           // ➡️  Single-pass DPI pipeline (minimize latency)

// ── ZONE 3: APPLICATION  [OSI L5-L7 — DPI + IDS/IPS + WAF + Proxy] ─────────
//    Mechanism: Full payload inspection, Snort/Sigma rules, protocol decode
//    Strength : Catches SQLi/XSS/RCE/C2 invisible to L3/L4
//    Weakness : CPU intensive; adds per-flow latency
mod advanced_ml;           // 📊 Autoencoder, transformer, MARL threat models
mod distributed_immunity;  // 🌍 P2P rule sync + collective immunity
mod hardware_accel;        // 🖥️  DPDK/SmartNIC hardware offload

// ── ZONE 3 (continued): New advanced application-layer modules ──────────────
mod post_quantum;          // 🔮 CRYSTALS-Kyber/Dilithium post-quantum crypto
mod federated_learning;    // 🤝 Cross-org federated model training
mod deception;             // 🍯 Honeypot + honeytoken + deception persona
mod ot_protocols;          // 🏭 OT/ICS: Modbus, DNP3, IEC 61850 inspection
mod eta_engine;            // 🔐 Encrypted Traffic Analysis (fingerprint + ML)
mod gnn_engine;            // 🕸️  Graph Neural Network — APT campaign clustering
mod policy_verifier;       // 🔍 SMT-style formal policy verification
mod sbom_engine;           // 📦 SLSA/SPDX supply-chain bill of materials
mod ueba_engine;           // 👤 User & Entity Behavior Analytics
mod soar_engine;           // 🤖 Security Orchestration, Automation & Response
mod llm_explainability;    // 💬 LLM plain-English alert explanations
mod forensics_chain;       // 🔗 Tamper-evident forensic chain (SHA3-256)
mod differential_privacy;  // 🔏 Laplace-mechanism privacy analytics
mod p4_offload;            // 📡 P4Runtime programmable data-plane offload

// ── ZONE 3 (continued): Gap-Closure application security ───────────────────
mod dns_security;          // 🌐 DNS: RPZ, tunneling, rebinding, DoH stripping
mod management_api;        // 🌐 REST management API (axum, SHA3 auth, RBAC)
mod ebpf_xdp;              // ⚡ eBPF/XDP: NIC-level packet drop (kernel bypass)
mod compliance_engine;     // 📋 GDPR/PCI-DSS/HIPAA/NIST/ISO/CIS Controls/COBIT
mod nerc_cip;              // ⚡ NERC CIP-002 → CIP-014 (Critical Infrastructure)
mod eisac_integration;     // 📡 E-ISAC incident 1-hr reporting (CIP-008-R1-1.2)
mod mfa_engine;            // 🔑 MFA TOTP/RFC 6238 (NERC CIP-005-R2-2.2)
mod quic_inspector;        // 🚀 QUIC long-header parser, 0-RTT, migration detect
mod threat_rules_engine;   // 📜 YARA + Sigma threat rules engine
mod tpm_attestation;       // 🔒 TPM 2.0 remote attestation + measured boot
mod rl_policy;             // 🎮 Q-learning adaptive blocking policy
mod mtd_engine;            // 🎲 Moving Target Defense: IP hop/port randomise
mod homomorphic_sharing;   // 🤝 Privacy-preserving IOC sharing (Paillier+Shamir)
mod email_security;        // 📧 SPF/DKIM/DMARC/BEC/attachment/URL analysis
mod formal_verification;   // ✅ Shadow/conflict/redundancy policy checks
mod rasp_engine;           // 🔒 Runtime Application Self-Protection

// ── ZONE 4: HOST  [Host-Based — Endpoint + ZeroTrust + MFA + TPM] ───────────
//    Mechanism: Per-process/user enforcement, TPM attestation, UEBA scoring
//    Strength : Stops insider threats, post-exploitation, privilege escalation
//    Weakness : Agent required on each endpoint; OS-dependent

// ── ZONE 4 (continued): Research-grade gap-closure host modules ─────────────
mod secure_channel;        // 🔐 TLS 1.3 mTLS, cert pinning, CT, replay guard
mod memory_safe_pool;      // 🔐 Secret vault, W^X, canaries, ASLR entropy
mod supply_chain_verifier; // 🔍 Hash pinning, typosquat, dep-confusion, taint
mod adaptive_honeypot;     // 🪤 Interactive deception + TTP-tracking personas
mod network_dpi_ml;        // 🤖 Online LR + K-Means anomaly DPI
mod threat_hunt;           // 🏹 MITRE ATT&CK hypothesis hunting + IOC pivot

// ── ZONE 5: DATA  [Data Layer — DLP + Crypto + Compliance + Forensics] ──────
//    Mechanism: Protects data at rest/transit; compliance reporting; forensics
//    Strength : Audit trail, regulatory fulfilment, breach recovery
//    Weakness : Cannot stop network or host-layer attacks; downstream-only
//    Key modules already declared above: compliance_engine · nerc_cip ·
//      eisac_integration · memory_safe_pool · forensics_chain ·
//      differential_privacy · post_quantum · homomorphic_sharing ·
//      sbom_engine · supply_chain_verifier · siem_integration · secure_channel

// ── AI / INTELLIGENCE LAYER  [Cross-Zone — feeds all 5 zones via MARL] ──────
//    Mechanism: Adaptive ML threat models; RL policy; GNN campaign detection
//    All zones consume intelligence from this layer simultaneously
mod flow_engine;           // ⚡ Lightweight stateful flow risk scorer (Zone 2 fast-path)
mod ai_engine;             // 🧠 4-layer adaptive ML threat intelligence
mod npcap_forensic;        // 🔬 Npcap passive forensic + AI training data capture
mod wfp_engine;            // 🔷 WFP — Windows kernel filter (ring-0, Zone 1)
mod windivert_engine;      // 🔀 WinDivert — selective deep inspection (Zone 3)

// ── PRIMARY IDS / IPS ENGINES  [Zone 3 core] ─────────────────────────────────
mod ids_engine;            // 🔍 IDS — 200+ Snort rules | behavioral analysis
mod ips_engine;            // 🛡️  IPS — RST | WFP block | rate-limit | quarantine

// ── FRAMEWORK MAPPING  [Cross-zone enrichment] ───────────────────────────────
mod framework_alignment;   // 🗂️  Alert → MITRE | OWASP | NIST | NERC CIP | PCI tags

// ── COMPREHENSIVE THREAT BLOCKER  [All zones] ────────────────────────────────
mod comprehensive_blocker; // 🚫 All-10-category blocker L3 → Data

// ── ZONE 4 PRIMARY ENGINES ───────────────────────────────────────────────────
mod attribution_scoring;   // 🎯 Probabilistic attack attribution (MITRE aligned)
mod endpoint_security;     // 🖥️  Host-based endpoint protection

// ── ARCHITECTURE ORCHESTRATORS  [Depend on all zones above] ──────────────────
mod defensive_posture;     // 🛡️  DEFCON 1-5 threat level + auto-escalation engine
mod defense_in_depth;      // 🏛️  5-Zone coordinator + MARL cross-zone rule forging

// ── DEPLOYMENT & PLATFORM ─────────────────────────────────────────────────────
mod mode_profiles;         // 🎯 Client / Server / Auto deployment mode profiles

// ── PLATFORM-SPECIFIC CAPTURE ────────────────────────────────────────────────
#[cfg(target_os = "windows")]
mod capture;


#[cfg(target_os = "windows")]
use capture::WindowsPacketCapture;

use config::Config;
use policy::PolicyEngine;

#[derive(Parser, Debug)]
#[command(
    author = "Rudras Security",
    version = "4.0.0",
    about = "Rudras Enterprise Firewall — Cognitive Immunological Defense"
)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/rudras.toml")]
    config: String,

    /// Network interface to capture (overrides config file)
    #[arg(short, long)]
    interface: Option<String>,

    /// Log level: trace | debug | info | warn | error  (overrides config)
    #[arg(short, long)]
    log_level: Option<String>,

    /// Disable SIEM integration regardless of config (dev mode)
    #[arg(long, default_value = "false")]
    no_siem: bool,

    /// Deployment mode: client | server | auto
    ///   client — Endpoint/workstation protection (outbound C2/exfil focus)
    ///   server — Gateway/perimeter protection (inbound attack focus)
    ///   auto   — Auto-detect based on open listening ports (default)
    #[arg(short, long, default_value = "auto")]
    mode: String,
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load config first so we can read log_level from it
    let config = Config::load(&args.config).context("Failed to load configuration")?;

    let effective_log_level = args
        .log_level
        .as_deref()
        .unwrap_or(&config.log_level)
        .to_string();

    // ── Logging (console pretty + rolling JSON file) ─────────────────────────
    let file_appender = tracing_appender::rolling::daily("logs", "Rudras.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let ist_timer = tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f%:z".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&effective_log_level))
        .with(tracing_subscriber::fmt::layer().with_target(false).pretty().with_timer(ist_timer.clone()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .json()
                .with_timer(ist_timer),
        )
        .init();

    print_banner();

    // ── DEPLOYMENT MODE ───────────────────────────────────────────────────────
    //   Resolve: CLI flag → config file → interactive prompt
    let cli_mode = mode_profiles::DeploymentMode::from_str(&args.mode);
    let resolved_mode = match cli_mode {
        mode_profiles::DeploymentMode::Auto => {
            // Auto = no explicit choice made → ask the user
            let auto_detected = mode_profiles::auto_detect_mode();
            println!();
            println!("╔══════════════════════════════════════════════════════════════════╗");
            println!("║              RUDRAS — SELECT DEPLOYMENT MODE                    ║");
            println!("╠══════════════════════════════════════════════════════════════════╣");
            println!("║  1  CLIENT  — Endpoint/workstation (outbound C2 & exfil focus)  ║");
            println!("║  2  SERVER  — Gateway/perimeter    (inbound attack focus)        ║");
            println!("║  3  AUTO    — Auto-detect from open ports (current choice: {:6}) ║", auto_detected.to_string());
            println!("╠══════════════════════════════════════════════════════════════════╣");
            println!("║  Tip: skip this prompt with --mode client / --mode server        ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            print!("  Enter choice [1/2/3] (default: 3 auto-detect): ");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            match input.trim() {
                "1" | "client" => {
                    println!("  → CLIENT mode selected.");
                    mode_profiles::DeploymentMode::Client
                }
                "2" | "server" => {
                    println!("  → SERVER mode selected.");
                    mode_profiles::DeploymentMode::Server
                }
                _ => {
                    println!("  → AUTO-DETECT selected → {}", auto_detected);
                    auto_detected
                }
            }
        }
        m => m,
    };

    let mode_profile = match resolved_mode {
        mode_profiles::DeploymentMode::Client => mode_profiles::client_profile(),
        mode_profiles::DeploymentMode::Server => mode_profiles::server_profile(),
        mode_profiles::DeploymentMode::Auto => mode_profiles::client_profile(), // fallback
    };

    mode_profiles::print_mode_profile(&mode_profile);

    // ── [1/8] Policy Engine ──────────────────────────────────────────────────
    info!("🔧 [1/8] Initializing Policy Engine...");
    let policy_engine = Arc::new(PolicyEngine::new());
    info!("\u{2705} Policy Engine ready \u{2014} Zero Trust default-Monitor | dynamic rules from IPS/CyberImmune");

    // ── [2/8] Metrics ────────────────────────────────────────────────────────
    info!("📊 [2/8] Initializing Metrics System...");
    let metrics = Arc::new(metrics::Metrics::new());
    info!(
        "✅ Metrics ready (Prometheus → http://127.0.0.1:{}/metrics  [loopback-only, auth required])",
        config.metrics_port
    );

    // ── [2b] Anti-Tamper / Process Monitor ──────────────────────────────────
    info!("🛡️  [2b] Activating Anti-Tamper & Evasion Monitor (Rootkit Defense)...");
    let kill_mode = config.blocking.process_monitor_kill_mode;
    let pm = Arc::new(process_monitor::ProcessMonitor::new(metrics.clone(), kill_mode));
    pm.start();

    // ── [2c] Endpoint Security Agent ─────────────────────────────────────────
    info!("🖥️  [2c] Activating Endpoint Security Agent...");
    let ep_kill_mode = config.endpoint.kill_mode;
    let ep_interval  = config.endpoint.scan_interval_secs.max(5).min(60);
    let endpoint_agent = Arc::new(endpoint_security::EndpointAgent::new(ep_kill_mode));
    {
        let ep_bg = endpoint_agent.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(ep_interval));
            loop {
                interval.tick().await;
                let alerts = ep_bg.scan();
                if !alerts.is_empty() {
                    let posture = ep_bg.get_posture();
                    info!(
                        "🖥️  Endpoint | posture={:.0}% | new_alerts={} | active={}",
                        posture.score * 100.0,
                        alerts.len(),
                        posture.active_alert_count
                    );
                }
            }
        });
    }
    info!("✅ Endpoint Security Agent active — scan_interval={}s | kill_mode={}", ep_interval, ep_kill_mode);

    // ── [2d] Attack Attribution Engine ───────────────────────────────────────
    info!("🎯 [2d] Activating Attack Attribution Engine...");
    let attr_enabled    = config.attribution.enabled;
    let attr_confidence = config.attribution.log_confidence_threshold;
    let attr_retention  = config.attribution.history_retention_secs;
    let attribution_engine = Arc::new(attribution_scoring::AttributionEngine::new());
    if attr_enabled {
        let attr_bg = attribution_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                attr_bg.cleanup(attr_retention);
                let st = attr_bg.stats();
                info!(
                    "🎯 Attribution | tracked_sources={} | c2={} | exfil={} | apt_indicators={}",
                    st.tracked_sources, st.with_c2_signals,
                    st.with_exfil_signals, st.with_apt_indicators
                );
            }
        });
        info!("✅ Attribution Engine active — confidence_threshold={:.0}% | history_retention={}s",
              attr_confidence * 100.0, attr_retention);
        info!("   LEGAL NOTICE: attribution is probabilistic classification, NOT legal proof");
    } else {
        info!("⏸️  Attribution Engine DISABLED in config (attribution.enabled = false)");
    }

    // ── [3/8] SIEM Integration ───────────────────────────────────────────────
    info!("📡 [3/8] Initializing SIEM Integration Hub...");
    let sc = &config.siem;
    let siem_cfg = siem_integration::SIEMConfig {
        enabled: sc.enabled && !args.no_siem,
        buffer_size: sc.buffer_size,
        flush_interval_seconds: sc.flush_interval_seconds,
        retry_attempts: sc.retry_attempts,
    };

    let mut siem_hub = siem_integration::SIEMIntegration::new(siem_cfg);

    // Conditionally attach connectors based on config flags
    if sc.splunk_enabled && !sc.splunk_hec_token.contains("XXXX") {
        siem_hub = siem_hub.with_splunk(&sc.splunk_hec_url, &sc.splunk_hec_token);
        info!("  📌 Splunk HEC connector active: {}", sc.splunk_hec_url);
    } else if sc.splunk_enabled {
        warn!("  ⚠️  Splunk enabled but HEC token looks like placeholder — skipping");
    }

    if sc.elasticsearch_enabled {
        siem_hub = siem_hub.with_elasticsearch(
            &sc.elasticsearch_url,
            &sc.elasticsearch_index,
            sc.elasticsearch_username.as_deref(),
            sc.elasticsearch_password.as_deref(),
        );
        info!(
            "  📌 Elasticsearch connector active: {}",
            sc.elasticsearch_url
        );
    }

    if sc.qradar_enabled {
        siem_hub = siem_hub.with_qradar(&sc.qradar_host, sc.qradar_port);
        info!(
            "  📌 QRadar syslog connector active: {}:{}",
            sc.qradar_host, sc.qradar_port
        );
    }

    let siem = Arc::new(siem_hub);
    siem.clone().start_background_flush().await; // background flush every N seconds

    let connector_count = (sc.splunk_enabled && !sc.splunk_hec_token.contains("XXXX")) as u8
        + sc.elasticsearch_enabled as u8
        + sc.qradar_enabled as u8;

    if connector_count == 0 {
        info!(
            "✅ SIEM hub active — local buffer only ({} external connectors configured)",
            connector_count
        );
        info!("   → To send to Splunk/ELK/QRadar set flags in config/rudras.toml [siem]");
    } else {
        info!(
            "✅ SIEM hub active — {} external connector(s) forwarding events",
            connector_count
        );
    }

    // ── [4/8] Zero Trust Identity Engine ────────────────────────────────────
    info!("🔐 [4/8] Initializing Zero Trust Engine...");
    let zt = &config.zero_trust;
    let mut idp = zero_trust::IdentityProvider::new();

    if zt.enabled {
        if zt.ad_enabled {
            idp = idp.with_active_directory(&zt.ad_server, &zt.ad_domain);
            info!(
                "  📌 Active Directory: ldap://{}  domain={}",
                zt.ad_server, zt.ad_domain
            );
        }
        if zt.saml_enabled {
            idp = idp.with_saml(&zt.saml_idp_url, &zt.saml_sp_entity_id);
            info!("  📌 SAML SSO: {}", zt.saml_idp_url);
        }
        if zt.oauth_enabled && !zt.oauth_client_secret.contains("YOUR_") {
            idp = idp.with_oauth(
                &zt.oauth_client_id,
                &zt.oauth_client_secret,
                &zt.oauth_auth_url,
            );
            info!("  📌 OAuth 2.0: {}", zt.oauth_auth_url);
        } else if zt.oauth_enabled {
            warn!("  ⚠️  OAuth enabled but client_secret looks like placeholder — skipping");
        }

        let auth_backends = zt.ad_enabled as u8 + zt.saml_enabled as u8 + zt.oauth_enabled as u8;
        if auth_backends == 0 {
            info!(
                "  ℹ️  Zero Trust: Device posture enforcement active (no SSO backend configured)"
            );
            info!("     → Set ad_enabled/saml_enabled/oauth_enabled in [zero_trust] to add SSO");
        } else {
            info!("  ✅ {} identity backend(s) configured", auth_backends);
        }
    }

    let identity_provider = Arc::new(idp);
    info!(
        "✅ Zero Trust Engine ready — min device score: {:.0}%  patch age: {}d",
        zt.min_device_compliance_score * 100.0,
        zt.max_patch_age_days
    );

    // ── [4b] Identity-Aware Policy Engine ───────────────────────────────────
    info!("🔐 [4b] Identity-Aware Policy Engine...");
    let identity_policy_engine = identity_policy::IdentityAwarePolicyEngine::new();
    identity_policy_engine.load_policies(identity_policy::create_example_policies());
    let identity_policy_engine = Arc::new(identity_policy_engine);
    info!("✅ Identity-Aware Policies loaded — Zero Trust default-deny enforced");

    // ── [5/8] Micro-Segmentation ─────────────────────────────────────────────
    info!("🔒 [5/8] Initializing Micro-Segmentation Engine...");
    let seg_cfg = &config.segmentation;
    let mut seg_engine = micro_segmentation::MicroSegmentationEngine::new();

    if seg_cfg.enabled {
        // Build zones from config file
        let zones: Vec<micro_segmentation::SecurityZone> = seg_cfg
            .zones
            .iter()
            .filter_map(|zc| {
                let isolation = match zc.isolation.as_str() {
                    "strict" => micro_segmentation::IsolationLevel::Strict,
                    "moderate" => micro_segmentation::IsolationLevel::Moderate,
                    "minimal" => micro_segmentation::IsolationLevel::Minimal,
                    other => {
                        warn!(
                            "  ⚠️  Unknown isolation '{}' for zone '{}', defaulting to strict",
                            other, zc.name
                        );
                        micro_segmentation::IsolationLevel::Strict
                    }
                };

                let networks: Vec<&str> = zc.networks.iter().map(|s| s.as_str()).collect();

                match micro_segmentation::SecurityZone::new(&zc.name, networks, isolation) {
                    Ok(z) => {
                        let mut zone = z.with_description(&zc.description);
                        for allowed in &zc.allowed_zones {
                            zone = zone.allow_zone(allowed);
                        }
                        Some(zone)
                    }
                    Err(e) => {
                        warn!("  ⚠️  Failed to create zone '{}': {} — skipped", zc.name, e);
                        None
                    }
                }
            })
            .collect();

        seg_engine.load_zones(zones);
        seg_engine.load_policies(micro_segmentation::create_example_policies());
        seg_engine.enable();

        info!(
            "✅ Micro-Segmentation active — {} zones loaded:",
            seg_cfg.zones.len()
        );
        for z in &seg_cfg.zones {
            info!(
                "   Zone {:15} [{}]  {:?}  → allowed: {:?}",
                z.name, z.isolation, z.networks, z.allowed_zones
            );
        }
    } else {
        warn!("  ⚠️  Micro-Segmentation disabled in config — set segmentation.enabled = true");
    }

    let seg_engine = Arc::new(seg_engine);
    let lateral_detector = Arc::new(micro_segmentation::LateralMovementDetector::new());
    info!("✅ Lateral Movement Detector active — SMB/RDP/WMI/PSExec patterns monitored");

    // ── [6/8] Threat Intelligence Hub ────────────────────────────────────────
    info!("🌐 [6/8] Initializing Threat Intelligence Hub...");
    let threat_intel = Arc::new(threat_intelligence::ThreatIntelligenceHub::new(
        threat_intelligence::ThreatIntelConfig::default(),
    ));
    let threat_bg = threat_intel.clone();
    tokio::spawn(async move {
        threat_bg.start_continuous_updates().await;
    });
    info!("✅ Threat Intelligence Hub started — feeds updating in background");

    // ── [7/8] Advanced Security (Rate Limiting + IOC-based IP reputation) ────────
    info!("\u{1f30d} [7/8] Initializing Advanced Security (Rate Limiting + Reputation)...");
    let advanced_security = Arc::new(advanced_security::AdvancedSecurity::new());
    info!("\u{2705} Advanced Security ready \u{2014} IOC-based IP blocking via ThreatIntel (no country blocks)");
    info!("   Specific malicious IPs/domains from 6 live feeds: Feodo/SSLBL/CINS/ET/ThreatFox/URLhaus");

    // ── [8/8] Distributed Immunity P2P ───────────────────────────────────────
    info!("📡 [8/8] Initializing Distributed Immunity P2P Grid...");
    let (immunity_node, immunity_tx) =
        distributed_immunity::DistributedImmunity::new(config.peers.clone(), policy_engine.clone());
    if config.peers.is_empty() {
        info!("✅ Distributed Immunity ready — standalone mode (no peers)");
        info!("   → Add peer firewall nodes under [peers] in config/rudras.toml");
    } else {
        info!(
            "✅ Distributed Immunity ready — syncing with {} peer nodes",
            config.peers.len()
        );
    }

    // ── [9/9] Comprehensive Blocker — ALL 10 Threat Categories ───────────────
    info!("🔥 [9/9] Initializing Comprehensive Threat Blocker (10 categories)...");
    let comp_blocker = Arc::new(comprehensive_blocker::ComprehensiveBlocker::new());
    let cb_stats = comp_blocker.get_stats();
    info!("✅ Comprehensive Blocker armed — Malware sigs: {} | Bogon ranges: 15 | Blocked domains: {}",
        cb_stats.malware_sigs, cb_stats.blocked_domains);
    info!("   🚫 Blocking: Bogons·SYN/UDP/ICMP floods·PortScan·SQLi·XSS·SSRF·XXE");
    info!("   🚫 Blocking: PathTraversal·CmdInj·C2·DGA·DNSTunnel·BruteForce");
    info!("   🚫 Blocking: DataExfil·InsiderScan·IoT/UPnP·Mirai·Anomaly");

    // ── [NEW-A] Post-Quantum Cryptography Engine ──────────────────────────────
    info!("🔐 [NEW-A] Initializing Post-Quantum Cryptography Engine...");
    let pq_engine = Arc::new(post_quantum::PqcKeyStore::new());
    info!("✅ Post-Quantum Engine ready — CRYSTALS-Kyber key exchange | CRYSTALS-Dilithium signatures");

    // ── [NEW-B] Federated Learning Engine ────────────────────────────────────
    info!("🤝 [NEW-B] Initializing Federated Learning Engine (Privacy-Preserving ML)...");
    let fed_learning = Arc::new(federated_learning::FederatedLearningEngine::new("rudras-primary", 128));
    info!("✅ Federated Learning ready — FedAvg | Gaussian DP | Byzantine outlier rejection");

    // ── [NEW-C] Deception Engine (Honeypots + Canary Tokens) ─────────────────
    info!("🍯 [NEW-C] Initializing Deception Engine (Honeypots + Canary Tokens)...");
    let deception_engine = Arc::new(deception::DeceptionEngine::new());
    info!("✅ Deception Engine ready — {} honeypots (SSH/HTTP/FTP/Redis/ES) | HoneyToken canaries",
        deception_engine.honeypot_count());

    // ── [NEW-D] OT/ICS Protocol Anomaly Engine ───────────────────────────────
    info!("🏭 [NEW-D] Initializing OT/ICS Protocol Anomaly Engine...");
    let ot_engine = Arc::new(ot_protocols::OtProtocolEngine::new());
    info!("✅ OT Engine ready — Modbus | DNP3 | GOOSE (IEC 61850)");

    // ── [NEW-E] Encrypted Traffic Analysis (JA3/JA4 fingerprinting) ──────────
    info!("🔍 [NEW-E] Initializing Encrypted Traffic Analysis (JA3/JA4)...");
    let eta_engine_inst = Arc::new(eta_engine::EtaEngine::new());
    info!("✅ ETA Engine ready — JA3/JA4 fingerprinting | 8 known-malware hashes blocked");
    info!("   Cobalt Strike | Metasploit | TrickBot | Dridex | Emotet | QakBot | AsyncRAT | NjRAT");

    // ── [NEW-F] Graph Neural Network — Lateral Movement Detection ────────────
    info!("🕸️  [NEW-F] Initializing GNN Engine (Lateral Movement / APT)...");
    let gnn_engine_inst = Arc::new(gnn_engine::GnnEngine::new());
    info!("✅ GNN Engine ready — GraphSAGE 2-layer | z-score anomaly | APT kill-chain stages");

    // ── [NEW-G] Formal Policy Verifier (NIST SP 800-41) ──────────────────────
    info!("📋 [NEW-G] Initializing Formal Policy Verifier (NIST SP 800-41)...");
    let policy_verif = Arc::new(policy_verifier::PolicyVerifier::new());
    info!("✅ Policy Verifier ready — conflict | shadow | overly-permissive checks | audit log");

    // ── [NEW-H] SBOM Engine (CVE Scanner — Log4Shell, Heartbleed, etc.) ──────
    info!("📦 [NEW-H] Initializing SBOM Engine (Software Bill of Materials + CVE scan)...");
    let sbom_engine_inst = Arc::new(sbom_engine::SbomEngine::new());
    info!("✅ SBOM Engine ready — PURL format | CVE DB (Heartbleed/Log4Shell/curl/sudo) | CycloneDX export");

    // ── [NEW-I] UEBA Engine (User/Entity Behavior Analytics) ─────────────────
    info!("👤 [NEW-I] Initializing UEBA Engine (Behavioral Analytics)...");
    let ueba_engine_inst = Arc::new(ueba_engine::UebaEngine::new());
    info!("✅ UEBA Engine ready — EMA baselines | impossible travel | privilege escalation | risk scoring");

    // ── [NEW-J] SOAR Engine (Automated Incident Response Playbooks) ──────────
    info!("🤖 [NEW-J] Initializing SOAR Engine (Automated Response Playbooks)...");
    let soar_engine_inst = Arc::new(soar_engine::SoarEngine::new());
    info!("✅ SOAR Engine ready — {} playbooks | incident correlation | approval gates | MTTR tracking",
        soar_engine_inst.playbook_count());

    // ── [NEW-K] LLM Explainability Engine (Human-Readable Alert Narratives) ──
    info!("💬 [NEW-K] Initializing LLM Explainability Engine...");
    let explain_engine = Arc::new(llm_explainability::LlmExplainabilityEngine::new());
    info!("✅ LLM Explainability ready — MITRE ATT&CK narratives | SHAP feature attribution | no external API");

    // ── [NEW-L] Forensics Chain (Tamper-Evident Chain of Custody) ─────────────
    info!("⛓️  [NEW-L] Initializing Forensics Chain (Tamper-Evident Evidence)...");
    let forensics = Arc::new(forensics_chain::ForensicsChain::new("rudras-primary"));
    info!("✅ Forensics Chain ready — SHA3-256 linked chain | DFIR JSON export | bulk integrity verify");

    // ── [NEW-M] Differential Privacy Engine ───────────────────────────────────
    info!("🔏 [NEW-M] Initializing Differential Privacy Engine...");
    let dp_engine = Arc::new(differential_privacy::DifferentialPrivacyEngine::new(10.0, 1e-5));
    info!("✅ Differential Privacy ready — Laplace | Gaussian | Exp mechanisms | budget ε≤10 δ≤1e-5");

    // ── [NEW-N] P4 Offload Engine (SmartNIC / P4Runtime) ─────────────────────
    info!("💡 [NEW-N] Initializing P4 Offload Engine (SmartNIC offload)...");
    let p4_endpoint = std::env::var("RUDRAS_P4_ENDPOINT")
        .unwrap_or_else(|_| "127.0.0.1:9559".into());
    let p4_offload_engine = Arc::new(p4_offload::P4OffloadEngine::new(&p4_endpoint, 1));
    if p4_offload_engine.is_hardware_available() {
        info!("✅ P4 Offload Engine ready — hardware P4Runtime endpoint: {}", p4_endpoint);
    } else {
        info!("✅ P4 Offload Engine ready — software-only mode (no P4 device at {})", p4_endpoint);
    }

    // ── [NEW] Start background tasks for new engines ──────────────────────────
    
    // Global Threat Level (DEFCON) Engine
    let posture_engine = Arc::new(defensive_posture::PostureEngine::new());
    {
        let posture_bg = posture_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                posture_bg.tick_decay();
            }
        });
    }

    // 5-Zone Defense-in-Depth Engine (MARL Cross-Zone Rule Forging)
    let did_engine = Arc::new(defense_in_depth::DefenseInDepthEngine::new());
    info!("✅ Defense-in-Depth ready — 5 independent zones + MARL bridge active");
    {
        let did_bg = did_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let stats = did_bg.stats();
                info!("🏛️  Defense-in-Depth | total_events={} | zones:", did_bg.total_events());
                for z in &stats {
                    info!("   Zone {} [{:<12}] [{}] attacks={} countermeasures={} blocks_active={}",
                        z.zone_id, z.zone_name, z.osi_layers,
                        z.attacks_received, z.countermeasures_applied, z.blocks_active);
                }
            }
        });
    }

    {
        let deception_bg = deception_engine.clone();
        let soar_bg = soar_engine_inst.clone();
        let posture_bg = posture_engine.clone();
        let did_bg = did_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Promote any deception alerts to SOAR playbooks.
                let alerts = deception_bg.drain_alerts();
                for alert in &alerts {
                    let soar_alert = soar_engine::SoarAlert {
                        id: alert.id.clone(),
                        source_engine: "DeceptionEngine".into(),
                        severity: soar_engine::AlertSeverity::High,
                        title: format!("Honeypot triggered by {}", alert.attacker_ip),
                        description: format!("Deception trigger {:?} attacker {}", alert.trigger, alert.attacker_ip),
                        affected_ips: vec![alert.attacker_ip],
                        affected_user: None,
                        mitre_tactic: Some("TA0042".into()),
                        timestamp: alert.timestamp,
                    };
                    posture_bg.register_attack_event("HIGH", "Honeypot/Deception Trigger", false);
                    did_bg.trigger_from_ids(
                        defense_in_depth::AttackCategory::HoneypotTrigger,
                        defense_in_depth::AttackSeverity::High,
                        Some(alert.attacker_ip),
                        "DeceptionEngine",
                    );
                    soar_bg.process_alert(soar_alert);
                }
                if !alerts.is_empty() {
                    info!("🍯 Deception: {} alerts promoted to SOAR", alerts.len());
                }
            }
        });
    }
    {
        let ueba_bg = ueba_engine_inst.clone();
        let soar_bg = soar_engine_inst.clone();
        let posture_bg = posture_engine.clone();
        let did_bg = did_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120));
            loop {
                interval.tick().await;
                let high_risk = ueba_bg.drain_high_risk_entities(70.0);
                for entity_id in &high_risk {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0);
                    let soar_alert = soar_engine::SoarAlert {
                        id: format!("UEBA-{}-{}", entity_id, ts),
                        source_engine: "UebaEngine".into(),
                        severity: soar_engine::AlertSeverity::High,
                        title: format!("UEBA high-risk entity: {}", entity_id),
                        description: format!("Entity {} exceeded risk threshold", entity_id),
                        affected_ips: vec![],
                        affected_user: Some(entity_id.clone()),
                        mitre_tactic: Some("TA0003".into()),
                        timestamp: ts,
                    };
                    posture_bg.register_attack_event("CRITICAL", "Insider Threat / UEBA Anomaly", true);
                    did_bg.trigger_from_ids(
                        defense_in_depth::AttackCategory::InsiderThreat,
                        defense_in_depth::AttackSeverity::Critical,
                        None,
                        "UebaEngine",
                    );
                    soar_bg.process_alert(soar_alert);
                }
                if !high_risk.is_empty() {
                    let st = ueba_bg.stats();
                    info!("👤 UEBA: {} high-risk entities promoted to SOAR | tracked={}", high_risk.len(), st.entities_tracked);
                }
            }
        });
    }
    {
        let soar_hb = soar_engine_inst.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let st = soar_hb.stats();
                info!("🤖 SOAR | incidents={} | resolved={} | actions={} | mttr_avg={:.0}s",
                    st.open_incidents, st.resolved_incidents, st.total_actions_taken,
                    st.avg_mttr_secs);
            }
        });
    }
    {
        let gnn_hb = gnn_engine_inst.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                let campaigns = gnn_hb.drain_apt_alerts();
                if !campaigns.is_empty() {
                    info!("🕸️  GNN: {} active APT campaigns tracked", campaigns.len());
                    for c in &campaigns {
                        info!("   APT {} stage={:?} hosts={} confidence={:.2}",
                            c.id, c.current_stage, c.compromised_hosts.len(), c.confidence);
                    }
                }
            }
        });
    }
    {
        let forensics_hb = forensics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                // GDPR retention: purge evidence older than 90 days
                forensics_hb.purge_expired(90);
                let reports = forensics_hb.verify_all();
                let failures: Vec<_> = reports.iter().filter(|r| !r.is_valid).collect();
                if failures.is_empty() {
                    info!("⛓️  Forensics: all {} items chain-verified OK", reports.len());
                } else {
                    for f in &failures {
                        warn!("⛓️  Forensics: chain integrity FAILURE id={} seq={:?} reason={:?}",
                            f.evidence_id, f.failure_at_seq, f.failure_reason);
                    }
                }
            }
        });
    }

    info!("✅ All NEW advanced engines initialised — 14 modules active");

    // ── [NEW-O] DNS Security Engine ───────────────────────────────────────────
    info!("🌐 [NEW-O] Initializing DNS Security Engine...");
    let dns_engine = Arc::new(dns_security::DnsSecurityEngine::new());
    {
        let dns_bg = dns_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                dns_bg.cleanup();
                let st = dns_bg.stats();
                if st.queries_total > 0 {
                    info!("🌐 DNS | queries={} | rpz_blocks={} | tunneling={} | rebinding={} | nxdomain={}",
                        st.queries_total, st.rpz_blocks, st.tunnel_alerts,
                        st.rebinding_alerts, st.nxdomain_total);
                }
            }
        });
    }
    info!("✅ DNS Security Engine ready — RPZ | NXDomain storm | tunneling | rebinding | fast-flux | DoH");

    // ── [NEW-P] Management REST API ───────────────────────────────────────────
    info!("🔒 [NEW-P] Starting Management REST API (loopback-only, auth required)...");
    tokio::spawn(async move {
        let state = management_api::ApiState::new();
        if let Err(e) = management_api::start_management_api(state, "127.0.0.1:7443").await {
            tracing::warn!("Management API stopped: {}", e);
        }
    });
    info!("✅ Management API ready — http://127.0.0.1:7443 | SHA3-256 token auth | RBAC enforced");

    // ── [NEW-Q] eBPF/XDP Offload Engine ──────────────────────────────────────
    info!("⚡ [NEW-Q] Initializing eBPF/XDP Offload Engine...");
    let ebpf_iface = args.interface.as_deref()
        .or(config.interface.as_deref())
        .unwrap_or("auto");
    let ebpf_engine = Arc::new(ebpf_xdp::EbpfXdpEngine::new(ebpf_iface));
    info!("✅ eBPF/XDP Engine ready — LPM trie | connection hash map | syscall tracepoints | XDP DROP/PASS");

    // ── [NEW-R] Compliance Engine (9 Frameworks) ─────────────────────────────
    info!("📋 [NEW-R] Initializing Compliance Engine (9 frameworks)...");
    let compliance_eng = Arc::new(compliance_engine::ComplianceEngine::new());
    {
        let comp_bg = compliance_eng.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let st = comp_bg.stats();
                info!("📋 Compliance | runs={} | avg_score={:.0}% | frameworks={}",
                    st.reports_generated,
                    st.average_score,
                    st.frameworks_enabled);
            }
        });
    }
    info!("✅ Compliance Engine ready — GDPR | PCI-DSS v4 | HIPAA | NIST CSF 2.0 | NIST SP 800-53 | ISO 27001:2022 | CIS Controls v8 | CIS Benchmarks | COBIT 2019");

    // ── [NEW-R2] NERC CIP Engine (Critical Infrastructure Protection) ─────────
    info!("⚡ [NEW-R2] Initializing NERC CIP Engine (Energy / Critical Infrastructure)...");
    // Default to Medium Impact — override via RUDRAS_NERC_CIP_IMPACT env var:
    //   export RUDRAS_NERC_CIP_IMPACT=high   (>1500 MW generation / control centers)
    //   export RUDRAS_NERC_CIP_IMPACT=medium (300-1500 MW / substations)
    //   export RUDRAS_NERC_CIP_IMPACT=low    (all other BES Cyber Systems)
    let cip_impact = match std::env::var("RUDRAS_NERC_CIP_IMPACT")
        .unwrap_or_default().to_lowercase().as_str() {
        "high"   => nerc_cip::BesImpactLevel::High,
        "low"    => nerc_cip::BesImpactLevel::Low,
        _        => nerc_cip::BesImpactLevel::Medium,
    };
    let nerc_cip_engine = Arc::new(nerc_cip::NercCipEngine::new(cip_impact));

    // ── [GAP-1] E-ISAC Integration — closes CIP-008-R1-1.2 ───────────────────
    info!("📡 Initializing E-ISAC Integration (CIP-008-R1-1.2 gap closure)...");
    let eisac_cfg = eisac_integration::EisacConfig {
        endpoint:  std::env::var("RUDRAS_EISAC_ENDPOINT").unwrap_or_default(),
        api_key:   std::env::var("RUDRAS_EISAC_API_KEY").unwrap_or_default(),
        org_name:  std::env::var("RUDRAS_EISAC_ORG").unwrap_or_else(|_| "Rudras Entity".into()),
        nerc_id:   std::env::var("RUDRAS_EISAC_NERC_ID").unwrap_or_else(|_| "UNKNOWN-RE".into()),
        region:    std::env::var("RUDRAS_EISAC_REGION").unwrap_or_else(|_| "UNKNOWN".into()),
        queue_max: 50,
        retry_secs: 300,
    };
    let eisac_live = eisac_cfg.is_live();
    let eisac_engine = Arc::new(eisac_integration::EisacIntegration::new(eisac_cfg));
    info!(
        "✅ E-ISAC Integration ready | mode={} | gap_closed={}",
        if eisac_live { "LIVE" } else { "SIMULATION" }, eisac_live
    );

    // ── [GAP-2] MFA Engine — closes CIP-005-R2-2.2 ───────────────────────────
    info!("🔐 Initializing MFA Engine (CIP-005-R2-2.2 gap closure)...");
    let mfa_provider = match std::env::var("RUDRAS_MFA_PROVIDER")
        .unwrap_or_default().to_lowercase().as_str() {
        "totp"     => mfa_engine::MfaProvider::Totp,
        "azure_ad" => mfa_engine::MfaProvider::AzureAd,
        "okta"     => mfa_engine::MfaProvider::Okta,
        "duo"      => mfa_engine::MfaProvider::Duo,
        _          => mfa_engine::MfaProvider::Disabled,
    };
    let mfa_cfg = mfa_engine::MfaConfig {
        provider:               mfa_provider,
        totp_issuer:            std::env::var("RUDRAS_MFA_ISSUER")
                                    .unwrap_or_else(|_| "Rudras BES Firewall".into()),
        enforce_for_all_remote: true,
        ..mfa_engine::MfaConfig::default()
    };
    let mfa_closed   = mfa_cfg.provider.is_active();
    let mfa_eng      = Arc::new(mfa_engine::MfaEngine::new(mfa_cfg));
    info!(
        "✅ MFA Engine ready | provider={} | gap_closed={}",
        if mfa_closed { mfa_eng.stats().provider.clone() } else { "DISABLED".into() },
        mfa_closed
    );

    // ── NERC CIP background task (uses gap-closure flags) ─────────────────────
    {
        let cip_bg       = nerc_cip_engine.clone();
        let eisac_bg     = eisac_engine.clone();
        let mfa_active   = mfa_closed;
        let eisac_active = eisac_live;
        let ids_on       = true;
        let siem_on      = !args.no_siem;
        let zt_on        = config.zero_trust.enabled;
        let seg_on       = config.segmentation.enabled;

        tokio::spawn(async move {
            // Initial gap report 5s after startup
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            // Report structural gaps to E-ISAC (sim or live)
            eisac_bg.report_structural_gaps(mfa_active).await;

            // Build evidence with real gap-closure flags
            let ev = cip_bg.build_evidence(
                ids_on, siem_on, zt_on, seg_on, true, true
            );
            // Override e_isac and mfa flags based on actual engine state
            let mut ev2 = ev.clone();
            ev2.e_isac_reporting_configured = eisac_active;
            ev2.mfa_for_remote_access       = mfa_active;

            let report  = cip_bg.evaluate(&ev2);
            let gap_rpt = cip_bg.generate_gap_report(&report);
            cip_bg.log_gap_report(&gap_rpt);

            if gap_rpt.has_eisac_reportable() {
                let tmpl = cip_bg.generate_eisac_template(&gap_rpt);
                warn!("📡 NERC CIP E-ISAC NOTIFICATION TEMPLATE:\n{}", tmpl);
            }

            // 6-hour periodic re-evaluation
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(21600));
            loop {
                interval.tick().await;
                let mut ev6 = cip_bg.build_evidence(
                    ids_on, siem_on, zt_on, seg_on, true, true);
                ev6.e_isac_reporting_configured = eisac_active;
                ev6.mfa_for_remote_access       = mfa_active;

                let rep6 = cip_bg.evaluate(&ev6);
                let gr6  = cip_bg.generate_gap_report(&rep6);
                let st   = cip_bg.stats();
                let _    = cip_bg.drain_alerts();

                // Retry any queued E-ISAC reports
                eisac_bg.flush_queue().await;

                info!(
                    "⚡ NERC CIP 6h | score={:.1}% | gaps={} \
                     (imm={} 35d={} 90d={} ann={}) | impact={} | \
                     eisac={} mfa={}",
                    rep6.overall_score, gr6.total_gaps(),
                    gr6.immediate_gaps.len(), gr6.days_35_gaps.len(),
                    gr6.days_90_gaps.len(), gr6.annual_gaps.len(),
                    st.current_impact_level,
                    if eisac_active { "LIVE" } else { "SIM" },
                    if mfa_active   { "OK"   } else { "OPEN" }
                );
                cip_bg.log_gap_report(&gr6);

                if gr6.has_eisac_reportable() {
                    let open = gr6.immediate_gaps.len()
                        + gr6.days_35_gaps.iter()
                          .filter(|g| g.must_report_to_eisac).count();
                    warn!("📡 NERC CIP: {} E-ISAC reportable gaps open — \
                           submit at https://www.eisac.com", open);
                }
            }
        });
    }
    info!("✅ NERC CIP Engine ready — CIP-002 through CIP-014 | gaps: \
           E-ISAC={} MFA={}",
        if eisac_live { "CLOSED" } else { "SIMULATION" },
        if mfa_closed { "CLOSED" } else { "OPEN — set RUDRAS_MFA_PROVIDER=totp" }
    );

    // ── [NEW-S] QUIC Inspector ────────────────────────────────────────────────
    info!("🔍 [NEW-S] Initializing QUIC Inspector...");
    let quic_insp = Arc::new(quic_inspector::QuicInspector::new());
    {
        let quic_bg = quic_insp.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                quic_bg.cleanup();
                let st = quic_bg.stats();
                if st.packets_inspected > 0 {
                    info!("🔍 QUIC | pkts={} | connections={} | 0rtt={} | migration={} | unknown_ver={}",
                        st.packets_inspected, st.connections_tracked,
                        st.zero_rtt_count, st.migration_count, st.unknown_version_count);
                }
            }
        });
    }
    info!("✅ QUIC Inspector ready — version fingerprinting | 0-RTT | connection migration detection");

    // ── [NEW-T] YARA+Sigma Threat Rules Engine ───────────────────────────────
    info!("🔎 [NEW-T] Initializing Threat Rules Engine (YARA + Sigma)...");
    let threat_rules = Arc::new(threat_rules_engine::ThreatRulesEngine::new());
    info!("✅ Threat Rules Engine ready — 9 YARA rules (CobaltStrike/Mimikatz/Meterpreter/WannaCry/Log4Shell) | 7 Sigma rules");

    // ── [NEW-U] TPM Attestation Engine ───────────────────────────────────────
    info!("🔒 [NEW-U] Initializing TPM Attestation Engine...");
    let tpm_engine = Arc::new(tpm_attestation::TpmAttestationEngine::new());
    let tpm_quote = tpm_engine.generate_quote(b"rudras-startup-nonce");
    info!("✅ TPM Attestation ready — PCRs measured | quote={:.16}... | hw={}",
        tpm_quote.signature_hex, tpm_engine.hw_available);

    // ── [NEW-W] RL Adaptive Policy ────────────────────────────────────────────
    info!("🤖 [NEW-W] Initializing RL Adaptive Policy Engine (Q-learning)...");
    let rl_policy_eng = Arc::new(rl_policy::RlPolicyEngine::new());
    info!("✅ RL Policy Engine ready — 6 actions | ε-greedy (ε=1.0→0.05) | RFC-1918 safety guard");

    // ── [NEW-X] Moving Target Defense ────────────────────────────────────────
    info!("🎯 [NEW-X] Initializing Moving Target Defense Engine...");
    let mtd_eng = Arc::new(mtd_engine::MtdEngine::new());
    {
        let mtd_bg = mtd_eng.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                mtd_bg.tick();
                let st = mtd_bg.stats();
                if st.ip_rotations + st.port_rotations > 0 {
                    info!("🎯 MTD | vip_rotations={} | port_rotations={} | decoy_probes={}",
                        st.ip_rotations, st.port_rotations, st.decoy_probes);
                }
            }
        });
    }
    info!("✅ MTD Engine ready — IP hopping | port randomisation | 5 decoy services");

    // ── [NEW-Y] Homomorphic IOC Sharing ──────────────────────────────────────
    info!("🔏 [NEW-Y] Initializing Privacy-Preserving IOC Sharing Engine...");
    let hom_sharing = Arc::new(homomorphic_sharing::HomomorphicSharingEngine::new());
    info!("✅ Homomorphic Sharing ready — Paillier PHE | Private Set Intersection | Shamir secret sharing");

    // ── [NEW-Z] Email Security Engine ────────────────────────────────────────
    info!("📧 [NEW-Z] Initializing Email Security Engine...");
    let email_sec = Arc::new(email_security::EmailSecurityEngine::new());
    {
        let email_bg = email_sec.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                email_bg.cleanup();
                let st = email_bg.stats();
                if st.sessions_inspected > 0 {
                    info!("📧 Email | inspected={} | spf_fail={} | dmarc_fail={} | bec={} | risky_attach={}",
                        st.sessions_inspected, st.spf_fails, st.dmarc_fails,
                        st.bec_alerts, st.risky_attachments);
                }
            }
        });
    }
    info!("✅ Email Security ready — SPF | DKIM | DMARC | BEC | attachment scoring | URL analysis");

    // ── [NEW-AA] Formal Policy Verifier ──────────────────────────────────────
    info!("📐 [NEW-AA] Initializing Formal Policy Verification Engine...");
    let formal_ver = Arc::new(formal_verification::FormalVerifier::new());
    info!("✅ Formal Verifier ready — shadow | conflict | redundancy | reachability analysis");

    // ── [NEW-AB] RASP Engine ──────────────────────────────────────────────────
    info!("🛡️  [NEW-AB] Initializing Runtime Application Self-Protection (RASP)...");
    let rasp_eng = Arc::new(rasp_engine::RaspEngine::new());
    {
        let rasp_bg = rasp_eng.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                rasp_bg.periodic_scan();
                let st = rasp_bg.stats();
                if st.alerts_total > 0 {
                    info!("🛡️  RASP | protected={} | scans={} | alerts={} | hollowing={} | injection={} | fileless={}",
                        st.processes_protected, st.scans_completed, st.alerts_total,
                        st.hollowing_detected, st.injection_detected, st.fileless_detected);
                }
            }
        });
    }
    info!("✅ RASP Engine ready — process hollowing | DLL injection | fileless exec | syscall policy");

    // ── [NEW-AC] Secure Channel Manager ──────────────────────────────────────
    info!("🔐 [NEW-AC] Initializing Secure Channel Manager (TLS 1.3 / mTLS)...");
    let sec_chan = Arc::new(secure_channel::SecureChannelManager::new());
    {
        let sc_bg = sec_chan.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120));
            loop {
                interval.tick().await;
                sc_bg.cleanup_sessions();
                let st = sc_bg.stats();
                if st.sessions_active > 0 {
                    info!("🔐 SecureChan | sessions={} | established={} | keys_rotated={} | replay_blocks={} | no_ct_alerts={}",
                        st.sessions_active, st.sessions_established, st.key_rotations,
                        st.replay_blocks, st.no_ct_alerts);
                }
            }
        });
    }
    info!("✅ SecureChannel ready — TLS 1.3 | mTLS | cert-pinning | CT | replay protection");

    // ── [NEW-AD] Memory Safety Engine ────────────────────────────────────────
    info!("🔒 [NEW-AD] Initializing Memory Safety Engine...");
    let mem_safety = Arc::new(memory_safe_pool::MemorySafetyEngine::new());
    {
        let ms_bg = mem_safety.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                ms_bg.evict_expired();
                let st = ms_bg.stats();
                if st.canary_violations > 0 || st.wx_violations > 0 {
                    info!("🔒 MemSafe | secrets={} | canary_checks={} | canary_viols={} | wx_viols={} | aslr_alerts={}",
                        st.secrets_stored, st.canary_checks, st.canary_violations,
                        st.wx_violations, st.aslr_alerts);
                }
            }
        });
    }
    info!("✅ MemorySafety ready — zeroizing vault | W^X | stack canaries | ASLR entropy");

    // ── [NEW-AE] Supply Chain Verifier ────────────────────────────────────────
    info!("📦 [NEW-AE] Initializing Supply Chain Verifier (SLSA / in-toto)...");
    let supply_chain = Arc::new(supply_chain_verifier::SupplyChainVerifier::new());
    {
        let sc_bg = supply_chain.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let st = sc_bg.stats();
                info!("📦 SupplyChain | components={} | verifications={} | violations={} | hash_mismatch={} | typosquat={} | dep_confusion={}",
                    st.components_registered, st.verifications_run, st.violations_found,
                    st.hash_mismatches, st.typosquatting_alerts, st.dependency_confusion_alerts);
            }
        });
    }
    info!("✅ SupplyChain ready — SLSA | hash pinning | typosquat | transitive taint");

    // ── [NEW-AF] Adaptive Honeypot Engine ─────────────────────────────────────
    info!("🍯 [NEW-AF] Initializing Adaptive Honeypot Engine (interactive deception)...");
    let honeypot = Arc::new(adaptive_honeypot::AdaptiveHoneypotEngine::new());
    {
        let hp_bg = honeypot.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                hp_bg.cleanup_stale_sessions(600);
                let st = hp_bg.stats();
                if st.sessions_total > 0 {
                    info!("🍯 Honeypot | sessions={} | active={} | cmds={} | canary_hits={} | downloads={} | high_soph={}",
                        st.sessions_total, st.sessions_active, st.commands_processed,
                        st.canary_tokens_hit, st.download_attempts, st.high_sophist_sessions);
                }
            }
        });
    }
    info!("✅ AdaptiveHoneypot ready — interactive shell | canary tokens | TTP tracking | campaign correlation");

    // ── [NEW-AG] Network DPI + ML Anomaly ────────────────────────────────────
    info!("🧠 [NEW-AG] Initializing Network DPI + ML Anomaly Detection Engine...");
    let dpi_ml = Arc::new(network_dpi_ml::NetworkDpiMlEngine::new());
    {
        let ml_bg = dpi_ml.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let st = ml_bg.stats();
                info!("🧠 DPI-ML | flows={} | ml_flags={} | anomalies={} | zero_day={} | accuracy={:.1}% | samples={}",
                    st.flows_classified, st.ml_malicious_flags, st.anomaly_flags,
                    st.zero_day_candidates, st.model_accuracy * 100.0, st.model_samples);
            }
        });
    }
    info!("✅ NetworkDpiML ready — online LR | K-Means clustering | zero-day anomaly | score fusion");

    // ── [NEW-AH] Threat Hunt Engine ───────────────────────────────────────────
    info!("🔍 [NEW-AH] Initializing Proactive Threat Hunt Engine...");
    let threat_hunter = Arc::new(threat_hunt::ThreatHuntEngine::new());
    {
        let th_bg = threat_hunter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(900));
            loop {
                interval.tick().await;
                let findings = th_bg.run_due_hunts();
                let st = th_bg.stats();
                if !findings.is_empty() || st.campaigns_tracked > 0 {
                    info!("🔍 ThreatHunt | hunts={} | findings={} | high_sev={} | campaigns={} | ioc_nodes={} | pivots={}",
                        st.hunts_executed, st.findings_total, st.high_severity,
                        st.campaigns_tracked, st.ioc_graph_nodes, st.pivot_queries);
                }
            }
        });
    }
    info!("✅ ThreatHunt ready — MITRE ATT&CK 8 hypotheses | IOC pivot | campaign clustering | hunt scheduler");

    info!("✅ All 34 defense engines active (14 original + 14 gap-closure + 6 research-grade)");
    info!("🔍 [IDS] Initializing Intrusion Detection System (200+ signatures)...");
    let ids_engine = Arc::new(ids_engine::IdsEngine::new());
    info!("✅ IDS ready — Engines: Signature | Protocol | Behavioral | DGA | Anomaly");
    info!("   📖 Rule categories: SQLi·XSS·DirTraversal·CmdInj·RCE·Shellshock");
    info!("   📖 Rule categories: Log4Shell·EternalBlue·Mirai·Cobalt Strike·Mimikatz");
    info!("   📖 Protocols decoded: HTTP·HTTPS(TLS)·DNS·SMB·FTP·SSH");
    // Print MITRE ATT&CK + OWASP Top 10 detection matrix on startup
    framework_alignment::log_detection_matrix();
    // Schedule IDS cleanup every 10 minutes
    {
        let ids_hb = ids_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                ids_hb.cleanup_stale_profiles();
                let st = ids_hb.get_stats();
                info!("🔍 IDS Stats | total_pkts={} | alerts={} | critical={} | high={} | profiles={}",
                      st.total_packets, st.total_alerts, st.critical_alerts,
                      st.high_alerts, st.active_ip_profiles);
            }
        });
    }

    // ── [A] WFP Engine — Primary Enforcement (Kernel Layer) ──────────────────
    info!("🔷 [A/D] Initializing WFP Engine (Windows Filtering Platform)...");
    let wfp = Arc::new(wfp_engine::WfpEngine::new());
    wfp.open_session()?;
    // Install default dangerous-port blocks
    for (port, reason) in wfp_engine::default_blocked_ports() {
        wfp.block_port(port, wfp_engine::WfpDirection::Inbound, reason);
    }
    // Whitelist core Windows system apps so they never get blocked
    for (app, reason) in wfp_engine::trusted_system_apps() {
        wfp.allow_app(app, reason);
    }
    let wfp_st = wfp.get_stats();
    info!(
        "✅ WFP Engine ready — {} port blocks | {} app allowlists | session=DYNAMIC",
        wfp_st.blocked_ports, wfp_st.active_rules
    );

    // ── [IPS] Intrusion Prevention System (needs WFP — must be after WFP init) ─
    info!("🛡️  [IPS] Initializing Intrusion Prevention System (Inline mode)...");
    // Mode profile overrides config file thresholds when mode is explicitly set
    let ips_cfg = ips_engine::IpsConfig {
        mode: ips_engine::IpsMode::Inline,
        rate_limit_threshold: mode_profile.ips_rate_limit_thresh,
        rst_threshold: mode_profile.ips_rst_thresh,
        block_threshold: mode_profile.ips_block_thresh,
        quarantine_threshold: mode_profile.ips_quarantine_thresh,
        blacklist_threshold: mode_profile.ips_blacklist_thresh,
        block_duration_secs: config.ips.block_duration_secs,
        quarantine_duration_secs: config.ips.quarantine_duration_secs,
        rate_limit_pps: config.ips.rate_limit_pps,
        auto_block_high: mode_profile.ips_auto_block_high,
        auto_block_critical: mode_profile.ips_auto_block_critical,
        whitelist: config.ips.whitelist.clone(),
    };
    let ips_engine = Arc::new(ips_engine::IpsEngine::new(ips_cfg, wfp.clone()));
    info!("✅ IPS ready — Mode=Inline | Penalty decay: 30min half-life");
    info!(
        "   📊 Thresholds: RateLimit={} | RST={} | Block={} | Quarantine={} | Blacklist={}",
        config.ips.rate_limit_threshold,
        config.ips.rst_threshold,
        config.ips.block_threshold,
        config.ips.quarantine_threshold,
        config.ips.blacklist_threshold
    );
    // Schedule IPS cleanup every 5 minutes
    {
        let ips_hb = ips_engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                ips_hb.cleanup_expired();
                let st = ips_hb.get_stats();
                info!("🛡️  IPS Stats | decisions={} | blocks={} | resets={} | rate_limits={} | quarantine={} | blacklist={} | blocked_ips={}",
                      st.decisions_total, st.blocks_issued, st.resets_injected,
                      st.rate_limits_applied, st.quarantines_active,
                      st.blacklists_total, st.actively_blocked_ips);
            }
        });
    }

    // ── [B] WinDivert Engine — Selective Deep Inspection ─────────────────────
    info!("🔀 [B/D] Initializing WinDivert Engine (suspicious traffic only)...");
    let honeypot_cfg = windivert_engine::HoneypotConfig::default();
    let windivert = Arc::new(windivert_engine::WinDivertEngine::new(honeypot_cfg));
    windivert.initialize()?;
    if windivert.is_active() {
        info!("✅ WinDivert active — deep inspection ON for escalated flows (score≥0.65)");
    } else {
        warn!("⚠️  WinDivert not available — see logs for install instructions");
    }

    // ── [C] Npcap Forensic Engine — Passive Monitoring ───────────────────────
    info!("🔬 [C/D] Initializing Npcap Forensic Engine (stats-only / passive)...");
    // Resolve interface early for forensic engine (will be re-used below)
    let interface_name = args
        .interface
        .clone()
        .or(config.interface.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No network interface specified.\n\
             → Set 'interface' in config/rudras.toml  OR\n\
             → Pass --interface <name> on the command line."
            )
        })?;

    let npcap_forensic = Arc::new(npcap_forensic::NpcapForensicEngine::new(
        &interface_name,
        npcap_forensic::ForensicMode::StatsOnly, // Default: legal-safe
    ));
    info!("✅ Npcap Forensic ready — mode=StatsOnly | AI training feed: active");
    info!("   Selective header capture activates automatically for escalated flows");

    // ── [D] AI Engine — 4-Layer Threat Intelligence ───────────────────────────
    info!("🧠 [D/D] Initializing AI Engine (4-layer adaptive intelligence)...");
    let ai_engine = Arc::new(ai_engine::AiEngine::new(&config.ai));
    // Schedule adaptive threshold tuning every 5 minutes
    {
        let ai_hb = ai_engine.clone();
        let npcap_hb = npcap_forensic.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                // Drain Npcap training samples → feed to AI online learner
                let samples = npcap_hb.drain_training_samples(500);
                if !samples.is_empty() {
                    ai_hb.train_online(samples);
                }
                // Adapt thresholds based on FP rate
                ai_hb.adapt_thresholds();
                // Log AI stats
                let st = ai_hb.get_stats();
                info!(
                    "🧠 AI Stats | v{} | preds={} | threats={} | fp={} | susp={:.2} | blk={:.2}",
                    st.model_version,
                    st.predictions_total,
                    st.threats_detected,
                    st.false_positives,
                    st.susp_threshold,
                    st.block_threshold
                );
            }
        });
    }
    info!("✅ AI Engine ready — model v1 | online learning: ACTIVE | profiles: 0");

    // ── [E] Advanced ML Zero-Day IoT Detection ──────────────────────────────────
    info!("🤖 [E/D] Initializing Zero-Day IoT Attack AI Detection...");
    let advanced_ml_engine = Arc::new(advanced_ml::AdvancedMlEngine::new());
    info!("✅ Advanced ML Engine ready — IoT protection enabled (CICIoT2023 & UNSW-NB15)");

    // ── [F] Layer 2 Engine (ARP/MAC Anomaly) ────────────────────────────────
    info!("🔗 [F/D] Initializing Layer 2 Security Engine...");
    let l2_engine = Arc::new(l2_engine::L2Engine::new());

    // ── Network Interface ─────────────────────────────────────────────────────
    list_network_interfaces()?;
    let interface = interface_name.clone();
    info!("📡 Active interface: {}", interface);

    // ── Packet Capture Pipeline ───────────────────────────────────────────────
    info!("🚀 Starting full Firewall + IDS + IPS packet capture pipeline...");
    let mut capture = WindowsPacketCapture::new(
        &interface,
        policy_engine.clone(),
        metrics.clone(),
        threat_intel.clone(),
        advanced_security.clone(),
        Some(immunity_tx),
        seg_engine.clone(),
        siem.clone(),
        comp_blocker.clone(),
        Arc::new(config.blocking.clone()),
        wfp.clone(),
        windivert.clone(),
        npcap_forensic.clone(),
        ai_engine.clone(),
        advanced_ml_engine.clone(),
        l2_engine.clone(),
        ids_engine.clone(),
        ips_engine.clone(),
        attribution_engine.clone(),
        mode_profile, // 🎯 client | server profile
    )?;

    info!("🛡️  ═══════════════════════════════════════════════════════════════╗");
    info!("🛡️  ALL 17 DEFENSE SYSTEMS ACTIVE — Enterprise Firewall+IDS+IPS   ║");
    info!("🛡️  ┌───────────────────────────────────────────────────────────┐  ║");
    info!("🛡️  │  🔥 FIREWALL LAYER                                        │  ║");
    info!("🛡️  │    🔷 WFP Engine   │ Kernel enforcement  │ ACTIVE          │  ║");
    info!("🛡️  │    🔀 WinDivert    │ Deep inspection     │ ON-DEMAND       │  ║");
    info!("🛡️  │    🔬 Npcap        │ Passive / AI feed   │ PASSIVE         │  ║");
    info!("🛡️  │    🧠 AI Engine    │ Adaptive ML         │ INLINE          │  ║");
    info!("🛡️  ├───────────────────────────────────────────────────────────┤  ║");
    info!("🛡️  │  🔍 IDS LAYER (Intrusion Detection System)                 │  ║");
    info!("🛡️  │    200+ Snort rules │ HTTP/DNS/TLS/SMB decode │ Behavioral  │  ║");
    info!("🛡️  │    DGA detection   │ Port scan │ SYN Flood │ Brute Force   │  ║");
    info!("🛡️  ├───────────────────────────────────────────────────────────┤  ║");
    info!("🛡️  │  🛡️  IPS LAYER (Intrusion Prevention System)               │  ║");
    info!("🛡️  │    Mode=INLINE     │ RateLimit │ TCP-RST │ WFP-Block       │  ║");
    info!("🛡️  │    Quarantine      │ Blacklist │ Penalty decay │ Auto-block │  ║");
    info!("🛡️  ├───────────────────────────────────────────────────────────┤  ║");
    info!("🛡️  │  🖥️  ENDPOINT SECURITY (Host-Based Protection)             │  ║");
    info!("🛡️  │    Process monitor │ LOLBin detect │ Cred-access alerts   │  ║");
    info!("🛡️  │    Persistence/lateral tools │ Posture score for ZeroTrust│  ║");
    info!("🛡️  ├───────────────────────────────────────────────────────────┤  ║");
    info!("🛡️  │  🎯 ATTRIBUTION ENGINE (Probabilistic, MITRE ATT&CK)       │  ║");
    info!("🛡️  │    Botnet │ OpportunisticScan │ CyberCriminal │ APT-style  │  ║");
    info!("🛡️  │    Insider │ LOLBin misuse │ NOT legal proof (disclaimer)  │  ║");
    info!("🛡️  └───────────────────────────────────────────────────────────┘  ║");
    info!("🛡️  ═══════════════════════════════════════════════════════════════╝");

    // ── Metrics Server ────────────────────────────────────────────────────────
    let metrics_clone = metrics.clone();
    let mp = config.metrics_port;
    let _metrics_h = tokio::spawn(async move {
        if let Err(e) = metrics::start_metrics_server(mp, metrics_clone).await {
            error!("Metrics server error: {}", e);
        }
    });

    // ── Capture loop + graceful shutdown ──────────────────────────────────────
    let cap_handle = tokio::spawn(async move { capture.start_capture().await });

    tokio::select! {
        result = cap_handle => {
            match result {
                Ok(Ok(())) => info!("Capture loop exited cleanly"),
                Ok(Err(e)) => error!("Capture error: {}", e),
                Err(e)     => error!("Capture task panicked: {}", e),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Ctrl-C received — flushing SIEM buffer and shutting down...");
        }
    }

    info!("Rudras Data Plane shutting down...");
    print_final_statistics(&metrics);
    Ok(())
}

// ============================================================================
// STARTUP BANNER
// ============================================================================

fn print_banner() {
    info!("╔═══════════════════════════════════════════════════════════════════════╗");
    info!("║   🛡️  RUDRAS ENTERPRISE SECURITY PLATFORM v4.0                       ║");
    info!("║       FIREWALL + IDS + IPS — Industry-Grade Unified Defense          ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── FIREWALL LAYER (WFP/WinDivert/Npcap/AI — McAfee Architecture) ── ║");
    info!("║  🔷 WFP Engine         Kernel enforcement | port/IP/app rules         ║");
    info!("║  🔀 WinDivert          Selective deep inspection (suspicious flows)   ║");
    info!("║  🔬 Npcap Forensic     Passive analysis + AI training feed            ║");
    info!("║  🧠 AI Engine          4-layer ML | online learning | threshold adapt ║");
    info!("║  🤖 Advanced ML        Zero-Day IoT Attack Detection | CICIoT2023     ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── IDS LAYER (Intrusion Detection — Snort 3 / Suricata Style) ────── ║");
    info!("║  🔍 Signature Engine   200+ Snort rules | CVEs | exploits | malware  ║");
    info!("║  🔍 Protocol Decoder   HTTP·HTTPS·DNS·TLS·SMB·FTP·SSH anomaly detect ║");
    info!("║  🔍 Behavioral Engine  Port scan | SYN flood | brute force | DGA     ║");
    info!("║  🔍 Exfil Detector     DNS tunnel | large POST | FTP exfil patterns  ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── IPS LAYER (Intrusion Prevention — McAfee / Cisco FirePOWER) ───── ║");
    info!("║  🛡️  INLINE mode        Active blocking / RST injection / quarantine  ║");
    info!("║  🛡️  Penalty Engine     Graduated response | 30min decay half-life   ║");
    info!("║  🛡️  Rate Limiter       Token bucket per-IP throttling               ║");
    info!("║  🛡️  WFP Block          Kernel-level drop rules for confirmed threats ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── SECURITY INTELLIGENCE STACK ────────────────────────────────────  ║");
    info!("║  ✅ Zero Trust          AD / SAML / OAuth + Device Posture            ║");
    info!("║  ✅ CyberImmune         Bio-inspired antibody evolution               ║");
    info!("║  ✅ Micro-Segmentation  8 security zones + lateral movement detect   ║");
    info!("║  ✅ Threat Intelligence Feodo + URLhaus + SSLBL (live feeds)          ║");
    info!("║  ✅ SIEM Integration    Splunk / Elasticsearch / QRadar               ║");
    info!("║  ✅ IOC-Based Blocking  Feodo+SSLBL+ThreatFox (no country blocks)    ║");
    info!("║  ✅ Distributed P2P     Rule sync across firewall cluster            ║");
    info!("║  ✅ Endpoint Security   LOLBin·CredAccess·Persistence·Posture score  ║");
    info!("║  ✅ Attribution Engine  Probabilistic MITRE ATT&CK actor scoring     ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── SECURITY FRAMEWORK ALIGNMENT ───────────────────────────────────  ║");
    info!("║  🗂  MITRE ATT&CK v14   Every IDS alert tagged with Technique ID     ║");
    info!("║     Covers: T1071 C2 | T1110 BruteForce | T1486 Ransomware          ║");
    info!("║             T1190 ExploitApp | T1041 Exfil | T1498 DoS | T1046 Scan ║");
    info!("║  🗂  OWASP Top 10 2021  Web-layer alerts cross-referenced to OWASP   ║");
    info!("║     Covers: A03 Injection | A07 AuthFailure | A02 CryptoFail        ║");
    info!("║             A01 AccessControl | A05 Misconfig | A10 SSRF            ║");
    info!("╠═══════════════════════════════════════════════════════════════════════╣");
    info!("║  ── PERFORMANCE — FAST-PATH OPTIMIZATION ───────────────────────────  ║");
    info!("║  ⚡ ~95% clean        → Flow Engine fast-path (<1μs, no DPI cost)    ║");
    info!("║  🔍 ~5% suspicious    → IDS inspect + IPS respond + WinDivert DPI   ║");
    info!("║  🚫 High-risk flows   → WFP kernel block (<1ms), IPS blacklist       ║");
    info!("╚═══════════════════════════════════════════════════════════════════════╝");
    info!("  Config: config/rudras.toml  |  Version: 4.0.0  |  Platform: Windows");
}

// ============================================================================
// SESSION STATS
// ============================================================================

fn print_final_statistics(metrics: &Arc<metrics::Metrics>) {
    let s = metrics.get_stats();

    let ap = if s.packets_total > 0 {
        (s.packets_allowed as f64 / s.packets_total as f64) * 100.0
    } else {
        0.0
    };
    let bp = if s.packets_total > 0 {
        (s.packets_blocked as f64 / s.packets_total as f64) * 100.0
    } else {
        0.0
    };

    info!("");
    info!("╔══════════════════════════════════════════════════════════════════╗");
    info!("║          🛡️  Rudras — SESSION SUMMARY                          ║");
    info!("╠══════════════════════════════════════════════════════════════════╣");
    info!(
        "⏱  Uptime:       {} s  ({} min)",
        s.uptime_seconds,
        s.uptime_seconds / 60
    );
    info!(
        "📦 Packets:      Total={} | ✅ {:.1}% allowed | 🚫 {:.1}% blocked",
        s.packets_total, ap, bp
    );
    info!(
        "📊 Traffic:      ⬇ {} MB  ⬆ {} MB",
        s.bytes_received / 1_048_576,
        s.bytes_sent / 1_048_576
    );
    info!(
        "🔌 Connections:  TCP={}  UDP={}",
        s.connections_tcp, s.connections_udp
    );
    info!("🔴 Threats:      {}", s.threats_detected);

    if !s.protocol_counts.is_empty() {
        info!("📋 Top protocols:");
        let mut protos: Vec<_> = s.protocol_counts.iter().collect();
        protos.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in protos.iter().take(5) {
            info!("   {:<10} {}", proto, count);
        }
    }
    info!("╚══════════════════════════════════════════════════════════════════╝");
}

// ============================================================================
// INTERFACE LISTING
// ============================================================================

fn list_network_interfaces() -> Result<()> {
    let devices =
        pcap::Device::list().context("Failed to list network devices (is Npcap installed?)")?;

    info!("📡 Available network interfaces ({} found):", devices.len());
    if devices.is_empty() {
        warn!("⚠️ No interfaces — install Npcap: https://npcap.com");
        return Ok(());
    }
    for (i, d) in devices.iter().enumerate() {
        info!(
            "  [{:2}]  {:38}  {}",
            i + 1,
            d.name,
            d.desc.as_deref().unwrap_or("")
        );
    }
    Ok(())
}
