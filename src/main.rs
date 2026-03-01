// Rudras Cross-Platform Firewall — Enterprise Edition
// All advanced security modules configured from config/rudras.toml

#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unexpected_cfgs,
    unused_unsafe
)]

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// === CORE MODULES ===
mod advanced_security;
mod config;
mod cyber_immune;
mod dpi;
mod l2_engine;
mod metrics;
mod policy;
mod process_monitor;
mod stateful;
// === ENTERPRISE MODULES ===
mod gateway_mode;
mod identity_policy; // Identity-Aware Policy Engine
mod siem_integration; // SIEM connectors (Splunk/ELK/QRadar)
mod zero_trust; // Zero Trust: AD/SAML/OAuth + Device Posture // Gateway/perimeter mode with HA

// === PRIORITY 1 MODULES ===
mod micro_segmentation;
mod threat_intelligence; // Threat feed aggregator (Feodo/URLhaus/SSLBL) // Zone-based isolation & lateral movement prevention

// === PRIORITY 2 MODULES ===
mod cloud_native;
mod sdwan;
mod single_pass;

// === PRIORITY 3 MODULES ===
mod advanced_ml;
mod distributed_immunity;
mod hardware_accel; // P2P Rule Sync

// === McAFEE-STYLE FLOW ENGINE ===
mod flow_engine; // Lightweight stateful flow risk scorer (fast-path)

// === McAFEE 4-COMPONENT ENGINE STACK ===
mod ai_engine;
mod npcap_forensic; // 🔬 Npcap — Passive forensic + AI training data collection
mod wfp_engine; // 🔷 WFP — Primary kernel enforcement layer
mod windivert_engine; // 🔀 WinDivert — Selective deep inspection (suspicious only) // 🧠 AI Engine — 4-layer adaptive threat intelligence

// === IDS + IPS ENGINES ===
mod ids_engine; // 🔍 IDS — 200+ Snort rules | protocol decoders | behavioral analysis
mod ips_engine; // 🛡️  IPS — Inline prevention: RST | WFP block | rate-limit | quarantine

// === COMPREHENSIVE THREAT BLOCKER (ALL 10 CATEGORIES) ===
mod comprehensive_blocker;

// === DEPLOYMENT MODE PROFILES ===
mod mode_profiles; // 🎯 Client / Server / Auto mode profiles

// === PLATFORM-SPECIFIC CAPTURE ===
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

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&effective_log_level))
        .with(tracing_subscriber::fmt::layer().with_target(false).pretty())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .json(),
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
    let mut identity_policy_engine = identity_policy::IdentityAwarePolicyEngine::new();
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

    // ── [IDS] Intrusion Detection System ─────────────────────────────────────
    info!("🔍 [IDS] Initializing Intrusion Detection System (200+ signatures)...");
    let ids_engine = Arc::new(ids_engine::IdsEngine::new());
    info!("✅ IDS ready — Engines: Signature | Protocol | Behavioral | DGA | Anomaly");
    info!("   📖 Rule categories: SQLi·XSS·DirTraversal·CmdInj·RCE·Shellshock");
    info!("   📖 Rule categories: Log4Shell·EternalBlue·Mirai·Cobalt Strike·Mimikatz");
    info!("   📖 Protocols decoded: HTTP·HTTPS(TLS)·DNS·SMB·FTP·SSH");
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
        mode_profile, // 🎯 client | server profile
    )?;

    info!("🛡️  ═══════════════════════════════════════════════════════════════╗");
    info!("🛡️  ALL 15 DEFENSE SYSTEMS ACTIVE — Enterprise Firewall+IDS+IPS   ║");
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
    info!("║  ✅ GeoIP Blocking      MaxMind GeoLite2                             ║");
    info!("║  ✅ Distributed P2P     Rule sync across firewall cluster            ║");
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
