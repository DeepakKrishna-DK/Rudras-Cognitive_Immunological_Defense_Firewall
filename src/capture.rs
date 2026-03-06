// ============================================================================
// Rudras Packet Capture — Full McAfee-Style 4-Component Pipeline
// ============================================================================
//
// Execution order per packet:
//
//  Every packet:
//   ── WFP fast-path: is this IP kernel-blocked? → drop instantly (<1µs)
//   ── Npcap Forensic: observe_packet() → stats feed (always, O(1))
//   ── Flow Engine: update() → risk score
//
//  If Flow score < 0.65 (Allow):
//   ── Fast-path allow → done
//
//  If Flow score 0.65–0.85 (Escalate):
//   ── Full Shield Stack: CompBlocker → Policy → ThreatIntel → MicroSeg → AI
//   ── WinDivert: deep payload inspection + optional honeypot redirect
//   ── AI Engine: predict() → refine block/allow decision
//   ── WFP: install block rule if AI confirms threat (persistent kernel rule)
//
//  If Flow score > 0.85 (Block):
//   ── WFP: block_ip() → kernel rule (future packets drop at kernel, no userspace)

#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unexpected_cfgs,
    unused_unsafe
)]

use anyhow::Result;
use pcap::{Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::cyber_immune::{CyberImmuneSystem, ResponseAction};
use crate::distributed_immunity::AntibodyPayload;
use crate::metrics::Metrics;
use crate::policy::{ActionType, HybridRule, PolicyEngine, RuleOrigin};
use tokio::sync::mpsc;

use crate::advanced_security::AdvancedSecurity;
use crate::comprehensive_blocker::{BlockVerdict, ComprehensiveBlocker, Direction as BlkDir};
use crate::flow_engine::{FlowDecision, FlowEngine, SUSPICIOUS_RISK_THRESHOLD};
use crate::micro_segmentation::MicroSegmentationEngine;
use crate::mode_profiles::ModeProfile;
use crate::siem_integration::{SIEMIntegration, SecurityEvent};
use crate::threat_intelligence::ThreatIntelligenceHub;

// ── 4 McAfee-style + IDS/IPS components ──────────────────────────────────────────
use crate::advanced_ml::AdvancedMlEngine;
use crate::ai_engine::{AiEngine, AiRecommendation};
use crate::ids_engine::{IdsEngine, IdsSeverity}; // 🔍 Intrusion Detection
use crate::ips_engine::{IpsAction, IpsEngine}; // 🛡️  Intrusion Prevention
use crate::l2_engine::L2Engine; // 🔗 Layer 2 Security
use crate::npcap_forensic::NpcapForensicEngine;
use crate::wfp_engine::{WfpEngine, WfpRuleOrigin};
use crate::windivert_engine::WinDivertEngine;
use pnet::packet::arp::ArpPacket;

pub struct WindowsPacketCapture {
    interface: String,
    policy_engine: Arc<PolicyEngine>,
    metrics: Arc<Metrics>,
    cyber_immune: Arc<CyberImmuneSystem>,
    threat_intel: Arc<ThreatIntelligenceHub>,
    advanced_security: Arc<AdvancedSecurity>,
    micro_seg: Arc<MicroSegmentationEngine>,
    siem: Arc<SIEMIntegration>,
    comp_blocker: Arc<ComprehensiveBlocker>,
    blocking_config: Arc<crate::config::BlockingConfig>,
    flow_engine: Arc<FlowEngine>,
    // ── McAfee 4-Component Stack ─────────────────────────────────────────────
    wfp: Arc<WfpEngine>,                       // 🔷 Primary kernel enforcement
    windivert: Arc<WinDivertEngine>,           // 🔀 Selective deep inspection
    npcap_forensic: Arc<NpcapForensicEngine>,  // 🔬 Passive analytics + AI feed
    ai_engine: Arc<AiEngine>,                  // 🧠 4-layer ML intelligence
    advanced_ml_engine: Arc<AdvancedMlEngine>, // 🤖 Zero-Day IoT Protection
    l2_engine: Arc<L2Engine>,                  // 🔗 ARP/MAC Security
    // ── IDS + IPS ────────────────────────────────────────────────────────────
    ids_engine: Arc<IdsEngine>, // 🔍 Snort-style detection
    ips_engine: Arc<IpsEngine>, // 🛡️  Inline prevention
    // ── Deployment Mode Profile ──────────────────────────────────────────────
    mode_profile: ModeProfile, // 🎯 client | server thresholds
    // ── Counters ────────────────────────────────────────────────────────────
    packets_processed: AtomicU64,
    packets_allowed: AtomicU64,
    packets_blocked: AtomicU64,
    packets_fast_path: AtomicU64,
    immunity_tx: Option<mpsc::Sender<AntibodyPayload>>,
}

impl WindowsPacketCapture {
    pub fn new(
        interface: &str,
        policy_engine: Arc<PolicyEngine>,
        metrics: Arc<Metrics>,
        threat_intel: Arc<ThreatIntelligenceHub>,
        advanced_security: Arc<AdvancedSecurity>,
        immunity_tx: Option<mpsc::Sender<AntibodyPayload>>,
        micro_seg: Arc<MicroSegmentationEngine>,
        siem: Arc<SIEMIntegration>,
        comp_blocker: Arc<ComprehensiveBlocker>,
        blocking_config: Arc<crate::config::BlockingConfig>,
        wfp: Arc<WfpEngine>,
        windivert: Arc<WinDivertEngine>,
        npcap_forensic: Arc<NpcapForensicEngine>,
        ai_engine: Arc<AiEngine>,
        advanced_ml_engine: Arc<AdvancedMlEngine>,
        l2_engine: Arc<L2Engine>,
        ids_engine: Arc<IdsEngine>,
        ips_engine: Arc<IpsEngine>,
        mode_profile: ModeProfile,
    ) -> Result<Self> {
        Ok(Self {
            interface: interface.to_string(),
            policy_engine,
            metrics,
            cyber_immune: Arc::new(CyberImmuneSystem::new()),
            threat_intel,
            advanced_security,
            micro_seg,
            siem,
            comp_blocker,
            blocking_config,
            flow_engine: Arc::new(FlowEngine::new()),
            wfp,
            windivert,
            npcap_forensic,
            ai_engine,
            advanced_ml_engine,
            l2_engine,
            ids_engine,
            ips_engine,
            mode_profile,
            packets_processed: AtomicU64::new(0),
            packets_allowed: AtomicU64::new(0),
            packets_blocked: AtomicU64::new(0),
            packets_fast_path: AtomicU64::new(0),
            immunity_tx,
        })
    }

    pub async fn start_capture(&mut self) -> Result<()> {
        info!("Starting packet capture on {}", self.interface);

        // Open the device for live capture
        // Case-insensitive match: pcap returns uppercase GUIDs on Windows but
        // user configs may use lowercase — treat them as equivalent.
        let iface_input = self.interface.to_lowercase();
        let devices = Device::list()?;

        // 1. Try Exact match
        let mut device = devices
            .iter()
            .find(|d| d.name.to_lowercase() == iface_input);

        // 2. Try Partial match (e.g. just the GUID or "Wi-Fi")
        if device.is_none() {
            device = devices
                .iter()
                .find(|d| d.name.to_lowercase().contains(&iface_input));
        }

        // 3. Try Index match (if input is a number like "4")
        if device.is_none() {
            if let Ok(idx) = iface_input.parse::<usize>() {
                if idx > 0 && idx <= devices.len() {
                    device = Some(&devices[idx - 1]);
                }
            }
        }

        let device = device.cloned().ok_or_else(|| {
            let available = devices
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    format!(
                        "\n  [{}] {} ({})",
                        i + 1,
                        d.name,
                        d.desc.as_deref().unwrap_or("No description")
                    )
                })
                .collect::<String>();

            anyhow::anyhow!(
                "Interface '{}' not found. Available:{}",
                self.interface,
                available
            )
        })?;

        // Open the device for live capture.
        // Promiscuous mode captures ALL traffic on the segment (including other hosts').
        // It is disabled by default for legal/privacy reasons — enable only when you
        // own the entire segment and have authorisation to inspect all traffic on it.
        // Set promiscuous_capture = true in [blocking] config to opt in.
        let promisc = self.blocking_config.promiscuous_capture;
        if promisc {
            warn!("⚠️  LEGAL NOTICE: Promiscuous capture is ENABLED. This captures all traffic on the");
            warn!("    network segment, including other hosts. Ensure you have legal authority to do so.");
        }
        let mut cap = Capture::from_device(device)?
            .promisc(promisc)
            .snaplen(65535)
            .timeout(100) // 100ms timeout for responsive shutdown
            .open()?;

        info!("✅ Capture started successfully (Native Windows mode)");
        info!("📊 Processing packets in real-time...");

        let metrics_heartbeat = self.metrics.clone();
        let flow_engine_hb = self.flow_engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let s = metrics_heartbeat.get_stats();
                let fs = flow_engine_hb.get_stats();
                // Expire stale flow records every 60 s
                flow_engine_hb.cleanup();
                info!(
                    "📡 Heartbeat | Pkts: {} | Flows: {} active, {} high-risk, {} escalated | Avg risk: {:.3}",
                    s.packets_total,
                    fs.active_flows, fs.high_risk_flows, fs.escalated_flows,
                    fs.avg_risk_score
                );
            }
        });

        let mut stats_counter = 0u64;
        let stats_interval = 10000; // Print stats every 10k packets

        // Match the data link type (Ethernet is 1)
        let link_type = cap.get_datalink();
        info!("🧬 Data Link Type: {:?} ({})", link_type, link_type.0);

        // Main capture loop - processes packets in real-time
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    // Update global total BEFORE processing
                    self.metrics.record_processed();
                    self.packets_processed.fetch_add(1, Ordering::Relaxed);

                    // Process and handle errors without exiting the loop (Robust Mode)
                    if let Err(e) = self.process_packet(&packet.data) {
                        debug!("Packet skipped: {}", e);
                    }

                    stats_counter += 1;
                    if stats_counter >= stats_interval {
                        self.print_stats();

                        // 🧬 Trigger evolution every 10K packets
                        info!("🧬 Triggering CyberImmune evolution...");
                        self.cyber_immune.evolve_defenses();

                        // Display immune system stats
                        let immune_stats = self.cyber_immune.get_stats();
                        info!(
                            "🛡️ CyberImmune Stats | Threats: {} | Blocked: {} | Memory: {} | Antibodies: {} | Gen: {} | Threshold: {:.3}",
                            immune_stats.total_threats_seen,
                            immune_stats.total_threats_blocked,
                            immune_stats.unique_threats_in_memory,
                            immune_stats.active_antibodies,
                            immune_stats.evolution_generation,
                            immune_stats.current_threshold
                        );

                        stats_counter = 0;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal, just continue
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => {
                    warn!("Packet capture error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn process_packet(&self, data: &[u8]) -> Result<()> {
        // NOTE: metrics.record_processed() is called ONCE here.
        //       process_ipv4/ipv6 must NOT call it again.
        self.metrics
            .record_bytes(data.len() as u64, crate::metrics::Direction::Inbound);

        // Parse Ethernet frame
        let ethernet = match EthernetPacket::new(data) {
            Some(eth) => eth,
            None => return Ok(()), // Invalid / truncated frame
        };

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    self.process_ipv4_packet(&ipv4)?;
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()) {
                    self.process_ipv6_packet(&ipv6)?;
                } else {
                    debug!("Invalid IPv6 packet");
                }
            }
            EtherTypes::Arp => {
                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                    let is_reply = arp.get_operation() == pnet::packet::arp::ArpOperations::Reply;
                    if !self.l2_engine.inspect_arp(
                        arp.get_sender_hw_addr(),
                        arp.get_sender_proto_addr(),
                        is_reply,
                    ) {
                        // In an inline block scenario, we would drop here.
                        self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                        self.metrics.record_blocked();
                        return Ok(());
                    }
                }
                self.metrics.record_allowed();
            }
            _ => {
                // other non-IP — allow without inspection
                debug!("Non-IP EtherType: {:?}", ethernet.get_ethertype());
                self.metrics.record_allowed();
            }
        }

        Ok(())
    }

    fn process_ipv4_packet(&self, ipv4: &Ipv4Packet) -> Result<()> {
        let source_ip = ipv4.get_source();
        let dest_ip = ipv4.get_destination();

        let mut src_port: u16 = 0;
        let mut dest_port: u16 = 0;
        let mut tcp_flags: u8 = 0;

        let proto_num: u8;
        let protocol: &str = match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                proto_num = 6;
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    src_port = tcp.get_source();
                    dest_port = tcp.get_destination();
                    tcp_flags = tcp.get_flags();
                    debug!(
                        "TCP: {}:{} -> {}:{}",
                        source_ip, src_port, dest_ip, dest_port
                    );
                    self.metrics.record_connection("tcp");
                }
                "tcp"
            }
            IpNextHeaderProtocols::Udp => {
                proto_num = 17;
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    src_port = udp.get_source();
                    dest_port = udp.get_destination();
                    debug!(
                        "UDP: {}:{} -> {}:{}",
                        source_ip, src_port, dest_ip, dest_port
                    );
                    self.metrics.record_connection("udp");
                }
                "udp"
            }
            IpNextHeaderProtocols::Icmp => {
                proto_num = 1;
                "icmp"
            }
            _ => {
                proto_num = 0;
                "other"
            }
        };

        self.metrics.record_protocol(protocol);

        // ════════════════════════════════════════════════════════════════════
        // MODE-AWARE DIRECTION DETECTION
        //   Determine if this packet is inbound (external → us) or outbound.
        //   • Server mode:  inbound gets priority; all external-source traffic
        //                   is escalated past fast-path unless clean flow.
        //   • Client mode:  outbound to suspicious ports is flagged early;
        //                   inbound on non-server ports is treated as scan.
        // ════════════════════════════════════════════════════════════════════
        let is_inbound = !is_private_ip(source_ip); // source is public  → inbound
        let is_outbound = is_private_ip(source_ip) && !is_private_ip(dest_ip); // LAN → internet

        // Server mode: inbound traffic to an unexpected port is immediately suspicious
        let mode_escalate_inbound = if is_inbound
            && !self.mode_profile.allowed_inbound_ports.is_empty()
            && !self.mode_profile.allowed_inbound_ports.contains(&dest_port)
            && dest_port != 0
        {
            // Traffic arriving on a port this server doesn't expose → suspicious
            debug!(
                "🏛️  SERVER: Unexpected inbound port {} from {} — escalating",
                dest_port, source_ip
            );
            true
        } else {
            false
        };

        // Client mode: outbound connection to a known bad/unusual port → flag early
        let mode_flag_outbound = if is_outbound && self.mode_profile.monitor_outbound {
            matches!(dest_port, 4444 | 6666 | 1337 | 31337 | 8888 | 9999 | 12345)
        } else {
            false
        };

        if mode_flag_outbound {
            debug!(
                "🖥️  CLIENT: Suspicious outbound port {} → {} — escalating",
                dest_port, dest_ip
            );
        }

        //   If this source IP was previously confirmed as a threat and WFP
        //   has already installed a block rule, skip ALL processing instantly.
        //   In production: the WFP kernel driver drops before userspace,
        //   but we still check here for correctness.
        // ════════════════════════════════════════════════════════════════════
        let src_addr_v4 = std::net::IpAddr::V4(source_ip);

        // ── CRITICAL INFRASTRUCTURE PROTECTION (CIP) ──
        // Solves the "Weaponized Denial of Service" disadvantage.
        // If a hacker spoofs a database IP (e.g. 10.0.0.50), Rudras will never
        // kernel-block it and break the network. It will merely alert heavily.
        let mut is_cip_protected = source_ip == std::net::Ipv4Addr::new(10, 0, 0, 50)
            || source_ip == std::net::Ipv4Addr::new(192, 168, 1, 100);

        // ── DYNAMIC CIP REVOCATION (Anti-Sacred Cow Strategy) ──
        // If the AI Engine or IPS Engine registers that this 'protected' server is actively beaconing C2
        // malware or engaging in critically high threat activity, we REVOKE its CIP status immediately.
        // It becomes treated like any generic hostile node and is isolated from the network.
        if is_cip_protected && self.ips_engine.is_actively_blocked(src_addr_v4) {
            warn!("⚔️ FATAL COMPROMISE: Critical Asset ({}) is infected! Revoking CIP Immunity and isolating host...", source_ip);
            is_cip_protected = false;
        }

        if self.wfp.is_blocked_ip(&src_addr_v4) {
            if is_cip_protected {
                warn!(
                    "⚠️ CIP PROTECT: Ignoring WFP Kernel Block for Critical Asset ({})",
                    source_ip
                );
            } else {
                debug!("🔷 WFP fast-drop: {} (cached kernel block)", source_ip);
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
        }

        // ── IPS PRE-CHECK: active block or rate-limit (O(1)) ─────────────────
        if self.ips_engine.is_actively_blocked(src_addr_v4) {
            if is_cip_protected {
                warn!(
                    "⚠️ CIP PROTECT: Ignoring IPS Quarantine for Critical Asset ({})",
                    source_ip
                );
            } else {
                debug!(
                    "🛡️  IPS fast-drop: {} (active quarantine/blacklist)",
                    source_ip
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
        }
        if !self.ips_engine.rate_check(src_addr_v4) {
            debug!("🛡️  IPS rate-drop: {} (pps limit exceeded)", source_ip);
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_blocked();
            return Ok(());
        }

        // ── Npcap Forensic: observe every packet (O(1) counters, no alloc) ───
        self.npcap_forensic.observe_packet(
            src_addr_v4,
            std::net::IpAddr::V4(dest_ip),
            src_port,
            dest_port,
            proto_num,
            ipv4.payload().len(),
            tcp_flags,
        );

        // ════════════════════════════════════════════════════════════════════
        // ANTI-EVASION ENGINE (Blocks Nmap, Wireshark trickery, TCP Anomalies)
        // Hackers use illegal TCP flag combinations to bypass firewalls and
        // fingerprint the OS. This shuts down all loopholes immediately.
        // ════════════════════════════════════════════════════════════════════
        if proto_num == 6 {
            // TCP
            // Null Scan (No flags)
            if tcp_flags == 0x00 {
                warn!("🚨 ANTI-EVASION: Blocking NULL Scan from {}", source_ip);
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            // XMAS Scan (FIN | PSH | URG = 0x29)
            if (tcp_flags & 0x29) == 0x29 {
                warn!("🚨 ANTI-EVASION: Blocking XMAS Scan from {}", source_ip);
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            // SYN+FIN evasion
            if (tcp_flags & 0x02) != 0 && (tcp_flags & 0x01) != 0 {
                warn!(
                    "🚨 ANTI-EVASION: Blocking SYN+FIN Protocol Anomaly from {}",
                    source_ip
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            // SYN+RST evasion
            if (tcp_flags & 0x02) != 0 && (tcp_flags & 0x04) != 0 {
                warn!(
                    "🚨 ANTI-EVASION: Blocking SYN+RST Protocol Anomaly from {}",
                    source_ip
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            // FIN scan (FIN without ACK) - wait, could be noisy, but strict firewall requires ACK with FIN usually. We'll stick to the clearest evasions above to prevent false positives.
        }

        // ════════════════════════════════════════════════════════════════════
        // LAYER 0 — FLOW ENGINE  (McAfee stateful inspection equivalent)
        //   Runs for EVERY packet. O(1) cost. Returns a risk score.
        //   → Allow  (score < 0.65): fast-path, skip heavy shields
        //   → Escalate (0.65–0.85): run full shield stack
        //   → Block  (score > 0.85): drop immediately, no further processing
        // ════════════════════════════════════════════════════════════════════
        let flow_decision = self.flow_engine.update(
            std::net::IpAddr::V4(source_ip),
            std::net::IpAddr::V4(dest_ip),
            src_port,
            dest_port,
            proto_num,
            ipv4.payload().len(),
            tcp_flags,
        );

        let mut final_decision = flow_decision;
        if matches!(final_decision, FlowDecision::Allow { .. }) {
            if mode_escalate_inbound {
                final_decision = FlowDecision::Escalate { score: 0.70 }; // Force escalate server anomalies
            } else if mode_flag_outbound {
                final_decision = FlowDecision::Escalate { score: 0.75 }; // Force escalate bad client outbounds
            }
        }

        match &final_decision {
            FlowDecision::Block { score, reason } => {
                warn!(
                    "🌊 FLOW-BLOCK [IPv4]: {} → {}:{} | score={:.2} | {}",
                    source_ip, dest_ip, dest_port, score, reason
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                self.metrics.record_threat();
                // 🔷 Install WFP kernel rule so future packets are dropped without userspace
                self.wfp.block_ip(
                    std::net::IpAddr::V4(source_ip),
                    reason,
                    WfpRuleOrigin::FlowEngine,
                );
                return Ok(());
            }
            FlowDecision::Allow { .. } => {
                // ── FAST PATH: clean flow, skip all heavy shields ────────
                self.packets_fast_path.fetch_add(1, Ordering::Relaxed);
                self.packets_allowed.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_allowed();
                return Ok(());
            }
            FlowDecision::Escalate { score } => {
                debug!("⚡ Flow escalated (score={:.2}) — running full shield stack + WinDivert for {} → {}:{}",
                       score, source_ip, dest_ip, dest_port);
                // 🔬 Npcap Forensic: switch to header-capture mode for this flow
                self.npcap_forensic.record_forensic(
                    std::net::IpAddr::V4(source_ip),
                    std::net::IpAddr::V4(dest_ip),
                    src_port,
                    dest_port,
                    proto_num,
                    ipv4.payload().len() as u16,
                    tcp_flags,
                    ipv4.packet(),
                );
                // Fall through to full shield stack below
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // FULL SHIELD STACK  (only reached for Escalate decisions)
        // Mirrors McAfee's layered engine: each shield is a separate
        // inspection stage that can short-circuit the pipeline on Block.
        // ════════════════════════════════════════════════════════════════════

        // 🔥 SHIELD 0: COMPREHENSIVE BLOCKER — 10 Threat Categories (DPI)
        {
            let direction = if is_private_ip(source_ip) {
                BlkDir::Internal
            } else {
                BlkDir::Inbound
            };
            let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;
            match self.comp_blocker.evaluate(
                &source_ip.to_string(),
                &dest_ip.to_string(),
                0,
                dest_port,
                protocol,
                ipv4.payload(),
                is_syn,
                direction,
                &self.blocking_config,
            ) {
                BlockVerdict::Block(reason) => {
                    warn!(
                        "🔥 COMP-BLOCK [IPv4]: {} → {}:{} | {}",
                        source_ip, dest_ip, dest_port, reason
                    );
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();
                    self.metrics.record_threat();
                    return Ok(());
                }
                BlockVerdict::Alert(reason) => {
                    warn!(
                        "⚠️  COMP-ALERT [IPv4]: {} → {}:{} | {}",
                        source_ip, dest_ip, dest_port, reason
                    );
                }
                BlockVerdict::Allow => {}
            }
        }

        // 🛡️ SHIELD 1: STATIC POLICY & COMPLIANCE
        let policy_action = if dest_port > 0 {
            self.policy_engine.evaluate_with_port(
                &source_ip.to_string(),
                &dest_ip.to_string(),
                protocol,
                dest_port,
            )
        } else {
            self.policy_engine
                .evaluate(&source_ip.to_string(), &dest_ip.to_string(), protocol)
        };
        match policy_action {
            ActionType::Block => {
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            ActionType::Quarantine(_) => {
                return Ok(());
            }
            _ => {}
        }

        // 🌍 SHIELD 1.5: THREAT INTELLIGENCE + GEOIP
        // ── BOILING FROG / FALSE FLAG SABOTAGE FIX ──
        // Hackers cannot BGP-hijack a Threat Intelligence server to force the firewall to
        // block internal Core Services (like 10.0.0.x or Active Directory).
        // Any IP fitting the RFC 1918 Private Sovereign range mathematically bypasses
        // external Threat Hub blocking.
        let is_sovereign_local = match source_ip.octets() {
            [10, ..] => true,
            [172, b, ..] if b >= 16 && b <= 31 => true,
            [192, 168, ..] => true,
            [127, ..] => true,
            _ => false,
        };

        if !is_sovereign_local && !is_cip_protected {
            if let Some(threat) = self
                .threat_intel
                .is_malicious_ip(&std::net::IpAddr::V4(source_ip))
            {
                warn!(
                    "🚫 MALICIOUS IP [IPv4]: {} | src={} | type={:?} | conf={:.2}",
                    source_ip, threat.source, threat.category, threat.confidence
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                self.metrics.record_threat();
                return Ok(());
            }
        }
        if let Some(country) = self
            .advanced_security
            .is_ip_geo_blocked(std::net::IpAddr::V4(source_ip))
        {
            warn!("🌍 GeoIP BLOCK [IPv4]: {} ({})", source_ip, country);
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_blocked();
            return Ok(());
        }
        if self
            .advanced_security
            .is_ip_geo_blocked(std::net::IpAddr::V4(dest_ip))
            .is_some()
        {
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_blocked();
            return Ok(());
        }

        // 🔒 SHIELD 2: MICRO-SEGMENTATION
        {
            let src_addr = std::net::IpAddr::V4(source_ip);
            let dst_addr = std::net::IpAddr::V4(dest_ip);
            let verdict = self
                .micro_seg
                .evaluate_traffic(&src_addr, &dst_addr, dest_port, protocol);
            if !verdict.allowed {
                warn!(
                    "🔒 MICRO-SEG BLOCK [IPv4]: {} → {}:{} | {}",
                    source_ip, dest_ip, dest_port, verdict.reason
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
        }

        // 🧠 SHIELD 3: COGNITIVE BRAIN — CyberImmune AI
        //    Only reached for escalated (anomalous) flows.
        //    McAfee equivalent: behavioral engine / endpoint protection.
        let threat_assessment = self.cyber_immune.detect_threat(
            &source_ip.to_string(),
            dest_port,
            protocol,
            ipv4.payload(),
        );

        if threat_assessment.is_threat {
            self.metrics.record_threat();
            let defense_result = self.cyber_immune.execute_defense(&threat_assessment);

            if let crate::cyber_immune::DefenseResult::Blocked = defense_result {
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();

                // 🔄 Adaptive rule: feed block back into Layer 1 (static policy)
                let new_rule = HybridRule {
                    action: ActionType::Block,
                    confidence: threat_assessment.severity,
                    origin: RuleOrigin::CyberImmuneSystem,
                    created_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: Some(chrono::Utc::now().timestamp() as u64 + 3600),
                };
                self.policy_engine
                    .add_policy(format!("src:{}", source_ip), new_rule.clone());

                // 📡 Distributed Immunity broadcast
                if let Some(tx) = &self.immunity_tx {
                    let _ = tx.try_send(AntibodyPayload {
                        key: format!("src:{}", source_ip),
                        rule: new_rule,
                        origin_node_id: "local".to_string(),
                        auth_hmac: String::new(), // Populated by Control Plane
                    });
                }

                warn!(
                    "🧬 CYBERIMMUNE: Antibody for {} → {} | severity={:.2}",
                    source_ip, dest_ip, threat_assessment.severity
                );

                // 📡 SIEM event
                let siem_event = SecurityEvent::new_threat_detected(
                    &source_ip.to_string(),
                    &dest_ip.to_string(),
                    dest_port,
                    "CyberImmune-Antibody",
                    threat_assessment.severity,
                );
                let siem_clone = self.siem.clone();
                tokio::spawn(async move {
                    siem_clone.log_event(siem_event).await;
                });

                return Ok(());
            }
        }

        // ── SHIELD 4: AI ENGINE + WINDIVERT (final confirmation layer) ────────
        // The AI Engine runs a 4-layer prediction and may:
        //   a) Allow: traffic is clean after all shields
        //   b) Monitor: suspicious but not confirmed
        //   c) Escalate: hand off to WinDivert for payload analysis
        //   d) Block/BlockAndAlert: WFP rule + SIEM alert installed
        {
            use crate::flow_engine::FlowFeatures;
            // Build a quick feature snapshot for AI (from what we have)
            let pkt_len = ipv4.payload().len() as f32;
            let features = FlowFeatures {
                pkt_rate: 1.0, // Single pkt — rate from FlowEngine next call
                byte_rate: pkt_len,
                imbalance_ratio: 0.5, // Unknown at this point
                syn_ratio: if (tcp_flags & 0x02) != 0 { 1.0 } else { 0.0 },
                rst_ratio: if (tcp_flags & 0x04) != 0 { 1.0 } else { 0.0 },
                unique_dst_ports: 1.0,
                flow_duration_sec: 1.0,
                avg_pkt_size: pkt_len,
            };

            // Get baseline deviation from Npcap forensic engine
            let baseline_dev = self.npcap_forensic.baseline_deviation(
                &src_addr_v4,
                features.pkt_rate,
                features.byte_rate,
                1,
            );

            let ai_pred = self.ai_engine.predict(src_addr_v4, &features, baseline_dev);

            match ai_pred.recommendation {
                AiRecommendation::BlockAndAlert | AiRecommendation::Block => {
                    warn!(
                        "🧠 AI BLOCK [IPv4]: {} | class={} | score={:.2} | conf={:.2}",
                        source_ip,
                        ai_pred.threat_class.label(),
                        ai_pred.threat_score,
                        ai_pred.confidence
                    );
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();
                    self.metrics.record_threat();
                    // 🔷 Persist WFP kernel block rule for this confirmed threat
                    self.wfp.block_ip(
                        src_addr_v4,
                        &format!(
                            "AI: {} (score={:.2})",
                            ai_pred.threat_class.label(),
                            ai_pred.threat_score
                        ),
                        WfpRuleOrigin::CyberImmune,
                    );
                    if matches!(ai_pred.recommendation, AiRecommendation::BlockAndAlert) {
                        let siem_event = SecurityEvent::new_threat_detected(
                            &source_ip.to_string(),
                            &dest_ip.to_string(),
                            dest_port,
                            ai_pred.threat_class.label(),
                            ai_pred.threat_score as f64,
                        );
                        let siem_c = self.siem.clone();
                        tokio::spawn(async move {
                            siem_c.log_event(siem_event).await;
                        });
                    }
                    return Ok(());
                }
                AiRecommendation::Escalate => {
                    // 🔀 WinDivert: deep payload inspection
                    if let Some(analysis) = self.windivert.submit_for_inspection(
                        src_addr_v4,
                        std::net::IpAddr::V4(dest_ip),
                        src_port,
                        dest_port,
                        proto_num,
                        ai_pred.threat_score,
                        ipv4.payload(),
                    ) {
                        use crate::windivert_engine::DivertVerdict;
                        if matches!(
                            analysis.verdict,
                            DivertVerdict::Drop | DivertVerdict::InjectReset
                        ) {
                            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                            self.metrics.record_blocked();
                            self.metrics.record_threat();
                            warn!(
                                "🔀 WINDIVERT BLOCK: {} | {} | conf={:.2}",
                                source_ip,
                                analysis.threat_type.as_deref().unwrap_or("unknown"),
                                analysis.confidence
                            );
                            // Persist WFP rule for confirmed WinDivert threat
                            self.wfp.block_ip(
                                src_addr_v4,
                                analysis
                                    .threat_type
                                    .as_deref()
                                    .unwrap_or("WinDivert confirmed"),
                                WfpRuleOrigin::WinDivert,
                            );
                            return Ok(());
                        }
                    }
                }
                AiRecommendation::Monitor => {
                    debug!(
                        "🧠 AI MONITOR: {} | class={} | score={:.2}",
                        source_ip,
                        ai_pred.threat_class.label(),
                        ai_pred.threat_score
                    );
                }
                AiRecommendation::Allow => {}
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // LAYER IDS — Intrusion Detection System
        //   Inspects payload for:
        //     • 200+ Snort-compatible signatures (SQLi / XSS / RCE / C2 / etc.)
        //     • HTTP / TLS / DNS protocol decoders
        //     • Behavioral engine (port scan, SYN flood, brute force)
        //     • DGA / DNS tunneling detectors
        // ════════════════════════════════════════════════════════════════════
        {
            let ids_alerts = self.ids_engine.inspect(
                src_addr_v4,
                std::net::IpAddr::V4(dest_ip),
                src_port,
                dest_port,
                proto_num,
                tcp_flags,
                ipv4.payload(),
            );

            if !ids_alerts.is_empty() {
                // Log every IDS alert
                for alert in &ids_alerts {
                    match alert.severity {
                        crate::ids_engine::IdsSeverity::Critical => {
                            warn!(
                                "🔍 IDS CRITICAL [SID:{}] {} → {}: {} | conf={:.0}%",
                                alert.rule_id,
                                source_ip,
                                dest_ip,
                                alert.rule_name,
                                alert.confidence * 100.0
                            );
                        }
                        crate::ids_engine::IdsSeverity::High => {
                            warn!(
                                "🔍 IDS HIGH     [SID:{}] {} → {}: {}",
                                alert.rule_id, source_ip, dest_ip, alert.rule_name
                            );
                        }
                        crate::ids_engine::IdsSeverity::Medium => {
                            debug!(
                                "🔍 IDS MEDIUM   [SID:{}] {} → {}: {}",
                                alert.rule_id, source_ip, dest_ip, alert.rule_name
                            );
                        }
                        crate::ids_engine::IdsSeverity::Low => {
                            debug!(
                                "🔍 IDS LOW      [SID:{}] {} → {}: {}",
                                alert.rule_id, source_ip, dest_ip, alert.rule_name
                            );
                        }
                    }
                }

                // ── LAYER IPS — Intrusion Prevention System ──────────────────
                //   Converts IDS alerts into graduated responses:
                //     Level 0  Monitor    (penalty <30)  : alert only
                //     Level 1  RateLimit  (penalty 30-60): token-bucket throttle
                //     Level 2  TCP Reset  (penalty 60-100): terminate connection
                //     Level 3  WFP Block  (penalty 100-200): kernel drop 1hr
                //     Level 4  Quarantine (penalty 200-350): kernel drop 24hr
                //     Level 5  Blacklist  (penalty >350)  : permanent kernel block
                if let Some(decision) = self.ips_engine.respond_to_alerts(&ids_alerts) {
                    match &decision.action {
                        IpsAction::Monitor => {
                            // IDS alert logged above — no blocking action
                        }
                        IpsAction::RateLimit { max_pps } => {
                            debug!("🛡️  IPS: Rate-limiting {} to {} pps", source_ip, max_pps);
                            // Rate-limit is enforced in ips_engine.rate_check() per packet
                        }
                        IpsAction::TcpReset => {
                            warn!(
                                "🛡️  IPS TCP-RST: Terminating {} → {} | {}",
                                source_ip, dest_ip, decision.reason
                            );
                            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                            self.metrics.record_blocked();
                            return Ok(());
                        }
                        IpsAction::WfpBlock { .. }
                        | IpsAction::Quarantine { .. }
                        | IpsAction::Blacklist => {
                            warn!(
                                "🛡️  IPS {}: Blocking {} permanently | penalty={:.0} | {}",
                                decision.action.label(),
                                source_ip,
                                decision.penalty,
                                decision.reason
                            );
                            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                            self.metrics.record_blocked();
                            self.metrics.record_threat();

                            // Build a fully-enriched SIEM event from the primary IDS
                            // alert.  This carries MITRE ATT&CK technique IDs and OWASP
                            // category IDs as top-level indexed fields into Splunk /
                            // Elasticsearch / QRadar — giving SOC analysts structured
                            // framework context on every blocked event.
                            let primary_alert = &ids_alerts[0];
                            let action_label = decision.action.label().to_string();
                            let mut siem_event =
                                SecurityEvent::from_ids_alert(primary_alert, &action_label);
                            // Override action_taken with the IPS graduated response label
                            siem_event.action_taken = format!(
                                "IPS-{}: {}",
                                action_label, primary_alert.rule_name
                            );
                            let siem_c = self.siem.clone();
                            tokio::spawn(async move {
                                siem_c.log_event(siem_event).await;
                            });

                            return Ok(());
                        }
                    }
                }

                // IDS flagged but IPS said Monitor — packet survives with note
                debug!(
                    "🔍 IDS: {} alert(s) for {} — IPS action=MONITOR (penalty below threshold)",
                    ids_alerts.len(),
                    source_ip
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // LAYER DOMAIN BLOCK — Malicious Domain Blocklist (ThreatIntel)
        //   Checks DNS queries (UDP port 53) against live blocklists from:
        //     • ThreatFox C2 domains (abuse.ch — confidence >= 0.92)
        //     • URLhaus malware delivery hosts (abuse.ch)
        //   Blocks at DNS-query time before any connection is attempted.
        // ════════════════════════════════════════════════════════════════════
        if proto_num == 17 && (dest_port == 53 || src_port == 53) && !ipv4.payload().is_empty() {
            if let Some(dns) = crate::ids_engine::ProtocolDecoder::decode_dns(ipv4.payload()) {
                if self.threat_intel.is_malicious_domain(&dns.qname) {
                    warn!(
                        "🚫 MALICIOUS DOMAIN [DNS]: {} queried \"{}\" | blocked (ThreatIntel feed)",
                        source_ip, dns.qname
                    );
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();
                    self.metrics.record_threat();
                    return Ok(());
                }
            }
        }

        // ── OUTBOUND ALLOWED TRAFFIC — DEEP EXFIL / COVERT CHANNEL CHECK ─────
        // Even traffic that passed all shields can carry covert channel abuse:
        //   • HTTP CONNECT tunnel (proxy escape via HTTPS port 443)
        //   • Large outbound HTTP POST (>50 KB to external) = potential exfil
        //   • DNS queries carrying unusually high-entropy labels = DNS tunnel
        //   • Outbound to Tor relay ports (9001/9030/9150) — detection only
        //     by default; set block_anonymization_networks=true to hard-block
        if is_outbound && !ipv4.payload().is_empty() {
            let payload = ipv4.payload();
            // HTTP CONNECT tunneling (proxy pivot / C2 via allowed proxy)
            if dest_port == 443 || dest_port == 80 || dest_port == 8080 {
                if payload.starts_with(b"CONNECT ") {
                    warn!(
                        "⚠️  OUTBOUND COVERT: HTTP CONNECT tunnel from {}:{} → {}:{} — possible C2 proxy pivot",
                        source_ip, src_port, dest_ip, dest_port
                    );
                    self.metrics.record_threat();
                    // Escalate: IDS for deeper analysis but don't hard-block (may be legit proxy)
                }
            }
            // Large outbound POST = potential data exfiltration
            if dest_port == 443 || dest_port == 80 {
                if payload.starts_with(b"POST ") && payload.len() > 51200 {
                    warn!(
                        "⚠️  OUTBOUND EXFIL: Large POST ({}B) from {} → {} — possible data exfiltration",
                        payload.len(), source_ip, dest_ip
                    );
                    self.metrics.record_threat();
                }
            }
            // Tor outbound (connections to Tor relay or browser SOCKS port).
            // Only blocked when block_anonymization_networks = true in config.
            // Tor is legal in most jurisdictions — do NOT block without explicit
            // administrator opt-in.  Default: DETECT and WARN only.
            if dest_port == 9001 || dest_port == 9030 || dest_port == 9150 {
                if self.blocking_config.block_anonymization_networks {
                    warn!(
                        "🚫 OUTBOUND TOR [BLOCKED by policy]: {} → {}:{} — anonymization network blocked per block_anonymization_networks=true",
                        source_ip, dest_ip, dest_port
                    );
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();
                    self.metrics.record_threat();
                    return Ok(());
                } else {
                    warn!(
                        "👁️  OUTBOUND TOR [DETECTED, not blocked]: {} → {}:{} — Tor relay traffic observed (set block_anonymization_networks=true to block)",
                        source_ip, dest_ip, dest_port
                    );
                    self.metrics.record_threat();
                }
            }
            // DNS tunnel over UDP 53: high-entropy query names (already in IDS but belt-and-suspenders)
            if proto_num == 17 && dest_port == 53 && payload.len() > 100 {
                // Suspiciously large DNS query = potential DNS tunnel
                warn!(
                    "⚠️  OUTBOUND DNS: Unusually large DNS query ({}B) from {} — possible DNS tunneling",
                    payload.len(), source_ip
                );
                self.metrics.record_threat();
            }
        }

        // Survived all shields — allowed
        self.packets_allowed.fetch_add(1, Ordering::Relaxed);
        self.metrics.record_allowed();
        Ok(())
    }

    fn process_ipv6_packet(&self, ipv6: &Ipv6Packet) -> Result<()> {
        let source_ip = ipv6.get_source();
        let dest_ip = ipv6.get_destination();

        let mut dest_port = 0;
        let protocol = match ipv6.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    let src_port = tcp.get_source();
                    dest_port = tcp.get_destination();

                    debug!(
                        "IPv6 TCP: [{}]:{} -> [{}]:{}",
                        source_ip, src_port, dest_ip, dest_port
                    );
                    self.metrics.record_connection("tcp");
                }
                "tcp"
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                    let src_port = udp.get_source();
                    dest_port = udp.get_destination();

                    debug!(
                        "IPv6 UDP: [{}]:{} -> [{}]:{}",
                        source_ip, src_port, dest_ip, dest_port
                    );
                    self.metrics.record_connection("udp");
                }
                "udp"
            }
            IpNextHeaderProtocols::Icmpv6 => "icmpv6",
            _ => "other",
        };

        // Record protocol in metrics
        self.metrics.record_protocol(protocol);

        // 🔥 SHIELD 0: COMPREHENSIVE BLOCKER (IPv6)
        {
            let direction = if is_private_ipv6(source_ip) {
                BlkDir::Internal
            } else {
                BlkDir::Inbound
            };
            let is_syn = matches!(
                ipv6.get_next_header(),
                pnet::packet::ip::IpNextHeaderProtocols::Tcp
            ) && {
                if let Some(tcp) = pnet::packet::tcp::TcpPacket::new(ipv6.payload()) {
                    tcp.get_flags() & 0x02 != 0
                } else {
                    false
                }
            };
            let verdict = self.comp_blocker.evaluate(
                &source_ip.to_string(),
                &dest_ip.to_string(),
                0,
                dest_port,
                protocol,
                ipv6.payload(),
                is_syn,
                direction,
                &self.blocking_config,
            );
            match verdict {
                BlockVerdict::Block(reason) => {
                    warn!(
                        "🔥 COMP-BLOCK [IPv6]: {} → {}:{} | {}",
                        source_ip, dest_ip, dest_port, reason
                    );
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();
                    self.metrics.record_threat();
                    return Ok(());
                }
                BlockVerdict::Alert(reason) => {
                    warn!(
                        "⚠️  COMP-ALERT [IPv6]: {} → {}:{} | {}",
                        source_ip, dest_ip, dest_port, reason
                    );
                }
                BlockVerdict::Allow => {}
            }
        }

        // 🛡️ SHIELD 1: STATIC POLICY (IPv6)
        let policy_action = if dest_port > 0 {
            self.policy_engine.evaluate_with_port(
                &source_ip.to_string(),
                &dest_ip.to_string(),
                protocol,
                dest_port,
            )
        } else {
            self.policy_engine
                .evaluate(&source_ip.to_string(), &dest_ip.to_string(), protocol)
        };

        match policy_action {
            ActionType::Block => {
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            ActionType::Quarantine(_) => return Ok(()),
            _ => {}
        }

        // 🌍 SHIELD 1.5: THREAT INTELLIGENCE
        // 🌍 SHIELD 1.5: THREAT INTELLIGENCE
        let is_v6_sovereign = source_ip.segments()[0] & 0xFE00 == 0xFC00 || source_ip.is_loopback();

        let is_cip_v6 = source_ip == std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50);

        if !is_v6_sovereign && !is_cip_v6 {
            if let Some(threat) = self
                .threat_intel
                .is_malicious_ip(&std::net::IpAddr::V6(source_ip))
            {
                warn!(
                    "🚫 BLOCKED MALICIOUS IPv6: {} | Source: {} | Type: {:?} | Confidence: {:.2}",
                    source_ip, threat.source, threat.category, threat.confidence
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                self.metrics.record_threat();
                return Ok(());
            }
        }

        // 📍 GEOIP BLOCKING (IPv6)
        if let Some(country) = self
            .advanced_security
            .is_ip_geo_blocked(std::net::IpAddr::V6(source_ip))
        {
            warn!(
                "🌍 GeoIP BLOCKED IPv6: {} (country: {})",
                source_ip, country
            );
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_blocked();
            return Ok(());
        }
        if let Some(country) = self
            .advanced_security
            .is_ip_geo_blocked(std::net::IpAddr::V6(dest_ip))
        {
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_blocked();
            return Ok(());
        }

        // 🔒 MICRO-SEGMENTATION (IPv6)
        {
            let src_addr = std::net::IpAddr::V6(source_ip);
            let dst_addr = std::net::IpAddr::V6(dest_ip);
            let verdict = self
                .micro_seg
                .evaluate_traffic(&src_addr, &dst_addr, dest_port, protocol);
            if !verdict.allowed {
                warn!(
                    "🔒 MICRO-SEG BLOCKED IPv6: {} → {}:{} | Reason: {}",
                    source_ip, dest_ip, dest_port, verdict.reason
                );
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
        }

        // 🧠 SHIELD 3: COGNITIVE BRAIN (IPv6)
        let threat_assessment = self.cyber_immune.detect_threat(
            &source_ip.to_string(),
            dest_port,
            protocol,
            ipv6.payload(),
        );

        if threat_assessment.is_threat {
            self.metrics.record_threat();
            let defense_result = self.cyber_immune.execute_defense(&threat_assessment);

            match defense_result {
                crate::cyber_immune::DefenseResult::Blocked => {
                    self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_blocked();

                    // 🔄 INFINITY LOOP (IPv6)
                    let new_rule = HybridRule {
                        action: ActionType::Block,
                        confidence: threat_assessment.severity,
                        origin: RuleOrigin::CyberImmuneSystem,
                        created_at: chrono::Utc::now().timestamp() as u64,
                        expires_at: Some(chrono::Utc::now().timestamp() as u64 + 3600),
                    };

                    self.policy_engine
                        .add_policy(format!("src:{}", source_ip), new_rule.clone());

                    // 📡 Distributed Immunity: Broadcast to peers
                    if let Some(tx) = &self.immunity_tx {
                        let payload = AntibodyPayload {
                            key: format!("src:{}", source_ip),
                            rule: new_rule,
                            origin_node_id: "local".to_string(),
                            auth_hmac: String::new(), // Populated by Control Plane
                        };
                        let _ = tx.try_send(payload);
                    }

                    warn!(
                        "AHA! IPv6 Threat detected & evolved: {} -> {}",
                        source_ip, dest_ip
                    );
                    return Ok(());
                }
                _ => {}
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // IDS + IPS — IPv6 (same pipeline as IPv4)
        // ════════════════════════════════════════════════════════════════════
        {
            let src6 = std::net::IpAddr::V6(source_ip);
            let dst6 = std::net::IpAddr::V6(dest_ip);

            // IPS fast-drop (quarantine/blacklist)
            if self.ips_engine.is_actively_blocked(src6) {
                debug!("🛡️  IPS fast-drop [IPv6]: {}", source_ip);
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }
            if !self.ips_engine.rate_check(src6) {
                debug!("🛡️  IPS rate-drop [IPv6]: {}", source_ip);
                self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_blocked();
                return Ok(());
            }

            let ids_alerts = self.ids_engine.inspect(
                src6,
                dst6,
                0,
                dest_port,
                // IPv6 next-header → proto num
                match ipv6.get_next_header() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => 6,
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => 17,
                    pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => 58,
                    _ => 0,
                },
                0u8, // TCP flags not parsed in IPv6 path yet
                ipv6.payload(),
            );

            if !ids_alerts.is_empty() {
                for alert in &ids_alerts {
                    match alert.severity {
                        crate::ids_engine::IdsSeverity::Critical
                        | crate::ids_engine::IdsSeverity::High => {
                            warn!(
                                "🔍 IDS [IPv6] {:?} [SID:{}] {} → {}: {}",
                                alert.severity, alert.rule_id, source_ip, dest_ip, alert.rule_name
                            );
                        }
                        _ => {
                            debug!(
                                "🔍 IDS [IPv6] {:?} [SID:{}] {} → {}: {}",
                                alert.severity, alert.rule_id, source_ip, dest_ip, alert.rule_name
                            );
                        }
                    }
                }

                if let Some(decision) = self.ips_engine.respond_to_alerts(&ids_alerts) {
                    match &decision.action {
                        IpsAction::Monitor => {}
                        IpsAction::RateLimit { .. } => {}
                        _ => {
                            warn!(
                                "🛡️  IPS [IPv6] {}: blocking {} | {}",
                                decision.action.label(),
                                source_ip,
                                decision.reason
                            );
                            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
                            self.metrics.record_blocked();
                            self.metrics.record_threat();
                            return Ok(());
                        }
                    }
                }
            }
        }

        self.packets_allowed.fetch_add(1, Ordering::Relaxed);
        self.metrics.record_allowed();

        Ok(())
    }

    fn print_stats(&self) {
        let processed = self.packets_processed.load(Ordering::Relaxed);
        let allowed = self.packets_allowed.load(Ordering::Relaxed);
        let blocked = self.packets_blocked.load(Ordering::Relaxed);
        let fast_path = self.packets_fast_path.load(Ordering::Relaxed);

        let block_rate = if processed > 0 {
            (blocked as f64 / processed as f64) * 100.0
        } else {
            0.0
        };

        let fast_rate = if processed > 0 {
            (fast_path as f64 / processed as f64) * 100.0
        } else {
            0.0
        };

        let flow_stats = self.flow_engine.get_stats();

        info!(
            "📊 Stats | Processed={} | ✅ Allowed={} | 🚫 Blocked={} ({:.1}%) | ⚡ FastPath={} ({:.1}%)",
            processed, allowed, blocked, block_rate, fast_path, fast_rate
        );
        info!(
            "🌊 Flows | Active={} | HighRisk={} | Escalated={} | AvgRisk={:.3}",
            flow_stats.active_flows,
            flow_stats.high_risk_flows,
            flow_stats.escalated_flows,
            flow_stats.avg_risk_score
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direction helpers for ComprehensiveBlocker
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if the IPv4 address is in a private / RFC-1918 range
fn is_private_ip(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    matches!(
        o,
        [10, ..] |                                  // 10.0.0.0/8
        [172, 16..=31, ..] |                        // 172.16.0.0/12
        [192, 168, ..] |                            // 192.168.0.0/16
        [127, ..] |                                 // Loopback
        [169, 254, ..] // Link-local
    )
}

/// Returns true if the IPv6 address is in a private / ULA / loopback range
fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let segs = ip.segments();
    ip.is_loopback()           // ::1
    || (segs[0] & 0xfe00) == 0xfc00  // fc00::/7  Unique Local Address
    || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-local
}
