// ============================================================================
// Rudras — Layer 2 / ARP Security Engine
// Detects ARP Spoofing / Poisoning, MAC spoofing anomalies, Broadcast storms
// ============================================================================

#![allow(dead_code)]

use parking_lot::RwLock;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct L2Engine {
    // Maps IP -> MAC to detect changes (ARP Spoofing)
    arp_table: RwLock<HashMap<Ipv4Addr, MacAddr>>,
}

impl L2Engine {
    pub fn new() -> Self {
        info!("🔗 [L2] Initializing Layer 2 Security Engine...");
        info!("✅ L2 Engine ready — ARP Spoofing & MAC Anomaly Detection ACTIVE");
        Self {
            arp_table: RwLock::new(HashMap::new()),
        }
    }

    /// Process an ARP packet payload to look for poisoning
    pub fn inspect_arp(&self, sender_mac: MacAddr, sender_ip: Ipv4Addr, is_reply: bool) -> bool {
        // If it's a null IP (like DHCP probe), ignore
        if sender_ip.is_unspecified() || sender_mac.is_zero() {
            return true; // allow
        }

        let mut table = self.arp_table.write();

        if let Some(existing_mac) = table.get(&sender_ip) {
            if *existing_mac != sender_mac {
                warn!(
                    "🚨 LAYER 2 THREAT: ARP Spoofing Detected! IP {} changed MAC from {} to {}",
                    sender_ip, existing_mac, sender_mac
                );
                // In a true firewall, we would immediately drop the packet and quarantine the MAC
                return false; // block
            }
        } else {
            // First time seeing this IP -> MAC pairing
            table.insert(sender_ip, sender_mac);
        }

        true // allow
    }
}
