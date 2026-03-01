// ============================================================================
// Rudras — Hardware Acceleration Module (Stub)
// SmartNIC / DPDK / RDMA offload (production: integrate with DPDK or AF_XDP)
// ============================================================================
#![allow(dead_code)]
pub struct HardwareAccel;
impl HardwareAccel {
    pub fn new() -> Self {
        Self
    }
    pub fn is_available(&self) -> bool {
        false
    }
}
