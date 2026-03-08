// ============================================================================
// Rudras — Cloud-Native Security Engine
//
// Full implementation replacing the empty stub.  Covers:
//   • Kubernetes NetworkPolicy enforcement (CNI-style decision engine)
//   • Container/Pod escape detection (namespace breakout, pivot_root)
//   • Cloud metadata SSRF detection (AWS/GCP/Azure IMDS — 169.254.169.254)
//   • Docker socket exposure detection
//   • Service mesh mTLS certificate validation anomaly
//   • Pod-to-pod micro-segmentation enforcement
//   • Cloud-provider IAM credential theft pattern detection
//
// ETHICAL GUARANTEE: Detection and blocking only. No container modification,
// no privilege escalation, no exploit generation.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

const AWS_IMDS_IP: &str = "169.254.169.254";
const ALI_METADATA_IP: &str = "100.100.100.200";

// ── Kubernetes NetworkPolicy ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkPolicyDecision { Allow, Deny, Log }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodLabel { pub key: String, pub value: String }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkProtocol { Tcp, Udp, Sctp, Any }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyRule {
    pub id: String,
    pub namespace: String,
    pub from_labels: Vec<PodLabel>,
    pub to_labels: Vec<PodLabel>,
    pub ports: Vec<u16>,
    pub protocols: Vec<NetworkProtocol>,
    pub decision: NetworkPolicyDecision,
    pub created_at: u64,
}

impl NetworkPolicyRule {
    pub fn matches(
        &self, namespace: &str,
        from_labels: &[(&str, &str)], to_labels: &[(&str, &str)],
        dst_port: u16, proto: &NetworkProtocol,
    ) -> bool {
        if !self.namespace.is_empty() && self.namespace != namespace { return false; }
        for rl in &self.from_labels {
            if !from_labels.iter().any(|(k, v)| *k == rl.key && *v == rl.value) { return false; }
        }
        for rl in &self.to_labels {
            if !to_labels.iter().any(|(k, v)| *k == rl.key && *v == rl.value) { return false; }
        }
        if !self.ports.is_empty() && !self.ports.contains(&dst_port) { return false; }
        if !self.protocols.is_empty()
            && !self.protocols.contains(proto)
            && !self.protocols.contains(&NetworkProtocol::Any) { return false; }
        true
    }
}

// ── Container Escape Detection ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContainerEscapeType {
    NamespaceEscape, PivotRootAttempt, HostPidNamespaceAccess,
    DockerSocketExposure, PrivilegedContainer, HostPathWriteAttempt,
    KernelFeatureAbuse, HostNetworkAccess,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EscapeSeverity { Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEscapeAlert {
    pub id: String,
    pub escape_type: ContainerEscapeType,
    pub pod_name: String,
    pub namespace: String,
    pub container_id: String,
    pub process_name: String,
    pub process_pid: u32,
    pub syscall: Option<String>,
    pub details: String,
    pub severity: EscapeSeverity,
    pub timestamp: u64,
}

// ── Cloud Metadata SSRF ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CloudProvider { Aws, Gcp, Azure, Alibaba, Unknown }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetadataResource {
    IamCredentials, UserData, InstanceMetadata, ServiceAccountToken, Unknown,
}

impl MetadataResource {
    pub fn from_path(path: &str) -> Self {
        let p = path.to_lowercase();
        if p.contains("iam") || p.contains("credentials") || p.contains("security-credentials") {
            Self::IamCredentials
        } else if p.contains("user-data") {
            Self::UserData
        } else if p.contains("token") || p.contains("service-account") {
            Self::ServiceAccountToken
        } else if p.contains("meta-data") || p.contains("computemetadata") {
            Self::InstanceMetadata
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSsrfAlert {
    pub id: String,
    pub source_pod: String,
    pub source_ip: IpAddr,
    pub target_ip: String,
    pub target_path: String,
    pub http_method: String,
    pub cloud_provider: CloudProvider,
    pub targeted_resource: MetadataResource,
    pub timestamp: u64,
}

// ── mTLS Anomaly ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MtlsAnomalyType {
    WorkloadIdentityMismatch, UnencryptedServiceCall,
    InvalidCertificate, SpiffeIdMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsAnomalyAlert {
    pub id: String, pub source_pod: String, pub dest_service: String,
    pub anomaly_type: MtlsAnomalyType, pub details: String, pub timestamp: u64,
}

// ── IAM Credential Theft ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IamTheftPattern {
    MetadataRapidEnumeration, CredentialAnomalousUse,
    StsRoleChaining, GcpKeyExport, EnvCredentialDump,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamCredentialAlert {
    pub id: String, pub source_pod: String, pub source_ip: IpAddr,
    pub pattern: IamTheftPattern, pub details: String, pub timestamp: u64,
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudNativeStats {
    pub policy_decisions_total: u64,
    pub policy_denials: u64,
    pub escape_alerts: u64,
    pub ssrf_alerts: u64,
    pub mtls_anomalies: u64,
    pub iam_alerts: u64,
    pub active_policies: usize,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct CloudNative {
    policies: RwLock<Vec<NetworkPolicyRule>>,
    escape_alerts: RwLock<VecDeque<ContainerEscapeAlert>>,
    ssrf_alerts: RwLock<VecDeque<MetadataSsrfAlert>>,
    mtls_alerts: RwLock<VecDeque<MtlsAnomalyAlert>>,
    iam_alerts: RwLock<VecDeque<IamCredentialAlert>>,
    metadata_rate: RwLock<HashMap<String, (u32, u64)>>,
    decisions_total: AtomicU64,
    denials_total: AtomicU64,
    escape_count: AtomicU64,
    ssrf_count: AtomicU64,
    mtls_count: AtomicU64,
    iam_count: AtomicU64,
    alert_seq: AtomicU64,
}

impl CloudNative {
    pub fn new() -> Self {
        let engine = Self {
            policies: RwLock::new(Vec::new()),
            escape_alerts: RwLock::new(VecDeque::with_capacity(256)),
            ssrf_alerts: RwLock::new(VecDeque::with_capacity(256)),
            mtls_alerts: RwLock::new(VecDeque::with_capacity(256)),
            iam_alerts: RwLock::new(VecDeque::with_capacity(256)),
            metadata_rate: RwLock::new(HashMap::new()),
            decisions_total: AtomicU64::new(0),
            denials_total: AtomicU64::new(0),
            escape_count: AtomicU64::new(0),
            ssrf_count: AtomicU64::new(0),
            mtls_count: AtomicU64::new(0),
            iam_count: AtomicU64::new(0),
            alert_seq: AtomicU64::new(0),
        };
        engine.load_default_policies();
        engine
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.alert_seq.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", prefix, unix_secs(), n)
    }

    fn load_default_policies(&self) {
        let mut policies = self.policies.write();
        // Allow kube-system Prometheus scraping
        policies.push(NetworkPolicyRule {
            id: "allow-kube-system-monitoring".into(),
            namespace: "kube-system".into(),
            from_labels: vec![PodLabel { key: "app".into(), value: "prometheus".into() }],
            to_labels: vec![],
            ports: vec![9090, 9091, 8080, 8443],
            protocols: vec![NetworkProtocol::Tcp],
            decision: NetworkPolicyDecision::Allow,
            created_at: unix_secs(),
        });
        info!("☁️  CloudNative: {} default NetworkPolicy rules loaded", policies.len());
    }

    pub fn add_policy(&self, rule: NetworkPolicyRule) {
        let mut policies = self.policies.write();
        policies.retain(|r| r.id != rule.id);
        let id = rule.id.clone();
        let total = policies.len() + 1;
        policies.push(rule);
        debug!("☁️  NetworkPolicy '{}' added ({} total)", id, total);
    }

    pub fn evaluate_pod_flow(
        &self, namespace: &str,
        from_labels: &[(&str, &str)], to_labels: &[(&str, &str)],
        dst_port: u16, proto: NetworkProtocol,
    ) -> NetworkPolicyDecision {
        self.decisions_total.fetch_add(1, Ordering::Relaxed);
        let policies = self.policies.read();
        for rule in policies.iter() {
            if rule.matches(namespace, from_labels, to_labels, dst_port, &proto) {
                if rule.decision == NetworkPolicyDecision::Deny {
                    self.denials_total.fetch_add(1, Ordering::Relaxed);
                    debug!("☁️  NetworkPolicy DENY: ns={} port={} rule={}", namespace, dst_port, rule.id);
                }
                return rule.decision.clone();
            }
        }
        NetworkPolicyDecision::Allow
    }

    pub fn check_metadata_ssrf(
        &self, source_pod: &str, source_ip: IpAddr,
        dst_ip: &str, path: &str, method: &str,
    ) -> Option<MetadataSsrfAlert> {
        if !dst_ip.starts_with("169.254.") && dst_ip != ALI_METADATA_IP { return None; }

        let provider = if path.contains("latest/meta-data") || path.contains("latest/user-data") {
            CloudProvider::Aws
        } else if path.contains("computeMetadata") {
            CloudProvider::Gcp
        } else if path.contains("metadata/instance") {
            CloudProvider::Azure
        } else {
            CloudProvider::Unknown
        };

        // Rate-check: >10 requests/minute → credential harvesting
        let is_rapid = {
            let mut rate = self.metadata_rate.write();
            let entry = rate.entry(source_pod.to_string()).or_insert((0, unix_secs()));
            if unix_secs().saturating_sub(entry.1) > 60 {
                *entry = (1, unix_secs()); false
            } else {
                entry.0 += 1; entry.0 > 10
            }
        };
        if is_rapid {
            warn!("☁️  IMDS rapid enumeration: pod={} dst={}", source_pod, dst_ip);
            self.iam_count.fetch_add(1, Ordering::Relaxed);
            let iam = IamCredentialAlert {
                id: self.next_id("IAM"),
                source_pod: source_pod.into(), source_ip,
                pattern: IamTheftPattern::MetadataRapidEnumeration,
                details: format!("Pod {} made >10 metadata API calls/min to {}", source_pod, dst_ip),
                timestamp: unix_secs(),
            };
            self.iam_alerts.write().push_back(iam);
        }

        self.ssrf_count.fetch_add(1, Ordering::Relaxed);
        let alert = MetadataSsrfAlert {
            id: self.next_id("SSRF"), source_pod: source_pod.into(), source_ip,
            target_ip: dst_ip.into(), target_path: path.into(), http_method: method.into(),
            cloud_provider: provider,
            targeted_resource: MetadataResource::from_path(path),
            timestamp: unix_secs(),
        };
        warn!("☁️  Cloud metadata SSRF: pod={} -> {}{}", source_pod, dst_ip, path);
        self.ssrf_alerts.write().push_back(alert.clone());
        Some(alert)
    }

    pub fn check_container_escape(
        &self, pod_name: &str, namespace: &str, container_id: &str,
        process_name: &str, pid: u32, syscall: Option<&str>, file_path: Option<&str>,
    ) -> Option<ContainerEscapeAlert> {
        let escape_type = if let Some(sc) = syscall {
            match sc {
                "unshare"    => Some((ContainerEscapeType::NamespaceEscape,   EscapeSeverity::Critical)),
                "pivot_root" => Some((ContainerEscapeType::PivotRootAttempt,  EscapeSeverity::Critical)),
                "nsenter"    => Some((ContainerEscapeType::HostPidNamespaceAccess, EscapeSeverity::High)),
                _ => None,
            }
        } else if let Some(fp) = file_path {
            if fp.contains("/var/run/docker.sock") || fp.contains("/run/docker.sock") {
                Some((ContainerEscapeType::DockerSocketExposure, EscapeSeverity::High))
            } else if fp.contains("/proc/sysrq-trigger") {
                Some((ContainerEscapeType::KernelFeatureAbuse, EscapeSeverity::High))
            } else if fp.starts_with("/host") {
                Some((ContainerEscapeType::HostPathWriteAttempt, EscapeSeverity::Medium))
            } else { None }
        } else { None };

        escape_type.map(|(etype, sev)| {
            self.escape_count.fetch_add(1, Ordering::Relaxed);
            let details = format!(
                "Escape attempt: pod={} ns={} proc={} pid={} syscall={:?} path={:?}",
                pod_name, namespace, process_name, pid, syscall, file_path
            );
            warn!("☁️  CONTAINER ESCAPE: {} — {}", pod_name, details);
            let alert = ContainerEscapeAlert {
                id: self.next_id("CESCAPE"), escape_type: etype,
                pod_name: pod_name.into(), namespace: namespace.into(),
                container_id: container_id.into(), process_name: process_name.into(),
                process_pid: pid, syscall: syscall.map(|s| s.to_string()),
                details, severity: sev, timestamp: unix_secs(),
            };
            self.escape_alerts.write().push_back(alert.clone());
            alert
        })
    }

    pub fn check_mtls_anomaly(
        &self, source_pod: &str, dest_service: &str,
        is_encrypted: bool, cert_valid: bool, workload_id_match: bool,
    ) -> Option<MtlsAnomalyAlert> {
        let anomaly = if !is_encrypted {
            Some((MtlsAnomalyType::UnencryptedServiceCall,
                  format!("Unencrypted call {} -> {}", source_pod, dest_service)))
        } else if !cert_valid {
            Some((MtlsAnomalyType::InvalidCertificate,
                  format!("Invalid cert on {} -> {}", source_pod, dest_service)))
        } else if !workload_id_match {
            Some((MtlsAnomalyType::WorkloadIdentityMismatch,
                  format!("SPIFFE ID mismatch {} -> {}", source_pod, dest_service)))
        } else { None };

        anomaly.map(|(anomaly_type, details)| {
            self.mtls_count.fetch_add(1, Ordering::Relaxed);
            warn!("☁️  mTLS anomaly: {}", details);
            let alert = MtlsAnomalyAlert {
                id: self.next_id("MTLS"), source_pod: source_pod.into(),
                dest_service: dest_service.into(), anomaly_type, details, timestamp: unix_secs(),
            };
            self.mtls_alerts.write().push_back(alert.clone());
            alert
        })
    }

    pub fn drain_escape_alerts(&self) -> Vec<ContainerEscapeAlert> {
        self.escape_alerts.write().drain(..).collect()
    }
    pub fn drain_ssrf_alerts(&self) -> Vec<MetadataSsrfAlert> {
        self.ssrf_alerts.write().drain(..).collect()
    }
    pub fn drain_mtls_alerts(&self) -> Vec<MtlsAnomalyAlert> {
        self.mtls_alerts.write().drain(..).collect()
    }
    pub fn drain_iam_alerts(&self) -> Vec<IamCredentialAlert> {
        self.iam_alerts.write().drain(..).collect()
    }

    pub fn stats(&self) -> CloudNativeStats {
        CloudNativeStats {
            policy_decisions_total: self.decisions_total.load(Ordering::Relaxed),
            policy_denials: self.denials_total.load(Ordering::Relaxed),
            escape_alerts: self.escape_count.load(Ordering::Relaxed),
            ssrf_alerts: self.ssrf_count.load(Ordering::Relaxed),
            mtls_anomalies: self.mtls_count.load(Ordering::Relaxed),
            iam_alerts: self.iam_count.load(Ordering::Relaxed),
            active_policies: self.policies.read().len(),
        }
    }
}
