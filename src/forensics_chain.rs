#![allow(dead_code, unused_imports, unused_variables)]

//! Forensics Chain — tamper-evident evidence collection with blockchain-style chain of custody.
//! Every evidence item is SHA3-256 hashed; each chain entry includes the hash of the previous
//! entry, making the chain detectable as invalid if any record is altered or deleted.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha3_hex(data: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence types
// ─────────────────────────────────────────────────────────────────────────────

/// Categories of forensic evidence Rudras can collect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    PcapCapture,
    MemorySnapshot,
    ProcessList,
    NetworkConnections,
    FileHash,
    RegistrySnapshot,
    LogExtract,
    DnsQuery,
    TlsCertificate,
    PacketPayload,
}

impl EvidenceType {
    fn as_str(&self) -> &'static str {
        match self {
            EvidenceType::PcapCapture => "pcap_capture",
            EvidenceType::MemorySnapshot => "memory_snapshot",
            EvidenceType::ProcessList => "process_list",
            EvidenceType::NetworkConnections => "network_connections",
            EvidenceType::FileHash => "file_hash",
            EvidenceType::RegistrySnapshot => "registry_snapshot",
            EvidenceType::LogExtract => "log_extract",
            EvidenceType::DnsQuery => "dns_query",
            EvidenceType::TlsCertificate => "tls_certificate",
            EvidenceType::PacketPayload => "packet_payload",
        }
    }
}

/// Actions recorded in the chain of custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceAction {
    Collected,
    Transferred,
    Analyzed,
    Exported,
    Archived,
    AccessedBy(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain-of-custody entry
// ─────────────────────────────────────────────────────────────────────────────

/// A single link in the chain of custody linked list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Monotonic sequence number within this evidence item's chain.
    pub seq: u64,
    pub timestamp: u64,
    pub action: EvidenceAction,
    /// Identity of the actor (node ID, analyst name, or "rudras-auto").
    pub actor: String,
    /// SHA3-256 hash of the *previous* entry's serialised content (or all-zeros for the first).
    pub prev_hash: String,
    /// SHA3-256 hash of this entry's content (excluding `entry_hash` itself).
    pub entry_hash: String,
}

impl ChainEntry {
    /// Build a new entry and compute its hash.
    fn new(seq: u64, action: EvidenceAction, actor: &str, prev_hash: &str) -> Self {
        let timestamp = unix_secs();
        let action_str = format!("{:?}", action);
        // Hash over the fields that define content (not entry_hash itself).
        let content = format!("{seq}|{timestamp}|{action_str}|{actor}|{prev_hash}");
        let entry_hash = sha3_hex(content.as_bytes());
        ChainEntry {
            seq,
            timestamp,
            action,
            actor: actor.to_string(),
            prev_hash: prev_hash.to_string(),
            entry_hash,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Forensic evidence item
// ─────────────────────────────────────────────────────────────────────────────

/// A single piece of forensic evidence with its full chain of custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvidence {
    /// Unique evidence ID: `EVD-<unix_secs>-<counter>`.
    pub id: String,
    pub evidence_type: EvidenceType,
    /// SHA3-256 hash of the raw evidence bytes (the actual captured data).
    pub content_hash: String,
    /// Human-readable description of what was captured.
    pub description: String,
    /// Optional related incident or alert ID.
    pub incident_id: Option<String>,
    /// Source host / sensor node.
    pub source_node: String,
    pub collected_at: u64,
    /// Size of the original evidence in bytes.
    pub size_bytes: usize,
    /// Linked chain of custody entries (head = Collected).
    pub chain: Vec<ChainEntry>,
    /// Whether this evidence has passed integrity verification.
    pub verified: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// DFIR export format
// ─────────────────────────────────────────────────────────────────────────────

/// DFIR-compatible JSON export structure (compatible with DFIR-ORC, Velociraptor, etc.).
#[derive(Debug, Serialize, Deserialize)]
pub struct DfirExport {
    pub schema_version: &'static str,
    pub export_time: u64,
    pub exporter: &'static str,
    pub evidence_count: usize,
    pub items: Vec<DfirItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DfirItem {
    pub id: String,
    pub evidence_type: String,
    pub content_hash: String,
    pub description: String,
    pub incident_id: Option<String>,
    pub source_node: String,
    pub collected_at: u64,
    pub size_bytes: usize,
    pub chain_length: usize,
    pub chain_valid: bool,
    pub custody_log: Vec<CustodyLogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustodyLogEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub action: String,
    pub actor: String,
    pub entry_hash: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Integrity verification result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub evidence_id: String,
    pub chain_length: usize,
    pub is_valid: bool,
    /// Describes the first broken link if any.
    pub failure_at_seq: Option<u64>,
    pub failure_reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ForensicsStats {
    pub items_collected: AtomicU64,
    pub export_count: AtomicU64,
    pub integrity_checks: AtomicU64,
    pub integrity_failures: AtomicU64,
}

pub struct ForensicsChain {
    /// node_id identifies this Rudras sensor in chain entries.
    node_id: String,
    evidence: RwLock<HashMap<String, ForensicEvidence>>,
    counter: AtomicU64,
    pub stats: Arc<ForensicsStats>,
}

impl ForensicsChain {
    pub fn new(node_id: impl Into<String>) -> Self {
        ForensicsChain {
            node_id: node_id.into(),
            evidence: RwLock::new(HashMap::new()),
            counter: AtomicU64::new(1),
            stats: Arc::new(ForensicsStats::default()),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Collect evidence
    // ─────────────────────────────────────────────────────────────────────

    /// Hash `data`, create a new `ForensicEvidence` item, and append the
    /// initial `Collected` chain entry.  Returns the evidence ID.
    pub fn collect(
        &self,
        evidence_type: EvidenceType,
        data: &[u8],
        description: impl Into<String>,
        incident_id: Option<String>,
    ) -> String {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("EVD-{}-{:06}", unix_secs(), seq);
        let content_hash = sha3_hex(data);

        // Genesis chain entry – prev_hash is all-zeros.
        let genesis_prev = "0".repeat(64);
        let entry = ChainEntry::new(1, EvidenceAction::Collected, &self.node_id, &genesis_prev);

        let ev = ForensicEvidence {
            id: id.clone(),
            evidence_type,
            content_hash,
            description: description.into(),
            incident_id,
            source_node: self.node_id.clone(),
            collected_at: unix_secs(),
            size_bytes: data.len(),
            chain: vec![entry],
            verified: false,
        };

        info!(
            id = %ev.id,
            kind = %ev.evidence_type.as_str(),
            bytes = data.len(),
            "ForensicsChain: evidence collected"
        );

        self.evidence.write().insert(id.clone(), ev);
        self.stats.items_collected.fetch_add(1, Ordering::Relaxed);
        id
    }

    // ─────────────────────────────────────────────────────────────────────
    // Append custody action
    // ─────────────────────────────────────────────────────────────────────

    /// Append a new chain-of-custody entry to an existing evidence item.
    pub fn append_custody(
        &self,
        evidence_id: &str,
        action: EvidenceAction,
        actor: &str,
    ) -> bool {
        let mut store = self.evidence.write();
        if let Some(ev) = store.get_mut(evidence_id) {
            let prev = ev.chain.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| "0".repeat(64));
            let seq = ev.chain.len() as u64 + 1;
            let entry = ChainEntry::new(seq, action, actor, &prev);
            debug!(
                id = %evidence_id,
                seq = seq,
                actor = %actor,
                "ForensicsChain: custody entry appended"
            );
            ev.chain.push(entry);
            true
        } else {
            warn!(id = %evidence_id, "ForensicsChain: append_custody — evidence not found");
            false
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Integrity verification
    // ─────────────────────────────────────────────────────────────────────

    /// Walk the chain for `evidence_id`, verifying that each entry's
    /// `prev_hash` correctly references the preceding entry's `entry_hash`.
    pub fn verify_integrity(&self, evidence_id: &str) -> IntegrityReport {
        self.stats.integrity_checks.fetch_add(1, Ordering::Relaxed);
        let store = self.evidence.read();

        let ev = match store.get(evidence_id) {
            Some(e) => e,
            None => {
                return IntegrityReport {
                    evidence_id: evidence_id.to_string(),
                    chain_length: 0,
                    is_valid: false,
                    failure_at_seq: None,
                    failure_reason: Some("Evidence not found".into()),
                };
            }
        };

        let chain = &ev.chain;
        let chain_len = chain.len();

        // Verify the first entry's prev_hash is the genesis sentinel.
        if let Some(first) = chain.first() {
            let genesis = "0".repeat(64);
            if first.prev_hash != genesis {
                self.stats.integrity_failures.fetch_add(1, Ordering::Relaxed);
                return IntegrityReport {
                    evidence_id: evidence_id.to_string(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(1),
                    failure_reason: Some(format!(
                        "Genesis prev_hash mismatch: got {}",
                        first.prev_hash
                    )),
                };
            }
        }

        for i in 1..chain_len {
            let prev = &chain[i - 1];
            let curr = &chain[i];

            // Each entry must point back to the previous entry's hash.
            if curr.prev_hash != prev.entry_hash {
                self.stats.integrity_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    id = %evidence_id,
                    seq = curr.seq,
                    "ForensicsChain: chain broken — prev_hash mismatch"
                );
                return IntegrityReport {
                    evidence_id: evidence_id.to_string(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(curr.seq),
                    failure_reason: Some(format!(
                        "prev_hash {} does not match prior entry_hash {}",
                        curr.prev_hash, prev.entry_hash
                    )),
                };
            }

            // Recompute the entry's own hash and verify it hasn't been tampered with.
            let action_str = format!("{:?}", curr.action);
            let expected_content =
                format!("{}|{}|{}|{}|{}", curr.seq, curr.timestamp, action_str, curr.actor, curr.prev_hash);
            let expected_hash = sha3_hex(expected_content.as_bytes());
            if curr.entry_hash != expected_hash {
                self.stats.integrity_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    id = %evidence_id,
                    seq = curr.seq,
                    "ForensicsChain: chain tampered — entry_hash mismatch"
                );
                return IntegrityReport {
                    evidence_id: evidence_id.to_string(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(curr.seq),
                    failure_reason: Some(format!(
                        "entry_hash {} does not recompute correctly",
                        curr.entry_hash
                    )),
                };
            }
        }

        IntegrityReport {
            evidence_id: evidence_id.to_string(),
            chain_length: chain_len,
            is_valid: true,
            failure_at_seq: None,
            failure_reason: None,
        }
    }

    /// Bulk-verify all stored evidence items; returns a list of failed IDs.
    pub fn verify_all(&self) -> Vec<IntegrityReport> {
        let ids: Vec<String> = self.evidence.read().keys().cloned().collect();
        ids.iter().map(|id| self.verify_integrity(id)).collect()
    }

    // ─────────────────────────────────────────────────────────────────────
    // DFIR export
    // ─────────────────────────────────────────────────────────────────────

    /// Export all collected evidence to a DFIR-compatible JSON structure.
    pub fn export_to_dfir_format(&self) -> DfirExport {
        self.stats.export_count.fetch_add(1, Ordering::Relaxed);
        let store = self.evidence.read();

        let items: Vec<DfirItem> = store
            .values()
            .map(|ev| {
                let report = self.verify_integrity_inner(ev);
                let custody_log = ev
                    .chain
                    .iter()
                    .map(|e| CustodyLogEntry {
                        seq: e.seq,
                        timestamp: e.timestamp,
                        action: format!("{:?}", e.action),
                        actor: e.actor.clone(),
                        entry_hash: e.entry_hash.clone(),
                    })
                    .collect();

                DfirItem {
                    id: ev.id.clone(),
                    evidence_type: ev.evidence_type.as_str().to_string(),
                    content_hash: ev.content_hash.clone(),
                    description: ev.description.clone(),
                    incident_id: ev.incident_id.clone(),
                    source_node: ev.source_node.clone(),
                    collected_at: ev.collected_at,
                    size_bytes: ev.size_bytes,
                    chain_length: ev.chain.len(),
                    chain_valid: report.is_valid,
                    custody_log,
                }
            })
            .collect();

        info!(count = items.len(), "ForensicsChain: DFIR export generated");

        DfirExport {
            schema_version: "1.0",
            export_time: unix_secs(),
            exporter: "Rudras-ForensicsChain",
            evidence_count: items.len(),
            items,
        }
    }

    /// Internal verify (no stat bump) so export_to_dfir_format doesn't double-count.
    fn verify_integrity_inner(&self, ev: &ForensicEvidence) -> IntegrityReport {
        let chain = &ev.chain;
        let chain_len = chain.len();

        if let Some(first) = chain.first() {
            let genesis = "0".repeat(64);
            if first.prev_hash != genesis {
                return IntegrityReport {
                    evidence_id: ev.id.clone(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(1),
                    failure_reason: Some("Genesis prev_hash mismatch".into()),
                };
            }
        }

        for i in 1..chain_len {
            let prev = &chain[i - 1];
            let curr = &chain[i];
            if curr.prev_hash != prev.entry_hash {
                return IntegrityReport {
                    evidence_id: ev.id.clone(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(curr.seq),
                    failure_reason: Some("prev_hash mismatch".into()),
                };
            }
            let action_str = format!("{:?}", curr.action);
            let expected_content =
                format!("{}|{}|{}|{}|{}", curr.seq, curr.timestamp, action_str, curr.actor, curr.prev_hash);
            if curr.entry_hash != sha3_hex(expected_content.as_bytes()) {
                return IntegrityReport {
                    evidence_id: ev.id.clone(),
                    chain_length: chain_len,
                    is_valid: false,
                    failure_at_seq: Some(curr.seq),
                    failure_reason: Some("entry_hash recompute mismatch".into()),
                };
            }
        }

        IntegrityReport {
            evidence_id: ev.id.clone(),
            chain_length: chain_len,
            is_valid: true,
            failure_at_seq: None,
            failure_reason: None,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Accessors
    // ─────────────────────────────────────────────────────────────────────

    pub fn get_evidence(&self, id: &str) -> Option<ForensicEvidence> {
        self.evidence.read().get(id).cloned()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.read().len()
    }

    pub fn evidence_ids(&self) -> Vec<String> {
        self.evidence.read().keys().cloned().collect()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Data retention (GDPR compliance)
    // ─────────────────────────────────────────────────────────────────────

    /// Remove evidence items older than `retention_days` days.
    /// Call periodically from a background task (typically every 24 h).
    pub fn purge_expired(&self, retention_days: u64) {
        let cutoff = unix_secs().saturating_sub(retention_days * 86_400);
        let mut store = self.evidence.write();
        let before = store.len();
        store.retain(|_, ev| ev.collected_at >= cutoff);
        let purged = before - store.len();
        if purged > 0 {
            info!("⛓️  ForensicsChain: purged {} items older than {} days (GDPR retention)", purged, retention_days);
        }
    }
}
