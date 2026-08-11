//! Append-only, tamper-evident intrusion ledger. Each entry's hash commits to
//! the previous entry's hash, so any edit or deletion breaks the chain and is
//! detectable via [`LedgerIntrusionSink::verify`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use vault_domain::{BlobId, NamespaceId};
use vault_ports::{IntrusionRecord, IntrusionSink, PortResult};

/// One chained ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: u64,
    pub record: IntrusionRecord,
    /// Hex SHA-256 of the previous entry (`GENESIS` for the first).
    pub prev_hash: String,
    /// Hex SHA-256 of `seq || prev_hash || record`.
    pub hash: String,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn entry_hash(seq: u64, prev_hash: &str, record: &IntrusionRecord) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_be_bytes());
    h.update(prev_hash.as_bytes());
    // Field-tagged, stable encoding of the record.
    h.update(record.source_ip.as_bytes());
    h.update([0]);
    h.update(record.ja3.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    h.update(record.attack_class.as_bytes());
    h.update([0]);
    h.update(record.rejection_reason.as_bytes());
    h.update([0]);
    h.update(record.at_millis.to_be_bytes());
    hex::encode(h.finalize())
}

#[derive(Default)]
pub struct LedgerIntrusionSink {
    entries: Mutex<Vec<LedgerEntry>>,
}

impl LedgerIntrusionSink {
    pub fn new() -> Self {
        Self::default()
    }

    fn append(&self, record: IntrusionRecord) {
        let mut entries = self.entries.lock().unwrap();
        let seq = entries.len() as u64;
        let prev_hash = entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let hash = entry_hash(seq, &prev_hash, &record);
        entries.push(LedgerEntry {
            seq,
            record,
            prev_hash,
            hash,
        });
    }

    /// Snapshot of the ledger (for the admin/forensics view).
    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.entries.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Recompute the whole chain; `false` if any entry was altered/removed.
    pub fn verify(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        let mut prev = GENESIS.to_string();
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            if e.hash != entry_hash(e.seq, &e.prev_hash, &e.record) {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }
}

#[async_trait]
impl IntrusionSink for LedgerIntrusionSink {
    async fn record(&self, entry: IntrusionRecord) -> PortResult<()> {
        self.append(entry);
        Ok(())
    }

    async fn note_unauthorized_shard_access(
        &self,
        namespace: &NamespaceId,
        blob_id: &BlobId,
    ) -> PortResult<()> {
        self.append(IntrusionRecord {
            source_ip: "peer".into(),
            ja3: None,
            attack_class: "unauthorized_shard_access".into(),
            rejection_reason: format!("namespace={namespace} blob={blob_id}"),
            at_millis: 0,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(reason: &str) -> IntrusionRecord {
        IntrusionRecord {
            source_ip: "203.0.113.9".into(),
            ja3: Some("ja3fp".into()),
            attack_class: "bad_cert".into(),
            rejection_reason: reason.into(),
            at_millis: 42,
        }
    }

    #[tokio::test]
    async fn chain_is_tamper_evident() {
        let sink = LedgerIntrusionSink::new();
        sink.record(rec("no client cert")).await.unwrap();
        sink.record(rec("revoked cert")).await.unwrap();
        assert_eq!(sink.len(), 2);
        assert!(sink.verify());

        // Tamper with a stored record: the chain must no longer verify.
        {
            let mut e = sink.entries.lock().unwrap();
            e[0].record.rejection_reason = "edited".into();
        }
        assert!(!sink.verify());
    }
}
