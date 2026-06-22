use super::cache_io::{self, SyncCacheScope};
use super::error::{PayError, PayErrorCode};
use midnight_ledger::dust::DustLocalState;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(super) const SNAPSHOT_VERSION: u32 = 2;
pub(super) const CACHE_SUBDIR: &str = "dust";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DustSyncSnapshot {
    pub version: u32,
    pub indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id when the snapshot was written.
    #[serde(default)]
    pub chain_id: String,
    pub dust_public_key_hex: String,
    pub last_seen_event_id: i64,
    /// Chain tip `maxId` when this snapshot was written; used to detect completeness.
    #[serde(default)]
    pub max_id_when_saved: i64,
    /// Tagged-serialized `DustLocalState<InMemoryDB>`.
    pub state_hex: String,
    pub saved_at_unix: u64,
}

impl DustSyncSnapshot {
    #[allow(dead_code)]
    pub(super) fn is_complete(&self) -> bool {
        self.max_id_when_saved > 0 && self.last_seen_event_id >= self.max_id_when_saved
    }
}

pub(super) fn snapshot_path(
    indexer_url: &str,
    dust_pk_hex: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, dust_pk_hex, scope)
}

pub(super) fn try_load_snapshot(path: &Path) -> Option<DustSyncSnapshot> {
    cache_io::try_load_versioned(path, SNAPSHOT_VERSION)
}

pub(super) fn decode_state(hex_s: &str) -> Result<DustLocalState<InMemoryDB>, PayError> {
    let bytes = hex::decode(hex_s.strip_prefix("0x").unwrap_or(hex_s)).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid dust state hex: {e}"),
        )
    })?;
    let mut reader: &[u8] = &bytes;
    tagged_deserialize(&mut reader).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to decode dust state: {e}"),
        )
    })
}

pub(super) fn encode_state(state: &DustLocalState<InMemoryDB>) -> Result<String, PayError> {
    let mut out = Vec::new();
    tagged_serialize(state, &mut out).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to encode dust state: {e}"),
        )
    })?;
    Ok(hex::encode(out))
}
