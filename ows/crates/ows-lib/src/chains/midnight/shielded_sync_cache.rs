//! Disk snapshot for Midnight shielded (Zswap) balance sync.

use super::cache_io::{self, SyncCacheScope};
use super::ShieldedBalances;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(super) const SNAPSHOT_VERSION: u32 = 4;
const CACHE_SUBDIR: &str = "shielded";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ShieldedSyncSnapshot {
    pub version: u32,
    pub indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id when the snapshot was written.
    #[serde(default)]
    pub chain_id: String,
    /// Fingerprint of the viewing key used for `connect(viewingKey)`.
    pub viewing_key_fingerprint: String,
    pub highest_checked_end_index: i64,
    pub highest_end_index_when_saved: i64,
    /// Set when balances were produced via full `zswapLedgerEvents` replay.
    #[serde(default)]
    pub last_seen_zswap_event_id: i64,
    #[serde(default)]
    pub max_zswap_id_when_saved: i64,
    #[serde(default)]
    pub saved_at_unix: u64,
    pub balances: ShieldedBalances,
    /// Unspent shielded coins after zswap replay (enables incremental resume).
    #[serde(default)]
    pub zswap_owned_coins: Vec<ZswapOwnedCoinRecord>,
}

/// One unspent coin in a zswap-ledger snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ZswapOwnedCoinRecord {
    pub nullifier_hex: String,
    pub coin_hex: String,
}

impl ShieldedSyncSnapshot {
    #[allow(dead_code)]
    pub(super) fn is_complete(&self) -> bool {
        if self.max_zswap_id_when_saved > 0 {
            return self.last_seen_zswap_event_id >= self.max_zswap_id_when_saved;
        }
        self.highest_end_index_when_saved == 0
            || self.highest_checked_end_index >= self.highest_end_index_when_saved
    }
}

/// Cache key for zswap-ledger shielded balance snapshots (seed-scoped, not viewing-key).
pub(super) fn zswap_cache_key(seed_fingerprint: &str) -> String {
    format!("zswap:{seed_fingerprint}")
}

pub(super) fn shielded_seed_fingerprint(seed_32: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(seed_32)[..16].as_ref())
}

pub(super) fn viewing_key_fingerprint(viewing_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(viewing_key.as_bytes())[..16].as_ref())
}

pub(super) fn snapshot_path(
    indexer_url: &str,
    vk_fingerprint: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, vk_fingerprint, scope)
}

pub(super) fn try_load_snapshot(path: &Path) -> Option<ShieldedSyncSnapshot> {
    cache_io::try_load_versioned(path, SNAPSHOT_VERSION)
}

pub(super) fn try_save_snapshot(path: &Path, snap: &ShieldedSyncSnapshot) {
    cache_io::try_save(path, snap);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn zswap_snapshot_complete_when_last_seen_reaches_max() {
        let snap = ShieldedSyncSnapshot {
            version: SNAPSHOT_VERSION,
            indexer_fingerprint: "fp".into(),
            chain_id: "midnight:preview".into(),
            viewing_key_fingerprint: "zswap:abc".into(),
            highest_checked_end_index: 0,
            highest_end_index_when_saved: 0,
            last_seen_zswap_event_id: 2815,
            max_zswap_id_when_saved: 2815,
            saved_at_unix: 1,
            balances: BTreeMap::new(),
            zswap_owned_coins: vec![],
        };
        assert!(snap.is_complete());
    }

    #[test]
    fn zswap_snapshot_incomplete_when_events_missing() {
        let snap = ShieldedSyncSnapshot {
            version: SNAPSHOT_VERSION,
            indexer_fingerprint: "fp".into(),
            chain_id: "midnight:preview".into(),
            viewing_key_fingerprint: "zswap:abc".into(),
            highest_checked_end_index: 0,
            highest_end_index_when_saved: 0,
            last_seen_zswap_event_id: 100,
            max_zswap_id_when_saved: 2815,
            saved_at_unix: 1,
            balances: BTreeMap::from([("0x01".into(), 1u128)]),
            zswap_owned_coins: vec![],
        };
        assert!(!snap.is_complete());
    }
}
