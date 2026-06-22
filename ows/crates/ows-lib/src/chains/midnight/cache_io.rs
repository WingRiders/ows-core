//! Shared on-disk snapshot helpers for Midnight indexer sync caches.
//!
//! ## Layout
//!
//! When [`SyncCacheScope::wallet_id`] is set (typical for CLI / library wallet flows):
//!
//! `{vault}/sync/midnight/{unshielded|shielded|dust}/{wallet_id}/<hash>.json`
//!
//! `<hash>` covers `(indexer_url, chain_id, stream-specific key)` so preview / preprod /
//! mainnet never share a snapshot even when the dust or shielded key material matches.
//!
//! Without a wallet id, snapshots omit the `{wallet_id}/` segment. If no vault is
//! configured, the root is `~/.ows/sync/midnight/{subdir}/`, then
//! `~/.cache/ows-pay/{subdir}/`.
//!
//! ## Environment
//!
//! | Variable | Effect |
//! |----------|--------|
//! | `OWS_MIDNIGHT_SYNC_CACHE=0` | Disable disk snapshots |
//! | `OWS_MIDNIGHT_SYNC_CACHE_DIR` | Override cache root (still uses `{subdir}/` below it) |
//! | `OWS_MIDNIGHT_SNAPSHOT_MAX_AGE_SECS` | TTL for complete snapshots (default **120** when wallet-scoped, **0** otherwise) |
//! | `OWS_MIDNIGHT_UNSHIELDED_STALL_TIMEOUT_SECS` | Fail only if no unshielded indexer events for this long (default **120**) |
//! | `OWS_MIDNIGHT_UNSHIELDED_WS_IDLE_TIMEOUT_SECS` | Fail if the unshielded WebSocket sends no frames (default **90**) |
//! | `OWS_MIDNIGHT_DUST_STALL_TIMEOUT_SECS` | Fail only if no dust events applied for this long (default **120**; aliases: `OWS_MIDNIGHT_DUST_*_SYNC_TIMEOUT_SECS`) |
//! | `OWS_MIDNIGHT_DUST_SNAPSHOT_MAX_AGE_SECS` | TTL for signing fast-path snapshot reuse; fund balance always resumes from disk then syncs |
//! | `OWS_MIDNIGHT_DUST_WS_IDLE_TIMEOUT_SECS` | Reconnect if the WebSocket sends no frames (default **90**) |
//! | `OWS_MIDNIGHT_DUST_VERIFY_IDLE_TIMEOUT_SECS` | Tip-verify idle before reconnect/accept (default **15**) |
//! | `OWS_MIDNIGHT_WS_CONNECT_TIMEOUT_SECS` | WebSocket connect handshake timeout (default **30**) |
//! | `OWS_MIDNIGHT_SKIP_DUST_BALANCE=1` | Skip DUST ledger sync in `fund balance` |
//! | `OWS_MIDNIGHT_SYNC_LOG=1` | Progress lines during Midnight indexer sync (stderr) |
//! | `OWS_MIDNIGHT_SHIELDED_VK_FREE` | `1`/`true`: shielded **balance** sync uses only `zswapLedgerEvents` (never `connect(viewingKey)`); shielded **spends** fail until a VK-free spend path exists |
//! | `OWS_MIDNIGHT_SHIELDED_ZSWAP_FALLBACK` | `1`/`true` force on; `0`/`false` force off; default **on** for preview/preprod indexers when `shieldedTransactions` is empty; implied **on** when `SHIELDED_VK_FREE` is set |
//! | `OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS` | After node submit, wait up to this many seconds for the indexer to reflect the tx in unshielded state (default **120**; `0` skips wait but still clears session cache) |
//!
//! Legacy aliases for sync log and stall timeouts are documented in [`super::midnight_env`].
//!
//! In-process session caches (90s TTL) for unshielded, shielded, and DUST balances
//! live in [`super::session_cache`].

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub use super::midnight_env::midnight_sync_log_enabled;
pub(crate) use super::midnight_env::SyncPurpose;

/// Scope for Midnight sync disk caches (wallet/vault co-location).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncCacheScope {
    /// Wallet UUID from the encrypted wallet file; isolates cache per wallet.
    pub wallet_id: Option<String>,
    /// Explicit vault root (e.g. `~/.ows` or a custom `--vault-path`).
    pub vault_path: Option<PathBuf>,
    /// CAIP-2 Midnight chain id (`midnight:preview`, …); isolates cache per network.
    pub chain_id: Option<String>,
}

impl SyncCacheScope {
    pub fn for_wallet(wallet_id: impl Into<String>, vault_path: Option<&Path>) -> Self {
        Self {
            wallet_id: Some(wallet_id.into()),
            vault_path: vault_path.map(Path::to_path_buf),
            chain_id: None,
        }
    }

    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }
}

fn normalize_chain_id(chain_id: &str) -> String {
    chain_id.trim().to_ascii_lowercase()
}

pub fn normalize_indexer_base(indexer_url: &str) -> String {
    indexer_url.trim_end_matches('/').to_lowercase()
}

/// Fingerprint for `(indexer_url)` alone.
#[allow(dead_code)]
pub fn fingerprint_indexer(indexer_url: &str) -> String {
    let mut h = Sha256::new();
    h.update(normalize_indexer_base(indexer_url).as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// Fingerprint for `(indexer_url, chain_id)` used in snapshots and session cache.
pub fn sync_site_fingerprint(indexer_url: &str, scope: &SyncCacheScope) -> String {
    let mut h = Sha256::new();
    h.update(normalize_indexer_base(indexer_url).as_bytes());
    if let Some(chain_id) = scope.chain_id.as_deref() {
        h.update(b"|");
        h.update(normalize_chain_id(chain_id).as_bytes());
    }
    hex::encode(&h.finalize()[..16])
}

/// `chain_id` persisted in snapshot JSON (empty when scope has none).
pub fn snapshot_chain_id(scope: &SyncCacheScope) -> String {
    scope
        .chain_id
        .as_deref()
        .map(normalize_chain_id)
        .unwrap_or_default()
}

/// True when an on-disk snapshot's `chain_id` matches the active scope.
pub fn snapshot_chain_matches(scope: &SyncCacheScope, snap_chain_id: &str) -> bool {
    match scope.chain_id.as_deref() {
        Some(expected) => snap_chain_id.eq_ignore_ascii_case(expected),
        None => snap_chain_id.is_empty(),
    }
}

/// Validate indexer site + chain id for a loaded snapshot.
pub fn snapshot_site_matches(
    scope: &SyncCacheScope,
    snap_chain_id: &str,
    site_fp: &str,
    snap_site_fp: &str,
) -> bool {
    site_fp == snap_site_fp && snapshot_chain_matches(scope, snap_chain_id)
}

fn cache_disabled() -> bool {
    std::env::var("OWS_MIDNIGHT_SYNC_CACHE")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Default vault root: explicit scope → `~/.ows`.
fn vault_root(scope: &SyncCacheScope) -> Option<PathBuf> {
    if let Some(v) = &scope.vault_path {
        return Some(v.clone());
    }
    home_dir().map(|h| h.join(".ows"))
}

/// Cache root directory for `subdir` (e.g. `"unshielded"`).
pub fn cache_root_dir(subdir: &str, scope: &SyncCacheScope) -> Option<PathBuf> {
    if cache_disabled() {
        return None;
    }
    if let Ok(dir) = std::env::var("OWS_MIDNIGHT_SYNC_CACHE_DIR") {
        return Some(PathBuf::from(dir).join(subdir));
    }
    if let Some(vault) = vault_root(scope) {
        return Some(vault.join("sync").join("midnight").join(subdir));
    }
    home_dir().map(|h| h.join(".cache").join("ows-pay").join(subdir))
}

/// File path for the snapshot keyed by `(indexer_url, chain_id, key)` under `subdir`.
pub fn snapshot_path(
    subdir: &str,
    indexer_url: &str,
    key: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    let root = cache_root_dir(subdir, scope)?;
    let mut h = Sha256::new();
    h.update(normalize_indexer_base(indexer_url).as_bytes());
    h.update(b"|");
    if let Some(chain_id) = scope.chain_id.as_deref() {
        h.update(normalize_chain_id(chain_id).as_bytes());
        h.update(b"|");
    }
    h.update(key.as_bytes());
    let hashed = hex::encode(&h.finalize()[..16]);
    match &scope.wallet_id {
        Some(wid) => Some(root.join(wid).join(format!("{hashed}.json"))),
        None => Some(root.join(format!("{hashed}.json"))),
    }
}

/// Max age for returning a complete cached snapshot without hitting the indexer.
///
/// Reserved for legacy env tuning; balance and signing always catch up on the indexer.
///
/// Priority: `OWS_MIDNIGHT_SNAPSHOT_MAX_AGE_SECS` env → 120s when wallet-scoped → 0.
#[allow(dead_code)]
pub fn snapshot_max_age_secs(scope: &SyncCacheScope) -> u64 {
    if let Ok(v) = std::env::var("OWS_MIDNIGHT_SNAPSHOT_MAX_AGE_SECS") {
        if let Ok(n) = v.parse() {
            return n;
        }
    }
    if scope.wallet_id.is_some() {
        120
    } else {
        0
    }
}

/// Best-effort JSON load. Returns `None` on any I/O or decode error.
pub fn try_load<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Load a versioned snapshot; rejects `version == 0` or `version > max_version`.
pub fn try_load_versioned<T: DeserializeOwned>(path: &Path, max_version: u32) -> Option<T> {
    let snap: T = try_load(path)?;
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let version = v.get("version")?.as_u64()? as u32;
    (version != 0 && version <= max_version).then_some(snap)
}

/// Best-effort pretty-JSON save. Errors are silently ignored.
pub fn try_save<T: Serialize>(path: &Path, snap: &T) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(snap) {
        let _ = std::fs::write(path, bytes);
    }
}

#[allow(dead_code)]
pub fn dust_snapshot_max_age_secs(scope: &SyncCacheScope) -> u64 {
    if let Ok(v) = std::env::var("OWS_MIDNIGHT_DUST_SNAPSHOT_MAX_AGE_SECS") {
        if let Ok(n) = v.parse() {
            return n;
        }
    }
    snapshot_max_age_secs(scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_scoped_path_includes_wallet_id() {
        let scope = SyncCacheScope::for_wallet("wallet-abc", None);
        let p = snapshot_path(
            "unshielded",
            "https://indexer.example/graphql",
            "addr1",
            &scope,
        )
        .unwrap();
        assert!(p.to_string_lossy().contains("wallet-abc"));
    }

    #[test]
    fn default_max_age_wallet_scoped() {
        let scope = SyncCacheScope::for_wallet("w", None);
        assert_eq!(snapshot_max_age_secs(&scope), 120);
        assert_eq!(snapshot_max_age_secs(&SyncCacheScope::default()), 0);
    }

    #[test]
    fn chain_id_produces_distinct_snapshot_paths() {
        let base = SyncCacheScope::for_wallet("wallet-abc", None);
        let preview = base.clone().with_chain_id("midnight:preview");
        let preprod = base.with_chain_id("midnight:preprod");
        let url = "https://indexer.example/graphql";
        let key = "same-dust-pk";
        let p_preview = snapshot_path("dust", url, key, &preview).unwrap();
        let p_preprod = snapshot_path("dust", url, key, &preprod).unwrap();
        assert_ne!(p_preview, p_preprod);
    }

    #[test]
    fn sync_site_fingerprint_includes_chain_id() {
        let scope = SyncCacheScope::default().with_chain_id("midnight:preview");
        let fp = sync_site_fingerprint("https://indexer.example/graphql", &scope);
        let fp_mainnet = sync_site_fingerprint(
            "https://indexer.example/graphql",
            &SyncCacheScope::default(),
        );
        assert_ne!(fp, fp_mainnet);
    }
}
