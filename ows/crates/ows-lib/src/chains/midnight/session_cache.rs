//! In-process cache for Midnight sync results within a single CLI / library session.
//!
//! Avoids repeated indexer WebSocket replays when balance and sign run back-to-back.
//! Cleared after each successful Midnight submit once the indexer reflects the transaction.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::cache_io::SyncCacheScope;
use super::unshielded_sync::UnshieldedUtxo;
use super::ShieldedBalances;

const SESSION_TTL: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SessionKind {
    Unshielded,
    Shielded,
    Dust,
    DustLedgerState,
}

type SessionMap = HashMap<String, (Instant, Box<dyn Any + Send + Sync>)>;

static CACHE: Mutex<Option<HashMap<SessionKind, SessionMap>>> = Mutex::new(None);

fn session_key(scope: &SyncCacheScope, indexer_fp: &str, kind: SessionKind, key: &str) -> String {
    let kind_tag = match kind {
        SessionKind::Unshielded => "unshielded",
        SessionKind::Shielded => "shielded",
        SessionKind::Dust => "dust",
        SessionKind::DustLedgerState => "dust_ledger_state",
    };
    let chain_tag = scope.chain_id.as_deref().unwrap_or("").to_ascii_lowercase();
    format!(
        "{}|{chain_tag}|{indexer_fp}|{kind_tag}|{key}",
        scope.wallet_id.as_deref().unwrap_or("")
    )
}

fn get<T: Clone + Send + Sync + 'static>(
    kind: SessionKind,
    scope: &SyncCacheScope,
    indexer_fp: &str,
    key: &str,
) -> Option<T> {
    let cache_key = session_key(scope, indexer_fp, kind, key);
    let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.as_ref()?.get(&kind)?;
    let (at, value) = map.get(&cache_key)?;
    if at.elapsed() <= SESSION_TTL {
        value.downcast_ref::<T>().cloned()
    } else {
        None
    }
}

fn put<T: Clone + Send + Sync + 'static>(
    kind: SessionKind,
    scope: &SyncCacheScope,
    indexer_fp: &str,
    key: &str,
    value: T,
) {
    let cache_key = session_key(scope, indexer_fp, kind, key);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let by_kind = guard.get_or_insert_with(HashMap::new);
    let map = by_kind.entry(kind).or_default();
    map.insert(cache_key, (Instant::now(), Box::new(value)));
}

pub(super) fn get_unshielded(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    address: &str,
) -> Option<Vec<UnshieldedUtxo>> {
    get(SessionKind::Unshielded, scope, indexer_fp, address)
}

pub(super) fn put_unshielded(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    address: &str,
    utxos: Vec<UnshieldedUtxo>,
) {
    put(SessionKind::Unshielded, scope, indexer_fp, address, utxos);
}

pub(super) fn get_shielded(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    vk_fingerprint: &str,
) -> Option<ShieldedBalances> {
    get(SessionKind::Shielded, scope, indexer_fp, vk_fingerprint)
}

pub(super) fn put_shielded(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    vk_fingerprint: &str,
    balances: ShieldedBalances,
) {
    put(
        SessionKind::Shielded,
        scope,
        indexer_fp,
        vk_fingerprint,
        balances,
    );
}

pub(super) fn get_dust(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    dust_pk_hex: &str,
) -> Option<(usize, u128)> {
    get(SessionKind::Dust, scope, indexer_fp, dust_pk_hex)
}

pub(super) fn put_dust(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    dust_pk_hex: &str,
    balance: (usize, u128),
) {
    put(SessionKind::Dust, scope, indexer_fp, dust_pk_hex, balance);
}

pub(super) fn get_dust_ledger_state_hex(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    dust_pk_hex: &str,
) -> Option<String> {
    get(SessionKind::DustLedgerState, scope, indexer_fp, dust_pk_hex)
}

pub(super) fn put_dust_ledger_state_hex(
    scope: &SyncCacheScope,
    indexer_fp: &str,
    dust_pk_hex: &str,
    state_hex: String,
) {
    put(
        SessionKind::DustLedgerState,
        scope,
        indexer_fp,
        dust_pk_hex,
        state_hex,
    );
}

fn site_prefix(scope: &SyncCacheScope, indexer_fp: &str) -> String {
    let chain_tag = scope.chain_id.as_deref().unwrap_or("").to_ascii_lowercase();
    format!(
        "{}|{chain_tag}|{indexer_fp}|",
        scope.wallet_id.as_deref().unwrap_or("")
    )
}

/// Drop all in-process sync caches for a wallet/indexer/chain site (e.g. after submit).
pub(super) fn invalidate_site(scope: &SyncCacheScope, indexer_fp: &str) {
    let prefix = site_prefix(scope, indexer_fp);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(by_kind) = guard.as_mut() else {
        return;
    };
    for map in by_kind.values_mut() {
        map.retain(|k, _| !k.starts_with(prefix.as_str()));
    }
}
