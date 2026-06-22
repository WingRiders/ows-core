//! Shielded (Zswap) balance sync orchestration.

use std::collections::BTreeMap;

use super::error::{PayError, PayErrorCode};

use super::cache_io::{self, SyncCacheScope, SyncPurpose};
use super::midnight_env::{self, MidnightNetwork};
use super::session_cache;
use super::shielded_session::{self, get_shielded_balances_inner, SHIELDED_SYNC_TIMEOUT};
use super::shielded_sync_cache;
use super::zswap_ledger_sync;
use super::ShieldedBalances;

pub use shielded_session::{sync_shielded_wallet_state_scoped, ShieldedWalletState};

/// Shielded balances split by indexer source (for honest `ows fund balance` display).
#[derive(Debug, Clone, Default)]
pub struct ShieldedDisplayBalances {
    /// Coins visible via `connect(viewingKey)` + `shieldedTransactions` (spendable path).
    pub spendable: ShieldedBalances,
    /// Extra amounts only visible via full `zswapLedgerEvents` replay (may not be spendable).
    pub zswap_only: ShieldedBalances,
}

/// Fetch shielded token balances for a wallet from the indexer (wallet/vault-scoped caches).
pub async fn get_shielded_balances_scoped(
    indexer_url: &str,
    shielded_seed_32: &[u8],
    scope: &SyncCacheScope,
) -> Result<ShieldedBalances, PayError> {
    Ok(
        get_shielded_balances_for_display_scoped(indexer_url, shielded_seed_32, scope)
            .await?
            .spendable,
    )
}

/// Shielded balances for `ows fund balance` — always resumes from disk then catches up on the indexer.
pub async fn get_shielded_balances_for_display_scoped(
    indexer_url: &str,
    shielded_seed_32: &[u8],
    scope: &SyncCacheScope,
) -> Result<ShieldedDisplayBalances, PayError> {
    get_shielded_balances_impl(indexer_url, shielded_seed_32, scope, SyncPurpose::Display).await
}

async fn get_shielded_balances_impl(
    indexer_url: &str,
    shielded_seed_32: &[u8],
    scope: &SyncCacheScope,
    purpose: SyncPurpose,
) -> Result<ShieldedDisplayBalances, PayError> {
    let keys = shielded_session::zswap_secret_keys_from_seed(shielded_seed_32)?;
    let seed_fp = shielded_sync_cache::shielded_seed_fingerprint(shielded_seed_32);
    let zswap_cache_key = shielded_sync_cache::zswap_cache_key(&seed_fp);
    let session_enabled = midnight_env::shielded_indexer_session_enabled();
    let (viewing_key_candidates, vk_fp) = if session_enabled {
        let candidates =
            shielded_session::viewing_key_candidates_from_secret_keys(indexer_url, &keys)?;
        let fp = candidates
            .first()
            .map(|vk| shielded_sync_cache::viewing_key_fingerprint(vk))
            .unwrap_or_default();
        (candidates, fp)
    } else {
        (Vec::new(), String::new())
    };
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let network = MidnightNetwork::from_indexer_url(indexer_url);
    let zswap_fallback = midnight_env::shielded_zswap_fallback_enabled(network);

    if session_cache::session_cache_shortcut_allowed(purpose) {
        if let Some(cached) = session_cache::get_shielded(scope, &fp, &zswap_cache_key) {
            if zswap_fallback {
                return Ok(ShieldedDisplayBalances {
                    spendable: cached.clone(),
                    zswap_only: BTreeMap::new(),
                });
            }
        }
        if let Some(cached) = session_cache::get_shielded(scope, &fp, &vk_fp) {
            return Ok(ShieldedDisplayBalances {
                spendable: cached,
                zswap_only: BTreeMap::new(),
            });
        }
    }

    let zswap_fut = zswap_ledger_sync::get_shielded_balances_from_zswap_ledger_events_scoped(
        indexer_url,
        &keys,
        scope,
        &seed_fp,
        purpose,
    );
    let zswap_balances = if zswap_fallback {
        if purpose.is_display() {
            zswap_fut.await?
        } else {
            tokio::time::timeout(SHIELDED_SYNC_TIMEOUT, zswap_fut)
                .await
                .map_err(|_| {
                    PayError::new(
                        PayErrorCode::HttpTransport,
                        format!(
                            "Midnight indexer zswap ledger event replay timed out after {}s",
                            SHIELDED_SYNC_TIMEOUT.as_secs()
                        ),
                    )
                })??
        }
    } else {
        std::collections::BTreeMap::new()
    };

    let mut spendable = std::collections::BTreeMap::new();
    if session_enabled {
        let session_fut =
            get_shielded_balances_inner(indexer_url, &keys, &viewing_key_candidates, scope, &vk_fp);
        spendable = if purpose.is_display() {
            session_fut.await?
        } else {
            tokio::time::timeout(SHIELDED_SYNC_TIMEOUT, session_fut)
                .await
                .map_err(|_| {
                    PayError::new(
                        PayErrorCode::HttpTransport,
                        format!(
                            "Midnight indexer shielded sync timed out after {}s",
                            SHIELDED_SYNC_TIMEOUT.as_secs()
                        ),
                    )
                })??
        };
    }

    let zswap_only = zswap_only_delta(&zswap_balances, &spendable);
    let report = ShieldedDisplayBalances {
        spendable: spendable.clone(),
        zswap_only,
    };

    if zswap_fallback {
        session_cache::put_shielded(scope, &fp, &zswap_cache_key, spendable);
    } else {
        session_cache::put_shielded(scope, &fp, &vk_fp, report.spendable.clone());
    }
    Ok(report)
}

/// Per-token surplus in zswap-ledger balances over viewing-key session balances.
fn zswap_only_delta(zswap: &ShieldedBalances, session: &ShieldedBalances) -> ShieldedBalances {
    let mut out = ShieldedBalances::new();
    for (token, z_amt) in zswap {
        let s_amt = session.get(token).copied().unwrap_or(0);
        if *z_amt > s_amt {
            out.insert(token.clone(), z_amt.saturating_sub(s_amt));
        }
    }
    out
}
