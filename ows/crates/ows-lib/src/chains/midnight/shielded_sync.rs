//! Shielded (Zswap) balance sync orchestration.
//!
//! Primary path matches `@midnight-ntwrk/wallet-sdk-shielded`: subscribe to
//! `zswapLedgerEvents`, replay into `ZswapLocalState`, derive balances from local coins.
//! Optional `connect(viewingKey)` + `shieldedTransactions` is behind
//! `OWS_MIDNIGHT_SHIELDED_SESSION_SYNC=1` for comparison only.

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
    /// Spendable coins from `zswapLedgerEvents` replay (midnight-wallet-sdk / Lace path).
    pub spendable: ShieldedBalances,
    /// Extra amounts only visible via optional viewing-key session sync (diagnostic).
    pub session_only: ShieldedBalances,
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
    let session_sync = midnight_env::shielded_indexer_session_sync_enabled();
    let (viewing_key, vk_fp) = if session_sync {
        let vk = shielded_session::viewing_key_from_secret_keys(
            indexer_url,
            scope.chain_id.as_deref(),
            &keys,
        )?;
        let fp = shielded_sync_cache::viewing_key_fingerprint(&vk);
        (Some(vk), fp)
    } else {
        (None, String::new())
    };
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let network = MidnightNetwork::resolve(scope.chain_id.as_deref(), indexer_url)
        .map_err(|e| PayError::new(PayErrorCode::InvalidInput, e))?;
    let zswap_sync = midnight_env::shielded_zswap_ledger_sync_enabled(&network);

    if session_cache::session_cache_shortcut_allowed(purpose) {
        if let Some(cached) = session_cache::get_shielded(scope, &fp, &zswap_cache_key) {
            if zswap_sync {
                return Ok(ShieldedDisplayBalances {
                    spendable: cached,
                    session_only: BTreeMap::new(),
                });
            }
        }
        if session_sync {
            if let Some(cached) = session_cache::get_shielded(scope, &fp, &vk_fp) {
                return Ok(ShieldedDisplayBalances {
                    spendable: BTreeMap::new(),
                    session_only: cached,
                });
            }
        }
    }

    let zswap_fut = zswap_ledger_sync::get_shielded_balances_from_zswap_ledger_events_scoped(
        indexer_url,
        &keys,
        scope,
        &seed_fp,
        purpose,
    );
    let spendable = if zswap_sync {
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
        BTreeMap::new()
    };

    let mut session_balances = BTreeMap::new();
    if let Some(vk) = viewing_key.as_ref() {
        let session_fut = get_shielded_balances_inner(indexer_url, &keys, vk, scope);
        session_balances = tokio::time::timeout(SHIELDED_SYNC_TIMEOUT, session_fut)
            .await
            .map_err(|_| {
                PayError::new(
                    PayErrorCode::HttpTransport,
                    format!(
                        "Midnight indexer shielded session sync timed out after {}s",
                        SHIELDED_SYNC_TIMEOUT.as_secs()
                    ),
                )
            })??;
    }

    let session_only = session_only_delta(&session_balances, &spendable);
    let report = ShieldedDisplayBalances {
        spendable: spendable.clone(),
        session_only,
    };

    if zswap_sync {
        session_cache::put_shielded(scope, &fp, &zswap_cache_key, spendable);
    }
    if session_sync {
        session_cache::put_shielded(scope, &fp, &vk_fp, session_balances);
    }
    Ok(report)
}

/// Per-token surplus in optional session balances over zswap-ledger balances.
fn session_only_delta(session: &ShieldedBalances, zswap: &ShieldedBalances) -> ShieldedBalances {
    let mut out = ShieldedBalances::new();
    for (token, s_amt) in session {
        let z_amt = zswap.get(token).copied().unwrap_or(0);
        if *s_amt > z_amt {
            out.insert(token.clone(), s_amt.saturating_sub(z_amt));
        }
    }
    out
}
