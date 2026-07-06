//! After a successful node submit, wait for the indexer to reflect the transaction
//! and refresh on-disk sync snapshots (unshielded, shielded zswap wallet, dust).

use std::ops::Deref as _;
use std::time::{Duration, Instant};

use super::cache_io::{self, SyncCacheScope, SyncPurpose};
use super::dust_sync;
use super::error::{PayError, PayErrorCode};
use super::ledger_params;
use super::midnight_env::{midnight_sync_log_enabled, post_submit_indexer_wait_timeout};
use super::session_cache;
use super::shielded_session;
use super::shielded_sync_cache;
use super::unshielded_sync;
use super::zswap_ledger_sync;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_ledger::dust::DustActions;
use midnight_ledger::structure::{ProofKind, ProofMarker, Transaction, UnshieldedOffer};
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;

type SealedTx = midnight_ledger::structure::Transaction<
    midnight_base_crypto::signatures::Signature,
    ProofMarker,
    <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
    InMemoryDB,
>;

/// Which indexer sync streams must reflect a submitted transaction before the next sign.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PostSubmitSyncPlan {
    pub needs_unshielded: bool,
    pub needs_zswap: bool,
    pub needs_dust: bool,
    /// True when the submitted tx included DUST spends (not registration-only).
    pub needs_dust_spends_in_tx: bool,
}

fn normalize_ledger_tx_hash(h: &str) -> String {
    let bare = h.strip_prefix("0x").unwrap_or(h).to_ascii_lowercase();
    format!("0x{bare}")
}

fn unshielded_offer_active(offer: &UnshieldedOffer<MnSig, InMemoryDB>) -> bool {
    offer.inputs.iter_deref().count() > 0 || offer.outputs.iter_deref().count() > 0
}

fn dust_actions_active<P: ProofKind<InMemoryDB>>(dust: &DustActions<MnSig, P, InMemoryDB>) -> bool {
    dust.spends.iter_deref().count() > 0 || dust.registrations.iter_deref().count() > 0
}

/// Classify which sync streams a sealed transaction touches.
pub(super) fn plan_from_sealed_tx(sealed_bytes: &[u8]) -> PostSubmitSyncPlan {
    let mut plan = PostSubmitSyncPlan::default();
    let mut reader: &[u8] = sealed_bytes;
    let Ok(tx) = tagged_deserialize::<SealedTx>(&mut reader) else {
        return PostSubmitSyncPlan {
            needs_unshielded: true,
            needs_zswap: true,
            needs_dust: true,
            needs_dust_spends_in_tx: false,
        };
    };
    let Transaction::Standard(stx) = tx else {
        return plan;
    };

    if let Some(offer) = stx.guaranteed_coins.as_ref() {
        let offer = offer.deref();
        if !offer.inputs.is_empty() || !offer.outputs.is_empty() {
            plan.needs_zswap = true;
        }
    }
    for offer in stx.fallible_coins.values() {
        if !offer.inputs.is_empty() || !offer.outputs.is_empty() {
            plan.needs_zswap = true;
        }
    }
    for pair in stx.intents.iter() {
        let (_, intent_sp) = pair.deref();
        let intent = intent_sp.deref();
        if let Some(offer) = intent.guaranteed_unshielded_offer.as_ref() {
            if unshielded_offer_active(offer.deref()) {
                plan.needs_unshielded = true;
            }
        }
        if let Some(fallible) = intent.fallible_unshielded_offer.as_ref() {
            if unshielded_offer_active(fallible.deref()) {
                plan.needs_unshielded = true;
            }
        }
        if let Some(dust) = intent.dust_actions.as_ref() {
            let dust = dust.deref();
            if dust_actions_active(dust) {
                plan.needs_dust = true;
            }
            if dust.spends.iter_deref().count() > 0 {
                plan.needs_dust_spends_in_tx = true;
            }
        }
    }
    plan
}

fn post_submit_timeout_error(
    wait_timeout: Duration,
    target: &str,
    blocker: Option<String>,
) -> PayError {
    let detail = blocker
        .unwrap_or_else(|| "indexer did not reflect the submitted transaction in time".to_string());
    PayError::new(
        PayErrorCode::HttpTransport,
        format!(
            "post-submit sync timed out after {}s for tx {target}: {detail}. \
             The transaction was already accepted by the node; run `ows fund balance` or retry \
             after the indexer catches up. Increase OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS \
             if the indexer is slow.",
            wait_timeout.as_secs()
        ),
    )
}

/// Poll until the indexer and on-disk snapshots reflect `ledger_tx_hash`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn ensure_submitted_tx_reflected(
    indexer_url: &str,
    scope: &SyncCacheScope,
    ledger_tx_hash: &str,
    plan: PostSubmitSyncPlan,
    unshielded_address: Option<&str>,
    shielded_seed: Option<&[u8; 32]>,
    dust_seed: Option<&[u8; 32]>,
    wait_timeout: Duration,
) -> Result<(), PayError> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let sync_dust_after_submit = dust_seed.is_some() || plan.needs_dust;
    let target = normalize_ledger_tx_hash(ledger_tx_hash);
    let log = midnight_sync_log_enabled();

    let mut scope = scope.clone();
    let mut last_blocker: Option<String> = None;

    if log {
        eprintln!(
            "[ows-midnight] post-submit: waiting for indexer to reflect tx {target} \
(unshielded={} zswap={} dust={} dust_always={}; up to {}s)…",
            plan.needs_unshielded,
            plan.needs_zswap,
            plan.needs_dust,
            sync_dust_after_submit,
            wait_timeout.as_secs(),
        );
    }

    let deadline = Instant::now() + wait_timeout;
    while Instant::now() < deadline {
        session_cache::invalidate_site(&scope, &fp);
        last_blocker = None;

        let tx_summary =
            match ledger_params::fetch_indexer_transaction_by_hash(indexer_url, &target).await {
                Ok(Some(summary)) => summary,
                Ok(None) => {
                    last_blocker = Some(format!("tx {target} not in indexer HTTP API yet"));
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: {}; retrying…",
                            last_blocker.as_deref().unwrap_or("")
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Err(e) => {
                    last_blocker = Some(format!("indexer tx query failed: {e}"));
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: {}; retrying…",
                            last_blocker.as_deref().unwrap_or("")
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        if let Ok(height) = ledger_params::fetch_indexer_block_height(indexer_url).await {
            scope.indexer_block_height = Some(height);
        }

        let mut ready = true;

        if plan.needs_unshielded {
            if let Some(addr) = unshielded_address {
                match unshielded_sync::unshielded_tx_visible_in_indexer(
                    indexer_url,
                    addr,
                    &scope,
                    &target,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        ready = false;
                        last_blocker = Some(format!("tx {target} not in unshielded stream yet"));
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: {}; retrying…",
                                last_blocker.as_deref().unwrap_or("")
                            );
                        }
                    }
                    Err(e) => {
                        ready = false;
                        last_blocker = Some(format!("unshielded refresh failed: {e}"));
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: {}; retrying…",
                                last_blocker.as_deref().unwrap_or("")
                            );
                        }
                    }
                }
            }
        }

        if plan.needs_zswap {
            match shielded_seed {
                None => {
                    ready = false;
                    last_blocker = Some(
                        "tx uses shielded zswap but no shielded seed; cannot refresh spend wallet"
                            .to_string(),
                    );
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: {}; retrying…",
                            last_blocker.as_deref().unwrap_or("")
                        );
                    }
                }
                Some(_) if tx_summary.zswap_ledger_event_count == 0 => {
                    ready = false;
                    last_blocker = Some(format!("tx {target} indexed but zswapLedgerEvents empty"));
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: {}; retrying…",
                            last_blocker.as_deref().unwrap_or("")
                        );
                    }
                }
                Some(seed) => {
                    let keys = shielded_session::zswap_secret_keys_from_seed(seed)?;
                    let seed_fp = shielded_sync_cache::shielded_seed_fingerprint(seed);
                    match zswap_ledger_sync::sync_shielded_wallet_from_zswap_ledger_scoped(
                        indexer_url,
                        &keys,
                        &scope,
                        &seed_fp,
                        SyncPurpose::Signing,
                    )
                    .await
                    {
                        Ok(mut wallet) => {
                            if let Err(e) =
                                shielded_session::ensure_shielded_merkle_ready(&mut wallet)
                            {
                                ready = false;
                                last_blocker = Some(format!("shielded merkle not ready: {e}"));
                                if log {
                                    eprintln!(
                                        "[ows-midnight] post-submit: {}; retrying…",
                                        last_blocker.as_deref().unwrap_or("")
                                    );
                                }
                            }

                            let cursor = zswap_ledger_sync::snapshot_last_seen_zswap_event_id(
                                indexer_url,
                                &scope,
                                &seed_fp,
                            );
                            if let Some(required) = tx_summary.max_zswap_ledger_event_id {
                                if cursor.is_none_or(|c| c < required) {
                                    ready = false;
                                    last_blocker = Some(format!(
                                        "zswap snapshot cursor {cursor:?} has not reached \
                                         submitted tx event id {required}"
                                    ));
                                    if log {
                                        eprintln!(
                                            "[ows-midnight] post-submit: {}; retrying…",
                                            last_blocker.as_deref().unwrap_or("")
                                        );
                                    }
                                }
                            }
                            if ready && log {
                                eprintln!(
                                    "[ows-midnight] post-submit: shielded wallet snapshot refreshed \
({} spendable coins)",
                                    wallet.zswap.coins.iter().count()
                                );
                            }
                        }
                        Err(e) => {
                            ready = false;
                            last_blocker = Some(format!("zswap wallet refresh failed: {e}"));
                            if log {
                                eprintln!(
                                    "[ows-midnight] post-submit: {}; retrying…",
                                    last_blocker.as_deref().unwrap_or("")
                                );
                            }
                        }
                    }
                }
            }
        }

        if sync_dust_after_submit {
            match dust_seed {
                None => {
                    if plan.needs_dust {
                        ready = false;
                        last_blocker = Some(
                            "no dust seed; cannot refresh dust ledger after submit".to_string(),
                        );
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: {}; retrying…",
                                last_blocker.as_deref().unwrap_or("")
                            );
                        }
                    }
                }
                Some(seed) => {
                    let waiting_for_indexed_dust = (plan.needs_dust
                        || tx_summary.dust_ledger_event_count > 0)
                        && tx_summary.dust_ledger_event_count == 0;
                    if waiting_for_indexed_dust {
                        ready = false;
                        last_blocker = Some(format!(
                            "tx {target} indexed but dustLedgerEvents empty (expected dust ledger events)"
                        ));
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: {}; retrying…",
                                last_blocker.as_deref().unwrap_or("")
                            );
                        }
                    } else {
                        let dsk = midnight_ledger::dust::DustSecretKey::derive_secret_key(seed);
                        let dust_opts = dust_sync::DustSyncOptions {
                            min_required_event_id: tx_summary.max_dust_ledger_event_id,
                            ..Default::default()
                        };
                        match dust_sync::sync_dust_local_state_scoped_with_options(
                            indexer_url,
                            &dsk,
                            &scope,
                            dust_opts,
                        )
                        .await
                        {
                            Ok(_) => {
                                let cursor = dust_sync::snapshot_last_seen_dust_event_id_for_key(
                                    indexer_url,
                                    &scope,
                                    &dsk,
                                )?;
                                if let Some(required) = tx_summary.max_dust_ledger_event_id {
                                    if cursor.is_none_or(|c| c < required) {
                                        ready = false;
                                        last_blocker = Some(format!(
                                            "dust snapshot cursor {cursor:?} has not reached \
                                             submitted tx event id {required}"
                                        ));
                                        if log {
                                            eprintln!(
                                                "[ows-midnight] post-submit: {}; retrying…",
                                                last_blocker.as_deref().unwrap_or("")
                                            );
                                        }
                                    }
                                } else if plan.needs_dust {
                                    ready = false;
                                    last_blocker = Some(format!(
                                        "tx {target} has dust actions but no max dust event id"
                                    ));
                                    if log {
                                        eprintln!(
                                            "[ows-midnight] post-submit: {}; retrying…",
                                            last_blocker.as_deref().unwrap_or("")
                                        );
                                    }
                                }
                                if ready && log {
                                    eprintln!(
                                        "[ows-midnight] post-submit: dust ledger snapshot refreshed \
(cursor={cursor:?})"
                                    );
                                }
                            }
                            Err(e) => {
                                ready = false;
                                last_blocker = Some(format!("dust refresh failed: {e}"));
                                if log {
                                    eprintln!(
                                        "[ows-midnight] post-submit: {}; retrying…",
                                        last_blocker.as_deref().unwrap_or("")
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        if ready {
            if log {
                eprintln!(
                    "[ows-midnight] post-submit: indexer and local snapshots caught up for tx {target}"
                );
            }
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    Err(post_submit_timeout_error(
        wait_timeout,
        &normalize_ledger_tx_hash(ledger_tx_hash),
        last_blocker,
    ))
}

/// Wait for the indexer to index `ledger_tx_hash`, refresh local snapshots, then return.
///
/// Post-submit indexer sync must finish before `sign send-tx` returns; timeout is an error so
/// the next sign does not build DUST spends from stale ledger state (tx may already be on-chain).
/// Session cache is always cleared; disk snapshots are updated when sync succeeds.
#[allow(clippy::too_many_arguments)]
pub async fn refresh_after_submit(
    indexer_url: &str,
    scope: &SyncCacheScope,
    ledger_tx_hash: &str,
    sealed_bytes: &[u8],
    unshielded_address: Option<&str>,
    shielded_seed: Option<&[u8; 32]>,
    dust_seed: Option<&[u8; 32]>,
) -> Result<(), PayError> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    session_cache::invalidate_site(scope, &fp);

    let wait_timeout = post_submit_indexer_wait_timeout();
    if wait_timeout.as_secs() == 0 {
        return Ok(());
    }

    let plan = plan_from_sealed_tx(sealed_bytes);
    ensure_submitted_tx_reflected(
        indexer_url,
        scope,
        ledger_tx_hash,
        plan,
        unshielded_address,
        shielded_seed,
        dust_seed,
        wait_timeout,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_requests_all_streams() {
        let plan = plan_from_sealed_tx(b"not-a-tx");
        assert!(plan.needs_unshielded);
        assert!(plan.needs_zswap);
        assert!(plan.needs_dust);
        assert!(!plan.needs_dust_spends_in_tx);
    }
}
