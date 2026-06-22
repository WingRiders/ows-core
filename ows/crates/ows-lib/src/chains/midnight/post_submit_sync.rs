//! After a successful node submit, wait for the indexer to reflect the transaction
//! and refresh on-disk sync snapshots (unshielded, shielded zswap wallet, dust).

use std::ops::Deref as _;
use std::time::{Duration, Instant};

use super::cache_io::{self, SyncCacheScope, SyncPurpose};
use super::dust_sync;
use super::error::PayError;
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
            if dust_actions_active(dust.deref()) {
                plan.needs_dust = true;
            }
        }
    }
    plan
}

/// Wait for the indexer to index `ledger_tx_hash`, refresh local snapshots, then return.
///
/// Best-effort on timeout (same as [`unshielded_sync::refresh_unshielded_after_submit`]):
/// session cache is always cleared; disk snapshots are updated when sync succeeds.
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
    let target = normalize_ledger_tx_hash(ledger_tx_hash);
    let log = midnight_sync_log_enabled();

    let mut scope = scope.clone();

    if log {
        eprintln!(
            "[ows-midnight] post-submit: waiting for indexer to reflect tx {target} \
(unshielded={} zswap={} dust={}; up to {}s)…",
            plan.needs_unshielded,
            plan.needs_zswap,
            plan.needs_dust,
            wait_timeout.as_secs()
        );
    }

    let deadline = Instant::now() + wait_timeout;
    while Instant::now() < deadline {
        session_cache::invalidate_site(&scope, &fp);

        let tx_summary = match ledger_params::fetch_indexer_transaction_by_hash(
            indexer_url,
            &target,
        )
        .await
        {
            Ok(Some(summary)) => summary,
            Ok(None) => {
                if log {
                    eprintln!(
                        "[ows-midnight] post-submit: tx {target} not in indexer HTTP API yet; retrying…"
                    );
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(e) => {
                if log {
                    eprintln!(
                        "[ows-midnight] post-submit: indexer tx query failed ({e}); retrying…"
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
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: tx {target} not in unshielded stream yet; retrying…"
                            );
                        }
                    }
                    Err(e) => {
                        ready = false;
                        if log {
                            eprintln!(
                                "[ows-midnight] post-submit: unshielded refresh failed ({e}); retrying…"
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
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: tx uses shielded zswap but no shielded seed; \
cannot refresh spend wallet"
                        );
                    }
                }
                Some(_) if tx_summary.zswap_ledger_event_count == 0 => {
                    ready = false;
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: tx {target} indexed but zswapLedgerEvents empty; retrying…"
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
                                if log {
                                    eprintln!(
                                        "[ows-midnight] post-submit: shielded merkle not ready ({e}); retrying…"
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
                                    if log {
                                        eprintln!(
                                            "[ows-midnight] post-submit: zswap snapshot cursor \
{cursor:?} has not reached submitted tx event id {required}; retrying…"
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
                            if log {
                                eprintln!(
                                    "[ows-midnight] post-submit: zswap wallet refresh failed ({e}); retrying…"
                                );
                            }
                        }
                    }
                }
            }
        }

        if plan.needs_dust {
            match dust_seed {
                None => {
                    ready = false;
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: tx uses dust but no dust seed; cannot refresh dust ledger"
                        );
                    }
                }
                Some(_) if tx_summary.dust_ledger_event_count == 0 => {
                    ready = false;
                    if log {
                        eprintln!(
                            "[ows-midnight] post-submit: tx {target} indexed but dustLedgerEvents empty; retrying…"
                        );
                    }
                }
                Some(seed) => {
                    let dsk = midnight_ledger::dust::DustSecretKey::derive_secret_key(seed);
                    match dust_sync::sync_dust_local_state_scoped(indexer_url, &dsk, &scope).await {
                        Ok(_) => {
                            let cursor = dust_sync::snapshot_last_seen_dust_event_id_for_key(
                                indexer_url,
                                &scope,
                                &dsk,
                            )?;
                            if let Some(required) = tx_summary.max_dust_ledger_event_id {
                                if cursor.is_none_or(|c| c < required) {
                                    ready = false;
                                    if log {
                                        eprintln!(
                                            "[ows-midnight] post-submit: dust snapshot cursor \
{cursor:?} has not reached submitted tx event id {required}; retrying…"
                                        );
                                    }
                                }
                            }
                            if ready && log {
                                eprintln!(
                                    "[ows-midnight] post-submit: dust ledger snapshot refreshed"
                                );
                            }
                        }
                        Err(e) => {
                            ready = false;
                            if log {
                                eprintln!(
                                    "[ows-midnight] post-submit: dust refresh failed ({e}); retrying…"
                                );
                            }
                        }
                    }
                }
            }
        }

        if ready {
            if log {
                eprintln!("[ows-midnight] post-submit: indexer and local snapshots caught up for tx {target}");
            }
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    if log {
        eprintln!(
            "[ows-midnight] post-submit: timed out after {}s waiting for indexer tx {target} \
(set OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS to increase)",
            wait_timeout.as_secs()
        );
    }
    Ok(())
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
    }
}
