//! Full `zswapLedgerEvents` replay fallback for shielded balance sync.

use super::error::{PayError, PayErrorCode};
use midnight_coin_structure::coin::{self, QualifiedInfo as QualifiedCoinInfo};
use midnight_coin_structure::transfer;
use midnight_ledger::events::{Event, EventDetails};
use midnight_ledger::semantics::ZswapLocalStateExt;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use midnight_zswap::keys::SecretKeys as ZswapSecretKeys;
use midnight_zswap::local::State as ZswapLocalState;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::cache_io::{self, SyncCacheScope, SyncPurpose};
use super::indexer_ws::{self, IndexerWs};
use super::midnight_env::{self, SyncStream};
use super::shielded_sync_cache;
use super::ShieldedBalances;

const ZSWAP_LEDGER_SUB: &str = r#"
subscription ZswapLedgerEvents($id: Int) {
  zswapLedgerEvents(id: $id) { id raw maxId protocolVersion }
}
"#;

/// Short WebSocket idle when resuming incrementally from a complete on-disk snapshot.
///
/// Never use `id: null` (genesis re-stream). Display uses a ~3s idle; signing uses full stall.
fn zswap_short_idle_verify(purpose: SyncPurpose, snapshot_at_saved_tip: bool) -> bool {
    snapshot_at_saved_tip && !purpose.must_catch_up_to_indexer_tip()
}

fn zswap_wallet_feed_enabled(
    purpose: SyncPurpose,
    wallet_sync_ready: bool,
    short_idle_verify: bool,
) -> bool {
    wallet_sync_ready && (purpose.must_catch_up_to_indexer_tip() || !short_idle_verify)
}

/// `last_seen_zswap_event_id` from the on-disk snapshot when site keys match.
pub(super) fn snapshot_last_seen_zswap_event_id(
    indexer_url: &str,
    scope: &SyncCacheScope,
    seed_fp: &str,
) -> Option<i64> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let zswap_cache_key = shielded_sync_cache::zswap_cache_key(seed_fp);
    let path = shielded_sync_cache::snapshot_path(indexer_url, &zswap_cache_key, scope)?;
    let snap = shielded_sync_cache::try_load_snapshot(&path)?;
    if snap.indexer_fingerprint != fp
        || !cache_io::snapshot_chain_matches(scope, &snap.chain_id)
        || snap.viewing_key_fingerprint != zswap_cache_key
    {
        return None;
    }
    Some(snap.last_seen_zswap_event_id)
}

pub(super) fn balances_from_owned_coins(
    owned: &BTreeMap<coin::Nullifier, coin::Info>,
) -> ShieldedBalances {
    let mut balances: ShieldedBalances = BTreeMap::new();
    for ci in owned.values() {
        *balances
            .entry(super::shielded_session::token_type_hex(ci))
            .or_insert(0) += ci.value;
    }
    balances
}

pub(super) struct ZswapLedgerReplayState {
    pub owned: BTreeMap<coin::Nullifier, coin::Info>,
}

pub(super) async fn get_shielded_balances_from_zswap_ledger_events_scoped(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    scope: &SyncCacheScope,
    seed_fp: &str,
    purpose: SyncPurpose,
) -> Result<ShieldedBalances, PayError> {
    let state = zswap_ledger_replay_scoped(indexer_url, keys, scope, seed_fp, purpose).await?;
    Ok(balances_from_owned_coins(&state.owned))
}

/// Spendable shielded wallet from full `zswapLedgerEvents` replay (correct Merkle tree + coins).
pub(super) async fn sync_shielded_wallet_from_zswap_ledger_scoped(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    scope: &SyncCacheScope,
    seed_fp: &str,
    purpose: SyncPurpose,
) -> Result<super::shielded_session::ShieldedWalletState, PayError> {
    let zswap =
        zswap_ledger_replay_wallet_scoped(indexer_url, keys, scope, seed_fp, purpose).await?;
    Ok(super::shielded_session::ShieldedWalletState {
        keys: keys.clone(),
        zswap,
    })
}

enum ZswapReplayTarget<'a> {
    Balance {
        owned: &'a mut BTreeMap<coin::Nullifier, coin::Info>,
        qualified: &'a mut BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
    },
}

fn apply_zswap_ledger_event_balance(
    owned: &mut BTreeMap<coin::Nullifier, coin::Info>,
    qualified: &mut BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
    keys: &ZswapSecretKeys,
    ev: &Event<InMemoryDB>,
    n_outputs_decrypted: &mut u64,
) {
    match &ev.content {
        EventDetails::ZswapOutput {
            preimage_evidence,
            mt_index,
            ..
        } => {
            if let Some(ci) = preimage_evidence.try_with_keys(keys) {
                *n_outputs_decrypted = n_outputs_decrypted.saturating_add(1);
                let nul = ci.nullifier(&transfer::SenderEvidence::User(
                    std::borrow::Cow::Borrowed(&keys.coin_secret_key),
                ));
                let qci = ci.qualify(*mt_index);
                owned.insert(nul, ci);
                qualified.insert(nul, qci);
            }
        }
        EventDetails::ZswapInput { nullifier, .. } => {
            owned.remove(nullifier);
            qualified.remove(nullifier);
        }
        _ => {}
    }
}

fn apply_zswap_ledger_event_wallet(
    zswap: &mut ZswapLocalState<InMemoryDB>,
    keys: &ZswapSecretKeys,
    ev: &Event<InMemoryDB>,
    n_outputs_decrypted: &mut u64,
) -> Result<(), PayError> {
    let coins_before = zswap.coins.iter().count();
    let prev = std::mem::replace(zswap, ZswapLocalState::new());
    *zswap = prev.replay_events(keys, std::iter::once(ev)).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("zswap ledger event replay failed: {e}"),
        )
    })?;
    let coins_after = zswap.coins.iter().count();
    if coins_after > coins_before {
        *n_outputs_decrypted = n_outputs_decrypted.saturating_add(1);
    }
    Ok(())
}

async fn zswap_ledger_replay_scoped(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    scope: &SyncCacheScope,
    seed_fp: &str,
    purpose: SyncPurpose,
) -> Result<ZswapLedgerReplayState, PayError> {
    let log = midnight_env::midnight_sync_log_enabled();
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let zswap_cache_key = shielded_sync_cache::zswap_cache_key(seed_fp);
    let cache_path = shielded_sync_cache::snapshot_path(indexer_url, &zswap_cache_key, scope);

    let mut owned: BTreeMap<coin::Nullifier, coin::Info> = BTreeMap::new();
    let mut qualified: BTreeMap<coin::Nullifier, QualifiedCoinInfo> = BTreeMap::new();
    let mut saved_zswap_state_hex = String::new();
    let mut zswap_wallet = ZswapLocalState::new();
    let mut wallet_sync_ready = false;
    let mut last_seen_id: i64 = -1;
    let mut saved_max_id: i64 = 0;
    let mut saved_block_height: i64 = 0;

    if let Some(ref path) = cache_path {
        if let Some(snap) = shielded_sync_cache::try_load_snapshot(path) {
            if snap.indexer_fingerprint == fp
                && cache_io::snapshot_chain_matches(scope, &snap.chain_id)
                && snap.viewing_key_fingerprint == zswap_cache_key
            {
                saved_max_id = snap.max_zswap_id_when_saved;
                saved_block_height = snap.block_height_when_saved;
                saved_zswap_state_hex = snap.zswap_state_hex.clone();
                last_seen_id = snap.last_seen_zswap_event_id;
                if !snap.zswap_state_hex.is_empty() {
                    match shielded_sync_cache::decode_zswap_state(&snap.zswap_state_hex) {
                        Ok(w) => {
                            zswap_wallet = w;
                            wallet_sync_ready = true;
                        }
                        Err(e) if log => {
                            eprintln!(
                                "[ows-midnight] zswapLedgerEvents: ignoring stale spend-wallet state ({e})"
                            );
                            saved_zswap_state_hex.clear();
                        }
                        Err(_) => {
                            saved_zswap_state_hex.clear();
                        }
                    }
                }
                if !snap.zswap_owned_coins.is_empty() {
                    match decode_zswap_owned_coins(&snap.zswap_owned_coins) {
                        Ok((map, qmap)) => {
                            owned = map;
                            qualified = qmap;
                            if log {
                                eprintln!(
                                    "[ows-midnight] zswapLedgerEvents: resuming from on-disk state at event id {} ({} unspent coins, saved_max_id={})",
                                    snap.last_seen_zswap_event_id.saturating_add(1),
                                    owned.len(),
                                    if saved_max_id > 0 {
                                        saved_max_id.to_string()
                                    } else {
                                        "?".to_string()
                                    }
                                );
                            }
                        }
                        Err(e) => {
                            if log {
                                eprintln!(
                                    "[ows-midnight] zswapLedgerEvents: ignoring stale snapshot ({e}); replaying from genesis"
                                );
                            }
                            saved_max_id = 0;
                            saved_zswap_state_hex.clear();
                        }
                    }
                } else if !snap.zswap_state_hex.is_empty() {
                    if let Ok(wallet_state) =
                        shielded_sync_cache::decode_zswap_state(&snap.zswap_state_hex)
                    {
                        if wallet_state.coins.iter().count() > 0 {
                            (owned, qualified) = owned_maps_from_wallet(&wallet_state);
                            if log {
                                eprintln!(
                                    "[ows-midnight] zswapLedgerEvents: recovered {} unspent coins from saved spend-wallet state",
                                    owned.len()
                                );
                            }
                        }
                    }
                } else if log {
                    eprintln!("[ows-midnight] zswapLedgerEvents: no coin state in snapshot, replaying from genesis");
                }
            }
        }
    }

    if last_seen_id < 0 && log {
        eprintln!("[ows-midnight] zswapLedgerEvents: replaying from genesis");
    }

    let snapshot_at_saved_tip = saved_max_id > 0 && last_seen_id >= saved_max_id;
    let short_idle_verify = zswap_short_idle_verify(purpose, snapshot_at_saved_tip);
    if !purpose.must_catch_up_to_indexer_tip()
        && super::tip_verify::snapshot_fresh_by_http_tip(
            scope,
            saved_block_height,
            snapshot_at_saved_tip,
        )
    {
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: HTTP tip unchanged (block height={saved_block_height}), using snapshot"
            );
        }
        return Ok(ZswapLedgerReplayState { owned });
    }
    if !purpose.must_catch_up_to_indexer_tip()
        && snapshot_at_saved_tip
        && super::tip_verify::indexer_block_height_matches_saved(indexer_url, saved_block_height)
            .await
    {
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: HTTP tip unchanged on re-check (block height={saved_block_height}), using snapshot"
            );
        }
        return Ok(ZswapLedgerReplayState { owned });
    }
    if snapshot_at_saved_tip && log {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: snapshot at saved tip (last_seen_id={last_seen_id} max_id={saved_max_id}), catching up on indexer…"
        );
    }

    let mut max_id: Option<i64> = if saved_max_id > 0 {
        Some(saved_max_id)
    } else {
        None
    };
    let mut n_events: u64 = 0;
    let mut n_outputs_decrypted: u64 = 0;
    let progress_interval = if purpose.is_display() { 1000 } else { 5000 };
    let ws_idle = midnight_env::ws_idle_timeout(SyncStream::Shielded);
    let stall_timeout = midnight_env::stall_timeout(SyncStream::Shielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;
    let max_attempts = if short_idle_verify {
        midnight_env::dust_verify_max_attempts_for(purpose)
    } else {
        4
    };

    for attempt in 0..max_attempts {
        if log && attempt > 0 {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: reconnecting (attempt {}) from event id {}",
                attempt + 1,
                last_seen_id.saturating_add(1)
            );
        }

        if log {
            eprintln!("[ows-midnight] zswapLedgerEvents: connecting to indexer websocket…");
        }

        let mut ws =
            indexer_ws::connect_and_init(indexer_url, ws_idle, Some("zswapLedgerEvents")).await?;

        let resume_id = last_seen_id.saturating_add(1);
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: subscribed from event id {resume_id} (last_seen_id={last_seen_id} saved_max_id={saved_max_id})"
            );
        }
        indexer_ws::subscribe(
            &mut ws,
            "1",
            ZSWAP_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        let mut target = ZswapReplayTarget::Balance {
            owned: &mut owned,
            qualified: &mut qualified,
        };
        // Keep Merkle wallet state in sync when a spend-wallet snapshot exists so signing can
        // resume incrementally after `fund balance`.
        let wallet_arg = if wallet_sync_ready {
            Some(&mut zswap_wallet)
        } else {
            None
        };
        let (dropped, attempt_events) = replay_zswap_ws_loop(
            &mut ws,
            keys,
            Some(&mut target),
            wallet_arg,
            &mut last_seen_id,
            &mut max_id,
            &mut n_events,
            &mut n_outputs_decrypted,
            ws_idle,
            stall_timeout,
            sync_started,
            &mut last_event_at,
            progress_interval,
            log,
            short_idle_verify,
            purpose,
        )
        .await?;

        drop(ws);

        if !dropped && max_id.is_some_and(|m| last_seen_id >= m) {
            if log {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents: caught up (last_seen_id={last_seen_id} max_id={})",
                    max_id.unwrap_or(-1)
                );
            }
            break;
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(
                250u64.saturating_mul((attempt + 1) as u64),
            ))
            .await;
            continue;
        }
        if attempt_events == 0 && max_id.is_some_and(|m| last_seen_id >= m) {
            if log && short_idle_verify {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents: accepting saved tip after verify \
(last_seen_id={last_seen_id} max_id={})",
                    max_id.unwrap_or(-1)
                );
            }
            break;
        }
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!(
                "zswap ledger sync incomplete: last_seen_id={last_seen_id} max_id={max_id:?}; \
try again or set OWS_MIDNIGHT_SYNC_LOG=1"
            ),
        ));
    }

    let balances = balances_from_owned_coins(&owned);

    if log {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents replay done: events_seen={n_events} decrypted_outputs={n_outputs_decrypted} token_kinds={} last_seen_id={last_seen_id} max_id={:?}",
            balances.len(),
            max_id
        );
        eprintln!("[ows-midnight] zswapLedgerEvents: saving snapshot…");
    }

    if let Some(ref path) = cache_path {
        let saved_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let owned_records = encode_zswap_owned_coins(&owned, &qualified)?;
        let zswap_state_hex = if wallet_sync_ready {
            shielded_sync_cache::encode_zswap_state(&zswap_wallet).unwrap_or(saved_zswap_state_hex)
        } else if n_events > 0 {
            // Applied ledger events without a spend wallet — do not leave a stale Merkle snapshot.
            String::new()
        } else {
            saved_zswap_state_hex
        };
        shielded_sync_cache::try_save_snapshot(
            path,
            &shielded_sync_cache::ShieldedSyncSnapshot {
                version: shielded_sync_cache::SNAPSHOT_VERSION,
                indexer_fingerprint: fp,
                chain_id: cache_io::snapshot_chain_id(scope),
                viewing_key_fingerprint: zswap_cache_key,
                highest_checked_end_index: 0,
                highest_end_index_when_saved: 0,
                last_seen_zswap_event_id: last_seen_id,
                max_zswap_id_when_saved: max_id.unwrap_or(last_seen_id),
                block_height_when_saved: super::tip_verify::block_height_for_snapshot(scope),
                saved_at_unix: saved_at,
                balances: balances.clone(),
                zswap_owned_coins: owned_records,
                zswap_state_hex,
            },
        );
    }

    Ok(ZswapLedgerReplayState { owned })
}

fn zswap_merkle_gap_error(err: &PayError) -> bool {
    err.message
        .contains("inserted non-linearly into zswap commitment tree")
}

/// Spendable `ZswapLocalState` from snapshot + incremental `zswapLedgerEvents` replay.
async fn zswap_ledger_replay_wallet_scoped(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    scope: &SyncCacheScope,
    seed_fp: &str,
    purpose: SyncPurpose,
) -> Result<ZswapLocalState<InMemoryDB>, PayError> {
    match zswap_ledger_replay_wallet_scoped_inner(indexer_url, keys, scope, seed_fp, purpose, false)
        .await
    {
        Err(e) if zswap_merkle_gap_error(&e) => {
            if midnight_env::midnight_sync_log_enabled() {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents (spend wallet): inconsistent Merkle snapshot \
({e}); replaying from genesis"
                );
            }
            zswap_ledger_replay_wallet_scoped_inner(
                indexer_url,
                keys,
                scope,
                seed_fp,
                purpose,
                true,
            )
            .await
        }
        other => other,
    }
}

async fn zswap_ledger_replay_wallet_scoped_inner(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    scope: &SyncCacheScope,
    seed_fp: &str,
    purpose: SyncPurpose,
    force_genesis: bool,
) -> Result<ZswapLocalState<InMemoryDB>, PayError> {
    let log = midnight_env::midnight_sync_log_enabled();
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let zswap_cache_key = shielded_sync_cache::zswap_cache_key(seed_fp);
    let cache_path = shielded_sync_cache::snapshot_path(indexer_url, &zswap_cache_key, scope);

    let mut zswap = ZswapLocalState::new();
    let mut last_seen_id: i64 = -1;
    let mut saved_max_id: i64 = 0;
    let mut saved_block_height: i64 = 0;
    let mut saved_zswap_state_hex = String::new();
    // When true, `zswap` has a consistent Merkle tree and may receive incremental events.
    let mut wallet_sync_ready = false;

    if force_genesis {
        wallet_sync_ready = true;
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): replaying from genesis for Merkle + coins"
            );
        }
    } else if let Some(ref path) = cache_path {
        if let Some(snap) = shielded_sync_cache::try_load_snapshot(path) {
            if snap.indexer_fingerprint == fp
                && cache_io::snapshot_chain_matches(scope, &snap.chain_id)
                && snap.viewing_key_fingerprint == zswap_cache_key
            {
                saved_max_id = snap.max_zswap_id_when_saved;
                saved_block_height = snap.block_height_when_saved;
                last_seen_id = snap.last_seen_zswap_event_id;
                saved_zswap_state_hex = snap.zswap_state_hex.clone();
                if !snap.zswap_state_hex.is_empty() {
                    match shielded_sync_cache::decode_zswap_state(&snap.zswap_state_hex) {
                        Ok(w) => {
                            zswap = w;
                            wallet_sync_ready = true;
                            if log {
                                eprintln!(
                                    "[ows-midnight] zswapLedgerEvents (spend wallet): resuming from on-disk wallet state at event id {} ({} spendable coins, saved_max_id={})",
                                    last_seen_id.saturating_add(1),
                                    zswap.coins.iter().count(),
                                    if saved_max_id > 0 {
                                        saved_max_id.to_string()
                                    } else {
                                        "?".to_string()
                                    }
                                );
                            }
                        }
                        Err(e) if log => {
                            eprintln!(
                                "[ows-midnight] zswapLedgerEvents (spend wallet): ignoring stale wallet state ({e}); replaying from genesis"
                            );
                            saved_zswap_state_hex.clear();
                        }
                        Err(_) => {
                            saved_zswap_state_hex.clear();
                        }
                    }
                }
            }
        }
    }

    if last_seen_id < 0 {
        wallet_sync_ready = true;
        if log && !force_genesis {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): replaying from genesis for Merkle + coins"
            );
        }
    } else if !wallet_sync_ready {
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): balance snapshot without wallet state; replaying from genesis for Merkle + coins"
            );
        }
        last_seen_id = -1;
        saved_max_id = 0;
        wallet_sync_ready = true;
    }

    let snapshot_at_saved_tip = saved_max_id > 0 && last_seen_id >= saved_max_id;
    let short_idle_verify = zswap_short_idle_verify(purpose, snapshot_at_saved_tip);
    if !purpose.must_catch_up_to_indexer_tip()
        && super::tip_verify::snapshot_fresh_by_http_tip(
            scope,
            saved_block_height,
            snapshot_at_saved_tip && wallet_sync_ready && last_seen_id >= 0,
        )
    {
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): HTTP tip unchanged (block height={saved_block_height}), using snapshot wallet"
            );
        }
        return Ok(zswap);
    }
    if !purpose.must_catch_up_to_indexer_tip()
        && snapshot_at_saved_tip
        && super::tip_verify::indexer_block_height_matches_saved(indexer_url, saved_block_height)
            .await
    {
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): HTTP tip unchanged on re-check (block height={saved_block_height}), using snapshot wallet"
            );
        }
        return Ok(zswap);
    }
    if snapshot_at_saved_tip && log {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents (spend wallet): snapshot at saved tip (last_seen_id={last_seen_id} max_id={saved_max_id}), catching up on indexer…"
        );
    }

    let mut max_id: Option<i64> = if saved_max_id > 0 {
        Some(saved_max_id)
    } else {
        None
    };
    let mut n_events: u64 = 0;
    let mut n_outputs_decrypted: u64 = 0;
    let progress_interval = if purpose.is_display() { 1000 } else { 5000 };
    let ws_idle = midnight_env::ws_idle_timeout(SyncStream::Shielded);
    let stall_timeout = midnight_env::stall_timeout(SyncStream::Shielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;
    let max_attempts = if short_idle_verify {
        midnight_env::dust_verify_max_attempts_for(purpose)
    } else {
        4
    };

    for attempt in 0..max_attempts {
        if log && attempt > 0 {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): reconnecting (attempt {}) from event id {}",
                attempt + 1,
                last_seen_id.saturating_add(1)
            );
        }
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): connecting to indexer websocket…"
            );
        }

        let mut ws =
            indexer_ws::connect_and_init(indexer_url, ws_idle, Some("zswapLedgerEvents")).await?;

        let resume_id = last_seen_id.saturating_add(1);
        if log {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents (spend wallet): subscribed from event id {resume_id} (last_seen_id={last_seen_id} saved_max_id={saved_max_id})"
            );
        }
        indexer_ws::subscribe(
            &mut ws,
            "1",
            ZSWAP_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        let wallet_arg = if zswap_wallet_feed_enabled(purpose, wallet_sync_ready, short_idle_verify)
        {
            Some(&mut zswap)
        } else {
            None
        };
        let (dropped, attempt_events) = replay_zswap_ws_loop(
            &mut ws,
            keys,
            None,
            wallet_arg,
            &mut last_seen_id,
            &mut max_id,
            &mut n_events,
            &mut n_outputs_decrypted,
            ws_idle,
            stall_timeout,
            sync_started,
            &mut last_event_at,
            progress_interval,
            log,
            short_idle_verify,
            purpose,
        )
        .await?;
        drop(ws);

        if !dropped && max_id.is_some_and(|m| last_seen_id >= m) {
            if log {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents (spend wallet): caught up (last_seen_id={last_seen_id} max_id={})",
                    max_id.unwrap_or(-1)
                );
            }
            break;
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(
                250u64.saturating_mul((attempt + 1) as u64),
            ))
            .await;
            continue;
        }
        if attempt_events == 0 && max_id.is_some_and(|m| last_seen_id >= m) {
            if log && short_idle_verify {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents (spend wallet): accepting saved tip after verify \
(last_seen_id={last_seen_id} max_id={})",
                    max_id.unwrap_or(-1)
                );
            }
            break;
        }
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!(
                "zswap ledger spend-wallet sync incomplete: last_seen_id={last_seen_id} max_id={max_id:?}; \
try again or set OWS_MIDNIGHT_SYNC_LOG=1"
            ),
        ));
    }

    if log {
        let spendable: u128 = zswap.coins.iter().map(|(_, q)| q.value).sum();
        eprintln!(
            "[ows-midnight] zswapLedgerEvents (spend wallet) done: events_seen={n_events} decrypted_outputs={n_outputs_decrypted} spendable_coins={} coins_unspent={spendable} last_seen_id={last_seen_id}",
            zswap.coins.iter().count()
        );
        eprintln!("[ows-midnight] zswapLedgerEvents (spend wallet): saving snapshot…");
    }

    if let Some(ref path) = cache_path {
        let (owned, qualified) = owned_maps_from_wallet(&zswap);
        let saved_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let owned_records = encode_zswap_owned_coins(&owned, &qualified)?;
        let zswap_state_hex = if wallet_sync_ready {
            shielded_sync_cache::encode_zswap_state(&zswap).unwrap_or(saved_zswap_state_hex)
        } else {
            saved_zswap_state_hex
        };
        shielded_sync_cache::try_save_snapshot(
            path,
            &shielded_sync_cache::ShieldedSyncSnapshot {
                version: shielded_sync_cache::SNAPSHOT_VERSION,
                indexer_fingerprint: fp,
                chain_id: cache_io::snapshot_chain_id(scope),
                viewing_key_fingerprint: zswap_cache_key,
                highest_checked_end_index: 0,
                highest_end_index_when_saved: 0,
                last_seen_zswap_event_id: last_seen_id,
                max_zswap_id_when_saved: max_id.unwrap_or(last_seen_id),
                block_height_when_saved: super::tip_verify::block_height_for_snapshot(scope),
                saved_at_unix: saved_at,
                balances: balances_from_owned_coins(&owned),
                zswap_owned_coins: owned_records,
                zswap_state_hex,
            },
        );
    }

    Ok(zswap)
}

#[allow(clippy::too_many_arguments)]
async fn replay_zswap_ws_loop(
    ws: &mut IndexerWs,
    keys: &ZswapSecretKeys,
    mut balance: Option<&mut ZswapReplayTarget<'_>>,
    mut wallet: Option<&mut ZswapLocalState<InMemoryDB>>,
    last_seen_id: &mut i64,
    max_id: &mut Option<i64>,
    n_events: &mut u64,
    n_outputs_decrypted: &mut u64,
    ws_idle: Duration,
    stall_timeout: Duration,
    sync_started: Instant,
    last_event_at: &mut Option<Instant>,
    progress_interval: u64,
    log: bool,
    short_idle_verify: bool,
    purpose: SyncPurpose,
) -> Result<(bool, u64), PayError> {
    let mut attempt_events: u64 = 0;
    let verify_idle = midnight_env::dust_verify_idle_timeout_for(purpose);

    loop {
        let effective_stall = if short_idle_verify && attempt_events == 0 {
            verify_idle
        } else {
            stall_timeout
        };
        let stall_elapsed = last_event_at.unwrap_or(sync_started).elapsed();
        if stall_elapsed > effective_stall {
            if short_idle_verify
                && attempt_events == 0
                && max_id.is_some_and(|m| *last_seen_id >= m)
            {
                if log {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: verify stall {}s, accepting saved tip \
(last_seen_id={last_seen_id} max_id={max_id:?})",
                        effective_stall.as_secs()
                    );
                }
                return Ok((false, attempt_events));
            }
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!(
                    "no zswap ledger events for {}s (last_seen_id={last_seen_id} max_id={max_id:?}); \
indexer may be stalled",
                    effective_stall.as_secs()
                ),
            ));
        }

        let read_timeout = if short_idle_verify && attempt_events == 0 {
            verify_idle
        } else {
            ws_idle
        };

        let t = match indexer_ws::read_subscription_text(ws, read_timeout).await? {
            indexer_ws::SubscriptionTextRead::Text(t) => {
                *last_event_at = Some(Instant::now());
                t
            }
            indexer_ws::SubscriptionTextRead::Closed => {
                let at_tip = attempt_events == 0 && max_id.is_some_and(|m| *last_seen_id >= m);
                if log {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: connection closed{} \
(last_seen_id={last_seen_id} max_id={max_id:?})",
                        if at_tip { " at tip" } else { "" }
                    );
                }
                return Ok((!at_tip, attempt_events));
            }
            indexer_ws::SubscriptionTextRead::IdleTimeout => {
                let at_tip = attempt_events == 0 && max_id.is_some_and(|m| *last_seen_id >= m);
                if log {
                    if at_tip {
                        eprintln!(
                            "[ows-midnight] zswapLedgerEvents: no new events (already at tip last_seen_id={last_seen_id} max_id={max_id:?})"
                        );
                    } else {
                        eprintln!(
                            "[ows-midnight] zswapLedgerEvents: no indexer message for {}s (last_seen_id={last_seen_id} max_id={max_id:?})",
                            read_timeout.as_secs()
                        );
                    }
                }
                return Ok((!at_tip, attempt_events));
            }
        };

        let frame: indexer_ws::WsFrame<ZswapWsData> = serde_json::from_str(&t)
            .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
        match frame.r#type.as_str() {
            "next" => {
                let Some(payload) = frame.payload else {
                    continue;
                };
                if let Some(errs) = payload.errors.as_ref() {
                    let msg = errs
                        .first()
                        .and_then(|e| e.get("message").and_then(|m| m.as_str()))
                        .unwrap_or("unknown GraphQL error");
                    return Err(PayError::new(
                        PayErrorCode::ProtocolMalformed,
                        format!("indexer GraphQL error: {msg}"),
                    ));
                }
                let Some(zdata) = payload.data else {
                    continue;
                };
                let Some(evt) = zdata.zswap_ledger_events else {
                    continue;
                };
                if max_id.is_none() {
                    *max_id = Some(evt.max_id);
                } else {
                    *max_id = Some(max_id.unwrap().max(evt.max_id));
                }
                *last_seen_id = (*last_seen_id).max(evt.id);
                *n_events = n_events.saturating_add(1);
                attempt_events = attempt_events.saturating_add(1);

                let raw_hex = evt.raw.strip_prefix("0x").unwrap_or(evt.raw.as_str());
                let bytes = hex::decode(raw_hex).map_err(|e| {
                    PayError::new(
                        PayErrorCode::ProtocolMalformed,
                        format!("invalid zswap event raw hex: {e}"),
                    )
                })?;
                let mut reader: &[u8] = &bytes;
                let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader).map_err(|e| {
                    PayError::new(
                        PayErrorCode::ProtocolMalformed,
                        format!("decode zswap event: {e}"),
                    )
                })?;

                if let Some(ZswapReplayTarget::Balance { owned, qualified }) =
                    balance.as_deref_mut()
                {
                    apply_zswap_ledger_event_balance(
                        owned,
                        qualified,
                        keys,
                        &ev,
                        n_outputs_decrypted,
                    );
                }
                if let Some(zswap) = wallet.as_deref_mut() {
                    apply_zswap_ledger_event_wallet(zswap, keys, &ev, n_outputs_decrypted)?;
                }

                if log && (*n_events == 1 || n_events.is_multiple_of(progress_interval)) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents replay progress: last_seen_id={last_seen_id} max_id={max_id:?} events_applied={n_events} decrypted_outputs={n_outputs_decrypted}"
                    );
                }

                if max_id.is_some_and(|m| *last_seen_id >= m) {
                    return Ok((false, attempt_events));
                }
            }
            "complete" => return Ok((false, attempt_events)),
            "error" => {
                return Err(PayError::new(
                    PayErrorCode::ProtocolMalformed,
                    format!("indexer zswap subscription error: {t}"),
                ));
            }
            _ => {}
        }
    }
}

fn owned_maps_from_wallet(
    zswap: &ZswapLocalState<InMemoryDB>,
) -> (
    BTreeMap<coin::Nullifier, coin::Info>,
    BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
) {
    let mut owned = BTreeMap::new();
    let mut qualified = BTreeMap::new();
    for (nul, qci) in zswap.coins.iter() {
        qualified.insert(nul, *qci);
        owned.insert(
            nul,
            coin::Info {
                nonce: qci.nonce,
                type_: qci.type_,
                value: qci.value,
            },
        );
    }
    (owned, qualified)
}

fn encode_zswap_owned_coins(
    owned: &BTreeMap<coin::Nullifier, coin::Info>,
    qualified: &BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
) -> Result<Vec<shielded_sync_cache::ZswapOwnedCoinRecord>, PayError> {
    let mut out = Vec::with_capacity(owned.len());
    for (nul, ci) in owned {
        let mut nul_b = Vec::new();
        let mut ci_b = Vec::new();
        tagged_serialize(nul, &mut nul_b)
            .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
        tagged_serialize(ci, &mut ci_b)
            .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
        let mt_index = qualified.get(nul).map(|q| q.mt_index);
        out.push(shielded_sync_cache::ZswapOwnedCoinRecord {
            nullifier_hex: hex::encode(nul_b),
            coin_hex: hex::encode(ci_b),
            mt_index,
        });
    }
    Ok(out)
}

type ZswapOwnedSnapshotMaps = (
    BTreeMap<coin::Nullifier, coin::Info>,
    BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
);

/// Qualified unspent coins from the wallet's on-disk zswap-ledger snapshot (if any).
pub(super) fn load_zswap_qualified_coins_from_snapshot(
    indexer_url: &str,
    scope: &SyncCacheScope,
    seed_fp: &str,
) -> BTreeMap<coin::Nullifier, QualifiedCoinInfo> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let zswap_cache_key = shielded_sync_cache::zswap_cache_key(seed_fp);
    let Some(path) = shielded_sync_cache::snapshot_path(indexer_url, &zswap_cache_key, scope)
    else {
        return BTreeMap::new();
    };
    let Some(snap) = shielded_sync_cache::try_load_snapshot(&path) else {
        return BTreeMap::new();
    };
    if snap.indexer_fingerprint != fp
        || !cache_io::snapshot_chain_matches(scope, &snap.chain_id)
        || snap.viewing_key_fingerprint != zswap_cache_key
        || snap.zswap_owned_coins.is_empty()
    {
        return BTreeMap::new();
    }
    decode_zswap_owned_coins(&snap.zswap_owned_coins)
        .map(|(_, q)| q)
        .unwrap_or_default()
}

fn decode_zswap_owned_coins(
    records: &[shielded_sync_cache::ZswapOwnedCoinRecord],
) -> Result<ZswapOwnedSnapshotMaps, PayError> {
    let mut owned = BTreeMap::new();
    let mut qualified = BTreeMap::new();
    for rec in records {
        let nul_b = hex::decode(
            rec.nullifier_hex
                .strip_prefix("0x")
                .unwrap_or(&rec.nullifier_hex),
        )
        .map_err(|e| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("invalid nullifier hex: {e}"),
            )
        })?;
        let ci_b =
            hex::decode(rec.coin_hex.strip_prefix("0x").unwrap_or(&rec.coin_hex)).map_err(|e| {
                PayError::new(
                    PayErrorCode::ProtocolMalformed,
                    format!("invalid coin hex: {e}"),
                )
            })?;
        let mut nul_r: &[u8] = &nul_b;
        let mut ci_r: &[u8] = &ci_b;
        let nul: coin::Nullifier = tagged_deserialize(&mut nul_r).map_err(|e| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("decode nullifier: {e}"),
            )
        })?;
        let ci: coin::Info = tagged_deserialize(&mut ci_r).map_err(|e| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("decode coin info: {e}"),
            )
        })?;
        owned.insert(nul, ci);
        if let Some(mt_index) = rec.mt_index {
            qualified.insert(nul, ci.qualify(mt_index));
        }
    }
    Ok((owned, qualified))
}

#[derive(Debug, Default, Deserialize)]
struct ZswapWsData {
    #[serde(rename = "zswapLedgerEvents")]
    #[serde(default)]
    zswap_ledger_events: Option<ZswapLedgerEventWire>,
}

#[derive(Debug, Deserialize)]
struct ZswapLedgerEventWire {
    id: i64,
    raw: String,
    #[serde(rename = "maxId")]
    max_id: i64,
}
