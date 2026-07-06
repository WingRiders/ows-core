//! Sync local Dust state by replaying `dustLedgerEvents` from the indexer.
//!
//! This mirrors the Midnight ledger `DustLocalState::replay_events` logic by decoding the raw
//! `Event` payloads and applying them in-order. Also exposes
//! [`get_dust_balance_for_display_scoped`] (apply ledger decay rules at a given chain time) and
//! [`format_dust_specks`] (render `SPECKS_PER_DUST`-denominated values).

use super::error::{PayError, PayErrorCode};
use midnight_ledger::dust::{
    DustLocalState, DustPublicKey, DustSecretKey, INITIAL_DUST_PARAMETERS,
};
use midnight_ledger::events::Event;
use midnight_serialize::tagged_deserialize;
use midnight_serialize::Serializable;
use midnight_storage::db::InMemoryDB;
use serde::Deserialize;
use std::time::{Duration, Instant};

use super::cache_io::{self, SyncPurpose};
use super::indexer_ws;
use super::midnight_env::{self, SyncStream};
use super::session_cache;

/// Options for a dust-ledger WebSocket replay.
#[derive(Debug, Clone, Copy)]
pub struct DustSyncOptions {
    /// Fail only when no dust ledger events are applied for this long (not total wall time).
    pub stall_timeout: Duration,
    pub log_progress: bool,
    /// Reconnect when the indexer WebSocket sends no frames for this long.
    pub ws_idle_timeout: Duration,
    pub purpose: SyncPurpose,
    /// When set, tip-verify early exit is disabled until `last_seen_event_id` reaches this id
    /// (post-submit catch-up).
    pub min_required_event_id: Option<i64>,
}

impl Default for DustSyncOptions {
    fn default() -> Self {
        Self {
            stall_timeout: midnight_env::stall_timeout(SyncStream::Dust),
            log_progress: midnight_env::midnight_sync_log_enabled(),
            ws_idle_timeout: midnight_env::ws_idle_timeout(SyncStream::Dust),
            purpose: SyncPurpose::Signing,
            min_required_event_id: None,
        }
    }
}

fn save_dust_progress_snapshot(
    path: &std::path::Path,
    scope: &super::cache_io::SyncCacheScope,
    fp: &str,
    dust_pk_hex: &str,
    state: &DustLocalState<InMemoryDB>,
    last_seen_id: i64,
    max_id: Option<i64>,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(state_hex) = super::dust_sync_cache::encode_state(state) {
        cache_io::try_save(
            path,
            &super::dust_sync_cache::DustSyncSnapshot {
                version: super::dust_sync_cache::SNAPSHOT_VERSION,
                indexer_fingerprint: fp.to_string(),
                chain_id: cache_io::snapshot_chain_id(scope),
                dust_public_key_hex: dust_pk_hex.to_string(),
                last_seen_event_id: last_seen_id,
                max_id_when_saved: max_id.map(|m| m.max(last_seen_id)).unwrap_or(last_seen_id),
                state_hex,
                block_height_when_saved: super::tip_verify::block_height_for_snapshot(scope),
                saved_at_unix: now,
            },
        );
    }
}

fn try_load_dust_state_from_disk(
    indexer_url: &str,
    dust_pk_hex: &str,
    scope: &super::cache_io::SyncCacheScope,
) -> Option<(DustLocalState<InMemoryDB>, i64, i64)> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let path = super::dust_sync_cache::snapshot_path(indexer_url, dust_pk_hex, scope)?;
    let snap = super::dust_sync_cache::try_load_snapshot(&path)?;
    if !cache_io::snapshot_site_matches(scope, &snap.chain_id, &fp, &snap.indexer_fingerprint)
        || snap.dust_public_key_hex != dust_pk_hex
    {
        return None;
    }
    let st = super::dust_sync_cache::decode_state(&snap.state_hex).ok()?;
    Some((st, snap.last_seen_event_id, snap.max_id_when_saved))
}

impl DustSyncOptions {
    fn snapshot_interval(&self) -> u64 {
        if self.log_progress {
            1000
        } else {
            2000
        }
    }

    /// `ows fund balance` — runs until caught up unless the indexer stalls.
    pub fn for_fund_balance_display() -> Self {
        Self {
            purpose: SyncPurpose::Display,
            ..Self::default()
        }
    }
}

fn stall_elapsed(last_applied_at: Option<Instant>, sync_started: Instant) -> Duration {
    last_applied_at.unwrap_or(sync_started).elapsed()
}

fn dust_merge_max_id(current: Option<i64>, event_max_id: i64) -> Option<i64> {
    if event_max_id <= 0 {
        return current;
    }
    Some(current.map_or(event_max_id, |m| m.max(event_max_id)))
}

fn dust_at_chain_tip(last_seen_id: i64, max_id: Option<i64>) -> bool {
    max_id.is_some_and(|m| m > 0 && last_seen_id >= m)
}

fn dust_sync_caught_up(
    min_required_event_id: Option<i64>,
    last_seen_id: i64,
    max_id: Option<i64>,
) -> bool {
    if !dust_at_chain_tip(last_seen_id, max_id) {
        return false;
    }
    min_required_event_id.is_none_or(|min| last_seen_id >= min)
}

/// Whether dust sync may return. Signing requires live indexer contact in this run — not
/// returning on the on-disk snapshot alone before opening the WebSocket. An idle timeout
/// at chain tip counts as contact (indexer had nothing new to send).
fn dust_ready_to_return(
    purpose: SyncPurpose,
    min_required_event_id: Option<i64>,
    sync_baseline_last_seen: i64,
    last_seen_id: i64,
    max_id: Option<i64>,
    ws_tip_confirmed: bool,
    events_applied_this_run: u64,
) -> bool {
    if !dust_sync_caught_up(min_required_event_id, last_seen_id, max_id) {
        return false;
    }
    if !purpose.must_catch_up_to_indexer_tip() {
        return true;
    }
    // Snapshot cursor can lag ledger state: do not accept "at tip" without applying events
    // that the caller explicitly needs (post-submit catch-up for the tx we just submitted).
    if let Some(min) = min_required_event_id {
        if sync_baseline_last_seen < min && events_applied_this_run == 0 {
            return false;
        }
    }
    ws_tip_confirmed || events_applied_this_run > 0
}

fn mark_ws_tip_confirmed_at_chain_tip(
    ws_tip_confirmed: &mut bool,
    last_seen_id: i64,
    max_id: Option<i64>,
) {
    if dust_at_chain_tip(last_seen_id, max_id) {
        *ws_tip_confirmed = true;
    }
}

fn dust_ws_read_timeout(
    verifying_at_tip: bool,
    attempt_events: u64,
    ws_idle: Duration,
    purpose: SyncPurpose,
) -> Duration {
    if verifying_at_tip && attempt_events == 0 {
        midnight_env::dust_verify_idle_timeout_for(purpose)
    } else {
        ws_idle
    }
}

fn dust_verify_attempt_limit(verifying_at_tip: bool, purpose: SyncPurpose) -> u32 {
    if verifying_at_tip {
        midnight_env::dust_verify_max_attempts_for(purpose)
    } else {
        4
    }
}

fn finish_dust_sync_with_session_cache(
    state: &DustLocalState<InMemoryDB>,
    scope: &super::cache_io::SyncCacheScope,
    fp: &str,
    dust_pk_hex: &str,
) {
    if let Ok(state_hex) = super::dust_sync_cache::encode_state(state) {
        session_cache::put_dust_ledger_state_hex(scope, fp, dust_pk_hex, state_hex);
    }
}

fn dust_stall_error(stall_timeout: Duration, last_seen_id: i64, max_id: Option<i64>) -> PayError {
    PayError::new(
        PayErrorCode::HttpTransport,
        format!(
            "no dust ledger events applied for {}s (last_seen_id={last_seen_id} max_id={max_id:?}); \
indexer may be stalled",
            stall_timeout.as_secs()
        ),
    )
}

pub use midnight_env::fund_balance_skip_dust_sync;

const DUST_LEDGER_SUB: &str = r#"
subscription DustLedgerEvents($id: Int) {
  dustLedgerEvents(id: $id) {
    __typename
    id
    raw
    maxId
    protocolVersion
    ... on DustInitialUtxo { output { nonce } }
  }
}
"#;

#[derive(Debug, Default, Deserialize)]
struct DustWsData {
    #[serde(rename = "dustLedgerEvents")]
    #[serde(default)]
    dust_ledger_events: Option<DustLedgerEvent>,
}

#[derive(Debug, Deserialize)]
struct DustLedgerEvent {
    id: i64,
    raw: String,
    #[serde(rename = "maxId")]
    max_id: i64,
}

pub(crate) async fn sync_dust_local_state_scoped(
    indexer_url: &str,
    dust_sk: &DustSecretKey,
    scope: &super::cache_io::SyncCacheScope,
) -> Result<DustLocalState<InMemoryDB>, PayError> {
    sync_dust_local_state_scoped_with_options(
        indexer_url,
        dust_sk,
        scope,
        DustSyncOptions::default(),
    )
    .await
}

/// `last_seen_event_id` from the on-disk dust snapshot when site keys match.
pub(super) fn snapshot_last_seen_dust_event_id(
    indexer_url: &str,
    scope: &super::cache_io::SyncCacheScope,
    dust_pk_hex: &str,
) -> Option<i64> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let path = super::dust_sync_cache::snapshot_path(indexer_url, dust_pk_hex, scope)?;
    let snap = super::dust_sync_cache::try_load_snapshot(&path)?;
    if snap.indexer_fingerprint != fp
        || !cache_io::snapshot_chain_matches(scope, &snap.chain_id)
        || snap.dust_public_key_hex != dust_pk_hex
    {
        return None;
    }
    Some(snap.last_seen_event_id)
}

pub(super) fn snapshot_last_seen_dust_event_id_for_key(
    indexer_url: &str,
    scope: &super::cache_io::SyncCacheScope,
    dust_sk: &DustSecretKey,
) -> Result<Option<i64>, PayError> {
    let dust_pk_hex = dust_public_key_hex(dust_sk)?;
    Ok(snapshot_last_seen_dust_event_id(
        indexer_url,
        scope,
        &dust_pk_hex,
    ))
}

pub async fn sync_dust_local_state_scoped_with_options(
    indexer_url: &str,
    dust_sk: &DustSecretKey,
    scope: &super::cache_io::SyncCacheScope,
    options: DustSyncOptions,
) -> Result<DustLocalState<InMemoryDB>, PayError> {
    sync_dust_local_state_inner(indexer_url, dust_sk, scope, &options).await
}

async fn sync_dust_local_state_inner(
    indexer_url: &str,
    dust_sk: &DustSecretKey,
    scope: &super::cache_io::SyncCacheScope,
    options: &DustSyncOptions,
) -> Result<DustLocalState<InMemoryDB>, PayError> {
    // Resume from disk snapshot when available.
    let dust_pk_hex = dust_public_key_hex(dust_sk)?;
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);

    if session_cache::session_cache_shortcut_allowed(options.purpose) {
        if let Some(state_hex) = session_cache::get_dust_ledger_state_hex(scope, &fp, &dust_pk_hex)
        {
            if let Ok(state) = super::dust_sync_cache::decode_state(&state_hex) {
                if options.log_progress {
                    eprintln!("[ows-midnight] dust sync: using in-process session cache");
                }
                return Ok(state);
            }
        }
    }

    let cache_path = super::dust_sync_cache::snapshot_path(indexer_url, &dust_pk_hex, scope);
    // IMPORTANT: Start from genesis dust parameters.
    // The dust ledger event stream is replayed from (potentially) genesis, and
    // parameter changes are applied via events/state transitions.
    let mut state = DustLocalState::new(INITIAL_DUST_PARAMETERS);
    let mut start_id: i64 = midnight_env::dust_sync_start_id();
    let mut saved_max_id: i64 = 0;
    let mut saved_block_height: i64 = 0;
    if let Some(ref path) = cache_path {
        if let Some(snap) = super::dust_sync_cache::try_load_snapshot(path) {
            if snap.indexer_fingerprint == fp
                && cache_io::snapshot_chain_matches(scope, &snap.chain_id)
                && snap.dust_public_key_hex == dust_pk_hex
            {
                saved_max_id = snap.max_id_when_saved;
                saved_block_height = snap.block_height_when_saved;
                if let Ok(st) = super::dust_sync_cache::decode_state(&snap.state_hex) {
                    state = st;
                    start_id = snap.last_seen_event_id.saturating_add(1);
                }
            }
        }
    }

    let log_progress = options.log_progress;
    let snapshot_at_saved_tip = saved_max_id > 0 && start_id.saturating_sub(1) >= saved_max_id;
    if !options.purpose.must_catch_up_to_indexer_tip()
        && super::tip_verify::snapshot_fresh_by_http_tip(
            scope,
            saved_block_height,
            snapshot_at_saved_tip,
        )
    {
        if log_progress {
            eprintln!(
                "[ows-midnight] dust sync: HTTP tip unchanged (block height={saved_block_height}), using snapshot"
            );
        }
        finish_dust_sync_with_session_cache(&state, scope, &fp, &dust_pk_hex);
        return Ok(state);
    }
    if !options.purpose.must_catch_up_to_indexer_tip()
        && snapshot_at_saved_tip
        && super::tip_verify::indexer_block_height_matches_saved(indexer_url, saved_block_height)
            .await
    {
        if log_progress {
            eprintln!(
                "[ows-midnight] dust sync: HTTP tip unchanged on re-check (block height={saved_block_height}), using snapshot"
            );
        }
        finish_dust_sync_with_session_cache(&state, scope, &fp, &dust_pk_hex);
        return Ok(state);
    }
    let ws_idle = options.ws_idle_timeout;
    let stall_timeout = options.stall_timeout;
    let sync_started = Instant::now();
    let mut last_applied_at: Option<Instant> = None;

    if log_progress && start_id > 0 {
        eprintln!("[ows-midnight] dust sync: resuming from on-disk state at event id {start_id}");
    } else if log_progress {
        eprintln!("[ows-midnight] dust sync: no snapshot, replaying from genesis");
    }

    let mut max_id: Option<i64> = if saved_max_id > 0 {
        Some(saved_max_id)
    } else {
        None
    };
    let mut last_seen_id: i64 = start_id.saturating_sub(1);
    let sync_baseline_last_seen = last_seen_id;

    // Snapshot already at the saved chain tip — still reconnect so we learn the
    // current max event id; otherwise proofs can be built against stale roots.
    if saved_max_id > 0 && last_seen_id >= saved_max_id && log_progress {
        eprintln!(
            "[ows-midnight] dust sync: snapshot at saved tip (last_seen_id={last_seen_id} max_id={saved_max_id}), verifying with indexer…"
        );
    }
    let mut n_events: u64 = 0;
    let verifying_at_tip = saved_max_id > 0 && last_seen_id >= saved_max_id;
    let max_attempts = dust_verify_attempt_limit(verifying_at_tip, options.purpose);
    let verify_idle = midnight_env::dust_verify_idle_timeout_for(options.purpose);
    let mut ws_tip_confirmed = false;

    for attempt in 0..max_attempts {
        let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;

        let resume_id = last_seen_id.saturating_add(1);
        indexer_ws::subscribe(
            &mut ws,
            "1",
            DUST_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        #[allow(unused_assignments)]
        let mut dropped = true;
        let mut attempt_events: u64 = 0;
        let attempt_started = Instant::now();
        loop {
            let effective_stall = if verifying_at_tip && n_events == 0 {
                verify_idle
            } else {
                stall_timeout
            };
            if stall_elapsed(last_applied_at, sync_started) > effective_stall {
                mark_ws_tip_confirmed_at_chain_tip(&mut ws_tip_confirmed, last_seen_id, max_id);
                if dust_ready_to_return(
                    options.purpose,
                    options.min_required_event_id,
                    sync_baseline_last_seen,
                    last_seen_id,
                    max_id,
                    ws_tip_confirmed,
                    n_events,
                ) {
                    if let Some(ref path) = cache_path {
                        save_dust_progress_snapshot(
                            path,
                            scope,
                            &fp,
                            &dust_pk_hex,
                            &state,
                            last_seen_id,
                            max_id,
                        );
                    }
                    return Ok(state);
                }
                if let Some(ref path) = cache_path {
                    save_dust_progress_snapshot(
                        path,
                        scope,
                        &fp,
                        &dust_pk_hex,
                        &state,
                        last_seen_id,
                        max_id,
                    );
                }
                return Err(dust_stall_error(effective_stall, last_seen_id, max_id));
            }

            if verifying_at_tip && attempt_events == 0 && attempt_started.elapsed() > verify_idle {
                mark_ws_tip_confirmed_at_chain_tip(&mut ws_tip_confirmed, last_seen_id, max_id);
                if dust_ready_to_return(
                    options.purpose,
                    options.min_required_event_id,
                    sync_baseline_last_seen,
                    last_seen_id,
                    max_id,
                    ws_tip_confirmed,
                    n_events,
                ) {
                    if log_progress {
                        eprintln!(
                            "[ows-midnight] dust sync: verify idle {}s, accepting saved tip \
(last_seen_id={last_seen_id} max_id={max_id:?})",
                            verify_idle.as_secs()
                        );
                    }
                    dropped = false;
                    break;
                }
                if log_progress {
                    eprintln!(
                        "[ows-midnight] dust sync: verify idle {}s with no ledger data, reconnecting…",
                        verify_idle.as_secs()
                    );
                }
                dropped = true;
                break;
            }

            let read_timeout =
                dust_ws_read_timeout(verifying_at_tip, attempt_events, ws_idle, options.purpose);
            let t = match indexer_ws::read_subscription_text(&mut ws, read_timeout).await? {
                indexer_ws::SubscriptionTextRead::Text(t) => t,
                indexer_ws::SubscriptionTextRead::Closed => {
                    dropped = true;
                    break;
                }
                indexer_ws::SubscriptionTextRead::IdleTimeout => {
                    mark_ws_tip_confirmed_at_chain_tip(&mut ws_tip_confirmed, last_seen_id, max_id);
                    if attempt_events == 0
                        && dust_ready_to_return(
                            options.purpose,
                            options.min_required_event_id,
                            sync_baseline_last_seen,
                            last_seen_id,
                            max_id,
                            ws_tip_confirmed,
                            n_events,
                        )
                    {
                        if log_progress {
                            eprintln!(
                                "[ows-midnight] dust sync: no new events (already at tip last_seen_id={last_seen_id} max_id={max_id:?})"
                            );
                        }
                        dropped = false;
                    } else if verifying_at_tip && attempt_events == 0 {
                        if log_progress {
                            eprintln!(
                                "[ows-midnight] dust sync: verify read idle {}s, reconnecting…",
                                read_timeout.as_secs()
                            );
                        }
                        dropped = true;
                    } else {
                        if log_progress {
                            eprintln!(
                                "[ows-midnight] dust sync: no indexer message for {}s, reconnecting…",
                                read_timeout.as_secs()
                            );
                        }
                        dropped = true;
                    }
                    break;
                }
            };
            let frame: indexer_ws::WsFrame<DustWsData> = serde_json::from_str(&t)
                .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
            match frame.r#type.as_str() {
                "next" => {
                    ws_tip_confirmed = true;
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
                    let Some(evt) = payload.data.and_then(|d| d.dust_ledger_events) else {
                        continue;
                    };
                    max_id = dust_merge_max_id(max_id, evt.max_id);
                    last_seen_id = last_seen_id.max(evt.id);
                    let raw_hex = evt.raw.strip_prefix("0x").unwrap_or(evt.raw.as_str());
                    let bytes = hex::decode(raw_hex).map_err(|e| {
                        PayError::new(
                            PayErrorCode::ProtocolMalformed,
                            format!("invalid event raw hex: {e}"),
                        )
                    })?;
                    let mut reader: &[u8] = &bytes;
                    let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader).map_err(|e| {
                        PayError::new(
                            PayErrorCode::ProtocolMalformed,
                            format!("decode dust event: {e}"),
                        )
                    })?;
                    state = state
                        .replay_events(dust_sk, std::iter::once(&ev))
                        .map_err(|e| {
                            PayError::new(
                                PayErrorCode::ProtocolMalformed,
                                format!("dust event replay failed: {e}"),
                            )
                        })?;
                    n_events = n_events.saturating_add(1);
                    attempt_events = attempt_events.saturating_add(1);
                    last_applied_at = Some(Instant::now());

                    if log_progress && (n_events == 1 || n_events.is_multiple_of(1000)) {
                        eprintln!(
                            "[ows-midnight] midnight dust sync progress: last_seen_id={last_seen_id} max_id={:?} events_applied={n_events}",
                            max_id
                        );
                    }

                    if options.snapshot_interval() > 0
                        && n_events.is_multiple_of(options.snapshot_interval())
                    {
                        if let Some(ref path) = cache_path {
                            save_dust_progress_snapshot(
                                path,
                                scope,
                                &fp,
                                &dust_pk_hex,
                                &state,
                                last_seen_id,
                                max_id,
                            );
                        }
                    }
                    if dust_ready_to_return(
                        options.purpose,
                        options.min_required_event_id,
                        sync_baseline_last_seen,
                        last_seen_id,
                        max_id,
                        ws_tip_confirmed,
                        n_events,
                    ) {
                        dropped = false;
                        break;
                    }
                }
                "complete" => {
                    if max_id.is_none() && last_seen_id >= 0 {
                        max_id = Some(last_seen_id);
                    }
                    mark_ws_tip_confirmed_at_chain_tip(&mut ws_tip_confirmed, last_seen_id, max_id);
                    dropped = !dust_ready_to_return(
                        options.purpose,
                        options.min_required_event_id,
                        sync_baseline_last_seen,
                        last_seen_id,
                        max_id,
                        ws_tip_confirmed,
                        n_events,
                    );
                    break;
                }
                _ => {}
            }
        }

        drop(ws);

        if dropped {
            if let Some(ref path) = cache_path {
                save_dust_progress_snapshot(
                    path,
                    scope,
                    &fp,
                    &dust_pk_hex,
                    &state,
                    last_seen_id,
                    max_id,
                );
            }
        }

        if !dropped
            && dust_ready_to_return(
                options.purpose,
                options.min_required_event_id,
                sync_baseline_last_seen,
                last_seen_id,
                max_id,
                ws_tip_confirmed,
                n_events,
            )
        {
            break;
        }
        if attempt + 1 < max_attempts {
            let backoff_ms = if verifying_at_tip {
                500u64.saturating_mul((attempt + 1) as u64)
            } else {
                250u64.saturating_mul((attempt + 1) as u64)
            };
            if log_progress && dropped {
                eprintln!(
                    "[ows-midnight] dust sync: retry {}/{} in {}ms…",
                    attempt + 2,
                    max_attempts,
                    backoff_ms
                );
            }
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            continue;
        }
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("dust ledger sync websocket connection dropped after {max_attempts} attempts"),
        ));
    }

    if let Some(ref path) = cache_path {
        save_dust_progress_snapshot(path, scope, &fp, &dust_pk_hex, &state, last_seen_id, max_id);
    }

    if let Ok(state_hex) = super::dust_sync_cache::encode_state(&state) {
        session_cache::put_dust_ledger_state_hex(scope, &fp, &dust_pk_hex, state_hex);
    }

    Ok(state)
}

/// DUST balance for `ows fund balance` — loads any on-disk snapshot, then incrementally syncs
/// new `dustLedgerEvents` on top (runs until caught up unless the indexer stops sending events).
pub async fn get_dust_balance_for_display_scoped(
    indexer_url: &str,
    dust_seed: &[u8; 32],
    dust_ctime_unix_secs: u64,
    scope: &super::cache_io::SyncCacheScope,
) -> Result<(usize, u128), PayError> {
    get_dust_balance_scoped_with_options(
        indexer_url,
        dust_seed,
        dust_ctime_unix_secs,
        scope,
        DustSyncOptions::for_fund_balance_display(),
        SyncPurpose::Display,
    )
    .await
}

async fn get_dust_balance_scoped_with_options(
    indexer_url: &str,
    dust_seed: &[u8; 32],
    dust_ctime_unix_secs: u64,
    scope: &super::cache_io::SyncCacheScope,
    sync_options: DustSyncOptions,
    purpose: SyncPurpose,
) -> Result<(usize, u128), PayError> {
    let dust_sk = DustSecretKey::derive_secret_key(dust_seed);
    let dust_pk_hex = dust_public_key_hex(&dust_sk)?;
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);

    if session_cache::session_cache_shortcut_allowed(purpose) {
        if let Some(cached) = session_cache::get_dust(scope, &fp, &dust_pk_hex) {
            return Ok(cached);
        }
    }

    // Always load snapshot inside sync (if present) and catch up incrementally.
    let st =
        match sync_dust_local_state_scoped_with_options(indexer_url, &dust_sk, scope, sync_options)
            .await
        {
            Ok(st) => st,
            Err(e)
                if purpose.is_display()
                    && e.to_string().contains("no dust ledger events applied") =>
            {
                match try_load_dust_state_from_disk(indexer_url, &dust_pk_hex, scope) {
                    Some((st, last, max)) => {
                        let tip = if max > 0 {
                            max.to_string()
                        } else {
                            "unknown (snapshot missing chain tip maxId)".to_string()
                        };
                        eprintln!(
                            "[ows-midnight] dust sync: stalled at event {last}/{tip}; \
showing best-effort balance from last saved snapshot \
(increase OWS_MIDNIGHT_DUST_STALL_TIMEOUT_SECS if the indexer is still catching up)"
                        );
                        st
                    }
                    None => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
    let bal = dust_balance_from_state(&st, dust_ctime_unix_secs);
    session_cache::put_dust(scope, &fp, &dust_pk_hex, bal);
    Ok(bal)
}

fn dust_public_key_hex(dust_sk: &DustSecretKey) -> Result<String, PayError> {
    let dust_pk = DustPublicKey::from(dust_sk.clone());
    let mut b = Vec::new();
    dust_pk
        .serialize(&mut b)
        .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
    Ok(hex::encode(b))
}

fn dust_balance_from_state(
    st: &DustLocalState<InMemoryDB>,
    dust_ctime_unix_secs: u64,
) -> (usize, u128) {
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger::dust::DustOutput;

    let dust_ctime = Timestamp::from_secs(dust_ctime_unix_secs);
    let mut sum: u128 = 0;
    let mut n: usize = 0;
    for qdo in st.utxos().collect::<Vec<_>>() {
        let Some(gen_info) = st.generation_info(&qdo) else {
            continue;
        };
        n += 1;
        let v = DustOutput::from(qdo).updated_value(&gen_info, dust_ctime, &st.params);
        sum = sum.saturating_add(v);
    }
    (n, sum)
}

/// Format DUST amount (specks) into a human-readable decimal string.
///
/// The ledger denominates DUST in `SPECKS_PER_DUST` "specks". If that constant is a power of 10
/// (as expected), we render a fixed-point decimal; otherwise we fall back to `"<specks> specks"`.
pub fn format_dust_specks(specks: u128) -> String {
    let scale = midnight_ledger::structure::SPECKS_PER_DUST;
    if scale == 0 {
        return specks.to_string();
    }

    // Check scale is \(10^k\) so fixed-point formatting is unambiguous.
    let mut tmp = scale;
    let mut decimals: u32 = 0;
    while tmp.is_multiple_of(10) {
        tmp /= 10;
        decimals += 1;
    }
    if tmp != 1 {
        return format!("{specks} specks");
    }

    let whole = specks / scale;
    let frac = specks % scale;
    if decimals == 0 {
        return whole.to_string();
    }
    format!("{whole}.{frac:0width$}", width = decimals as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::midnight::cache_io::SyncPurpose;

    #[test]
    fn signing_accepts_chain_tip_after_ws_idle_without_new_events() {
        assert!(dust_ready_to_return(
            SyncPurpose::Signing,
            None,
            100,
            100,
            Some(100),
            true,
            0,
        ));
    }

    #[test]
    fn signing_requires_apply_when_catching_up_to_min_required_event() {
        assert!(!dust_ready_to_return(
            SyncPurpose::Signing,
            Some(101),
            100,
            101,
            Some(101),
            true,
            0,
        ));
        assert!(dust_ready_to_return(
            SyncPurpose::Signing,
            Some(101),
            100,
            101,
            Some(101),
            true,
            1,
        ));
    }

    #[test]
    fn display_may_use_snapshot_tip_without_ws_ack() {
        assert!(dust_ready_to_return(
            SyncPurpose::Display,
            None,
            100,
            100,
            Some(100),
            false,
            0,
        ));
    }
}
