//! Sync the unshielded UTXO set for a Midnight address via the indexer's
//! `unshieldedTransactions` GraphQL-over-WebSocket subscription.
//!
//! Mirrors [`super::shielded_sync`] for the unshielded (transparent) ledger:
//! we replay `created` / `spent` events until we reach `highestTransactionId`,
//! resuming from on-disk snapshots, then verifying catch-up at the indexer chain tip.

use super::error::{PayError, PayErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use super::cache_io::{self, SyncCacheScope, SyncPurpose};
use super::indexer_ws;
use super::midnight_env::{
    dust_verify_idle_timeout_for, midnight_sync_log_enabled, stall_timeout, ws_idle_timeout,
    SyncStream,
};
use super::session_cache;

const SNAPSHOT_VERSION: u32 = 5;
const CACHE_SUBDIR: &str = "unshielded";

/// One spendable unshielded UTXO as reported by the indexer (after replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldedUtxo {
    pub token_type: String,
    pub value: u128,
    pub intent_hash: String,
    pub output_index: i64,
    pub owner: String,
    /// Block timestamp (seconds since Unix epoch) for the creating transaction, when the indexer
    /// provides `transaction.block.timestamp`. Used to bound DUST fee allowance from Night inputs.
    #[serde(default)]
    pub ctime_unix_secs: Option<u64>,
    /// Whether this UTXO is already registered for Dust generation (indexer field).
    /// Matches the ledger's `night_indices` membership used by `generationless_fee_availability`.
    #[serde(default)]
    pub registered_for_dust_generation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnshieldedSyncSnapshot {
    version: u32,
    indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id when the snapshot was written.
    #[serde(default)]
    chain_id: String,
    address: String,
    last_seen_tx_id: i64,
    highest_tx_id_when_saved: i64,
    #[serde(default)]
    block_height_when_saved: i64,
    saved_at_unix: u64,
    utxos: Vec<UnshieldedUtxo>,
}

impl UnshieldedSyncSnapshot {
    fn is_complete(&self) -> bool {
        self.highest_tx_id_when_saved == 0 || self.last_seen_tx_id >= self.highest_tx_id_when_saved
    }
}

fn seed_utxos_from_snapshot(
    snap: &UnshieldedSyncSnapshot,
) -> BTreeMap<(String, i64, String), UnshieldedUtxo> {
    snap.utxos
        .iter()
        .map(|u| {
            let key = (u.intent_hash.clone(), u.output_index, u.token_type.clone());
            (key, u.clone())
        })
        .collect()
}

/// GraphQL subscription (indexer v4 supports optional `transactionId` resume).
const UNSHIELDED_SUBSCRIPTION: &str = r#"
subscription UnshieldedTransactions($address: UnshieldedAddress!, $transactionId: Int) {
  unshieldedTransactions(address: $address, transactionId: $transactionId) {
    __typename
    ... on UnshieldedTransaction {
      transaction { id hash block { timestamp } }
      createdUtxos { tokenType value intentHash outputIndex owner ctime registeredForDustGeneration }
      spentUtxos { tokenType value intentHash outputIndex owner ctime registeredForDustGeneration }
    }
    ... on UnshieldedTransactionsProgress {
      highestTransactionId
    }
  }
}
"#;

/// Retrieve the current *unshielded* UTXO set for a Midnight address (signing / tx-building).
///
/// Resumes from on-disk snapshots then always catches up on the indexer before returning.
pub(crate) async fn get_unshielded_utxos_scoped(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let mut tx_seen = false;
    get_unshielded_utxos_inner(
        indexer_url,
        address,
        scope,
        SyncPurpose::Signing,
        None,
        &mut tx_seen,
    )
    .await
}

/// Unshielded UTXOs for `ows fund balance` — always resumes from disk then catches up on the indexer.
pub async fn get_unshielded_utxos_for_display_scoped(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let mut tx_seen = false;
    get_unshielded_utxos_inner(
        indexer_url,
        address,
        scope,
        SyncPurpose::Display,
        None,
        &mut tx_seen,
    )
    .await
}

fn normalize_ledger_tx_hash(h: &str) -> String {
    let bare = h.strip_prefix("0x").unwrap_or(h).to_ascii_lowercase();
    format!("0x{bare}")
}

fn tx_hashes_match(indexer_hash: &str, ledger_hash: &str) -> bool {
    normalize_ledger_tx_hash(indexer_hash) == normalize_ledger_tx_hash(ledger_hash)
}

/// True when `ledger_tx_hash` appears in a single unshielded sync pass for `address`.
pub(super) async fn unshielded_tx_visible_in_indexer(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
    ledger_tx_hash: &str,
) -> Result<bool, PayError> {
    let target = normalize_ledger_tx_hash(ledger_tx_hash);
    let mut tx_seen = false;
    get_unshielded_utxos_inner(
        indexer_url,
        address,
        scope,
        SyncPurpose::Signing,
        Some(&target),
        &mut tx_seen,
    )
    .await?;
    Ok(tx_seen)
}

/// After node submit, wait until the indexer reflects `ledger_tx_hash` for `address`,
/// then refresh the on-disk snapshot and in-process cache.
///
/// Prefer [`super::post_submit_sync::refresh_after_submit`] when shielded or dust state
/// must also be refreshed.
pub async fn refresh_unshielded_after_submit(
    indexer_url: &str,
    address: &str,
    ledger_tx_hash: &str,
    scope: &SyncCacheScope,
) -> Result<(), PayError> {
    use super::midnight_env::{midnight_sync_log_enabled, post_submit_indexer_wait_timeout};

    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    session_cache::invalidate_site(scope, &fp);

    let wait_timeout = post_submit_indexer_wait_timeout();
    if wait_timeout.as_secs() == 0 {
        return Ok(());
    }

    let target = normalize_ledger_tx_hash(ledger_tx_hash);
    let log = midnight_sync_log_enabled();
    if log {
        eprintln!(
            "[ows-midnight] post-submit: waiting for indexer to reflect tx {target} (up to {}s)…",
            wait_timeout.as_secs()
        );
    }

    let result = tokio::time::timeout(
        wait_timeout,
        wait_until_unshielded_tx_indexed(indexer_url, address, scope, &target, log),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            if log {
                eprintln!(
                    "[ows-midnight] post-submit: timed out after {}s waiting for indexer tx {target}",
                    wait_timeout.as_secs()
                );
            }
            Ok(())
        }
    }
}

async fn wait_until_unshielded_tx_indexed(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
    target_tx_hash: &str,
    log: bool,
) -> Result<(), PayError> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    loop {
        session_cache::invalidate_site(scope, &fp);
        let mut tx_seen = false;
        get_unshielded_utxos_inner(
            indexer_url,
            address,
            scope,
            SyncPurpose::Signing,
            Some(target_tx_hash),
            &mut tx_seen,
        )
        .await?;
        if tx_seen {
            return Ok(());
        }
        if log {
            eprintln!(
                "[ows-midnight] post-submit: tx {target_tx_hash} not in indexer stream yet; retrying…"
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn unshielded_sync_done(progress_received: bool, highest: Option<i64>, last_seen: i64) -> bool {
    if !progress_received {
        return false;
    }
    let Some(h) = highest else {
        return false;
    };
    // `midnight-wallet-cli` / balance-subscription.ts: done when highest is 0 (empty chain tip)
    // or we've applied all transactions up to the reported highest id.
    h == 0 || last_seen >= h
}

fn parse_indexer_timestamp_secs(v: &serde_json::Value) -> Option<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    // Indexer docs say seconds, but some deployments return milliseconds.
    // Heuristic: anything >= year 33658 in seconds is definitely ms.
    if n >= 1_000_000_000_000 {
        Some(n / 1000)
    } else {
        Some(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn process_unshielded_event(
    transaction: TransactionRef,
    created_utxos: Vec<UnshieldedUtxoWire>,
    spent_utxos: Vec<UnshieldedUtxoWire>,
    resume_last_seen: i64,
    last_seen: &mut i64,
    n_txs: &mut u64,
    utxos: &mut BTreeMap<(String, i64, String), UnshieldedUtxo>,
    progress_received: bool,
    highest: Option<i64>,
    log_progress: bool,
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<bool, PayError> {
    if let Some(target) = wait_for_tx_hash {
        if tx_hashes_match(&transaction.hash, target) {
            *tx_seen = true;
        }
    }
    if transaction.id <= resume_last_seen {
        *last_seen = (*last_seen).max(transaction.id);
        *n_txs = n_txs.saturating_add(1);
        if log_progress && (*n_txs == 1 || n_txs.is_multiple_of(1000)) {
            eprintln!(
                "[ows-midnight] unshielded sync progress: last_seen={last_seen} highest={highest:?} txs_seen={n_txs}"
            );
        }
        return Ok(unshielded_sync_done(progress_received, highest, *last_seen));
    }
    *last_seen = (*last_seen).max(transaction.id);
    *n_txs = n_txs.saturating_add(1);
    let block_ts = transaction
        .block
        .as_ref()
        .and_then(|b| b.timestamp.as_ref())
        .and_then(parse_indexer_timestamp_secs);
    for u in created_utxos {
        let key = (u.intent_hash.clone(), u.output_index, u.token_type.clone());
        let val: u128 = u
            .value
            .parse()
            .map_err(|_| PayError::new(PayErrorCode::ProtocolMalformed, "invalid u128 value"))?;
        let utxo_ctime = u
            .ctime
            .as_ref()
            .and_then(parse_indexer_timestamp_secs)
            .or(block_ts);
        utxos.insert(
            key,
            UnshieldedUtxo {
                token_type: u.token_type,
                value: val,
                intent_hash: u.intent_hash,
                output_index: u.output_index,
                owner: u.owner,
                ctime_unix_secs: utxo_ctime,
                registered_for_dust_generation: u.registered_for_dust_generation.unwrap_or(false),
            },
        );
    }
    for u in spent_utxos {
        let key = (u.intent_hash, u.output_index, u.token_type);
        utxos.remove(&key);
    }
    if log_progress && (*n_txs == 1 || n_txs.is_multiple_of(1000)) {
        eprintln!(
            "[ows-midnight] unshielded sync progress: last_seen={last_seen} highest={highest:?} txs_seen={n_txs}"
        );
    }
    Ok(unshielded_sync_done(progress_received, highest, *last_seen))
}

async fn get_unshielded_utxos_inner(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
    purpose: SyncPurpose,
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    if session_cache::session_cache_shortcut_allowed(purpose) {
        if let Some(cached) = session_cache::get_unshielded(scope, &fp, address) {
            return Ok(cached);
        }
    }

    let cache_path = cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, address, scope);

    let mut resume_last_seen: i64 = 0;
    let mut saved_highest_tx_id: i64 = 0;
    let mut saved_block_height: i64 = 0;
    let mut snapshot_at_saved_tip = false;
    let mut utxos: BTreeMap<(String, i64, String), UnshieldedUtxo> = BTreeMap::new();

    if let Some(ref path) = cache_path {
        if let Some(snap) =
            cache_io::try_load_versioned::<UnshieldedSyncSnapshot>(path, SNAPSHOT_VERSION)
        {
            if cache_io::snapshot_site_matches(
                scope,
                &snap.chain_id,
                &fp,
                &snap.indexer_fingerprint,
            ) && snap.address == address
            {
                resume_last_seen = snap.last_seen_tx_id;
                saved_highest_tx_id = snap.highest_tx_id_when_saved;
                saved_block_height = snap.block_height_when_saved;
                snapshot_at_saved_tip = snap.is_complete() && saved_highest_tx_id > 0;
                utxos = seed_utxos_from_snapshot(&snap);
            }
        }
    }

    let log_progress = midnight_sync_log_enabled();
    if super::tip_verify::snapshot_fresh_by_http_tip(
        scope,
        saved_block_height,
        snapshot_at_saved_tip,
    ) {
        if log_progress {
            eprintln!(
                "[ows-midnight] unshielded sync: HTTP tip unchanged (block height={saved_block_height}), using snapshot"
            );
        }
        let list: Vec<UnshieldedUtxo> = utxos.into_values().collect();
        session_cache::put_unshielded(scope, &fp, address, list.clone());
        return Ok(list);
    }
    if snapshot_at_saved_tip
        && super::tip_verify::indexer_block_height_matches_saved(indexer_url, saved_block_height)
            .await
    {
        if log_progress {
            eprintln!(
                "[ows-midnight] unshielded sync: HTTP tip unchanged on re-check (block height={saved_block_height}), using snapshot"
            );
        }
        let list: Vec<UnshieldedUtxo> = utxos.into_values().collect();
        session_cache::put_unshielded(scope, &fp, address, list.clone());
        return Ok(list);
    }
    if snapshot_at_saved_tip && !purpose.must_catch_up_to_indexer_tip() {
        if log_progress {
            eprintln!(
                "[ows-midnight] unshielded sync: display mode — complete on-disk snapshot, skipping WebSocket catch-up"
            );
        }
        let list: Vec<UnshieldedUtxo> = utxos.into_values().collect();
        session_cache::put_unshielded(scope, &fp, address, list.clone());
        return Ok(list);
    }

    let mut last_seen: i64 = resume_last_seen;

    let start_tx_id = if resume_last_seen > 0 {
        Some(resume_last_seen.saturating_add(1))
    } else {
        None
    };

    if log_progress && resume_last_seen > 0 {
        eprintln!(
            "[ows-midnight] unshielded sync: resuming from on-disk state at tx id {} ({} UTXOs)",
            start_tx_id.unwrap_or(1),
            utxos.len()
        );
    } else if log_progress {
        eprintln!("[ows-midnight] unshielded sync: no snapshot, syncing from genesis");
    }

    let stall_timeout = stall_timeout(SyncStream::Unshielded);
    let ws_idle = ws_idle_timeout(SyncStream::Unshielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;
    let short_idle_verify = wait_for_tx_hash.is_none()
        && snapshot_at_saved_tip
        && resume_last_seen > 0
        && resume_last_seen >= saved_highest_tx_id
        && !purpose.must_catch_up_to_indexer_tip();
    let verify_idle = dust_verify_idle_timeout_for(purpose);
    if short_idle_verify && log_progress {
        eprintln!(
            "[ows-midnight] unshielded sync: snapshot at saved tip \
(last_seen_tx_id={resume_last_seen} highest={saved_highest_tx_id}), verifying with indexer…"
        );
    }

    let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;

    let mut sub_vars = serde_json::json!({ "address": address });
    if let Some(id) = start_tx_id {
        sub_vars["transactionId"] = serde_json::json!(id);
    }
    indexer_ws::subscribe(&mut ws, "1", UNSHIELDED_SUBSCRIPTION, sub_vars).await?;

    let mut highest: Option<i64> = None;
    let mut progress_received = false;
    let mut n_txs: u64 = 0;
    let mut sync_done = false;

    while !sync_done {
        let effective_stall = if short_idle_verify && !progress_received {
            verify_idle
        } else {
            stall_timeout
        };
        let stall_elapsed = last_event_at.unwrap_or(sync_started).elapsed();
        if stall_elapsed > effective_stall {
            let tip_id = highest.unwrap_or(saved_highest_tx_id);
            if short_idle_verify && last_seen >= tip_id.max(saved_highest_tx_id) {
                if log_progress {
                    eprintln!(
                        "[ows-midnight] unshielded sync: verify stall {}s, accepting saved tip \
(last_seen_tx_id={last_seen} highest={tip_id})",
                        effective_stall.as_secs()
                    );
                }
                sync_done = true;
                break;
            }
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!(
                    "no unshielded indexer events for {}s (last_seen_tx_id={last_seen} highest={highest:?}); \
indexer may be stalled",
                    effective_stall.as_secs()
                ),
            ));
        }

        let read_timeout = if short_idle_verify && !progress_received {
            verify_idle
        } else {
            ws_idle
        };
        let t = match indexer_ws::read_subscription_text(&mut ws, read_timeout).await? {
            indexer_ws::SubscriptionTextRead::Text(t) => {
                last_event_at = Some(Instant::now());
                t
            }
            indexer_ws::SubscriptionTextRead::Closed => break,
            indexer_ws::SubscriptionTextRead::IdleTimeout => {
                let tip_id = highest.unwrap_or(saved_highest_tx_id);
                if short_idle_verify && last_seen >= tip_id.max(saved_highest_tx_id) {
                    if log_progress {
                        eprintln!(
                            "[ows-midnight] unshielded sync: verify idle {}s, accepting saved tip \
(last_seen_tx_id={last_seen} highest={tip_id})",
                            read_timeout.as_secs()
                        );
                    }
                    sync_done = true;
                    break;
                }
                if log_progress {
                    eprintln!(
                        "[ows-midnight] unshielded sync: no indexer message for {}s (last_seen={last_seen} highest={highest:?})",
                        read_timeout.as_secs()
                    );
                }
                return Err(PayError::new(
                    PayErrorCode::HttpTransport,
                    format!(
                        "Midnight indexer unshielded sync: no WebSocket data for {}s \
(last_seen_tx_id={last_seen} highest={highest:?})",
                        read_timeout.as_secs()
                    ),
                ));
            }
        };

        let frame: indexer_ws::WsFrame<UnshieldedWsData> = serde_json::from_str(&t)
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
                let Some(evt) = payload.data.and_then(|d| d.unshielded_transactions) else {
                    continue;
                };
                match evt {
                    UnshieldedEvent::Progress {
                        highest_transaction_id,
                    } => {
                        highest = Some(highest_transaction_id);
                        progress_received = true;
                        if log_progress {
                            eprintln!(
                                        "[ows-midnight] unshielded sync progress: last_seen={last_seen} highest={highest_transaction_id}"
                                    );
                        }
                        if unshielded_sync_done(progress_received, highest, last_seen) {
                            sync_done = true;
                            if log_progress {
                                eprintln!(
                                            "[ows-midnight] unshielded sync: caught up (last_seen={last_seen} highest={highest_transaction_id})"
                                        );
                            }
                        }
                    }
                    UnshieldedEvent::Tx {
                        transaction,
                        created_utxos,
                        spent_utxos,
                    } => {
                        sync_done = process_unshielded_event(
                            transaction,
                            created_utxos,
                            spent_utxos,
                            resume_last_seen,
                            &mut last_seen,
                            &mut n_txs,
                            &mut utxos,
                            progress_received,
                            highest,
                            log_progress,
                            wait_for_tx_hash,
                            tx_seen,
                        )?;
                    }
                }
            }
            "error" => {
                return Err(PayError::new(
                    PayErrorCode::ProtocolMalformed,
                    format!("indexer subscription error: {t}"),
                ));
            }
            "complete" => break,
            _ => {}
        }
    }

    // Drop the socket instead of awaiting `complete` — some indexers never ack it and block for minutes.
    drop(ws);

    if !sync_done && !unshielded_sync_done(progress_received, highest, last_seen) {
        let tip_id = highest.unwrap_or(saved_highest_tx_id);
        if !(short_idle_verify && last_seen >= tip_id.max(saved_highest_tx_id)) {
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                "Midnight indexer closed the unshielded subscription before sync completed; \
try again or check indexer health."
                    .to_string(),
            ));
        }
    }

    let list: Vec<UnshieldedUtxo> = utxos.into_values().collect();
    let saved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(path) = cache_path {
        let snap = UnshieldedSyncSnapshot {
            version: SNAPSHOT_VERSION,
            indexer_fingerprint: fp.clone(),
            chain_id: cache_io::snapshot_chain_id(scope),
            address: address.to_string(),
            last_seen_tx_id: last_seen,
            highest_tx_id_when_saved: highest.unwrap_or(last_seen),
            block_height_when_saved: super::tip_verify::block_height_for_snapshot(scope),
            saved_at_unix: saved_at,
            utxos: list.clone(),
        };
        cache_io::try_save(&path, &snap);
    }

    session_cache::put_unshielded(scope, &fp, address, list.clone());
    if log_progress {
        eprintln!(
            "[ows-midnight] unshielded sync: finished ({} UTXOs)",
            list.len()
        );
    }
    Ok(list)
}

#[derive(Debug, Default, Deserialize)]
struct UnshieldedWsData {
    #[serde(rename = "unshieldedTransactions")]
    #[serde(default)]
    unshielded_transactions: Option<UnshieldedEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "__typename")]
enum UnshieldedEvent {
    #[serde(rename = "UnshieldedTransactionsProgress")]
    Progress {
        #[serde(rename = "highestTransactionId")]
        highest_transaction_id: i64,
    },
    #[serde(rename = "UnshieldedTransaction")]
    Tx {
        transaction: TransactionRef,
        #[serde(rename = "createdUtxos")]
        created_utxos: Vec<UnshieldedUtxoWire>,
        #[serde(rename = "spentUtxos")]
        spent_utxos: Vec<UnshieldedUtxoWire>,
    },
}

#[derive(Debug, Deserialize)]
struct TransactionRef {
    id: i64,
    hash: String,
    #[serde(default)]
    block: Option<TransactionBlockRef>,
}

#[derive(Debug, Deserialize)]
struct TransactionBlockRef {
    /// Indexer may return seconds as JSON number or string.
    timestamp: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UnshieldedUtxoWire {
    #[serde(rename = "tokenType")]
    token_type: String,
    value: String,
    #[serde(rename = "intentHash")]
    intent_hash: String,
    #[serde(rename = "outputIndex")]
    output_index: i64,
    owner: String,
    #[serde(default)]
    ctime: Option<serde_json::Value>,
    #[serde(rename = "registeredForDustGeneration")]
    #[serde(default)]
    registered_for_dust_generation: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_hashes_match_normalizes_0x_and_case() {
        assert!(tx_hashes_match("0xAbCd", "abcd"));
        assert!(tx_hashes_match("ABCD", "0xabcd"));
        assert!(!tx_hashes_match("0xaaaa", "0xbbbb"));
    }

    #[test]
    fn snapshot_complete_when_last_seen_reaches_saved_highest() {
        let snap = UnshieldedSyncSnapshot {
            version: SNAPSHOT_VERSION,
            indexer_fingerprint: String::new(),
            chain_id: String::new(),
            address: String::new(),
            last_seen_tx_id: 500,
            highest_tx_id_when_saved: 500,
            block_height_when_saved: 0,
            saved_at_unix: 0,
            utxos: vec![],
        };
        assert!(snap.is_complete());
        assert!(snap.last_seen_tx_id >= snap.highest_tx_id_when_saved);
    }
}
