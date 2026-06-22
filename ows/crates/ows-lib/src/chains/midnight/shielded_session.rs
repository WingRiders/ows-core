//! Shielded indexer session: `connect(viewingKey)` + `shieldedTransactions` replay.

use super::error::{PayError, PayErrorCode};
use futures_util::SinkExt as _;
use midnight_coin_structure::coin::{self, QualifiedInfo as QualifiedCoinInfo};
use midnight_coin_structure::transfer;
use midnight_ledger::events::{Event, EventDetails};
use midnight_serialize::{tagged_deserialize, Serializable as _};
use midnight_storage::db::InMemoryDB;
use midnight_zswap::keys::{SecretKeys as ZswapSecretKeys, Seed as ZswapSeed};
use midnight_zswap::local::State as ZswapLocalState;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use transient_crypto::merkle_tree::MerkleTreeCollapsedUpdate;

use super::cache_io::{self, SyncCacheScope};
use super::indexer_ws::{self, IndexerWs};
use super::ledger_params::indexer_http_client;
use super::midnight_env::{self, MidnightNetwork, SyncStream};
use super::shielded_sync_cache;
use super::ShieldedBalances;

const CONNECT_MUTATION: &str = r#"mutation Connect($vk: ViewingKey!) { connect(viewingKey: $vk) }"#;
const DISCONNECT_MUTATION: &str =
    r#"mutation Disconnect($sid: HexEncoded!) { disconnect(sessionId: $sid) }"#;

/// Subscription shape for `shieldedTransactions` (Indexer v4).
pub(super) const SHIELDED_SUBSCRIPTION: &str = r#"
subscription ShieldedTransactions($sessionId: HexEncoded!, $index: Int) {
  shieldedTransactions(sessionId: $sessionId, index: $index) {
    __typename
    ... on RelevantTransaction {
      transaction {
        id
        raw
        startIndex
        endIndex
        zswapLedgerEvents { id raw maxId protocolVersion }
      }
      collapsedMerkleTree { startIndex endIndex update protocolVersion }
    }
    ... on ShieldedTransactionsProgress {
      highestEndIndex
      highestCheckedEndIndex
      highestRelevantEndIndex
    }
  }
}
"#;

/// Wall-clock timeout for a full shielded sync.
pub(super) const SHIELDED_SYNC_TIMEOUT: Duration = Duration::from_secs(300);

pub(super) fn zswap_secret_keys_from_seed(seed_32: &[u8]) -> Result<ZswapSecretKeys, PayError> {
    let arr: [u8; 32] = seed_32.try_into().map_err(|_| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("shielded seed must be 32 bytes (got {})", seed_32.len()),
        )
    })?;
    Ok(ZswapSecretKeys::from(ZswapSeed::from(arr)))
}

fn bech32m_encode(hrp: &str, payload: &[u8]) -> Result<String, PayError> {
    use bech32::{Bech32m, Hrp};
    let hrp = Hrp::parse(hrp)
        .map_err(|e| PayError::new(PayErrorCode::InvalidInput, format!("invalid hrp: {e}")))?;
    bech32::encode::<Bech32m>(hrp, payload)
        .map_err(|e| PayError::new(PayErrorCode::InvalidInput, format!("bech32m encode: {e}")))
}

/// The indexer `ViewingKey` is a bech32m-encoded Zswap **encryption secret key**
/// (`mn_shield-esk(_preview)?1...`), per the indexer validation error messages.
///
/// Unfortunately there are multiple encodings in the ecosystem; we try both:
/// - raw `repr()` bytes (32)
/// - canonical tagged serialization (`Serializable`)
pub(super) fn viewing_key_candidates_from_secret_keys(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
) -> Result<Vec<String>, PayError> {
    let hrp = MidnightNetwork::from_indexer_url(indexer_url).viewing_key_hrp();
    let mut out = Vec::new();
    let mut esk_ser = Vec::new();
    keys.encryption_secret_key
        .serialize(&mut esk_ser)
        .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
    out.push(bech32m_encode(hrp, &esk_ser)?);
    out.push(bech32m_encode(hrp, &keys.encryption_secret_key.repr())?);
    Ok(out)
}

pub(super) async fn connect_session(
    indexer_url: &str,
    viewing_key: &str,
) -> Result<String, PayError> {
    let client = indexer_http_client();
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": CONNECT_MUTATION,
            "variables": { "vk": viewing_key }
        }))
        .send()
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("indexer connect failed: {e}"),
            )
        })?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer connect returned {status}: {body}"),
        ));
    }

    #[derive(Deserialize)]
    struct ConnectData {
        connect: String,
    }
    #[derive(Deserialize)]
    struct GraphqlResp<T> {
        data: Option<T>,
        errors: Option<Vec<serde_json::Value>>,
    }

    let parsed: GraphqlResp<ConnectData> = serde_json::from_str(&body).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid indexer json: {e}"),
        )
    })?;
    if let Some(errs) = parsed.errors {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer connect GraphQL error: {errs:?}"),
        ));
    }
    parsed
        .data
        .map(|d| d.connect)
        .ok_or_else(|| PayError::new(PayErrorCode::ProtocolMalformed, "missing connect response"))
}

pub(super) async fn disconnect_session(indexer_url: &str, session_id: &str) {
    let client = indexer_http_client();
    let _ = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": DISCONNECT_MUTATION,
            "variables": { "sid": session_id }
        }))
        .send()
        .await;
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ShieldedWsData {
    #[serde(rename = "shieldedTransactions")]
    #[serde(default)]
    pub(super) shielded_transactions: Option<ShieldedEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "__typename")]
pub(super) enum ShieldedEvent {
    #[serde(rename = "ShieldedTransactionsProgress")]
    Progress {
        #[serde(rename = "highestEndIndex")]
        highest_end_index: i64,
        #[serde(rename = "highestCheckedEndIndex")]
        highest_checked_end_index: i64,
        #[serde(rename = "highestRelevantEndIndex")]
        highest_relevant_end_index: i64,
    },
    #[serde(rename = "RelevantTransaction")]
    RelevantTransaction {
        transaction: RegularTransactionRef,
        #[allow(dead_code)]
        #[serde(rename = "collapsedMerkleTree")]
        collapsed_merkle_tree: Option<CollapsedMerkleTreeRef>,
    },
}

#[derive(Debug, Deserialize)]
pub(super) struct CollapsedMerkleTreeRef {
    #[allow(dead_code)]
    #[serde(rename = "startIndex")]
    start_index: i64,
    #[allow(dead_code)]
    #[serde(rename = "endIndex")]
    end_index: i64,
    pub(super) update: String,
    #[allow(dead_code)]
    #[serde(rename = "protocolVersion")]
    protocol_version: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct RegularTransactionRef {
    #[allow(dead_code)]
    id: i64,
    #[allow(dead_code)]
    raw: String,
    #[allow(dead_code)]
    #[serde(rename = "startIndex")]
    start_index: i64,
    #[allow(dead_code)]
    #[serde(rename = "endIndex")]
    end_index: i64,
    #[serde(rename = "zswapLedgerEvents")]
    pub(super) zswap_ledger_events: Vec<ZswapLedgerEventRef>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ZswapLedgerEventRef {
    #[allow(dead_code)]
    pub(super) id: i64,
    pub(super) raw: String,
    #[allow(dead_code)]
    #[serde(rename = "maxId")]
    max_id: i64,
    #[allow(dead_code)]
    #[serde(rename = "protocolVersion")]
    protocol_version: i64,
}

pub(super) fn shielded_sync_done(
    progress_received: bool,
    highest_end: Option<i64>,
    highest_checked: i64,
    highest_relevant: i64,
) -> bool {
    if !progress_received {
        return false;
    }
    let Some(h) = highest_end else {
        return false;
    };
    if highest_checked < h {
        return false;
    }
    // Indexer can report tip 0 on an empty relevant set while the chain has blocks; wait until
    // relevant catch-up is also reported at the tip when the chain has relevant history.
    if h == 0 && highest_relevant > 0 {
        return false;
    }
    true
}

pub(super) fn token_type_hex(ci: &coin::Info) -> String {
    let t = ci.type_.into_inner();
    format!("0x{}", hex::encode(t.0))
}

/// Synced shielded wallet state used to build Zswap offers (e.g. DApp Connector `makeIntent`).
pub struct ShieldedWalletState {
    pub keys: ZswapSecretKeys,
    pub zswap: ZswapLocalState<InMemoryDB>,
}

/// Rehash the shielded Merkle tree after session replay (collapsed updates already applied).
///
/// Do not patch individual leaves here: `try_update_hash` on a collapsed tree produces a root
/// the chain does not recognize (`Invalid Transaction` / Zswap error 103).
pub(super) fn ensure_shielded_merkle_ready(
    wallet: &mut ShieldedWalletState,
) -> Result<(), PayError> {
    wallet.zswap.merkle_tree = wallet.zswap.merkle_tree.rehash();
    if wallet.zswap.merkle_tree.root().is_none() {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            "shielded Merkle tree has no root after sync; indexer shielded session may be incomplete",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum ShieldedReplayMode {
    BalanceOnly,
    WalletState,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum ShieldedReplayOutcome {
    Balances(ShieldedBalances),
    Wallet(ShieldedWalletState),
}

#[allow(clippy::large_enum_variant)]
enum ShieldedReplayAccum {
    Balance {
        owned: BTreeMap<coin::Nullifier, coin::Info>,
        relevant_txs: u64,
        zswap_events_seen: u64,
        zswap_outputs_seen: u64,
        zswap_outputs_decrypted: u64,
        zswap_inputs_seen: u64,
    },
    Wallet {
        zswap: ZswapLocalState<InMemoryDB>,
        owned: BTreeMap<coin::Nullifier, QualifiedCoinInfo>,
        relevant_txs: u64,
        zswap_outputs_decrypted: u64,
    },
}

fn apply_collapsed_merkle_update(
    zswap: &mut ZswapLocalState<InMemoryDB>,
    update_hex: &str,
) -> Result<(), PayError> {
    let raw = update_hex.strip_prefix("0x").unwrap_or(update_hex);
    let bytes = hex::decode(raw).map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("invalid collapsed merkle update hex: {e}"),
        )
    })?;
    let mut reader: &[u8] = &bytes;
    let upd: MerkleTreeCollapsedUpdate = tagged_deserialize(&mut reader).map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("decode collapsed merkle update: {e}"),
        )
    })?;
    let tree = zswap
        .merkle_tree
        .apply_collapsed_update(&upd)
        .map_err(|e| {
            PayError::new(
                PayErrorCode::InvalidInput,
                format!("apply collapsed merkle update: {e:?}"),
            )
        })?
        .rehash();
    zswap.merkle_tree = tree;
    zswap.first_free = zswap.first_free.max(upd.end.saturating_add(1));
    Ok(())
}

impl ShieldedReplayAccum {
    fn new(mode: ShieldedReplayMode) -> Self {
        match mode {
            ShieldedReplayMode::BalanceOnly => Self::Balance {
                owned: BTreeMap::new(),
                relevant_txs: 0,
                zswap_events_seen: 0,
                zswap_outputs_seen: 0,
                zswap_outputs_decrypted: 0,
                zswap_inputs_seen: 0,
            },
            ShieldedReplayMode::WalletState => Self::Wallet {
                zswap: ZswapLocalState::new(),
                owned: BTreeMap::new(),
                relevant_txs: 0,
                zswap_outputs_decrypted: 0,
            },
        }
    }

    fn on_collapsed_merkle(&mut self, update: &str) -> Result<(), PayError> {
        if let Self::Wallet { zswap, .. } = self {
            apply_collapsed_merkle_update(zswap, update)?;
        }
        Ok(())
    }

    fn on_zswap_event(&mut self, keys: &ZswapSecretKeys, ev: Event<InMemoryDB>) {
        match self {
            Self::Balance {
                owned,
                zswap_events_seen,
                zswap_outputs_seen,
                zswap_outputs_decrypted,
                zswap_inputs_seen,
                ..
            } => {
                *zswap_events_seen = zswap_events_seen.saturating_add(1);
                match ev.content {
                    EventDetails::ZswapOutput {
                        preimage_evidence,
                        mt_index: _,
                        ..
                    } => {
                        *zswap_outputs_seen = zswap_outputs_seen.saturating_add(1);
                        if let Some(ci) = preimage_evidence.try_with_keys(keys) {
                            *zswap_outputs_decrypted = zswap_outputs_decrypted.saturating_add(1);
                            let nul = ci.nullifier(&transfer::SenderEvidence::User(
                                std::borrow::Cow::Borrowed(&keys.coin_secret_key),
                            ));
                            owned.insert(nul, ci);
                        }
                    }
                    EventDetails::ZswapInput { nullifier, .. } => {
                        *zswap_inputs_seen = zswap_inputs_seen.saturating_add(1);
                        owned.remove(&nullifier);
                    }
                    _ => {}
                }
            }
            Self::Wallet {
                zswap,
                owned,
                relevant_txs: _,
                zswap_outputs_decrypted,
            } => match ev.content {
                EventDetails::ZswapOutput {
                    preimage_evidence,
                    mt_index,
                    ..
                } => {
                    if let Some(ci) = preimage_evidence.try_with_keys(keys) {
                        *zswap_outputs_decrypted = zswap_outputs_decrypted.saturating_add(1);
                        let qci = ci.qualify(mt_index);
                        let nul =
                            coin::Info::from(&qci).nullifier(&transfer::SenderEvidence::User(
                                std::borrow::Cow::Borrowed(&keys.coin_secret_key),
                            ));
                        owned.insert(nul, qci);
                        zswap.coins = zswap.coins.insert(nul, qci);
                        zswap.first_free = zswap.first_free.max(mt_index.saturating_add(1));
                    }
                }
                EventDetails::ZswapInput { nullifier, .. } => {
                    owned.remove(&nullifier);
                    zswap.coins = zswap.coins.remove(&nullifier);
                }
                _ => {}
            },
        }
    }

    fn finish(self, keys: &ZswapSecretKeys) -> ShieldedReplayOutcome {
        match self {
            Self::Balance { owned, .. } => {
                let mut balances: ShieldedBalances = BTreeMap::new();
                for ci in owned.into_values() {
                    *balances.entry(token_type_hex(&ci)).or_insert(0) += ci.value;
                }
                ShieldedReplayOutcome::Balances(balances)
            }
            Self::Wallet { zswap, .. } => {
                let mut wallet = ShieldedWalletState {
                    keys: keys.clone(),
                    zswap,
                };
                let _ = ensure_shielded_merkle_ready(&mut wallet);
                ShieldedReplayOutcome::Wallet(wallet)
            }
        }
    }
}

/// Insert qualified coins from zswap-ledger snapshot into session wallet state (no Merkle patching).
pub(super) fn hydrate_wallet_from_zswap_snapshot(
    indexer_url: &str,
    shielded_seed_32: &[u8],
    scope: &SyncCacheScope,
    wallet: &mut ShieldedWalletState,
) -> usize {
    let seed_fp = shielded_sync_cache::shielded_seed_fingerprint(shielded_seed_32);
    let qualified = super::zswap_ledger_sync::load_zswap_qualified_coins_from_snapshot(
        indexer_url,
        scope,
        &seed_fp,
    );
    let log = midnight_env::midnight_sync_log_enabled();
    let mut added = 0usize;
    for (nul, qci) in qualified {
        if wallet.zswap.coins.get(&nul).is_none() {
            wallet.zswap.coins = wallet.zswap.coins.insert(nul, qci);
            added = added.saturating_add(1);
        }
    }
    if log && added > 0 {
        eprintln!(
            "[ows-midnight] shielded spend: hydrated {added} qualified coin(s) from zswap-ledger snapshot"
        );
    }
    added
}

/// Full shielded wallet sync (Merkle tree + spendable qualified coins) for Zswap spends.
pub async fn sync_shielded_wallet_state_scoped(
    indexer_url: &str,
    shielded_seed_32: &[u8],
    scope: &SyncCacheScope,
) -> Result<ShieldedWalletState, PayError> {
    if midnight_env::shielded_vk_free_sync_enabled() {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            "shielded spend sync requires indexer connect(viewingKey); unset \
             OWS_MIDNIGHT_SHIELDED_VK_FREE or use unshielded-only transactions",
        ));
    }
    let keys = zswap_secret_keys_from_seed(shielded_seed_32)?;
    let network = MidnightNetwork::from_indexer_url(indexer_url);
    let viewing_key_candidates = viewing_key_candidates_from_secret_keys(indexer_url, &keys)?;

    tokio::time::timeout(SHIELDED_SYNC_TIMEOUT, async {
        let mut wallet = if midnight_env::shielded_zswap_spend_wallet_enabled(network) {
            if midnight_env::midnight_sync_log_enabled() {
                eprintln!(
                    "[ows-midnight] shielded spend: building wallet from zswapLedgerEvents replay"
                );
            }
            super::zswap_ledger_sync::sync_shielded_wallet_from_zswap_ledger_scoped(
                indexer_url,
                &keys,
                scope,
                super::midnight_env::SyncPurpose::Signing,
            )
            .await?
        } else {
            ShieldedWalletState {
                keys: keys.clone(),
                zswap: ZswapLocalState::new(),
            }
        };

        let zswap_coins = wallet.zswap.coins.iter().count();
        if zswap_coins == 0 {
            let (res, _vk_fp) = replay_shielded_session_best_vk(
                indexer_url,
                &keys,
                &viewing_key_candidates,
                ShieldedReplayMode::WalletState,
                None,
            )
            .await?;
            wallet = match res {
                ShieldedReplayOutcome::Wallet(w) => w,
                ShieldedReplayOutcome::Balances(_) => {
                    return Err(PayError::new(
                        PayErrorCode::InvalidInput,
                        "shielded wallet replay returned balances".to_string(),
                    ));
                }
            };
            if midnight_env::midnight_sync_log_enabled() {
                eprintln!(
                    "[ows-midnight] shielded spend: zswap replay empty, fell back to viewing-key session ({} coins)",
                    wallet.zswap.coins.iter().count()
                );
            }
        } else if midnight_env::midnight_sync_log_enabled() {
            eprintln!(
                "[ows-midnight] shielded spend: zswapLedgerEvents wallet ready ({zswap_coins} coins)"
            );
        }

        if midnight_env::shielded_zswap_spend_hydrate_enabled(network) {
            hydrate_wallet_from_zswap_snapshot(indexer_url, shielded_seed_32, scope, &mut wallet);
        }
        ensure_shielded_merkle_ready(&mut wallet)?;
        Ok(wallet)
    })
    .await
    .map_err(|_| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!(
                "Midnight shielded wallet sync timed out after {}s",
                SHIELDED_SYNC_TIMEOUT.as_secs()
            ),
        )
    })?
}

pub(super) async fn replay_shielded_transactions_via_session(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    session_id: &str,
    mode: ShieldedReplayMode,
    scope: Option<&SyncCacheScope>,
    vk_fp: Option<&str>,
) -> Result<ShieldedReplayOutcome, PayError> {
    let log = midnight_env::midnight_sync_log_enabled();
    let ws_idle = midnight_env::ws_idle_timeout(SyncStream::Shielded);

    let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;

    indexer_ws::subscribe(
        &mut ws,
        "1",
        SHIELDED_SUBSCRIPTION,
        serde_json::json!({ "sessionId": session_id, "index": null }),
    )
    .await?;

    let mut accum = ShieldedReplayAccum::new(mode);
    let mut highest_end: Option<i64> = None;
    let mut highest_checked: i64 = 0;
    let mut highest_relevant: i64 = 0;
    let mut progress_received = false;
    let mut applied_event_ids = BTreeSet::new();

    replay_shielded_ws_loop(
        &mut ws,
        keys,
        &mut accum,
        &mut highest_end,
        &mut highest_checked,
        &mut highest_relevant,
        &mut progress_received,
        &mut applied_event_ids,
        log,
    )
    .await?;

    let _ = ws
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({ "id": "1", "type": "complete" }).to_string(),
        ))
        .await;

    if !shielded_sync_done(
        progress_received,
        highest_end,
        highest_checked,
        highest_relevant,
    ) {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            "Midnight indexer closed the shielded subscription before sync completed; try again."
                .to_string(),
        ));
    }

    if log {
        match &accum {
            ShieldedReplayAccum::Balance {
                relevant_txs,
                zswap_events_seen,
                zswap_outputs_seen,
                zswap_outputs_decrypted,
                zswap_inputs_seen,
                owned,
            } => {
                let coins_unspent: u128 = owned.values().map(|ci| ci.value).sum();
                eprintln!(
                    "[ows-midnight] shielded sync done: relevant_txs={relevant_txs} zswap_events_seen={zswap_events_seen} zswap_outputs_seen={zswap_outputs_seen} zswap_outputs_decrypted={zswap_outputs_decrypted} zswap_inputs_seen={zswap_inputs_seen} coins_unspent={coins_unspent} highest_relevant_end_index={highest_relevant}"
                );
            }
            ShieldedReplayAccum::Wallet {
                relevant_txs,
                zswap_outputs_decrypted,
                zswap,
                ..
            } => {
                let coins_unspent: u128 = zswap.coins.iter().map(|(_, q)| q.value).sum();
                eprintln!(
                    "[ows-midnight] shielded wallet sync done: relevant_txs={relevant_txs} zswap_outputs_decrypted={zswap_outputs_decrypted} spendable_coins={} coins_unspent={coins_unspent} highest_relevant_end_index={highest_relevant}",
                    zswap.coins.iter().count()
                );
            }
        }
    }

    let outcome = accum.finish(keys);
    maybe_save_session_snapshot(
        indexer_url,
        scope,
        vk_fp,
        &outcome,
        highest_checked,
        highest_end,
    );
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
async fn replay_shielded_ws_loop(
    ws: &mut IndexerWs,
    keys: &ZswapSecretKeys,
    accum: &mut ShieldedReplayAccum,
    highest_end: &mut Option<i64>,
    highest_checked: &mut i64,
    highest_relevant: &mut i64,
    progress_received: &mut bool,
    applied_event_ids: &mut BTreeSet<i64>,
    log: bool,
) -> Result<(), PayError> {
    use std::time::Instant;

    let ws_idle = midnight_env::ws_idle_timeout(SyncStream::Shielded);
    let stall_timeout = midnight_env::stall_timeout(SyncStream::Shielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;

    loop {
        let stall_elapsed = last_event_at.unwrap_or(sync_started).elapsed();
        if stall_elapsed > stall_timeout {
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!(
                    "no shielded indexer events for {}s (highest_end={highest_end:?} highest_checked={highest_checked}); \
indexer may be stalled",
                    stall_timeout.as_secs()
                ),
            ));
        }

        let t = match indexer_ws::read_subscription_text(ws, ws_idle).await? {
            indexer_ws::SubscriptionTextRead::Text(t) => {
                last_event_at = Some(Instant::now());
                t
            }
            indexer_ws::SubscriptionTextRead::Closed => break,
            indexer_ws::SubscriptionTextRead::IdleTimeout => {
                return Err(PayError::new(
                    PayErrorCode::HttpTransport,
                    format!(
                        "Midnight indexer shielded sync: no WebSocket data for {}s \
(highest_end={highest_end:?} highest_checked={highest_checked})",
                        ws_idle.as_secs()
                    ),
                ));
            }
        };

        let frame: indexer_ws::WsFrame<ShieldedWsData> = serde_json::from_str(&t)
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
                let Some(evt) = payload.data.and_then(|d| d.shielded_transactions) else {
                    continue;
                };
                match evt {
                    ShieldedEvent::Progress {
                        highest_end_index,
                        highest_checked_end_index,
                        highest_relevant_end_index,
                    } => {
                        *highest_end = Some(highest_end_index);
                        *highest_checked = highest_checked_end_index;
                        *highest_relevant = (*highest_relevant).max(highest_relevant_end_index);
                        *progress_received = true;
                        if log {
                            eprintln!(
                                "[ows-midnight] shielded sync progress: highest_end_index={highest_end_index} highest_checked_end_index={highest_checked_end_index} highest_relevant_end_index={highest_relevant_end_index}"
                            );
                        }
                        if shielded_sync_done(
                            *progress_received,
                            *highest_end,
                            *highest_checked,
                            *highest_relevant,
                        ) {
                            break;
                        }
                    }
                    ShieldedEvent::RelevantTransaction {
                        transaction,
                        collapsed_merkle_tree,
                    } => {
                        if let Some(CollapsedMerkleTreeRef { update, .. }) = collapsed_merkle_tree {
                            accum.on_collapsed_merkle(&update)?;
                        }
                        for ze in &transaction.zswap_ledger_events {
                            if !applied_event_ids.insert(ze.id) {
                                continue;
                            }
                            let raw_hex = ze.raw.strip_prefix("0x").unwrap_or(ze.raw.as_str());
                            let bytes = hex::decode(raw_hex).map_err(|e| {
                                PayError::new(
                                    PayErrorCode::ProtocolMalformed,
                                    format!("invalid zswap event raw hex: {e}"),
                                )
                            })?;
                            let mut reader: &[u8] = &bytes;
                            let ev: Event<InMemoryDB> =
                                tagged_deserialize(&mut reader).map_err(|e| {
                                    PayError::new(
                                        PayErrorCode::ProtocolMalformed,
                                        format!("decode zswap event: {e}"),
                                    )
                                })?;
                            accum.on_zswap_event(keys, ev);
                        }
                        match accum {
                            ShieldedReplayAccum::Balance { relevant_txs, .. } => {
                                *relevant_txs = relevant_txs.saturating_add(1);
                            }
                            ShieldedReplayAccum::Wallet { relevant_txs, .. } => {
                                *relevant_txs = relevant_txs.saturating_add(1);
                            }
                        }
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
    Ok(())
}

fn maybe_save_session_snapshot(
    indexer_url: &str,
    scope: Option<&SyncCacheScope>,
    vk_fp: Option<&str>,
    outcome: &ShieldedReplayOutcome,
    highest_checked: i64,
    highest_end: Option<i64>,
) {
    let (ShieldedReplayOutcome::Balances(balances), Some(scope), Some(vk_fp)) =
        (outcome, scope, vk_fp)
    else {
        return;
    };
    let network = MidnightNetwork::from_indexer_url(indexer_url);
    if balances.is_empty() && midnight_env::shielded_zswap_fallback_enabled(network) {
        return;
    }
    if let Some(path) = shielded_sync_cache::snapshot_path(indexer_url, vk_fp, scope) {
        let saved_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        shielded_sync_cache::try_save_snapshot(
            &path,
            &shielded_sync_cache::ShieldedSyncSnapshot {
                version: shielded_sync_cache::SNAPSHOT_VERSION,
                indexer_fingerprint: cache_io::sync_site_fingerprint(indexer_url, scope),
                chain_id: cache_io::snapshot_chain_id(scope),
                viewing_key_fingerprint: vk_fp.to_string(),
                highest_checked_end_index: highest_checked,
                highest_end_index_when_saved: highest_end.unwrap_or(highest_checked),
                last_seen_zswap_event_id: 0,
                max_zswap_id_when_saved: 0,
                saved_at_unix: saved_at,
                balances: balances.clone(),
                zswap_owned_coins: vec![],
            },
        );
    }
}

fn shielded_replay_outcome_score(outcome: &ShieldedReplayOutcome) -> u128 {
    match outcome {
        ShieldedReplayOutcome::Balances(b) => b.values().copied().sum(),
        ShieldedReplayOutcome::Wallet(w) => w.zswap.coins.iter().map(|(_, q)| q.value).sum(),
    }
}

/// Try each viewing-key encoding; keep the session replay with the largest decrypted balance.
pub(super) async fn replay_shielded_session_best_vk(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    viewing_key_candidates: &[String],
    mode: ShieldedReplayMode,
    scope: Option<&SyncCacheScope>,
) -> Result<(ShieldedReplayOutcome, String), PayError> {
    let log = midnight_env::midnight_sync_log_enabled();
    let mut best: Option<(ShieldedReplayOutcome, String, u128)> = None;
    let mut last_connect_err: Option<PayError> = None;

    for vk in viewing_key_candidates {
        let vk_fp = shielded_sync_cache::viewing_key_fingerprint(vk);
        let session_id = match connect_session(indexer_url, vk).await {
            Ok(sid) => sid,
            Err(e) => {
                last_connect_err = Some(e);
                continue;
            }
        };
        let res = replay_shielded_transactions_via_session(
            indexer_url,
            keys,
            &session_id,
            mode,
            scope,
            Some(&vk_fp),
        )
        .await;
        disconnect_session(indexer_url, &session_id).await;
        let Ok(outcome) = res else {
            continue;
        };
        let score = shielded_replay_outcome_score(&outcome);
        if log {
            eprintln!(
                "[ows-midnight] shielded session vk_fp={vk_fp}: score={score} (picking best of {})",
                viewing_key_candidates.len()
            );
        }
        if best.as_ref().is_none_or(|(_, _, s)| score > *s) {
            best = Some((outcome, vk_fp, score));
        }
    }

    let Some((outcome, vk_fp, _)) = best else {
        return Err(last_connect_err.unwrap_or_else(|| {
            PayError::new(
                PayErrorCode::InvalidInput,
                "no viewing key candidates connected to the indexer".to_string(),
            )
        }));
    };
    Ok((outcome, vk_fp))
}

pub(super) async fn get_shielded_balances_inner(
    indexer_url: &str,
    keys: &ZswapSecretKeys,
    viewing_key_candidates: &[String],
    scope: &SyncCacheScope,
    _vk_fp: &str,
) -> Result<ShieldedBalances, PayError> {
    let (outcome, _) = replay_shielded_session_best_vk(
        indexer_url,
        keys,
        viewing_key_candidates,
        ShieldedReplayMode::BalanceOnly,
        Some(scope),
    )
    .await?;
    match outcome {
        ShieldedReplayOutcome::Balances(balances) => Ok(balances),
        ShieldedReplayOutcome::Wallet(_) => Err(PayError::new(
            PayErrorCode::InvalidInput,
            "shielded balance replay returned wallet state".to_string(),
        )),
    }
}
