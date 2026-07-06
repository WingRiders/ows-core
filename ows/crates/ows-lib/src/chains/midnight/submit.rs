//! Submit a finalized Midnight ledger transaction (`midnight:transaction…` bytes)
//! to a Midnight node via `author_submitExtrinsic`
//! (`Midnight::send_mn_transaction`).
//!
//! If `submit` fails, we also try `system_dryRun` and `payment_queryInfo` so the
//! caller gets the underlying runtime error rather than a bare submission error.

use super::error::{PayError, PayErrorCode};

use super::urls::http_url_to_ws_url;

/// Node ledger check failure (`InvalidTransaction::Custom(192)`). Observed on the Preview
/// node when an unshielded UTXO input was already spent (replay / stale indexer state).
const LEDGER_BALANCE_CHECK_OUT_OF_BOUNDS: u16 = 192;
/// Node ledger code for per-segment overspend (`InvalidTransaction::Custom(138)`).
const LEDGER_BALANCE_CHECK_OVERSPEND: u16 = 138;
/// Node ledger code for DUST spend proof verification failed (`InvalidTransaction::Custom(170)`).
const LEDGER_INVALID_DUST_SPEND_PROOF: u16 = 170;
/// DUST registration Schnorr signature failed (`InvalidTransaction::Custom(186)`).
const LEDGER_INVALID_DUST_REGISTRATION_SIGNATURE: u16 = 186;
/// Pedersen binding commitment mismatch (`InvalidTransaction::Custom(185)`).
const LEDGER_PEDERSEN_CHECK_FAILURE: u16 = 185;
/// Zswap apply failure: unknown Merkle root, double-spend, etc. (`InvalidTransaction::Custom(103)`).
const LEDGER_ZSWAP_INVALID: u16 = 103;
/// Input references a UTXO absent from ledger state (`InvalidTransaction::Custom(195)`).
const LEDGER_INPUT_NOT_IN_UTXOS: u16 = 195;
/// Unshielded offer input count ≠ signature count (`InvalidTransaction::Custom(191)`).
const LEDGER_INPUTS_SIGNATURES_LENGTH_MISMATCH: u16 = 191;

type SealedTx = midnight_ledger::structure::Transaction<
    midnight_base_crypto::signatures::Signature,
    midnight_ledger::structure::ProofMarker,
    <midnight_ledger::structure::ProofMarker as midnight_ledger::structure::ProofKind<
        midnight_storage::db::InMemoryDB,
    >>::Pedersen,
    midnight_storage::db::InMemoryDB,
>;

/// True when the tx looks like a single-party swap offer (inputs on one side, outputs on
/// another) rather than a self-contained contract call.
fn is_swap_shaped_offer(
    stx: &midnight_ledger::structure::StandardTransaction<
        midnight_base_crypto::signatures::Signature,
        midnight_ledger::structure::ProofMarker,
        <midnight_ledger::structure::ProofMarker as midnight_ledger::structure::ProofKind<
            midnight_storage::db::InMemoryDB,
        >>::Pedersen,
        midnight_storage::db::InMemoryDB,
    >,
) -> bool {
    use std::ops::Deref as _;

    let zswap_output_only = |inputs: usize, outputs: usize| inputs == 0 && outputs > 0;

    for pair_sp in stx.intents.iter() {
        let (_, intent_sp) = pair_sp.deref();
        let intent = intent_sp.deref();
        if let Some(offer) = intent.guaranteed_unshielded_offer.as_ref() {
            let offer = offer.deref();
            if !offer.inputs.is_empty() && offer.outputs.is_empty() {
                return true;
            }
        }
    }

    if let Some(offer) = stx.guaranteed_coins.as_ref() {
        let offer = offer.deref();
        if zswap_output_only(
            offer.inputs.iter_deref().count(),
            offer.outputs.iter_deref().count(),
        ) {
            return true;
        }
    }
    for offer in stx.fallible_coins.values() {
        if zswap_output_only(
            offer.inputs.iter_deref().count(),
            offer.outputs.iter_deref().count(),
        ) {
            return true;
        }
    }

    false
}

/// Detect sealed txs that the ledger will reject on submit (error 138).
///
/// Uses the ledger's own per-segment balance aggregation (intents, zswap deltas,
/// contract transcript effects). Contract calls such as `mintAndSendShielded` may
/// have zswap outputs with no inputs while still being balanced via transients,
/// deltas, and shielded mint effects — the old inputs-vs-outputs heuristic rejected
/// those incorrectly.
fn preflight_sealed_tx_submit(tx: &SealedTx) -> Result<(), PayError> {
    use midnight_ledger::structure::Transaction;

    let Transaction::Standard(stx) = tx else {
        return Ok(());
    };

    let balances = tx.balance(None).map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("transaction balance check failed: {e:?}"),
        )
    })?;

    let overspends: Vec<String> = balances
        .into_iter()
        .filter(|(_, bal)| *bal < 0)
        .map(|((_, segment), bal)| format!("segment {segment} overspent by {}", bal.unsigned_abs()))
        .collect();

    if overspends.is_empty() {
        return Ok(());
    }

    let swap_hint = if is_swap_shaped_offer(stx) {
        " Signing/proving succeeded, but this is not submittable alone: share the sealed hex \
         with a counterparty for balanceSealedTransaction, or use a balanced makeIntent / \
         makeTransfer. See docs/midnight/swap-intent.md"
    } else {
        ""
    };

    Err(PayError::new(
        PayErrorCode::InvalidInput,
        format!(
            "transaction is imbalanced ({}) and will be rejected by the node with ledger error \
             {LEDGER_BALANCE_CHECK_OVERSPEND} (BalanceCheckOverspend).{swap_hint}",
            overspends.join("; ")
        ),
    ))
}

fn append_inputs_signatures_length_mismatch_hint(msg: &mut String) {
    if msg.contains(&format!(
        "Custom error: {LEDGER_INPUTS_SIGNATURES_LENGTH_MISMATCH}"
    )) || msg.contains(&format!(
        "Custom({LEDGER_INPUTS_SIGNATURES_LENGTH_MISMATCH})"
    )) || msg.contains("InputsSignaturesLengthMismatch")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_INPUTS_SIGNATURES_LENGTH_MISMATCH} \
             (InputsSignaturesLengthMismatch): an unshielded offer has UTXO inputs without a \
             matching Schnorr signature per input. This often happens when the dapp pre-filled \
             deposit spends on a sealed tx or when balancing merged new inputs without re-signing. \
             Rebuild with a current `ows` and retry `ows sign send-tx` with a fresh dapp tx."
        ));
    }
}

fn append_balance_out_of_bounds_hint(msg: &mut String) {
    if msg.contains(&format!(
        "Custom error: {LEDGER_BALANCE_CHECK_OUT_OF_BOUNDS}"
    )) || msg.contains(&format!("Custom({LEDGER_BALANCE_CHECK_OUT_OF_BOUNDS})"))
        || msg.contains("BalanceCheckOutOfBounds")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_BALANCE_CHECK_OUT_OF_BOUNDS}: the node rejected the \
             transaction during its ledger check. Empirically the Preview node also returns this \
             code when an unshielded UTXO input was already spent (e.g. the same tx was submitted \
             twice, or the dapp built the tx from stale indexer state). Re-create the transaction \
             in the dapp against fresh wallet state and retry `ows sign send-tx`; if it persists, \
             check that the input UTXOs still exist via `ows fund balance`."
        ));
    }
}

fn append_balance_overspend_hint(msg: &mut String) {
    if msg.contains("Custom error: 138")
        || msg.contains(&format!("Custom({LEDGER_BALANCE_CHECK_OVERSPEND})"))
        || msg.contains("BalanceCheckOverspend")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_BALANCE_CHECK_OVERSPEND} (BalanceCheckOverspend): the tx is \
             cryptographically valid but not ledger-balanced. Swap-style makeIntent offers must be \
             completed via balanceSealedTransaction before submit (docs/midnight/swap-intent.md)."
        ));
    }
}

fn append_invalid_dust_spend_hint(msg: &mut String) {
    if msg.contains(&format!("Custom error: {LEDGER_INVALID_DUST_SPEND_PROOF}"))
        || msg.contains(&format!("Custom({LEDGER_INVALID_DUST_SPEND_PROOF})"))
        || msg.contains("InvalidDustSpendProof")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_INVALID_DUST_SPEND_PROOF} (InvalidDustSpendProof): DUST \
             spend ZK proof verification failed. This usually means stale dust sync (re-run send \
             so the dust ledger catches up), insufficient synced DUST balance, or using dust \
             spends when unregistered NIGHT inputs could fund a generationless registration \
             instead. Ensure the indexer returns block timestamps for UTXOs and pass the wallet \
             dust seed."
        ));
    }
}

fn append_invalid_dust_registration_hint(msg: &mut String) {
    if msg.contains(&format!(
        "Custom error: {LEDGER_INVALID_DUST_REGISTRATION_SIGNATURE}"
    )) || msg.contains(&format!(
        "Custom({LEDGER_INVALID_DUST_REGISTRATION_SIGNATURE})"
    )) || msg.contains("InvalidDustRegistrationSignature")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_INVALID_DUST_REGISTRATION_SIGNATURE} \
             (InvalidDustRegistrationSignature): generationless DUST registration was not signed \
             correctly for the final intent (often after balancing dropped contract claim outputs \
             from the guaranteed segment). Rebuild with a current `ows` and retry `ows sign send-tx`."
        ));
    }
}

fn append_zswap_invalid_hint(msg: &mut String) {
    if msg.contains(&format!("Custom error: {LEDGER_ZSWAP_INVALID}"))
        || msg.contains(&format!("Custom({LEDGER_ZSWAP_INVALID})"))
        || msg.contains("UnknownMerkleRoot")
        || msg.contains("NullifierAlreadyPresent")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_ZSWAP_INVALID} (Zswap): shielded spend rejected on-chain — \
often an unknown coin-tree Merkle root (stale or incorrect wallet sync) or a double-spend. \
Rebuild with a current `ows`, run `ows fund balance` to force shielded catch-up, then retry. \
Do not spend coins that only appear via zswapLedgerEvents fallback unless the shielded session \
also lists them."
        ));
    }
}

fn append_pedersen_check_failure_hint(msg: &mut String) {
    if msg.contains(&format!("Custom error: {LEDGER_PEDERSEN_CHECK_FAILURE}"))
        || msg.contains(&format!("Custom({LEDGER_PEDERSEN_CHECK_FAILURE})"))
        || msg.contains("PedersenCheckFailure")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_PEDERSEN_CHECK_FAILURE} (PedersenCheckFailure): the \
             transaction's Pedersen binding commitment does not match its shielded offers and \
             intents. This often happens when shielded inputs were merged into a proven contract \
             tx without refreshing binding randomness — rebuild with a current `ows` and retry \
             `ows sign send-tx`."
        ));
    }
}

fn append_input_not_in_utxos_hint(msg: &mut String) {
    if msg.contains(&format!("Custom error: {LEDGER_INPUT_NOT_IN_UTXOS}"))
        || msg.contains(&format!("Custom({LEDGER_INPUT_NOT_IN_UTXOS})"))
        || msg.contains("InputNotInUtxos")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_INPUT_NOT_IN_UTXOS} (InputNotInUtxos): a transaction input \
             references a coin that is no longer in the UTXO set (already spent or never existed). \
             This often happens when balancing reuses a cached UTXO snapshot from before a recent \
             submit — retry after `ows fund balance` or wait for wallet sync to catch up."
        ));
    }
}

/// Compute the **ledger** transaction hash (`0x` + 32-byte hex) for a `midnight:transaction…`
/// blob, derived consistently with `midnight-ledger`'s `Transaction::transaction_hash`.
fn midnight_ledger_tx_hash_hex(midnight_tx: &[u8]) -> Result<String, PayError> {
    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofKind, ProofMarker, ProofPreimageMarker, Transaction};
    use midnight_serialize::tagged_deserialize;
    use midnight_storage::db::InMemoryDB;

    type TxMarker = Transaction<
        MnSig,
        ProofMarker,
        <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;
    type TxPreimage = Transaction<
        MnSig,
        ProofPreimageMarker,
        <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;

    let mut reader: &[u8] = midnight_tx;
    if let Ok(tx) = tagged_deserialize::<TxMarker>(&mut reader) {
        let h = tx.transaction_hash();
        return Ok(format!("0x{}", hex::encode(h.0 .0)));
    }
    let mut reader: &[u8] = midnight_tx;
    let tx: TxPreimage = tagged_deserialize::<TxPreimage>(&mut reader).map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("invalid midnight ledger transaction: {e}"),
        )
    })?;
    let h = tx.transaction_hash();
    Ok(format!("0x{}", hex::encode(h.0 .0)))
}

fn node_ws_url(node_rpc_url: &str) -> Result<String, PayError> {
    let trimmed = node_rpc_url.trim_end_matches('/');
    if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        return Ok(trimmed.to_string());
    }
    let Some(ws) = http_url_to_ws_url(trimmed) else {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            format!("invalid Midnight node RPC URL scheme: {node_rpc_url}"),
        ));
    };
    Ok(ws)
}

fn node_http_url(node_rpc_url: &str) -> Result<String, PayError> {
    let trimmed = node_rpc_url.trim();
    let trimmed = trimmed.trim_end_matches('/');

    fn strip_ws_path_suffix(url: &str) -> String {
        // Many node deployments expose WebSocket at `/ws` while HTTP JSON-RPC is at `/`.
        // If a user pastes the WS URL (e.g. `wss://host/ws`), we want `https://host` for dry-run.
        url.strip_suffix("/ws")
            .or_else(|| url.strip_suffix("/ws/"))
            .unwrap_or(url)
            .to_string()
    }

    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return Ok(strip_ws_path_suffix(trimmed));
    }
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return Ok(strip_ws_path_suffix(&format!("https://{rest}")));
    }
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return Ok(strip_ws_path_suffix(&format!("http://{rest}")));
    }
    Err(PayError::new(
        PayErrorCode::InvalidInput,
        format!("invalid Midnight node RPC URL scheme: {node_rpc_url}"),
    ))
}

async fn dry_run_extrinsic(
    node_rpc_url: &str,
    ext_hex: &str,
) -> Result<serde_json::Value, PayError> {
    // Try HTTP first (some providers restrict this; we'll fall back to WS JSON-RPC).
    let http_attempt = async {
        let url = node_http_url(node_rpc_url)?;
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "system_dryRun",
            "params": [ext_hex],
        });
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| {
                PayError::new(
                    PayErrorCode::HttpTransport,
                    format!("system_dryRun request failed: {e}"),
                )
            })?;
        let text = resp.text().await.unwrap_or_default();
        serde_json::from_str(&text).map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("system_dryRun response not json: {e} (body={text})"),
            )
        })
    }
    .await;

    if http_attempt.is_ok() {
        return http_attempt;
    }

    // Fall back to WS JSON-RPC to avoid HTTP 403s / HTML frontends.
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::rpc_params;
    use jsonrpsee::ws_client::WsClientBuilder;

    let ws = node_ws_url(node_rpc_url)?;
    let client = WsClientBuilder::default().build(&ws).await.map_err(|e| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!("system_dryRun ws connect failed: {e}"),
        )
    })?;

    let val: serde_json::Value = client
        .request("system_dryRun", rpc_params![ext_hex])
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("system_dryRun ws request failed: {e}"),
            )
        })?;

    Ok(val)
}

async fn payment_query_info(
    node_rpc_url: &str,
    ext_hex: &str,
) -> Result<serde_json::Value, PayError> {
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::rpc_params;
    use jsonrpsee::ws_client::WsClientBuilder;

    let ws = node_ws_url(node_rpc_url)?;
    let client = WsClientBuilder::default().build(&ws).await.map_err(|e| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!("payment_queryInfo ws connect failed: {e}"),
        )
    })?;

    // `payment_queryInfo(extrinsic_hex, at_hash?)`
    // We pass null for `at` to query at the latest block.
    let val: serde_json::Value = client
        .request(
            "payment_queryInfo",
            rpc_params![ext_hex, serde_json::Value::Null],
        )
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("payment_queryInfo ws request failed: {e}"),
            )
        })?;
    Ok(val)
}

/// Submit a finalized Midnight ledger transaction (`midnight:transaction…` bytes) to a node.
///
/// `node_rpc_url` is a standard Midnight node HTTP JSON-RPC endpoint (e.g.
/// `https://rpc.preview.midnight.network/`). The extrinsic used is
/// `Midnight::send_mn_transaction` wrapping the raw ledger bytes.
///
/// On success returns the **ledger** transaction hash (`0x` + 32-byte hex).
pub async fn submit_unshielded_tx(
    node_rpc_url: &str,
    midnight_tx: &[u8],
) -> Result<String, PayError> {
    use subxt::dynamic::Value;
    use subxt::{OnlineClient, PolkadotConfig};

    let ledger_hex = midnight_ledger_tx_hash_hex(midnight_tx)?;

    // Best-effort local check before hitting the node (helps when broadcasting sealed swap offers).
    {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{ProofKind, ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use midnight_storage::db::InMemoryDB;

        type TxMarker = Transaction<
            MnSig,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;
        let mut reader: &[u8] = midnight_tx;
        if let Ok(tx) = tagged_deserialize::<TxMarker>(&mut reader) {
            preflight_sealed_tx_submit(&tx)?;
        }
    }

    let node_ws_url = node_ws_url(node_rpc_url)?;

    let api = OnlineClient::<PolkadotConfig>::from_url(&node_ws_url)
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("failed to connect to Midnight node RPC: {e}"),
            )
        })?;

    let call = subxt::dynamic::tx(
        "Midnight",
        "send_mn_transaction",
        vec![Value::from_bytes(midnight_tx)],
    );

    let tx_client = api.tx();

    let ext = tx_client.create_unsigned(&call).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to build unsigned extrinsic (check node metadata / pallet name): {e}"),
        )
    })?;

    // Precompute encoded extrinsic hex for diagnostics / dry-run.
    let ext_hex = format!("0x{}", hex::encode(ext.encoded()));

    if let Err(e) = ext.submit().await {
        // Attempt to extract a more helpful runtime error via `system_dryRun`.
        // This requires an HTTP JSON-RPC endpoint; if the user configured a WS-only URL,
        // we still surface that as a hint instead of silently dropping it.
        let mut msg = format!("submit failed: {e}");
        match dry_run_extrinsic(node_rpc_url, &ext_hex).await {
            Ok(dry_val) => {
                msg.push_str(&format!("\nMidnight system_dryRun: {dry_val}"));
                msg.push_str(
                    "\nIf this is a DUST fee / validity issue, ensure the indexer returns \
`transaction.block.timestamp` for UTXOs, pass the wallet dust seed (`UnshieldedTransfer.dust_seed` / \
`ows_lib::decrypt_midnight_dust_seed`), and use a fresh node RPC time for building.",
                );
            }
            Err(dry_err) => {
                msg.push_str(&format!("\nMidnight system_dryRun unavailable: {dry_err}"));
            }
        }

        // `system_dryRun` is often restricted; `payment_queryInfo` is a safer RPC that can still
        // surface useful validity details (or at least confirm the node can decode the extrinsic).
        match payment_query_info(node_rpc_url, &ext_hex).await {
            Ok(info) => msg.push_str(&format!("\nMidnight payment_queryInfo: {info}")),
            Err(info_err) => msg.push_str(&format!(
                "\nMidnight payment_queryInfo unavailable: {info_err}"
            )),
        }
        append_balance_out_of_bounds_hint(&mut msg);
        append_inputs_signatures_length_mismatch_hint(&mut msg);
        append_balance_overspend_hint(&mut msg);
        append_invalid_dust_spend_hint(&mut msg);
        append_invalid_dust_registration_hint(&mut msg);
        append_zswap_invalid_hint(&mut msg);
        append_pedersen_check_failure_hint(&mut msg);
        append_input_not_in_utxos_hint(&mut msg);
        return Err(PayError::new(PayErrorCode::HttpTransport, msg));
    }

    Ok(ledger_hex)
}
