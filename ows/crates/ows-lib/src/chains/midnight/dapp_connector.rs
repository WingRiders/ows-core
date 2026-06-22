//! DApp Connector [`makeTransfer`] and [`makeIntent`] inputs for sign/send flows.
//!
//! JSON field names and shapes follow the Midnight DApp Connector API specification.

use super::error::{PayError, PayErrorCode};
use bech32::Hrp;
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Info as CoinInfo, PublicKey as CoinPublicKey, QualifiedInfo as QualifiedCoinInfo,
    ShieldedTokenType, UnshieldedTokenType, UserAddress, NIGHT,
};
use midnight_ledger::structure::{
    Intent, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput,
    UtxoSpend,
};
use midnight_serialize::tagged_serialize;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Input as ZswapInput, Offer as ZswapOffer, Output as ZswapOutput};
use ows_signer::chains::MidnightSigner;
use ows_signer::ChainSigner as _;
use rand::{rngs::OsRng, Rng as _};
use serde::Deserialize;
use std::io::Cursor;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::encryption;
use transient_crypto::proofs::ProofPreimage;

use super::balance;
use super::shielded_session::{sync_shielded_wallet_state_scoped, ShieldedWalletState};
use super::{parse_token_type, SyncCacheScope, TokenType, UnshieldedUtxo};

fn err(msg: impl Into<String>) -> PayError {
    PayError::new(PayErrorCode::InvalidInput, msg)
}

/// Default intent segment for [`makeTransfer`] (connector convention).
pub const MAKE_TRANSFER_SEGMENT: u16 = 1;

/// Parsed DApp Connector `--tx` JSON.
#[derive(Debug, Clone)]
pub enum ConnectorTxRequest {
    MakeTransfer(MakeTransferRequest),
    MakeIntent(MakeIntentRequest),
}

/// `makeTransfer(desiredOutputs, options?)`
#[derive(Debug, Clone)]
pub struct MakeTransferRequest {
    pub desired_outputs: Vec<DesiredOutput>,
    pub pay_fees: bool,
}

/// `makeIntent(desiredInputs, desiredOutputs, options)`
#[derive(Debug, Clone)]
pub struct MakeIntentRequest {
    pub desired_inputs: Vec<DesiredInput>,
    pub desired_outputs: Vec<DesiredOutput>,
    pub intent_segment: u16,
    pub pay_fees: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferKind {
    Shielded,
    Unshielded,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredInput {
    pub kind: TransferKind,
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredOutput {
    pub kind: TransferKind,
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
    pub recipient: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeTransferJson {
    /// Absorbed from JSON; routing uses the top-level `method` key before this struct is parsed.
    #[serde(default, rename = "method")]
    _method: Option<String>,
    #[serde(default)]
    desired_outputs: Vec<DesiredOutput>,
    #[serde(default)]
    options: Option<PayFeesOptions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeIntentJson {
    #[serde(default, rename = "method")]
    _method: Option<String>,
    #[serde(default)]
    desired_inputs: Vec<DesiredInput>,
    #[serde(default)]
    desired_outputs: Vec<DesiredOutput>,
    options: MakeIntentOptionsJson,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeIntentOptionsJson {
    intent_id: IntentIdJson,
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IntentIdJson {
    Number(u16),
    Random(String),
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PayFeesOptions {
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

fn default_pay_fees() -> bool {
    true
}

fn deserialize_u128<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    parse_u128_value(&v).map_err(serde::de::Error::custom)
}

fn parse_u128_value(v: &serde_json::Value) -> Result<u128, String> {
    match v {
        serde_json::Value::String(s) => s
            .parse()
            .map_err(|e| format!("invalid integer string: {e}")),
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| "integer value out of range".to_string()),
        _ => Err("expected string or number for token amount".into()),
    }
}

/// Parse a JSON `--tx` payload as DApp Connector [`makeTransfer`] or [`makeIntent`].
pub fn parse_connector_tx_json(json: &str) -> Result<ConnectorTxRequest, PayError> {
    let trimmed = json.trim();
    if !trimmed.starts_with('{') {
        return Err(err("DApp Connector input must be a JSON object"));
    }
    let v: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| err(format!("invalid JSON: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| err("DApp Connector input must be a JSON object"))?;

    let method = obj
        .get("method")
        .and_then(|m| m.as_str())
        .map(str::to_ascii_lowercase);

    if method.as_deref() == Some("maketransfer") {
        return parse_make_transfer_value(v);
    }
    if method.as_deref() == Some("makeintent") {
        return parse_make_intent_value(v);
    }

    let has_inputs = obj.contains_key("desiredInputs");
    let has_outputs = obj.contains_key("desiredOutputs");
    match (has_inputs, has_outputs) {
        (true, _) => parse_make_intent_value(v),
        (false, true) => parse_make_transfer_value(v),
        _ => Err(err(
            "unrecognized DApp Connector JSON (expected makeTransfer or makeIntent fields)",
        )),
    }
}

fn parse_make_transfer_value(v: serde_json::Value) -> Result<ConnectorTxRequest, PayError> {
    let req: MakeTransferJson =
        serde_json::from_value(v).map_err(|e| err(format!("invalid makeTransfer JSON: {e}")))?;
    if req.desired_outputs.is_empty() {
        return Err(err("makeTransfer requires at least one desired output"));
    }
    Ok(ConnectorTxRequest::MakeTransfer(MakeTransferRequest {
        desired_outputs: req.desired_outputs,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    }))
}

fn parse_make_intent_value(v: serde_json::Value) -> Result<ConnectorTxRequest, PayError> {
    let req: MakeIntentJson =
        serde_json::from_value(v).map_err(|e| err(format!("invalid makeIntent JSON: {e}")))?;
    let segment = resolve_intent_segment(&req.options.intent_id)?;
    Ok(ConnectorTxRequest::MakeIntent(MakeIntentRequest {
        desired_inputs: req.desired_inputs,
        desired_outputs: req.desired_outputs,
        intent_segment: segment,
        pay_fees: req.options.pay_fees,
    }))
}

/// Ledger error surfaced by [`midnight-node`](https://github.com/midnightntwrk/midnight-node) as
/// `InvalidTransaction::Custom(138)` — see `MalformedError::BalanceCheckOverspend` in
/// `ledger/src/versions/common/types.rs`.
const LEDGER_BALANCE_CHECK_OVERSPEND: u16 = 138;

fn sum_desired_inputs(inputs: &[DesiredInput], kind: TransferKind) -> u128 {
    inputs
        .iter()
        .filter(|d| d.kind == kind)
        .map(|d| d.value)
        .sum()
}

fn sum_desired_outputs(outputs: &[DesiredOutput], kind: TransferKind) -> u128 {
    outputs
        .iter()
        .filter(|d| d.kind == kind)
        .map(|d| d.value)
        .sum()
}

/// Reject [`makeIntent`] requests that cannot pass the node's per-segment balancing check via
/// OWS sign/send alone (see [`LEDGER_BALANCE_CHECK_OVERSPEND`] in midnight-node).
fn validate_make_intent_self_submit(req: &MakeIntentRequest) -> Result<(), PayError> {
    let shielded_in = sum_desired_inputs(&req.desired_inputs, TransferKind::Shielded);
    let shielded_out = sum_desired_outputs(&req.desired_outputs, TransferKind::Shielded);
    let unshielded_in = sum_desired_inputs(&req.desired_inputs, TransferKind::Unshielded);
    let unshielded_out = sum_desired_outputs(&req.desired_outputs, TransferKind::Unshielded);

    if shielded_out > shielded_in {
        if unshielded_in > 0 && shielded_in == 0 {
            return Err(err(format!(
                "makeIntent cannot move unshielded inputs ({unshielded_in}) into shielded \
                 outputs ({shielded_out}) in one sign send-tx: unshielded and shielded NIGHT are \
                 separate ledger balances per segment, and the node rejects this with error \
                 {LEDGER_BALANCE_CHECK_OVERSPEND} (BalanceCheckOverspend). Fund shielded outputs \
                 with shielded inputs (shielded wallet seed) or complete via balanceSealedTransaction \
                 with a counterparty."
            )));
        }
        return Err(err(format!(
            "makeIntent shielded outputs ({shielded_out}) exceed shielded inputs ({shielded_in}); \
             submit would fail with node error {LEDGER_BALANCE_CHECK_OVERSPEND} \
             (BalanceCheckOverspend)."
        )));
    }

    if unshielded_in > unshielded_out && unshielded_out == 0 && shielded_out == 0 {
        return Err(err(format!(
            "makeIntent with unshielded inputs ({unshielded_in}) and no outputs is an imbalanced \
             swap offer; sign send-tx cannot submit it (node error \
             {LEDGER_BALANCE_CHECK_OVERSPEND}). Use balanceSealedTransaction with a counterparty."
        )));
    }

    Ok(())
}

fn shielded_inputs_covering_outputs(outputs: &[DesiredOutput]) -> Vec<DesiredInput> {
    use std::collections::HashMap;
    let mut by_token: HashMap<String, u128> = HashMap::new();
    for o in outputs {
        if o.kind == TransferKind::Shielded {
            *by_token.entry(o.token_type.clone()).or_insert(0) = by_token
                .get(&o.token_type)
                .copied()
                .unwrap_or(0)
                .saturating_add(o.value);
        }
    }
    by_token
        .into_iter()
        .map(|(token_type, value)| DesiredInput {
            kind: TransferKind::Shielded,
            token_type,
            value,
        })
        .collect()
}

fn resolve_intent_segment(intent_id: &IntentIdJson) -> Result<u16, PayError> {
    match intent_id {
        IntentIdJson::Number(0) => Err(err("intentId 0 is not allowed")),
        IntentIdJson::Number(n) => Ok(*n),
        IntentIdJson::Random(s) if s.eq_ignore_ascii_case("random") => {
            use rand::Rng as _;
            Ok(OsRng.gen_range(1..=u16::MAX))
        }
        IntentIdJson::Random(other) => Err(err(format!(
            "unsupported intentId value {other:?} (expected a number or \"random\")"
        ))),
    }
}

/// Build an unsealed `proof-preimage,embedded-fr` transaction for [`makeTransfer`].
///
/// Supports unshielded and/or shielded `desiredOutputs` (outputs only). Unshielded outputs are
/// completed via [`super::prepare_sealed_from_unsealed`]. Shielded outputs require `shielded_seed`
/// so this builder can attach matching Zswap inputs (otherwise the node rejects with error 138).
pub fn build_make_transfer_unsealed_tx(
    chain_id: &str,
    indexer_url: Option<&str>,
    shielded_seed: Option<[u8; 32]>,
    scope: Option<&SyncCacheScope>,
    req: &MakeTransferRequest,
) -> Result<Vec<u8>, PayError> {
    if req.desired_outputs.is_empty() {
        return Err(err("makeTransfer requires at least one desired output"));
    }

    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .cloned()
        .partition(|d| d.kind == TransferKind::Unshielded);

    let unshielded_offer = if unshielded_out.is_empty() {
        None
    } else {
        let outputs = desired_unshielded_outputs_to_utxo_outputs(chain_id, &unshielded_out)?;
        Some(UnshieldedOffer {
            inputs: vec![].into(),
            outputs: outputs.into(),
            signatures: vec![].into(),
        })
    };

    let zswap_offer = if shielded_out.is_empty() {
        None
    } else {
        let seed = shielded_seed.ok_or_else(|| {
            err("makeTransfer with shielded outputs requires a Midnight shielded wallet seed")
        })?;
        let indexer_url = indexer_url.ok_or_else(|| {
            err("makeTransfer with shielded outputs requires a Midnight indexer URL")
        })?;
        let scope = scope.ok_or_else(|| err("internal error: missing sync scope"))?;
        let rt = super::async_runtime::runtime();
        let mut wallet =
            rt.block_on(sync_shielded_wallet_state_scoped(indexer_url, &seed, scope))?;
        let shielded_in = shielded_inputs_covering_outputs(&shielded_out);
        Some(build_zswap_offer(
            chain_id,
            MAKE_TRANSFER_SEGMENT,
            Some(&mut wallet),
            &shielded_in,
            &shielded_out,
        )?)
    };

    build_make_intent_standard_tx(
        chain_id,
        MAKE_TRANSFER_SEGMENT,
        unshielded_offer,
        zswap_offer,
    )
}

/// Build an imbalanced unsealed transaction for [`makeIntent`] (inputs + outputs, no balancing).
///
/// Seal via [`super::seal_imbalanced_unsealed`] (sign → prove → seal only).
pub fn build_make_intent_unsealed_tx(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    shielded_seed: Option<[u8; 32]>,
    req: &MakeIntentRequest,
    scope: &SyncCacheScope,
) -> Result<Vec<u8>, PayError> {
    if req.desired_inputs.is_empty() && req.desired_outputs.is_empty() {
        return Err(err(
            "makeIntent requires at least one desired input or output",
        ));
    }

    let (unshielded_in, shielded_in): (Vec<_>, Vec<_>) = req
        .desired_inputs
        .iter()
        .cloned()
        .partition(|d| d.kind == TransferKind::Unshielded);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .cloned()
        .partition(|d| d.kind == TransferKind::Unshielded);

    if !shielded_in.is_empty() && shielded_seed.is_none() {
        return Err(err(
            "makeIntent with shielded inputs requires a Midnight shielded wallet seed",
        ));
    }

    let rt = super::async_runtime::runtime();
    let unshielded_offer = if unshielded_in.is_empty() && unshielded_out.is_empty() {
        None
    } else {
        let sender_addr = MidnightSigner
            .derive_address_for_chain_id(chain_id, sender_private_key)
            .map_err(|e| err(e.to_string()))?;
        let utxos = rt.block_on(super::unshielded_sync::get_unshielded_utxos_scoped(
            indexer_url,
            &sender_addr,
            scope,
        ))?;
        let mut inputs = desired_unshielded_inputs_to_utxo_spends(
            chain_id,
            &utxos,
            &sender_addr,
            sender_private_key,
            &unshielded_in,
        )?;
        let outputs = desired_unshielded_outputs_to_utxo_outputs(chain_id, &unshielded_out)?;
        inputs.sort();
        Some(UnshieldedOffer {
            inputs: inputs.into(),
            outputs: outputs.into(),
            signatures: vec![].into(),
        })
    };

    let zswap_offer = if shielded_in.is_empty() && shielded_out.is_empty() {
        None
    } else if shielded_in.is_empty() {
        Some(build_zswap_offer(
            chain_id,
            req.intent_segment,
            None,
            &[],
            &shielded_out,
        )?)
    } else {
        let seed = shielded_seed.expect("checked above");
        let mut wallet =
            rt.block_on(sync_shielded_wallet_state_scoped(indexer_url, &seed, scope))?;
        Some(build_zswap_offer(
            chain_id,
            req.intent_segment,
            Some(&mut wallet),
            &shielded_in,
            &shielded_out,
        )?)
    };

    build_make_intent_standard_tx(chain_id, req.intent_segment, unshielded_offer, zswap_offer)
}

fn build_make_intent_standard_tx(
    chain_id: &str,
    segment: u16,
    unshielded_offer: Option<UnshieldedOffer<MnSig, InMemoryDB>>,
    zswap_offer: Option<ZswapOffer<ProofPreimage, InMemoryDB>>,
) -> Result<Vec<u8>, PayError> {
    if unshielded_offer.is_none() && zswap_offer.is_none() {
        return Err(err("makeIntent produced no unshielded or shielded offer"));
    }
    let chain_time_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ttl = Timestamp::from_secs(chain_time_unix_secs.saturating_add(3600));
    let mut rng = OsRng;
    let intent = Intent::new(
        &mut rng,
        unshielded_offer,
        None,
        vec![],
        vec![],
        vec![],
        None,
        ttl,
    );
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(segment, intent);
    let mut fallible_coins: MnHashMap<u16, ZswapOffer<ProofPreimage, InMemoryDB>, InMemoryDB> =
        MnHashMap::new();
    if let Some(offer) = zswap_offer {
        fallible_coins = fallible_coins.insert(segment, offer);
    }
    let mut stx = StandardTransaction {
        network_id: super::ledger_network_id(chain_id).to_string(),
        intents,
        guaranteed_coins: None,
        fallible_coins,
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    let tx: Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Transaction::Standard(stx);
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Build shielded Zswap spend preimages covering per-token deficits (for contract-call balancing).
pub(super) fn collect_shielded_preimage_inputs(
    wallet: &mut ShieldedWalletState,
    segment: u16,
    deficits: &[(ShieldedTokenType, u128)],
) -> Result<Vec<ZswapInput<ProofPreimage, InMemoryDB>>, PayError> {
    super::shielded_session::ensure_shielded_merkle_ready(wallet)?;
    let mut rng = OsRng;
    let seg = Some(segment);
    let mut zswap_inputs = Vec::new();
    for (token_type, need_total) in deficits {
        if *need_total == 0 {
            continue;
        }
        let wire = hex::encode(token_type.into_inner().0);
        let mut need = *need_total;
        let mut coins: Vec<QualifiedCoinInfo> = wallet
            .zswap
            .coins
            .iter()
            .filter(|(_, qci)| shielded_token_matches(qci, &wire))
            .map(|(_, qci)| *qci)
            .collect();
        coins.sort_by(|a, b| b.value.cmp(&a.value));
        for coin in coins {
            if need == 0 {
                break;
            }
            let (st2, inp) = wallet
                .zswap
                .spend(&mut rng, &wallet.keys, &coin, seg)
                .map_err(|e| {
                    let hint = if format!("{e:?}").contains("InvalidIndex") {
                        " (often caused by OWS_MIDNIGHT_SHIELDED_ZSWAP_HYDRATE merging zswap-ledger \
coins into session state — unset that env var and use only viewing-key session coins)"
                    } else {
                        ""
                    };
                    err(format!("shielded spend failed: {e:?}{hint}"))
                })?;
            wallet.zswap = st2;
            need = need.saturating_sub(coin.value);
            zswap_inputs.push(inp);
        }
        if need > 0 {
            let have: u128 = wallet
                .zswap
                .coins
                .iter()
                .filter(|(_, qci)| shielded_token_matches(qci, &wire))
                .map(|(_, qci)| qci.value)
                .sum();
            return Err(err(format!(
                "insufficient shielded balance for token 0x{wire}: short by {need} in viewing-key \
wallet state (session has {have}). If `ows fund balance` lists this token under \"zswap-ledger only\", \
those coins are not spendable yet — run `ows fund balance` again, then sign; ensure \
OWS_MIDNIGHT_SHIELDED_VK_FREE is unset"
            )));
        }
    }
    Ok(zswap_inputs)
}

fn build_zswap_offer(
    chain_id: &str,
    segment: u16,
    wallet: Option<&mut ShieldedWalletState>,
    desired_inputs: &[DesiredInput],
    desired_outputs: &[DesiredOutput],
) -> Result<ZswapOffer<ProofPreimage, InMemoryDB>, PayError> {
    let mut rng = OsRng;
    let mut zswap_inputs: Vec<ZswapInput<ProofPreimage, InMemoryDB>> = Vec::new();

    if !desired_inputs.is_empty() {
        let wallet =
            wallet.ok_or_else(|| err("shielded inputs require synced shielded wallet state"))?;
        let deficits: Vec<(ShieldedTokenType, u128)> = desired_inputs
            .iter()
            .map(|d| {
                if d.value == 0 {
                    return Err(err("desired input value must be greater than zero"));
                }
                Ok((wire_type_to_shielded(&d.token_type)?, d.value))
            })
            .collect::<Result<Vec<_>, PayError>>()?;
        zswap_inputs = collect_shielded_preimage_inputs(wallet, segment, &deficits)?;
    }

    let seg = Some(segment);
    let mut zswap_outputs: Vec<ZswapOutput<ProofPreimage, InMemoryDB>> = Vec::new();
    for d in desired_outputs {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        let type_ = wire_type_to_shielded(&d.token_type)?;
        let (cpk, epk) = shielded_recipient_keys(chain_id, &d.recipient)?;
        let coin = CoinInfo {
            nonce: rng.r#gen(),
            type_,
            value: d.value,
        };
        let out = ZswapOutput::new(&mut rng, &coin, seg, &cpk, Some(epk))
            .map_err(|e| err(format!("shielded output failed: {e:?}")))?;
        zswap_outputs.push(out);
    }

    ZswapOffer::new(zswap_inputs, zswap_outputs, vec![])
        .ok_or_else(|| err("shielded Zswap offer is empty"))
}

pub fn materialize_connector_request(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    shielded_seed: Option<[u8; 32]>,
    req: ConnectorTxRequest,
    scope: &SyncCacheScope,
    for_self_submit: bool,
) -> Result<(Vec<u8>, bool, bool), PayError> {
    if for_self_submit {
        if let ConnectorTxRequest::MakeIntent(ref i) = req {
            validate_make_intent_self_submit(i)?;
        }
    }
    match req {
        ConnectorTxRequest::MakeTransfer(t) => {
            let pay_fees = t.pay_fees;
            let bytes = build_make_transfer_unsealed_tx(
                chain_id,
                Some(indexer_url),
                shielded_seed,
                Some(scope),
                &t,
            )?;
            Ok((bytes, pay_fees, true))
        }
        ConnectorTxRequest::MakeIntent(i) => {
            let pay_fees = i.pay_fees;
            let bytes = build_make_intent_unsealed_tx(
                chain_id,
                indexer_url,
                sender_private_key,
                shielded_seed,
                &i,
                scope,
            )?;
            Ok((bytes, pay_fees, false))
        }
    }
}

fn shielded_token_matches(qci: &QualifiedCoinInfo, token_wire: &str) -> bool {
    let t = qci.type_.into_inner();
    let hex = hex::encode(t.0);
    let wire = token_wire.strip_prefix("0x").unwrap_or(token_wire);
    hex.eq_ignore_ascii_case(wire)
}

fn wire_type_to_shielded(token_type: &str) -> Result<ShieldedTokenType, PayError> {
    let tt = parse_token_type(Some(token_type))?;
    Ok(match tt {
        TokenType::Native => ShieldedTokenType(HashOutput([0u8; 32])),
        TokenType::Custom(b) => ShieldedTokenType(HashOutput(b)),
    })
}

fn shielded_recipient_keys(
    chain_id: &str,
    recipient: &str,
) -> Result<(CoinPublicKey, encryption::PublicKey), PayError> {
    let hrp = MidnightSigner::shielded_hrp_for_chain_id(chain_id);
    let payload = decode_bech32m_payload(recipient, hrp)?;
    if payload.len() != 64 {
        return Err(err(format!(
            "shielded recipient address payload must be 64 bytes, got {}",
            payload.len()
        )));
    }
    let mut cpk = [0u8; 32];
    cpk.copy_from_slice(&payload[..32]);
    let mut cur = Cursor::new(payload[32..].to_vec());
    let epk =
        <encryption::PublicKey as midnight_serialize::Deserializable>::deserialize(&mut cur, 0)
            .map_err(|e| err(format!("invalid shielded encryption public key: {e}")))?;
    Ok((CoinPublicKey(HashOutput(cpk)), epk))
}

fn desired_unshielded_inputs_to_utxo_spends(
    _chain_id: &str,
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_sk: &[u8; 32],
    desired: &[DesiredInput],
) -> Result<Vec<UtxoSpend>, PayError> {
    let mut spends = Vec::new();
    for d in desired {
        if d.value == 0 {
            return Err(err("desired input value must be greater than zero"));
        }
        let wire = parse_token_type(Some(&d.token_type))?.to_wire_token_type();
        let type_ = wire_type_to_unshielded(&d.token_type)?;
        let selected = balance::select_utxos_for_token(
            utxos,
            sender_bech32,
            sender_sk,
            &wire,
            d.value,
            false,
        )?;
        for u in selected {
            let ih = balance::parse_intent_hash_hex(&u.intent_hash)?;
            let out_no =
                u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
            let vk = balance::resolve_owner_vk(&u.owner, sender_bech32, sender_sk)?;
            spends.push(UtxoSpend {
                value: u.value,
                owner: vk,
                type_,
                intent_hash: ih,
                output_no: out_no,
            });
        }
    }
    Ok(spends)
}

fn desired_unshielded_outputs_to_utxo_outputs(
    chain_id: &str,
    desired: &[DesiredOutput],
) -> Result<Vec<UtxoOutput>, PayError> {
    let mut outputs = Vec::with_capacity(desired.len());
    for d in desired {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        let owner = user_address_from_unshielded_recipient(chain_id, &d.recipient)?;
        let type_ = wire_type_to_unshielded(&d.token_type)?;
        outputs.push(UtxoOutput {
            value: d.value,
            owner,
            type_,
        });
    }
    outputs.sort();
    Ok(outputs)
}

fn wire_type_to_unshielded(token_type: &str) -> Result<UnshieldedTokenType, PayError> {
    let tt = parse_token_type(Some(token_type))?;
    Ok(match tt {
        TokenType::Native => NIGHT,
        TokenType::Custom(b) => UnshieldedTokenType(HashOutput(b)),
    })
}

fn user_address_from_unshielded_recipient(
    chain_id: &str,
    recipient: &str,
) -> Result<UserAddress, PayError> {
    let hrp = MidnightSigner::unshielded_hrp_for_chain_id(chain_id);
    let payload = decode_bech32m_payload(recipient, hrp)?;
    if payload.len() != 32 {
        return Err(err(format!(
            "unshielded recipient address payload must be 32 bytes, got {}",
            payload.len()
        )));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&payload);
    Ok(UserAddress(HashOutput(h)))
}

fn decode_bech32m_payload(addr: &str, expected_hrp: &str) -> Result<Vec<u8>, PayError> {
    let hrp = Hrp::parse(expected_hrp).map_err(|e| err(format!("invalid expected hrp: {e}")))?;
    let (got_hrp, payload) =
        bech32::decode(addr).map_err(|e| err(format!("invalid bech32m address: {e}")))?;
    if got_hrp != hrp {
        return Err(err(format!(
            "address HRP {got_hrp} does not match network (expected {expected_hrp})"
        )));
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_signer::chains::MidnightSigner;

    fn preview_shielded_recipient() -> String {
        let seed = [7u8; 32];
        MidnightSigner
            .derive_shielded_address_from_seed_for_chain_id("midnight:preview", &seed)
            .expect("preview shielded address")
    }

    #[test]
    fn parse_make_transfer_by_method() {
        let json = r#"{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"1000","recipient":"mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"}]}"#;
        match parse_connector_tx_json(json).unwrap() {
            ConnectorTxRequest::MakeTransfer(t) => {
                assert_eq!(t.desired_outputs.len(), 1);
                assert!(t.pay_fees);
            }
            _ => panic!("expected makeTransfer"),
        }
    }

    #[test]
    fn parse_make_transfer_implicit() {
        let json = r#"{"desiredOutputs":[{"kind":"unshielded","type":"night","value":42,"recipient":"mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"}],"options":{"payFees":false}}"#;
        match parse_connector_tx_json(json).unwrap() {
            ConnectorTxRequest::MakeTransfer(t) => assert!(!t.pay_fees),
            _ => panic!("expected makeTransfer"),
        }
    }

    #[test]
    fn parse_make_intent_requires_options() {
        let json = r#"{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"desiredOutputs":[],"options":{"intentId":1,"payFees":false}}"#;
        match parse_connector_tx_json(json).unwrap() {
            ConnectorTxRequest::MakeIntent(i) => {
                assert_eq!(i.intent_segment, 1);
                assert!(!i.pay_fees);
            }
            _ => panic!("expected makeIntent"),
        }
    }

    #[test]
    fn parse_make_intent_shielded_kinds() {
        let recipient = preview_shielded_recipient();
        let json = format!(
            r#"{{"method":"makeIntent","desiredInputs":[{{"kind":"shielded","type":"night","value":10}}],"desiredOutputs":[{{"kind":"shielded","type":"night","value":10,"recipient":"{recipient}"}}],"options":{{"intentId":1,"payFees":true}}}}"#
        );
        match parse_connector_tx_json(&json).unwrap() {
            ConnectorTxRequest::MakeIntent(i) => {
                assert_eq!(i.desired_inputs[0].kind, TransferKind::Shielded);
                assert_eq!(i.desired_outputs[0].kind, TransferKind::Shielded);
            }
            _ => panic!("expected makeIntent"),
        }
    }

    #[test]
    fn parse_make_transfer_shielded_output() {
        let recipient = preview_shielded_recipient();
        let json = format!(
            r#"{{"method":"makeTransfer","desiredOutputs":[{{"kind":"shielded","type":"night","value":5,"recipient":"{recipient}"}}]}}"#
        );
        match parse_connector_tx_json(&json).unwrap() {
            ConnectorTxRequest::MakeTransfer(t) => {
                assert_eq!(t.desired_outputs[0].kind, TransferKind::Shielded);
            }
            _ => panic!("expected makeTransfer"),
        }
    }

    #[test]
    fn make_transfer_shielded_requires_seed() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Shielded,
                token_type: "night".into(),
                value: 1,
                recipient: preview_shielded_recipient(),
            }],
            pay_fees: true,
        };
        let err = build_make_transfer_unsealed_tx("midnight:preview", None, None, None, &req)
            .unwrap_err();
        assert!(err.to_string().contains("shielded wallet seed"), "{err}");
    }

    #[test]
    fn build_make_transfer_tx_has_preimage_header() {
        use bech32::Bech32m;
        let hrp = MidnightSigner::unshielded_hrp_for_chain_id("midnight:preview");
        let recipient = bech32::encode::<Bech32m>(Hrp::parse(hrp).unwrap(), &[0xABu8; 32]).unwrap();
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1,
                recipient,
            }],
            pay_fees: true,
        };
        let bytes =
            build_make_transfer_unsealed_tx("midnight:preview", None, None, None, &req).unwrap();
        assert!(super::super::is_balance_unsealed_payload(&bytes));
    }

    #[test]
    fn swap_offer_json_matches_connector_swap_shape() {
        let recipient = preview_shielded_recipient();
        let json = serde_json::json!({
            "method": "makeIntent",
            "desiredInputs": [{
                "kind": "unshielded",
                "type": "night",
                "value": 10_000_000
            }],
            "desiredOutputs": [{
                "kind": "shielded",
                "type": "night",
                "value": 10_000_000,
                "recipient": recipient
            }],
            "options": {
                "intentId": 1,
                "payFees": true
            }
        })
        .to_string();
        let req = parse_connector_tx_json(&json).unwrap();
        let ConnectorTxRequest::MakeIntent(i) = req else {
            panic!("expected makeIntent");
        };
        assert_eq!(i.intent_segment, 1);
        assert_eq!(i.desired_inputs.len(), 1);
        assert_eq!(i.desired_outputs[0].recipient, recipient);
        assert!(validate_make_intent_self_submit(&i).is_err());
    }

    #[test]
    fn make_intent_rejects_unshielded_to_shielded_self_submit() {
        let recipient = preview_shielded_recipient();
        let req = MakeIntentRequest {
            desired_inputs: vec![DesiredInput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 10,
            }],
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Shielded,
                token_type: "night".into(),
                value: 10,
                recipient,
            }],
            intent_segment: 1,
            pay_fees: true,
        };
        let err = validate_make_intent_self_submit(&req).unwrap_err();
        assert!(
            err.to_string().contains("138"),
            "expected BalanceCheckOverspend hint: {}",
            err
        );
    }
}
