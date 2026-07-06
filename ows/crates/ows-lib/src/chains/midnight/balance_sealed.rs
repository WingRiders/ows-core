//! [`balanceSealedTransaction`](https://github.com/midnightntwrk/midnight-dapp-connector-api):
//! complete a maker's imbalanced sealed swap offer (MIP-0006 / offer files).
//!
//! The taker merges a complementary Zswap partial transaction, covers DUST fees, signs
//! their intent segments, and returns a balanced sealed transaction ready to submit.

use super::cache_io::SyncCacheScope;
use super::dapp_connector::{
    build_shielded_change_outputs, collect_shielded_preimage_inputs, ShieldedZswapSelection,
};
use super::error::{PayError, PayErrorCode};
use super::mip6;
use super::shielded_session::sync_shielded_wallet_state_scoped;
use midnight_base_crypto::signatures::{Signature as MnSig, SigningKey as MidnightSigningKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Info as CoinInfo, ShieldedTokenType, TokenType as LedgerTokenType, UnshieldedTokenType,
    UserAddress, NIGHT,
};
use midnight_ledger::dust::{DustActions, DustLocalState, DustSecretKey};
use midnight_ledger::structure::{
    Intent, ProofKind, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction,
    UnshieldedOffer, UtxoOutput, UtxoSpend,
};
use midnight_serialize::{tagged_deserialize, tagged_serialize, Serializable};
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_signer::chains::MidnightSigner;
use ows_signer::ChainSigner;
use rand::{rngs::OsRng, Rng as _};
use std::collections::BTreeMap;
use std::ops::Deref as _;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::{Proof as ZswapProof, ProofPreimage};

fn err(msg: impl Into<String>) -> PayError {
    PayError::new(PayErrorCode::InvalidInput, msg)
}

const TAG_SEALED: &[u8] = b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";
const TAG_PROVEN: &[u8] = b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";

type PedSealed = <ProofMarker as ProofKind<InMemoryDB>>::Pedersen;
type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;
type TxSealed = Transaction<MnSig, ProofMarker, PedSealed, InMemoryDB>;

/// Detect a sealed (`proof,pedersen-schnorr`) Midnight transaction blob.
pub fn is_sealed_midnight_payload(tx_bytes: &[u8]) -> bool {
    tx_bytes.starts_with(TAG_SEALED)
}

/// Detect a proven (`proof,embedded-fr`) Midnight transaction blob (e.g. from `zswapoffer` wrap).
pub fn is_proven_midnight_payload(tx_bytes: &[u8]) -> bool {
    tx_bytes.starts_with(TAG_PROVEN)
}

/// Sealed or proven maker swap payload that [`balance_sealed_transaction`] can complete.
pub fn is_balance_sealed_maker_payload(tx_bytes: &[u8]) -> bool {
    is_sealed_midnight_payload(tx_bytes) || is_proven_midnight_payload(tx_bytes)
}

/// Parse maker input: hex sealed/proven tx, `zswapoffer…` bech32, MIP-0006 JSON, or connector JSON.
pub fn parse_maker_swap_input(chain_id: &str, raw: &str) -> Result<Vec<u8>, PayError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| err(format!("invalid JSON: {e}")))?;
        if mip6::is_mip6_offer_payload(&v) {
            return mip6::materialize_validated_offer(chain_id, &v);
        }
        if let Some(tx) = v.get("tx").and_then(|t| t.as_str()) {
            return decode_maker_tx_hex_or_offer(chain_id, tx);
        }
        if let Some(tx) = v.get("transaction").and_then(|t| t.as_str()) {
            return decode_maker_tx_hex_or_offer(chain_id, tx);
        }
        return Err(err(
            "swap JSON must include a \"tx\" or \"transaction\" field (hex or zswapoffer bech32)",
        ));
    }
    decode_maker_tx_hex_or_offer(chain_id, trimmed)
}

/// Public entry for MIP-0006 validation (hex or `zswapoffer` in the `transaction` field).
pub fn decode_maker_tx_hex_or_offer_public(chain_id: &str, s: &str) -> Result<Vec<u8>, PayError> {
    decode_maker_tx_hex_or_offer(chain_id, s)
}

fn decode_maker_tx_hex_or_offer(chain_id: &str, s: &str) -> Result<Vec<u8>, PayError> {
    let t = s.trim();
    if t.starts_with("zswapoffer") {
        let segment = mip6::DEFAULT_ZSWAP_OFFER_SEGMENT;
        return wrap_zswap_offer_as_proven_tx(chain_id, t, segment);
    }
    let hex_s = t.strip_prefix("0x").unwrap_or(t);
    hex::decode(hex_s).map_err(|e| err(format!("invalid hex transaction: {e}")))
}

/// Decode a MIP-0005 `zswapoffer…` bech32 string into a Zswap offer.
pub fn decode_zswap_offer_bech32_public(
    s: &str,
) -> Result<ZswapOffer<ZswapProof, InMemoryDB>, PayError> {
    decode_zswap_offer_bech32(s)
}

/// Wrap a bare `zswapoffer…` bech32 offer in a minimal proven Midnight transaction.
pub fn wrap_zswap_offer_as_proven_tx_public(
    chain_id: &str,
    bech32_offer: &str,
    segment: u16,
) -> Result<Vec<u8>, PayError> {
    wrap_zswap_offer_as_proven_tx(chain_id, bech32_offer, segment)
}

fn decode_zswap_offer_bech32(s: &str) -> Result<ZswapOffer<ZswapProof, InMemoryDB>, PayError> {
    let (hrp, data) =
        bech32::decode(s.trim()).map_err(|e| err(format!("invalid zswap offer bech32: {e}")))?;
    if !hrp.as_str().starts_with("zswapoffer") {
        return Err(err(format!(
            "expected zswapoffer bech32 HRP, got {}",
            hrp.as_str()
        )));
    }
    let mut r: &[u8] = &data;
    tagged_deserialize(&mut r).map_err(|e| err(format!("failed to parse zswap offer: {e}")))
}

fn wrap_zswap_offer_as_proven_tx(
    chain_id: &str,
    bech32_offer: &str,
    segment: u16,
) -> Result<Vec<u8>, PayError> {
    let offer = decode_zswap_offer_bech32(bech32_offer)?;
    let mut fallible: MnHashMap<u16, ZswapOffer<ZswapProof, InMemoryDB>, InMemoryDB> =
        MnHashMap::new();
    fallible = fallible.insert(segment, offer);
    let stx = StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents: MnHashMap::new(),
        guaranteed_coins: None,
        fallible_coins: fallible,
        binding_randomness: Default::default(),
    };
    let tx: TxProven = Transaction::Standard(stx);
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

enum ParsedMaker {
    Sealed(TxSealed),
    Proven(TxProven),
}

fn parse_maker_tx(chain_id: &str, bytes: &[u8]) -> Result<ParsedMaker, PayError> {
    if bytes.starts_with(TAG_SEALED) {
        let mut r: &[u8] = bytes;
        let tx: TxSealed = tagged_deserialize(&mut r)
            .map_err(|e| err(format!("failed to parse sealed maker tx: {e}")))?;
        let Transaction::Standard(stx) = &tx else {
            return Err(err("expected Standard transaction"));
        };
        super::ensure_tx_network_id_matches_chain(chain_id, &stx.network_id)?;
        return Ok(ParsedMaker::Sealed(tx));
    }
    if bytes.starts_with(TAG_PROVEN) {
        let mut r: &[u8] = bytes;
        let tx: TxProven = tagged_deserialize(&mut r)
            .map_err(|e| err(format!("failed to parse proven maker tx: {e}")))?;
        let Transaction::Standard(stx) = &tx else {
            return Err(err("expected Standard transaction"));
        };
        super::ensure_tx_network_id_matches_chain(chain_id, &stx.network_id)?;
        return Ok(ParsedMaker::Proven(tx));
    }
    Err(err(
        "maker input must be a sealed or proven Midnight transaction, or a zswapoffer bech32 string",
    ))
}

#[derive(Debug, Clone)]
struct ShieldedImbalance {
    token: ShieldedTokenType,
    segment: u16,
    balance: i128,
}

type SegmentImbalanceMap = BTreeMap<
    u16,
    (
        Vec<(ShieldedTokenType, u128)>,
        Vec<(ShieldedTokenType, u128)>,
    ),
>;

fn shielded_imbalances<B>(
    tx: &Transaction<MnSig, ProofMarker, B, InMemoryDB>,
) -> Result<Vec<ShieldedImbalance>, PayError>
where
    B: midnight_storage::Storable<InMemoryDB> + Clone,
    Transaction<MnSig, ProofMarker, B, InMemoryDB>: Serializable,
{
    let mut out = Vec::new();
    for ((token, segment), bal) in tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
    {
        if let LedgerTokenType::Shielded(tt) = token {
            if bal != 0 {
                out.push(ShieldedImbalance {
                    token: tt,
                    segment,
                    balance: bal,
                });
            }
        }
    }
    Ok(out)
}

fn build_taker_zswap_preimage(
    wallet: &mut super::ShieldedWalletState,
    segment: u16,
    deficits: &[(ShieldedTokenType, u128)],
    surpluses: &[(ShieldedTokenType, u128)],
) -> Result<ZswapOffer<ProofPreimage, InMemoryDB>, PayError> {
    let mut rng = OsRng;
    let cpk = wallet.keys.coin_public_key();
    let epk = wallet.keys.enc_public_key();
    let seg = Some(segment);

    let selection: ShieldedZswapSelection = if deficits.is_empty() {
        ShieldedZswapSelection {
            inputs: vec![],
            spent_by_token: vec![],
        }
    } else {
        collect_shielded_preimage_inputs(wallet, segment, deficits)?
    };

    let mut outputs = Vec::new();
    for (token, amount) in surpluses {
        if *amount == 0 {
            continue;
        }
        let coin = CoinInfo {
            nonce: rng.r#gen(),
            type_: *token,
            value: *amount,
        };
        let out = ZswapOutput::new(&mut rng, &coin, seg, &cpk, Some(epk))
            .map_err(|e| err(format!("shielded surplus output failed: {e:?}")))?;
        outputs.push(out);
    }

    let change_outputs =
        build_shielded_change_outputs(wallet, segment, &selection.spent_by_token, deficits)?;
    outputs.extend(change_outputs);

    if selection.inputs.is_empty() && outputs.is_empty() {
        return Err(err(
            "no taker Zswap inputs or outputs to build for this segment",
        ));
    }

    ZswapOffer::new(selection.inputs, outputs, vec![])
        .ok_or_else(|| err("taker Zswap offer is empty"))
}

fn build_zswap_only_proven_tx(
    chain_id: &str,
    segment: u16,
    offer: ZswapOffer<ZswapProof, InMemoryDB>,
    binding_delta: PedersenRandomness,
) -> Result<TxProven, PayError> {
    let mut fallible: MnHashMap<u16, ZswapOffer<ZswapProof, InMemoryDB>, InMemoryDB> =
        MnHashMap::new();
    fallible = fallible.insert(segment, offer);
    Ok(Transaction::Standard(StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents: MnHashMap::new(),
        guaranteed_coins: None,
        fallible_coins: fallible,
        binding_randomness: binding_delta,
    }))
}

fn seal_proven_tx(tx: TxProven) -> Result<TxSealed, PayError> {
    use rand::{rngs::StdRng, SeedableRng as _};
    Ok(tx.seal(StdRng::from_entropy()))
}

fn merge_taker_zswap_complement_sealed(
    chain_id: &str,
    indexer_url: &str,
    scope: &SyncCacheScope,
    shielded_seed: [u8; 32],
    maker: TxSealed,
) -> Result<TxSealed, PayError> {
    let imbalances = shielded_imbalances(&maker)?;
    if imbalances.is_empty() {
        return Ok(maker);
    }

    let rt = super::async_runtime::runtime();
    let mut wallet = rt
        .block_on(sync_shielded_wallet_state_scoped(
            indexer_url,
            &shielded_seed,
            scope,
        ))
        .map_err(|e| err(format!("shielded wallet sync failed: {e}")))?;
    super::shielded_session::ensure_shielded_merkle_ready(&mut wallet)
        .map_err(|e| err(format!("shielded merkle tree not ready: {e}")))?;

    let mut by_segment: SegmentImbalanceMap = BTreeMap::new();
    for im in imbalances {
        let entry = by_segment.entry(im.segment).or_default();
        if im.balance < 0 {
            entry.0.push((im.token, im.balance.unsigned_abs()));
        } else {
            entry.1.push((im.token, im.balance as u128));
        }
    }

    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
    let mut merged = maker;

    for (segment, (deficits, surpluses)) in by_segment {
        let preimage = build_taker_zswap_preimage(&mut wallet, segment, &deficits, &surpluses)?;
        let mut binding_delta = PedersenRandomness::from(0);
        for inp in preimage.inputs.iter_deref() {
            binding_delta = binding_delta + inp.binding_randomness();
        }
        for out in preimage.outputs.iter_deref() {
            binding_delta = binding_delta + out.binding_randomness();
        }
        let (_seg, proven_offer) = rt
            .block_on(preimage.prove(prover.clone(), segment))
            .map_err(|e| err(format!("prove taker zswap offer failed: {e:?}")))?;
        let taker_proven =
            build_zswap_only_proven_tx(chain_id, segment, proven_offer, binding_delta)?;
        let taker_sealed = seal_proven_tx(taker_proven)?;
        merged = merged
            .merge(&taker_sealed)
            .map_err(|e| err(format!("merge taker zswap partial failed: {e:?}")))?;
    }

    if !shielded_imbalances(&merged)?.is_empty() {
        return Err(err(
            "merged transaction is still shielded-imbalanced after taker Zswap merge",
        ));
    }
    Ok(merged)
}

fn merge_taker_zswap_complement_proven(
    chain_id: &str,
    indexer_url: &str,
    scope: &SyncCacheScope,
    shielded_seed: [u8; 32],
    maker: TxProven,
) -> Result<TxProven, PayError> {
    let imbalances = shielded_imbalances(&maker)?;
    if imbalances.is_empty() {
        return Ok(maker);
    }

    let rt = super::async_runtime::runtime();
    let mut wallet = rt
        .block_on(sync_shielded_wallet_state_scoped(
            indexer_url,
            &shielded_seed,
            scope,
        ))
        .map_err(|e| err(format!("shielded wallet sync failed: {e}")))?;
    super::shielded_session::ensure_shielded_merkle_ready(&mut wallet)
        .map_err(|e| err(format!("shielded merkle tree not ready: {e}")))?;

    let mut by_segment: SegmentImbalanceMap = BTreeMap::new();
    for im in imbalances {
        let entry = by_segment.entry(im.segment).or_default();
        if im.balance < 0 {
            entry.0.push((im.token, im.balance.unsigned_abs()));
        } else {
            entry.1.push((im.token, im.balance as u128));
        }
    }

    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
    let mut merged = maker;

    for (segment, (deficits, surpluses)) in by_segment {
        let preimage = build_taker_zswap_preimage(&mut wallet, segment, &deficits, &surpluses)?;
        let mut binding_delta = PedersenRandomness::from(0);
        for inp in preimage.inputs.iter_deref() {
            binding_delta = binding_delta + inp.binding_randomness();
        }
        for out in preimage.outputs.iter_deref() {
            binding_delta = binding_delta + out.binding_randomness();
        }
        let (_seg, proven_offer) = rt
            .block_on(preimage.prove(prover.clone(), segment))
            .map_err(|e| err(format!("prove taker zswap offer failed: {e:?}")))?;
        let taker_tx = build_zswap_only_proven_tx(chain_id, segment, proven_offer, binding_delta)?;
        merged = merged
            .merge(&taker_tx)
            .map_err(|e| err(format!("merge taker zswap partial failed: {e:?}")))?;
    }

    if !shielded_imbalances(&merged)?.is_empty() {
        return Err(err(
            "merged transaction is still shielded-imbalanced after taker Zswap merge",
        ));
    }
    Ok(merged)
}

#[derive(Debug, Clone)]
struct UnshieldedImbalance {
    token: UnshieldedTokenType,
    balance: i128,
}

fn unshielded_imbalances<B>(
    tx: &Transaction<MnSig, ProofMarker, B, InMemoryDB>,
) -> Result<Vec<UnshieldedImbalance>, PayError>
where
    B: midnight_storage::Storable<InMemoryDB> + Clone,
    Transaction<MnSig, ProofMarker, B, InMemoryDB>: Serializable,
{
    let mut out = Vec::new();
    for ((token, _segment), bal) in tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
    {
        if let LedgerTokenType::Unshielded(tt) = token {
            if bal != 0 {
                out.push(UnshieldedImbalance {
                    token: tt,
                    balance: bal,
                });
            }
        }
    }
    Ok(out)
}

fn unshielded_token_wire(token: UnshieldedTokenType) -> String {
    if token == NIGHT {
        super::TokenType::Native.to_wire_token_type()
    } else {
        hex::encode(token.0 .0)
    }
}

fn next_free_intent_segment(
    stx: &StandardTransaction<MnSig, ProofMarker, PedSealed, InMemoryDB>,
) -> u16 {
    stx.intents
        .iter()
        .map(|p| *p.deref().0.deref())
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1)
}

fn merge_taker_unshielded_complement_sealed(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    scope: &SyncCacheScope,
    mut merged: TxSealed,
) -> Result<TxSealed, PayError> {
    let imbalances = unshielded_imbalances(&merged)?;
    if imbalances.is_empty() {
        return Ok(merged);
    }

    let rt = super::async_runtime::runtime();
    let signing_key = MidnightSigningKey::from_bytes(sender_private_key)
        .map_err(|e| err(format!("invalid signing key: {e}")))?;
    let taker_user = UserAddress::from(signing_key.verifying_key());
    let sender_addr = MidnightSigner
        .derive_address_for_chain_id(chain_id, sender_private_key)
        .map_err(|e| err(e.to_string()))?;

    let utxos = rt.block_on(super::unshielded_sync::get_unshielded_utxos_scoped(
        indexer_url,
        &sender_addr,
        scope,
    ))?;

    let mut outputs = Vec::new();
    let mut inputs = Vec::new();
    for im in &imbalances {
        if im.balance > 0 {
            outputs.push(UtxoOutput {
                value: im.balance as u128,
                owner: taker_user,
                type_: im.token,
            });
        } else {
            let need = im.balance.unsigned_abs();
            let token_wire = unshielded_token_wire(im.token);
            let selected = super::balance::select_utxos_for_token(
                &utxos,
                &sender_addr,
                sender_private_key,
                &token_wire,
                need,
                false,
            )?;
            let mut sum = 0u128;
            for u in selected {
                sum = sum.saturating_add(u.value);
                let ih = super::balance::parse_intent_hash_hex(&u.intent_hash)?;
                let out_no =
                    u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
                let vk =
                    super::balance::resolve_owner_vk(&u.owner, &sender_addr, sender_private_key)?;
                inputs.push(UtxoSpend {
                    value: u.value,
                    owner: vk,
                    type_: im.token,
                    intent_hash: ih,
                    output_no: out_no,
                });
            }
            let change = sum.saturating_sub(need);
            if change > 0 {
                outputs.push(UtxoOutput {
                    value: change,
                    owner: taker_user,
                    type_: im.token,
                });
            }
        }
    }

    if inputs.is_empty() && outputs.is_empty() {
        return Err(err(
            "no taker unshielded inputs or outputs to build for imbalances",
        ));
    }

    inputs.sort();
    outputs.sort();
    let offer = UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    };

    let Transaction::Standard(stx_ref) = &merged else {
        return Err(err("expected Standard transaction"));
    };
    let seg = next_free_intent_segment(stx_ref);

    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
    let (ledger_params, tip_secs) = rt
        .block_on(super::ledger_params::fetch_indexer_tip(indexer_url))
        .map_err(|e| err(format!("indexer block: {e}")))?;
    let ttl = Timestamp::from_secs(tip_secs.saturating_add(3600));
    let mut rng = OsRng;
    let intent_preimage: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Intent::new(
            &mut rng,
            Some(offer),
            None,
            vec![],
            vec![],
            vec![],
            None,
            ttl,
        );

    let (_seg, proven_intent) = rt
        .block_on(intent_preimage.prove(seg, prover, &ledger_params.cost_model.runtime_cost_model))
        .map_err(|e| err(format!("prove taker unshielded intent failed: {e:?}")))?;

    let intent_binding = proven_intent.binding_commitment;
    let mut unshielded_proven: TxProven = Transaction::Standard(StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents: MnHashMap::new().insert(seg, proven_intent),
        guaranteed_coins: None,
        fallible_coins: MnHashMap::new(),
        binding_randomness: intent_binding,
    });
    sign_proven_intent_segment(
        match &mut unshielded_proven {
            Transaction::Standard(stx) => stx,
            _ => return Err(err("expected Standard transaction")),
        },
        seg,
        &signing_key,
    )?;
    let unshielded_sealed = seal_proven_tx(unshielded_proven)?;
    merged = merged
        .merge(&unshielded_sealed)
        .map_err(|e| err(format!("merge taker unshielded partial failed: {e:?}")))?;

    if !unshielded_imbalances(&merged)?.is_empty() {
        return Err(err(
            "merged transaction is still unshielded-imbalanced after taker unshielded merge",
        ));
    }
    Ok(merged)
}

#[allow(clippy::type_complexity)]
fn signing_key_vectors(
    intent: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    signing_key: &MidnightSigningKey,
) -> Result<
    (
        Vec<MidnightSigningKey>,
        Vec<MidnightSigningKey>,
        Vec<MidnightSigningKey>,
    ),
    PayError,
> {
    let vk = signing_key.verifying_key();
    for inp in &intent.guaranteed_inputs() {
        if inp.owner != vk {
            return Err(err(
                "all guaranteed unshielded inputs must be owned by the signing key",
            ));
        }
    }
    for inp in &intent.fallible_inputs() {
        if inp.owner != vk {
            return Err(err(
                "all fallible unshielded inputs must be owned by the signing key",
            ));
        }
    }
    let n_g = intent.guaranteed_inputs().len();
    let n_f = intent.fallible_inputs().len();
    let g_keys = vec![signing_key.clone(); n_g];
    let f_keys = vec![signing_key.clone(); n_f];
    let n_regs = intent
        .dust_actions
        .as_ref()
        .map(|da| da.registrations.len())
        .unwrap_or(0);
    Ok((g_keys, f_keys, vec![signing_key.clone(); n_regs]))
}

fn sign_proven_intent_segment(
    stx: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    signing_key: &MidnightSigningKey,
) -> Result<(), PayError> {
    let Some(pair) = stx.intents.iter().find(|p| *p.deref().0.deref() == seg_id) else {
        return Ok(());
    };
    let intent = pair.deref().1.deref().clone();
    let (g_keys, f_keys, reg_keys) = signing_key_vectors(&intent, signing_key)?;
    let mut rng = OsRng;
    let signed = intent
        .sign(&mut rng, seg_id, &g_keys, &f_keys, &reg_keys)
        .map_err(|e| err(format!("intent signing failed for segment {seg_id}: {e:?}")))?;
    stx.intents = stx.intents.insert(seg_id, signed);
    Ok(())
}

fn sync_dust_state(
    rt: &tokio::runtime::Runtime,
    indexer_url: &str,
    seed: &[u8; 32],
    scope: &SyncCacheScope,
) -> Result<DustLocalState<InMemoryDB>, PayError> {
    let dsk = DustSecretKey::derive_secret_key(seed);
    rt.block_on(super::dust_sync::sync_dust_local_state_scoped(
        indexer_url,
        &dsk,
        scope,
    ))
    .map_err(|e| err(format!("dust sync failed: {e}")))
}

fn cover_dust_fees_sealed(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    dust_seed: [u8; 32],
    scope: &SyncCacheScope,
    mut merged: TxSealed,
    pay_fees: bool,
) -> Result<TxSealed, PayError> {
    if !super::chain_needs_dust_fee_registration(chain_id) || !pay_fees {
        return Ok(merged);
    }

    let Transaction::Standard(stx) = &merged else {
        return Err(err("expected Standard transaction"));
    };
    if stx.intents.iter().any(|p| {
        p.deref()
            .1
            .deref()
            .dust_actions
            .as_ref()
            .is_some_and(|da| !da.spends.is_empty())
    }) {
        return Ok(merged);
    }

    let rt = super::async_runtime::runtime();
    let (ledger_params, tip_secs) = rt
        .block_on(super::ledger_params::fetch_indexer_tip(indexer_url))
        .map_err(|e| err(format!("indexer block: {e}")))?;
    let dust_ctime = Timestamp::from_secs(tip_secs);
    let ttl = Timestamp::from_secs(dust_ctime.to_secs().saturating_add(3600));

    let Transaction::Standard(stx_ref) = &merged else {
        return Err(err("expected Standard transaction"));
    };
    // Intent segments must be >= 1; segment 0 is reserved (guaranteed) and rejects at submit (167).
    let fee_segment = stx_ref
        .intents
        .iter()
        .map(|p| *p.deref().0.deref())
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1);

    let mut fee_target = merged
        .fees(&ledger_params, false)
        .map_err(|e| err(format!("fee estimate failed: {e:?}")))?;

    let dsk = DustSecretKey::derive_secret_key(&dust_seed);
    let dust_state = sync_dust_state(rt, indexer_url, &dust_seed, scope)?;
    let signing_key = MidnightSigningKey::from_bytes(sender_private_key)
        .map_err(|e| err(format!("invalid signing key: {e}")))?;

    const MAX_ITERS: usize = 8;
    for attempt in 0..MAX_ITERS {
        let seg = fee_segment.saturating_add(attempt as u16);
        let spends = super::balance::select_dust_spends_preimage(
            dust_state.clone(),
            &dsk,
            fee_target,
            dust_ctime,
        )?;
        let dust_preimage = DustActions {
            spends: spends.into_iter().collect(),
            registrations: vec![].into(),
            ctime: dust_ctime,
        };
        let mut rng = OsRng;
        let intent_preimage: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
            Intent::new(
                &mut rng,
                None,
                None,
                vec![],
                vec![],
                vec![],
                Some(dust_preimage),
                ttl,
            );
        let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
        let (_fee_seg, proven_intent) = rt
            .block_on(intent_preimage.prove(
                seg,
                prover,
                &ledger_params.cost_model.runtime_cost_model,
            ))
            .map_err(|e| err(format!("prove dust fee intent failed: {e:?}")))?;
        let dust_proven = proven_intent
            .dust_actions
            .as_ref()
            .map(|sp| sp.deref().clone())
            .ok_or_else(|| err("proven dust intent did not contain dust actions"))?;

        // Transaction-level binding must include the intent witness scalar; merge only
        // adds partial bindings, so a zero here causes PedersenCheckFailure (185) at submit.
        let intent_binding = proven_intent.binding_commitment;
        let mut fee_proven: TxProven = Transaction::Standard(StandardTransaction {
            network_id: super::ledger_network_id(chain_id).map_err(err)?,
            intents: MnHashMap::new().insert(seg, proven_intent),
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: intent_binding,
        });
        sign_proven_intent_segment(
            match &mut fee_proven {
                Transaction::Standard(stx) => stx,
                _ => return Err(err("expected Standard transaction")),
            },
            seg,
            &signing_key,
        )?;
        let fee_sealed = seal_proven_tx(fee_proven)?;
        merged = merged
            .merge(&fee_sealed)
            .map_err(|e| err(format!("merge dust fee partial failed: {e:?}")))?;

        let imbalances: Vec<_> = merged
            .balance(Some(
                merged
                    .fees(&ledger_params, false)
                    .map_err(|e| err(format!("fee check failed: {e:?}")))?,
            ))
            .map_err(|e| err(format!("balance check failed: {e:?}")))?
            .into_iter()
            .filter(|(_, bal)| *bal < 0)
            .collect();
        if imbalances.is_empty() {
            return Ok(merged);
        }

        let actual_fee = merged
            .fees(&ledger_params, false)
            .map_err(|e| err(format!("fee re-estimate failed: {e:?}")))?;
        fee_target = actual_fee.max(fee_target.saturating_add(1)).max(
            dust_proven
                .spends
                .iter_deref()
                .map(|s| s.v_fee)
                .fold(0u128, |a, v| a.saturating_add(v))
                .saturating_add(1),
        );

        if attempt + 1 == MAX_ITERS {
            return Err(err(format!(
                "failed to cover dust fees after {MAX_ITERS} attempts (target={fee_target})"
            )));
        }
    }
    Ok(merged)
}

fn serialize_sealed(tx: TxSealed) -> Result<Vec<u8>, PayError> {
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).map_err(|e| err(format!("serialize sealed tx: {e}")))?;
    Ok(out)
}

/// Complete a maker swap offer: merge taker Zswap, cover fees, and return sealed bytes.
#[allow(clippy::too_many_arguments)]
pub fn balance_sealed_transaction(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    shielded_seed: Option<[u8; 32]>,
    dust_seed: Option<[u8; 32]>,
    maker_input: &[u8],
    scope: &mut SyncCacheScope,
    pay_fees: bool,
) -> Result<Vec<u8>, PayError> {
    super::tip_verify::refresh_indexer_block_height(scope, indexer_url);
    super::session_cache::invalidate_wallet_indexer_session_cache(indexer_url, scope);

    match parse_maker_tx(chain_id, maker_input)? {
        ParsedMaker::Sealed(maker) => {
            let needs_shielded = !shielded_imbalances(&maker)?.is_empty();
            let mut merged = if needs_shielded {
                let seed = shielded_seed.ok_or_else(|| {
                    err(
                        "balanceSealedTransaction requires a shielded wallet seed when the maker \
                         offer has shielded imbalances",
                    )
                })?;
                merge_taker_zswap_complement_sealed(chain_id, indexer_url, scope, seed, maker)?
            } else {
                maker
            };

            merged = merge_taker_unshielded_complement_sealed(
                chain_id,
                indexer_url,
                sender_private_key,
                scope,
                merged,
            )?;

            if super::chain_needs_dust_fee_registration(chain_id) && pay_fees {
                let seed = dust_seed.ok_or_else(|| {
                    err("Midnight Preview/Preprod requires a dust seed to pay transaction fees")
                })?;
                merged = cover_dust_fees_sealed(
                    chain_id,
                    indexer_url,
                    sender_private_key,
                    seed,
                    scope,
                    merged,
                    pay_fees,
                )?;
            }
            serialize_sealed(merged)
        }
        ParsedMaker::Proven(maker) => {
            let needs_shielded = !shielded_imbalances(&maker)?.is_empty();
            let merged = if needs_shielded {
                let seed = shielded_seed.ok_or_else(|| {
                    err(
                        "balanceSealedTransaction requires a shielded wallet seed when the maker \
                         offer has shielded imbalances",
                    )
                })?;
                merge_taker_zswap_complement_proven(chain_id, indexer_url, scope, seed, maker)?
            } else {
                maker
            };

            let mut bytes = Vec::new();
            tagged_serialize(&merged, &mut bytes)
                .map_err(|e| err(format!("serialize proven tx: {e}")))?;
            let balanced = super::balance::balance_unsealed_proven_standard_tx(
                chain_id,
                indexer_url,
                sender_private_key,
                shielded_seed,
                dust_seed,
                &bytes,
                scope,
                pay_fees,
            )?;
            super::sign::sign_and_seal(chain_id, &balanced, sender_private_key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maker_swap_json_tx_field() {
        let json =
            r#"{"method":"balanceSealedTransaction","tx":"0102ab","options":{"payFees":true}}"#;
        let bytes = parse_maker_swap_input("midnight:preview", json).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0xab]);
    }

    #[test]
    fn parse_mip6_offer_payload_rejects_non_midnight_transaction() {
        let json = r#"{"version":1,"transaction":"010203","gives":[],"wants":[]}"#;
        let err = parse_maker_swap_input("midnight:preview", json).unwrap_err();
        assert!(
            err.message.contains("sealed/proven") || err.message.contains("zswapoffer"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn unshielded_token_wire_matches_indexer_night_format() {
        assert_eq!(
            unshielded_token_wire(NIGHT),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn is_sealed_detects_tag() {
        assert!(is_sealed_midnight_payload(TAG_SEALED));
        assert!(!is_sealed_midnight_payload(TAG_PROVEN));
    }

    #[test]
    fn is_balance_sealed_maker_detects_sealed_and_proven() {
        assert!(is_balance_sealed_maker_payload(TAG_SEALED));
        assert!(is_balance_sealed_maker_payload(TAG_PROVEN));
        assert!(!is_balance_sealed_maker_payload(b"other"));
    }

    #[test]
    fn parse_maker_tx_rejects_proven_network_mismatch() {
        let tx = crate::chains::midnight::test_tx::minimal_proven_tx_bytes("preview");
        let err = parse_maker_tx("midnight:mainnet", &tx)
            .err()
            .expect("expected network mismatch");
        crate::chains::midnight::test_tx::assert_network_mismatch(&err);
    }
}
