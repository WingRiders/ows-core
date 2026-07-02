//! Wallet-style balancing of a Midnight Standard transaction (unshielded offer
//! + DUST registration / spends) against the indexer's UTXO set.
//!
//! Two entry points share the same plan:
//!
//! - [`balance_unsealed_preimage_standard_tx`] handles `proof-preimage,embedded-fr`
//!   payloads (dapp pre-prove output); fees are estimated by mock-proving the
//!   intent.
//! - [`balance_unsealed_proven_standard_tx`] handles `proof,embedded-fr` payloads
//!   (dapp post-prove output); existing ZK proofs are preserved verbatim and
//!   fees are estimated directly on the proven transaction. The wallet only
//!   needs to sign + seal afterwards.
//!
//! Both paths preserve `guaranteed_coins` / `fallible_coins` (shielded Zswap
//! offers) and the existing intent `binding_commitment`; the unshielded offer
//! itself does not contribute to the Pedersen binding, so we can re-balance it
//! without invalidating existing proofs.

use super::cache_io::SyncCacheScope;
use super::error::{PayError, PayErrorCode};
use midnight_base_crypto::signatures::{
    Signature as MnSig, SigningKey as MidnightSigningKey, VerifyingKey,
};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    ShieldedTokenType, TokenType as LedgerTokenType, UserAddress, NIGHT,
};
use midnight_ledger::dust::DustLocalState;
use midnight_ledger::dust::{
    DustActions, DustPublicKey, DustRegistration, DustSecretKey, DustSpend, INITIAL_DUST_PARAMETERS,
};
use midnight_ledger::structure::{
    Intent, ProofKind, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction,
    UnshieldedOffer, UtxoOutput, UtxoSpend,
};
use midnight_serialize::{
    tagged_deserialize, tagged_serialize, Deserializable as _, Serializable as _,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::MidnightSigner;
use ows_signer::ChainSigner as _;
use rand::rngs::OsRng;
use std::io::Cursor;
use std::ops::Deref as _;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof as ZswapProof;

use super::UnshieldedUtxo;

fn err(msg: impl Into<String>) -> PayError {
    PayError::new(PayErrorCode::InvalidInput, msg)
}

type TxPreimage = Transaction<
    MnSig,
    ProofPreimageMarker,
    <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
    InMemoryDB,
>;
type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

pub(super) fn parse_intent_hash_hex(
    s: &str,
) -> Result<midnight_ledger::structure::IntentHash, PayError> {
    use midnight_base_crypto::hash::HashOutput;
    use midnight_ledger::structure::IntentHash;
    let hex_s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_s).map_err(|e| err(format!("invalid intent hash: {e}")))?;
    if bytes.len() != 32 {
        return Err(err("intent hash must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(IntentHash(HashOutput(h)))
}

pub(super) fn resolve_owner_vk(
    owner_field: &str,
    sender_bech32: &str,
    sender_sk: &[u8; 32],
) -> Result<VerifyingKey, PayError> {
    let hex_s = owner_field.strip_prefix("0x").unwrap_or(owner_field);
    if let Ok(bytes) = hex::decode(hex_s) {
        if bytes.len() == 32 {
            let mut cur = Cursor::new(bytes);
            return VerifyingKey::deserialize(&mut cur, 0)
                .map_err(|e| err(format!("invalid owner verifying key: {e}")));
        }
    }
    if owner_field == sender_bech32 {
        let sk = MidnightSigningKey::from_bytes(sender_sk)
            .map_err(|e| err(format!("invalid signing key: {e}")))?;
        return Ok(sk.verifying_key());
    }
    Err(err(
        "UTXO owner must be 32-byte hex x-only pubkey or the sender's unshielded address",
    ))
}

pub(super) fn owner_matches_sender(owner: &str, sender_bech32: &str, vk_hex: &str) -> bool {
    if owner == sender_bech32 {
        return true;
    }
    let o = owner.strip_prefix("0x").unwrap_or(owner);
    o.eq_ignore_ascii_case(vk_hex)
}

/// Return sender-owned UTXOs for `token_wire`, sorted for coin selection.
pub(super) fn sender_utxos_sorted(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_sk: &[u8; 32],
    token_wire: &str,
    prefer_unregistered_for_dust: bool,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let vk = MidnightSigningKey::from_bytes(sender_sk)
        .map_err(|e| err(e.to_string()))?
        .verifying_key();
    let mut vk_raw = Vec::new();
    vk.serialize(&mut vk_raw).map_err(|e| err(e.to_string()))?;
    let vk_hex = hex::encode(&vk_raw);

    let night_wire = super::parse_token_type(Some("night"))?.to_wire_token_type();

    let mut cand: Vec<_> = utxos
        .iter()
        .filter(|u| owner_matches_sender(&u.owner, sender_bech32, &vk_hex))
        .filter(|u| u.token_type.eq_ignore_ascii_case(token_wire))
        .cloned()
        .collect();

    if prefer_unregistered_for_dust && token_wire.eq_ignore_ascii_case(&night_wire) {
        cand.sort_by(|a, b| {
            a.registered_for_dust_generation
                .cmp(&b.registered_for_dust_generation)
                .then_with(|| b.value.cmp(&a.value))
        });
    } else {
        cand.sort_by(|a, b| b.value.cmp(&a.value));
    }
    Ok(cand)
}

/// Pick just enough sender-owned UTXOs for `token_wire` to cover `need`.
pub(super) fn select_utxos_for_token(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_sk: &[u8; 32],
    token_wire: &str,
    need: u128,
    prefer_unregistered_for_dust: bool,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let cand = sender_utxos_sorted(
        utxos,
        sender_bech32,
        sender_sk,
        token_wire,
        prefer_unregistered_for_dust,
    )?;

    let mut out = Vec::new();
    let mut sum = 0u128;
    for u in cand {
        if sum >= need {
            break;
        }
        sum = sum.saturating_add(u.value);
        out.push(u);
    }
    if sum < need {
        return Err(err(format!(
            "insufficient balance for token {token_wire}: need {need}, have {sum}"
        )));
    }
    Ok(out)
}

/// Pick just enough sender-owned NIGHT UTXOs (in preference order) to cover `need`.
fn select_utxos_for_night(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_sk: &[u8; 32],
    need: u128,
    prefer_unregistered_for_dust: bool,
) -> Result<Vec<UnshieldedUtxo>, PayError> {
    let night_wire = super::parse_token_type(Some("night"))?.to_wire_token_type();
    select_utxos_for_token(
        utxos,
        sender_bech32,
        sender_sk,
        &night_wire,
        need,
        prefer_unregistered_for_dust,
    )
}

fn dust_allowance_from_night_inputs(
    selected: &[UnshieldedUtxo],
    dust_ctime: Timestamp,
) -> Result<u128, PayError> {
    let params = &INITIAL_DUST_PARAMETERS;
    let night_wire = super::parse_token_type(Some("night"))?.to_wire_token_type();

    let mut sum = 0u128;
    for u in selected {
        if !u.token_type.eq_ignore_ascii_case(&night_wire) {
            continue;
        }
        // Matches ledger: only unregistered Night inputs count towards generationless fee capacity.
        if u.registered_for_dust_generation {
            continue;
        }
        let value = u.value;
        let vfull = value.saturating_mul(params.night_dust_ratio as u128);
        let rate = value.saturating_mul(params.generation_decay_rate as u128);
        let Some(ts) = u.ctime_unix_secs else {
            return Err(err(
                "indexer did not provide block timestamp for unshielded UTXOs; cannot compute dust allowance",
            ));
        };
        let tstart = Timestamp::from_secs(ts);
        let dt = (dust_ctime - tstart).as_seconds();
        let dt = if dt < 0 { 0 } else { dt as u128 };
        let gen = dt.saturating_mul(rate);
        sum = sum.saturating_add(u128::min(vfull, gen));
    }
    Ok(sum)
}

/// Cap generationless allowance to a safe upper bound and ensure it covers the fee estimate.
fn cap_allow_fee_payment(dust_allow: u128, fee_dust: u128) -> Result<u128, PayError> {
    let allow_fee_payment = u128::min(
        dust_allow,
        fee_dust
            .saturating_mul(4)
            .max(fee_dust.saturating_add(50_000)),
    );
    if allow_fee_payment < fee_dust {
        return Err(err(format!(
            "DUST allowance {dust_allow} (capped to {allow_fee_payment}) is below estimated fee {fee_dust}"
        )));
    }
    Ok(allow_fee_payment)
}

fn registration_dust_actions<P>(
    dust_pk: DustPublicKey,
    night_vk: VerifyingKey,
    allow_fee_payment: u128,
    dust_ctime: Timestamp,
) -> DustActions<MnSig, P, InMemoryDB>
where
    P: ProofKind<InMemoryDB>,
{
    DustActions {
        spends: vec![].into(),
        registrations: vec![DustRegistration {
            allow_fee_payment,
            dust_address: Some(Sp::new(dust_pk)),
            night_key: night_vk,
            signature: None,
        }]
        .into(),
        ctime: dust_ctime,
    }
}

/// Generationless registration when unregistered NIGHT inputs cover fees; otherwise `None`.
fn try_registration_dust_actions<P>(
    bal: &BalancedUnshielded,
    fee_dust: u128,
    dust_pk: DustPublicKey,
    night_vk: VerifyingKey,
    dust_ctime: Timestamp,
) -> Result<Option<DustActions<MnSig, P, InMemoryDB>>, PayError>
where
    P: ProofKind<InMemoryDB>,
{
    let dust_allow = dust_allowance_from_night_inputs(&bal.selected, dust_ctime)?;
    if dust_allow == 0 {
        return Ok(None);
    }
    let allow_fee_payment = cap_allow_fee_payment(dust_allow, fee_dust)?;
    Ok(Some(registration_dust_actions(
        dust_pk,
        night_vk,
        allow_fee_payment,
        dust_ctime,
    )))
}

fn sync_dust_state(
    rt: &tokio::runtime::Runtime,
    indexer_url: &str,
    dsk: &DustSecretKey,
    scope: &SyncCacheScope,
) -> Result<DustLocalState<InMemoryDB>, PayError> {
    rt.block_on(super::dust_sync::sync_dust_local_state_scoped(
        indexer_url,
        dsk,
        scope,
    ))
    .map_err(|e| err(format!("dust sync failed: {e}")))
}

fn sum_dust_v_fee<P: ProofKind<InMemoryDB>>(
    spends: impl IntoIterator<Item = impl std::borrow::Borrow<DustSpend<P, InMemoryDB>>>,
) -> u128 {
    spends
        .into_iter()
        .map(|s| s.borrow().v_fee)
        .fold(0u128, |a, v| a.saturating_add(v))
}

/// Return ledger per-segment/token imbalances (negative = overspend).
fn tx_balance_imbalances(tx: &TxProven) -> Result<Vec<String>, PayError> {
    let imbalances: Vec<String> = tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
        .into_iter()
        .filter(|(_, bal)| *bal < 0)
        .map(|((_, segment), bal)| format!("segment {segment} overspent by {}", bal.unsigned_abs()))
        .collect();
    Ok(imbalances)
}

pub(super) fn select_dust_spends_preimage(
    mut st: DustLocalState<InMemoryDB>,
    dsk: &DustSecretKey,
    fee_dust: u128,
    dust_ctime: Timestamp,
) -> Result<Vec<DustSpend<ProofPreimageMarker, InMemoryDB>>, PayError> {
    let mut need = fee_dust.saturating_mul(2).saturating_add(100_000);
    let mut spends = Vec::new();
    for qdo in st.utxos().collect::<Vec<_>>() {
        if need == 0 {
            break;
        }
        let Some(gen_info) = st.generation_info(&qdo) else {
            continue;
        };
        let value = midnight_ledger::dust::DustOutput::from(qdo)
            .updated_value(&gen_info, dust_ctime, &st.params);
        if value == 0 {
            continue;
        }
        let v_fee = u128::min(value, need);
        let (st2, spend) = st
            .spend(dsk, &qdo, v_fee, dust_ctime)
            .map_err(|e| err(format!("dust spend build failed: {e}")))?;
        st = st2;
        spends.push(spend);
        need = need.saturating_sub(v_fee);
    }
    if need > 0 {
        return Err(err(
            "insufficient DUST balance to pay fees on Midnight Preview/Preprod",
        ));
    }
    Ok(spends)
}

/// Result of resolving sender UTXOs + building the rebalanced unshielded offer.
///
/// Identical regardless of proof kind: an `UnshieldedOffer` is just inputs +
/// outputs + signatures, with `S = MnSig` for both flows.
struct BalancedUnshielded {
    offer: UnshieldedOffer<MnSig, InMemoryDB>,
    selected: Vec<UnshieldedUtxo>,
}

struct DustActionBuildContext<'a> {
    rt: &'a tokio::runtime::Runtime,
    indexer_url: &'a str,
    sender_private_key: &'a [u8; 32],
    seed: [u8; 32],
    bal: &'a BalancedUnshielded,
    scope: &'a SyncCacheScope,
    dust_ctime: Timestamp,
    ledger_params: &'a midnight_ledger::structure::LedgerParameters,
}

fn fetch_indexer_tip_blocking(
    rt: &tokio::runtime::Runtime,
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), PayError> {
    rt.block_on(super::ledger_params::fetch_indexer_tip(indexer_url))
        .map_err(|e| err(format!("indexer block: {e}")))
}

/// Intent TTL anchored to chain time — matches the preimage balancing path and
/// avoids `OutsideTimeToDismiss` when the dapp used a wall-clock `ttlOneHour()`.
fn chain_aligned_intent_ttl(dust_ctime: Timestamp) -> Timestamp {
    Timestamp::from_secs(dust_ctime.to_secs().saturating_add(3600))
}

/// Resolve sender UTXOs, build the new unshielded offer (sorted), and report
/// which inputs were chosen so callers can compute the DUST allowance.
///
/// `outputs_in` should be the dapp-provided outputs (preimage path) or the
/// existing proven outputs (proven path). NIGHT outputs drive coin selection;
/// other token types (e.g. contract minted tokens) are copied verbatim.
fn build_balanced_unshielded_offer(
    rt: &tokio::runtime::Runtime,
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    has_fallible_unshielded: bool,
    outputs_in: Vec<UtxoOutput>,
    scope: &SyncCacheScope,
) -> Result<BalancedUnshielded, PayError> {
    if has_fallible_unshielded {
        return Err(err("fallible unshielded offers are not supported yet"));
    }

    let mut need_night: u128 = 0;
    for o in &outputs_in {
        if o.type_ == NIGHT {
            need_night = need_night.saturating_add(o.value);
        }
    }
    // If the tx has no NIGHT outputs (e.g. contract-only or custom-token send),
    // we still may need a NIGHT input for dust fee registration and/or general fee payment.

    let sender_addr = MidnightSigner
        .derive_address_for_chain_id(chain_id, sender_private_key)
        .map_err(|e| err(e.to_string()))?;

    // Incremental sync from disk/session cache; session cache is cleared after submit.
    let utxos = rt.block_on(super::unshielded_sync::get_unshielded_utxos_scoped(
        indexer_url,
        &sender_addr,
        scope,
    ))?;

    let needs_dust = super::chain_needs_dust_fee_registration(chain_id);
    let selected = if need_night == 0 && !needs_dust {
        vec![]
    } else if needs_dust {
        // Wallet-style: to maximize dust fee capacity, consider all sender NIGHT UTXOs.
        let night_wire = super::parse_token_type(Some("night"))?.to_wire_token_type();
        sender_utxos_sorted(&utxos, &sender_addr, sender_private_key, &night_wire, true)?
    } else {
        let need = if need_night == 0 { 1 } else { need_night };
        select_utxos_for_night(&utxos, &sender_addr, sender_private_key, need, needs_dust)?
    };

    let mut total_in = 0u128;
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    for u in &selected {
        total_in = total_in.saturating_add(u.value);
        let ih = parse_intent_hash_hex(&u.intent_hash)?;
        let out_no = u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
        let vk = resolve_owner_vk(&u.owner, &sender_addr, sender_private_key)?;
        inputs.push(UtxoSpend {
            value: u.value,
            owner: vk,
            type_: NIGHT,
            intent_hash: ih,
            output_no: out_no,
        });
    }

    let mut outputs = outputs_in;
    let change = total_in.saturating_sub(need_night);
    if change > 0 {
        // If we didn't add any inputs, there is no change to return.
        let sender_user = UserAddress::from(inputs[0].owner.clone());
        outputs.push(UtxoOutput {
            value: change,
            owner: sender_user,
            type_: NIGHT,
        });
    }

    // Ledger validity requires inputs/outputs to be sorted (MalformedError::InputsNotSorted = 189).
    inputs.sort();
    outputs.sort();

    // Start empty: `Intent::sign` appends signatures; pre-filling breaks well-formedness.
    let offer = UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    };
    Ok(BalancedUnshielded { offer, selected })
}

/// Build the rebalanced unshielded offer plus (if needed) a DUST registration / spend section
/// for a proof-preimage payload.
///
/// The output is a serialized proof-preimage v9 `Transaction::Standard` payload, suitable for
/// passing into [`super::sign::sign_prove_and_seal`].
pub(super) fn balance_unsealed_preimage_standard_tx(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    dust_seed: Option<[u8; 32]>,
    tx_bytes: &[u8],
    scope: &SyncCacheScope,
    pay_fees: bool,
) -> Result<Vec<u8>, PayError> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxPreimage = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse proof-preimage tx bytes: {e}")))?;
    let Transaction::Standard(stx) = tx else {
        return Err(err("expected Standard transaction"));
    };
    super::ensure_tx_network_id_matches_chain(chain_id, &stx.network_id)?;
    if stx.intents.iter().count() != 1 {
        return Err(err("expected exactly one intent segment"));
    }
    let pair_sp = stx.intents.iter().next().expect("count == 1");
    let (seg_id_sp, intent_sp) = pair_sp.deref();
    let seg_id: u16 = *seg_id_sp.deref();
    let intent_in = intent_sp.deref().clone();

    let outputs_in: Vec<UtxoOutput> = intent_in
        .guaranteed_unshielded_offer
        .as_ref()
        .map(|sp| {
            sp.deref()
                .outputs
                .iter_deref()
                .map(|o| UtxoOutput {
                    value: o.value,
                    owner: o.owner,
                    type_: o.type_,
                })
                .collect()
        })
        .unwrap_or_default();
    let rt = super::async_runtime::runtime();
    let bal = build_balanced_unshielded_offer(
        rt,
        chain_id,
        indexer_url,
        sender_private_key,
        intent_in.fallible_unshielded_offer.is_some(),
        outputs_in,
        scope,
    )?;
    let needs_dust = super::chain_needs_dust_fee_registration(chain_id);

    let dust_actions = if needs_dust && pay_fees {
        if intent_in.dust_actions.is_some() {
            return Err(err("existing dust actions are not supported yet"));
        }
        let seed = dust_seed.ok_or_else(|| err("Midnight Preview/Preprod requires dust seed"))?;
        let (ledger_params, tip_secs) = fetch_indexer_tip_blocking(rt, indexer_url)?;
        let dust_ctx = DustActionBuildContext {
            rt,
            indexer_url,
            sender_private_key,
            seed,
            bal: &bal,
            scope,
            dust_ctime: Timestamp::from_secs(tip_secs),
            ledger_params: &ledger_params,
        };
        Some(build_preimage_dust_actions(chain_id, seg_id, &dust_ctx)?)
    } else {
        None
    };

    let intent_out: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: Some(Sp::new(bal.offer)),
        fallible_unshielded_offer: None,
        actions: intent_in.actions.clone(),
        dust_actions: dust_actions.map(Sp::new),
        ttl: intent_in.ttl,
        binding_commitment: intent_in.binding_commitment,
    };
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_out);

    let mut stx_out: StandardTransaction<
        MnSig,
        ProofPreimageMarker,
        PedersenRandomness,
        InMemoryDB,
    > = StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents,
        guaranteed_coins: stx.guaranteed_coins.clone(),
        fallible_coins: stx.fallible_coins.clone(),
        binding_randomness: stx.binding_randomness,
    };
    stx_out.recompute_binding_randomness();
    let tx_out: TxPreimage = Transaction::Standard(stx_out);

    let mut out = Vec::new();
    tagged_serialize(&tx_out, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Same plan as [`balance_unsealed_preimage_standard_tx`], but for already-proven
/// (`proof,embedded-fr`) payloads. Existing ZK proofs in `actions`, `guaranteed_coins`,
/// and `fallible_coins` are preserved verbatim; we only inject unshielded inputs/outputs
/// and (for Preview/Preprod) a fresh DUST registration.
#[allow(clippy::too_many_arguments)]
pub(super) fn balance_unsealed_proven_standard_tx(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8; 32],
    shielded_seed: Option<[u8; 32]>,
    dust_seed: Option<[u8; 32]>,
    tx_bytes: &[u8],
    scope: &SyncCacheScope,
    pay_fees: bool,
) -> Result<Vec<u8>, PayError> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProven = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse proven tx bytes: {e}")))?;
    let Transaction::Standard(stx) = tx else {
        return Err(err("expected Standard transaction"));
    };
    super::ensure_tx_network_id_matches_chain(chain_id, &stx.network_id)?;

    let tx = if let Some(offer) = stx.guaranteed_coins.as_ref() {
        if zswap_offer_needs_shielded_inputs(offer.deref())
            || !ledger_shielded_deficits(&Transaction::Standard(stx.clone()))?.is_empty()
        {
            let seed = shielded_seed.ok_or_else(|| {
                err(
                    "contract transaction needs shielded coin inputs; use a mnemonic wallet \
                     (shielded seed at m/44'/2400'/0'/3/0) and ensure OWS_MIDNIGHT_SHIELDED_VK_FREE is unset",
                )
            })?;
            attach_shielded_proven_inputs_if_needed(
                indexer_url,
                scope,
                seed,
                Transaction::Standard(stx),
            )?
        } else {
            Transaction::Standard(stx)
        }
    } else {
        Transaction::Standard(stx)
    };

    let Transaction::Standard(stx) = tx else {
        return Err(err("expected Standard transaction"));
    };
    if stx.intents.iter().count() != 1 {
        return Err(err("expected exactly one intent segment"));
    }
    let pair_sp = stx.intents.iter().next().expect("count == 1");
    let (seg_id_sp, intent_sp) = pair_sp.deref();
    let seg_id: u16 = *seg_id_sp.deref();
    let intent_in = intent_sp.deref().clone();

    let outputs_in: Vec<UtxoOutput> = intent_in
        .guaranteed_unshielded_offer
        .as_ref()
        .map(|sp| {
            sp.deref()
                .outputs
                .iter_deref()
                .map(|o| UtxoOutput {
                    value: o.value,
                    owner: o.owner,
                    type_: o.type_,
                })
                .collect()
        })
        .unwrap_or_default();
    let rt = super::async_runtime::runtime();
    let bal = build_balanced_unshielded_offer(
        rt,
        chain_id,
        indexer_url,
        sender_private_key,
        intent_in.fallible_unshielded_offer.is_some(),
        outputs_in,
        scope,
    )?;
    let needs_dust = super::chain_needs_dust_fee_registration(chain_id);
    let indexer_tip = if needs_dust {
        Some(fetch_indexer_tip_blocking(rt, indexer_url)?)
    } else {
        None
    };
    let dust_ctime = indexer_tip
        .as_ref()
        .map(|(_, ts)| Timestamp::from_secs(*ts));

    // First pass: assemble intent / tx with an unsigned dust registration (placeholder
    // `allow_fee_payment` = 0) so we can ask the ledger for an accurate fee estimate
    // before we know the real `allow_fee_payment`.
    let intent_out_first = assemble_proven_intent(
        &intent_in,
        &bal,
        dust_seed,
        sender_private_key,
        needs_dust && pay_fees,
        dust_ctime,
    )?;
    let tx_first: TxProven = wrap_proven_standard(chain_id, &stx, seg_id, intent_out_first)?;

    let intent_ttl = dust_ctime
        .map(chain_aligned_intent_ttl)
        .unwrap_or(intent_in.ttl);

    let dust_actions = if needs_dust && pay_fees {
        if intent_in.dust_actions.is_some() {
            return Err(err("existing dust actions are not supported yet"));
        }
        let seed = dust_seed.ok_or_else(|| err("Midnight Preview/Preprod requires dust seed"))?;
        let (ledger_params, tip_secs) = indexer_tip
            .as_ref()
            .map(|(lp, ts)| (lp, *ts))
            .ok_or_else(|| err("Midnight Preview/Preprod requires chain timestamp for dust"))?;
        let dust_ctx = DustActionBuildContext {
            rt,
            indexer_url,
            sender_private_key,
            seed,
            bal: &bal,
            scope,
            dust_ctime: Timestamp::from_secs(tip_secs),
            ledger_params,
        };
        Some(cover_proven_dust_fees(
            chain_id, &dust_ctx, &tx_first, &stx, seg_id, &intent_in, intent_ttl,
        )?)
    } else {
        None
    };

    let intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: Some(Sp::new(bal.offer)),
        fallible_unshielded_offer: None,
        actions: intent_in.actions.clone(),
        dust_actions: dust_actions.map(Sp::new),
        ttl: intent_ttl,
        binding_commitment: intent_in.binding_commitment,
    };
    let tx_out = wrap_proven_standard(chain_id, &stx, seg_id, intent_out)?;

    let imbalances = tx_balance_imbalances(&tx_out)?;
    if !imbalances.is_empty() {
        return Err(err(format!(
            "balanced transaction is still ledger-imbalanced ({})",
            imbalances.join("; ")
        )));
    }

    let mut out = Vec::new();
    tagged_serialize(&tx_out, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Build a preview/preprod dust registration / spend section for the preimage flow.
///
/// Estimates fees by mock-proving an intent-only transaction, then sizes either
/// a registration's `allow_fee_payment` (preferred) or a set of dust spends as
/// fallback.
fn build_preimage_dust_actions(
    chain_id: &str,
    seg_id: u16,
    ctx: &DustActionBuildContext<'_>,
) -> Result<DustActions<MnSig, ProofPreimageMarker, InMemoryDB>, PayError> {
    let dsk = DustSecretKey::derive_secret_key(&ctx.seed);
    let dust_pk = DustPublicKey::from(dsk.clone());
    let night_vk = MidnightSigningKey::from_bytes(ctx.sender_private_key)
        .map_err(|e| err(e.to_string()))?
        .verifying_key();

    let dust_ctime = ctx.dust_ctime;
    let mut rng = OsRng;
    let ttl = chain_aligned_intent_ttl(dust_ctime);

    // Estimate fees by mock-proving a placeholder intent with the same unshielded
    // offer. We deliberately omit existing contract actions so the mock-prove
    // path stays cheap; the dust registration is just a fee accounting hint.
    let intent_no_dust = Intent::new(
        &mut rng,
        Some(ctx.bal.offer.clone()),
        None,
        vec![],
        vec![],
        vec![],
        None,
        ttl,
    );
    let intents0: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_no_dust);
    let network_id = super::ledger_network_id(chain_id).map_err(err)?;
    let tx0: TxPreimage = Transaction::from_intents(&network_id, intents0);
    let tx0p = tx0
        .mock_prove()
        .map_err(|e| err(format!("fee mock-prove failed: {e:?}")))?;
    let fee_dust = tx0p
        .fees(ctx.ledger_params, false)
        .map_err(|e| err(format!("fee estimate failed: {e:?}")))?;

    if let Some(actions) = try_registration_dust_actions::<ProofPreimageMarker>(
        ctx.bal, fee_dust, dust_pk, night_vk, dust_ctime,
    )? {
        return Ok(actions);
    }

    let dust_state = sync_dust_state(ctx.rt, ctx.indexer_url, &dsk, ctx.scope)?;
    let spends = select_dust_spends_preimage(dust_state, &dsk, fee_dust, dust_ctime)?;
    Ok(DustActions {
        spends: spends.into_iter().collect(),
        registrations: vec![].into(),
        ctime: dust_ctime,
    })
}

/// Assemble a proven-flow intent for the first-pass fee estimate.
///
/// When dust registration is needed, the registration is inserted with
/// `allow_fee_payment = 0` and `signature = None` — just enough to make the
/// fee model accurately account for its cost. The final allow value is filled
/// in by [`cover_proven_dust_fees`] using the resulting fee estimate.
fn assemble_proven_intent(
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    bal: &BalancedUnshielded,
    dust_seed: Option<[u8; 32]>,
    sender_private_key: &[u8; 32],
    needs_dust: bool,
    dust_ctime: Option<Timestamp>,
) -> Result<Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>, PayError> {
    let intent_ttl = dust_ctime
        .map(chain_aligned_intent_ttl)
        .unwrap_or(intent_in.ttl);

    let dust_actions_placeholder: Option<DustActions<MnSig, ProofMarker, InMemoryDB>> =
        if needs_dust {
            let seed =
                dust_seed.ok_or_else(|| err("Midnight Preview/Preprod requires dust seed"))?;
            let _dsk = DustSecretKey::derive_secret_key(&seed);
            let dust_pk = DustPublicKey::from(_dsk);
            let night_vk = MidnightSigningKey::from_bytes(sender_private_key)
                .map_err(|e| err(e.to_string()))?
                .verifying_key();

            let dust_ctime = dust_ctime
                .ok_or_else(|| err("Midnight Preview/Preprod requires chain timestamp for dust"))?;

            Some(DustActions {
                spends: vec![].into(),
                registrations: vec![DustRegistration {
                    allow_fee_payment: 0,
                    dust_address: Some(Sp::new(dust_pk)),
                    night_key: night_vk,
                    signature: None,
                }]
                .into(),
                ctime: dust_ctime,
            })
        } else {
            None
        };

    Ok(Intent {
        guaranteed_unshielded_offer: Some(Sp::new(bal.offer.clone())),
        fallible_unshielded_offer: None,
        actions: intent_in.actions.clone(),
        dust_actions: dust_actions_placeholder.map(Sp::new),
        ttl: intent_ttl,
        binding_commitment: intent_in.binding_commitment,
    })
}

/// Cover Preview/Preprod dust fees on a proven dapp tx, iterating until the ledger
/// reports a balanced transaction. Dust spend proofs add cost beyond the first-pass
/// estimate (placeholder registration on `tx_first`), so a single estimate is not
/// always enough.
fn cover_proven_dust_fees(
    chain_id: &str,
    ctx: &DustActionBuildContext<'_>,
    tx_first: &TxProven,
    stx: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    intent_ttl: Timestamp,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, PayError> {
    let dsk = DustSecretKey::derive_secret_key(&ctx.seed);
    let dust_pk = DustPublicKey::from(dsk.clone());
    let night_vk = MidnightSigningKey::from_bytes(ctx.sender_private_key)
        .map_err(|e| err(e.to_string()))?
        .verifying_key();

    let ledger_params = ctx.ledger_params;

    let mut fee_target = tx_first
        .fees(ledger_params, false)
        .map_err(|e| err(format!("fee estimate failed: {e:?}")))?;

    const MAX_FEE_ITERS: usize = 8;
    let mut dust_state: Option<DustLocalState<InMemoryDB>> = None;
    for attempt in 0..MAX_FEE_ITERS {
        if let Some(registration) = try_registration_dust_actions::<ProofMarker>(
            ctx.bal,
            fee_target,
            dust_pk,
            night_vk.clone(),
            ctx.dust_ctime,
        )? {
            let intent_out = Intent {
                guaranteed_unshielded_offer: Some(Sp::new(ctx.bal.offer.clone())),
                fallible_unshielded_offer: None,
                actions: intent_in.actions.clone(),
                dust_actions: Some(Sp::new(registration.clone())),
                ttl: intent_ttl,
                binding_commitment: intent_in.binding_commitment,
            };
            let tx_check = wrap_proven_standard(chain_id, stx, seg_id, intent_out)?;
            if tx_balance_imbalances(&tx_check)?.is_empty() {
                return Ok(registration);
            }
        }

        if dust_state.is_none() {
            dust_state = Some(sync_dust_state(ctx.rt, ctx.indexer_url, &dsk, ctx.scope)?);
        }
        let cached_dust = match &dust_state {
            Some(s) => s,
            None => unreachable!("dust state synced above"),
        };
        let dust_actions = build_proven_dust_spends(
            ctx,
            tx_first,
            seg_id,
            fee_target,
            ledger_params,
            cached_dust,
        )?;
        let intent_out = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(ctx.bal.offer.clone())),
            fallible_unshielded_offer: None,
            actions: intent_in.actions.clone(),
            dust_actions: Some(Sp::new(dust_actions.clone())),
            ttl: intent_ttl,
            binding_commitment: intent_in.binding_commitment,
        };
        let tx_check = wrap_proven_standard(chain_id, stx, seg_id, intent_out)?;

        if tx_balance_imbalances(&tx_check)?.is_empty() {
            return Ok(dust_actions);
        }

        let actual_fee = tx_check
            .fees(ledger_params, false)
            .map_err(|e| err(format!("fee re-estimate failed: {e:?}")))?;
        let dust_paid = sum_dust_v_fee(dust_actions.spends.iter_deref());
        fee_target = actual_fee
            .max(fee_target.saturating_add(1))
            .max(dust_paid.saturating_add(1));

        if attempt + 1 == MAX_FEE_ITERS {
            let imbalances = tx_balance_imbalances(&tx_check)?;
            return Err(err(format!(
                "failed to cover dust fees after {MAX_FEE_ITERS} attempts \
                 (target={fee_target}, paid={dust_paid}, fee={actual_fee}): {}",
                imbalances.join("; ")
            )));
        }
    }

    Err(err("failed to cover dust fees"))
}

fn build_proven_dust_spends(
    ctx: &DustActionBuildContext<'_>,
    tx_first: &TxProven,
    seg_id: u16,
    fee_target: u128,
    ledger_params: &midnight_ledger::structure::LedgerParameters,
    dust_state: &DustLocalState<InMemoryDB>,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, PayError> {
    let dsk = DustSecretKey::derive_secret_key(&ctx.seed);

    let spends = select_dust_spends_preimage(dust_state.clone(), &dsk, fee_target, ctx.dust_ctime)?;

    let Transaction::Standard(stx_first) = tx_first else {
        return Err(err("expected Standard transaction"));
    };
    if stx_first.intents.iter().count() != 1 {
        return Err(err("expected exactly one intent segment"));
    }
    let pair_sp = stx_first.intents.iter().next().expect("count == 1");
    let (_seg_id_sp, intent_sp) = pair_sp.deref();
    let intent_first = intent_sp.deref().clone();

    let dust_preimage: DustActions<MnSig, ProofPreimageMarker, InMemoryDB> = DustActions {
        spends: spends.into_iter().collect(),
        registrations: vec![].into(),
        ctime: ctx.dust_ctime,
    };
    let prove_intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: Some(Sp::new(dust_preimage)),
        ttl: intent_first.ttl,
        binding_commitment: intent_first.binding_commitment,
    };

    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
    let (_seg_id, proven_intent) = ctx
        .rt
        .block_on(prove_intent.prove(seg_id, prover, &ledger_params.cost_model.runtime_cost_model))
        .map_err(|e| err(format!("prove dust spends failed: {e:?}")))?;

    proven_intent
        .dust_actions
        .as_ref()
        .map(|sp| sp.deref().clone())
        .ok_or_else(|| err("proven dust spend intent did not contain dust actions"))
}

/// Per-segment shielded token deficits (ledger `balance` negative = overspend).
fn ledger_shielded_deficits(
    tx: &TxProven,
) -> Result<Vec<(ShieldedTokenType, u128, u16)>, PayError> {
    let mut out = Vec::new();
    for ((token, segment), bal) in tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
    {
        if let LedgerTokenType::Shielded(tt) = token {
            if bal < 0 {
                out.push((tt, bal.unsigned_abs(), segment));
            }
        }
    }
    Ok(out)
}

fn zswap_offer_needs_shielded_inputs(offer: &ZswapOffer<ZswapProof, InMemoryDB>) -> bool {
    offer.inputs.iter_deref().next().is_none() && offer.outputs.iter_deref().next().is_some()
}

/// Attach wallet shielded spends to an imbalanced proven `guaranteed_coins` offer (contract deposits).
fn attach_shielded_proven_inputs_if_needed(
    indexer_url: &str,
    scope: &SyncCacheScope,
    shielded_seed: [u8; 32],
    tx: TxProven,
) -> Result<TxProven, PayError> {
    let Transaction::Standard(mut stx) = tx else {
        return Err(err("expected Standard transaction"));
    };
    let Some(offer_sp) = stx.guaranteed_coins.as_ref() else {
        return Ok(Transaction::Standard(stx));
    };
    let offer = offer_sp.deref();
    if !zswap_offer_needs_shielded_inputs(offer) {
        let check = Transaction::Standard(stx.clone());
        if ledger_shielded_deficits(&check)?.is_empty() {
            return Ok(Transaction::Standard(stx));
        }
    }

    let deficits = ledger_shielded_deficits(&Transaction::Standard(stx.clone()))?;
    if deficits.is_empty() {
        return Ok(Transaction::Standard(stx));
    }

    let rt = super::async_runtime::runtime();
    let mut wallet = rt
        .block_on(super::shielded_sync::sync_shielded_wallet_state_scoped(
            indexer_url,
            &shielded_seed,
            scope,
        ))
        .map_err(|e| err(format!("shielded wallet sync failed: {e}")))?;

    super::shielded_session::ensure_shielded_merkle_ready(&mut wallet)
        .map_err(|e| err(format!("shielded merkle tree not ready for spend: {e}")))?;

    let mut inputs_by_segment: std::collections::BTreeMap<u16, Vec<(ShieldedTokenType, u128)>> =
        std::collections::BTreeMap::new();
    for (tt, need, segment) in deficits {
        inputs_by_segment
            .entry(segment)
            .or_default()
            .push((tt, need));
    }

    let mut merged_offer = offer.clone();
    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;
    let mut binding_delta = PedersenRandomness::from(0);

    for (segment, seg_deficits) in inputs_by_segment {
        let selection = super::dapp_connector::collect_shielded_preimage_inputs(
            &mut wallet,
            segment,
            &seg_deficits,
        )?;
        if selection.inputs.is_empty() {
            continue;
        }
        for inp in &selection.inputs {
            binding_delta = binding_delta + inp.binding_randomness();
        }
        let change_outputs = super::dapp_connector::build_shielded_change_outputs(
            &wallet,
            segment,
            &selection.spent_by_token,
            &seg_deficits,
        )?;
        for out in &change_outputs {
            binding_delta = binding_delta + out.binding_randomness();
        }
        let preimage_offer = ZswapOffer::new(selection.inputs, change_outputs, vec![])
            .ok_or_else(|| err("failed to build shielded input offer for contract balancing"))?;
        let (_seg, proven_partial) = rt
            .block_on(preimage_offer.prove(prover.clone(), segment))
            .map_err(|e| err(format!("prove shielded inputs failed: {e:?}")))?;
        merged_offer = merged_offer
            .merge(&proven_partial)
            .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?;
    }

    stx.guaranteed_coins = Some(Sp::new(merged_offer));
    // Proven txs cannot call `recompute_binding_randomness`; add spend randomness from preimages.
    stx.binding_randomness = stx.binding_randomness + binding_delta;
    Ok(Transaction::Standard(stx))
}

/// Reassemble a proven `StandardTransaction`, preserving shielded Zswap offers
/// and binding randomness (must already match `guaranteed_coins` / intents).
fn wrap_proven_standard(
    chain_id: &str,
    stx_in: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Result<TxProven, PayError> {
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_out);
    Ok(Transaction::Standard(StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents,
        guaranteed_coins: stx_in.guaranteed_coins.clone(),
        fallible_coins: stx_in.fallible_coins.clone(),
        binding_randomness: stx_in.binding_randomness,
    }))
}
