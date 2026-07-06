//! [MIP-0006](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mips/mip-0006-p2p-atomic-swaps.md)
//! offer payload validation and optional authentication.

use super::error::{PayError, PayErrorCode};
use super::parse_token_type;
use k256::schnorr::{signature::Verifier, Signature as SchnorrSignature, VerifyingKey};
use midnight_coin_structure::coin::ShieldedTokenType;
use midnight_serialize::{tagged_deserialize, Deserializable, Serializable};
use midnight_storage::db::InMemoryDB;
use midnight_zswap::Offer as ZswapOffer;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::Deref as _;
use transient_crypto::proofs::Proof as ZswapProof;

fn err(msg: impl Into<String>) -> PayError {
    PayError::new(PayErrorCode::InvalidInput, msg)
}

/// Default fallible segment when wrapping a bare [`zswapoffer`] bech32 (MIP-0005) into a proven tx.
pub const DEFAULT_ZSWAP_OFFER_SEGMENT: u16 = 1;

/// MIP-0005 bech32 human-readable part for a bare Zswap offer (`zswapoffer1…` on the wire).
pub const ZSWAP_OFFER_BECH32_HRP: &str = "zswapoffer";

#[derive(Debug, Clone, Deserialize)]
struct Mip6TokenAmountJson {
    token: String,
    amount: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Mip6AuthJson {
    #[serde(rename = "signerPublicKey")]
    signer_public_key: String,
    signature: String,
    scheme: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Mip6OfferPayloadJson {
    version: u32,
    transaction: String,
    wants: Vec<Mip6TokenAmountJson>,
    gives: Vec<Mip6TokenAmountJson>,
    #[serde(default)]
    auth: Option<Mip6AuthJson>,
}

/// `true` when `v` looks like a MIP-0006 offer payload (not connector `balanceSealedTransaction` JSON).
pub fn is_mip6_offer_payload(v: &serde_json::Value) -> bool {
    v.get("version").is_some()
        && v.get("transaction").is_some()
        && v.get("gives").is_some()
        && v.get("wants").is_some()
}

fn shielded_token_wire(token: ShieldedTokenType) -> String {
    parse_token_type(Some(&format!("0x{}", hex::encode(token.0 .0))))
        .map(|t| t.to_wire_token_type())
        .unwrap_or_else(|_| hex::encode(token.0 .0))
}

fn normalize_token_wire(token: &str) -> Result<String, PayError> {
    Ok(parse_token_type(Some(token))?.to_wire_token_type())
}

fn parse_amount_string(amount: &str) -> Result<u128, PayError> {
    amount
        .trim()
        .parse::<u128>()
        .map_err(|e| err(format!("invalid MIP-0006 amount {amount:?}: {e}")))
}

fn advertised_token_map(
    entries: &[Mip6TokenAmountJson],
    label: &str,
) -> Result<BTreeMap<String, u128>, PayError> {
    let mut out = BTreeMap::new();
    for entry in entries {
        let token = normalize_token_wire(&entry.token)?;
        let amount = parse_amount_string(&entry.amount)?;
        if amount == 0 {
            return Err(err(format!(
                "MIP-0006 {label} entry for token {token} must be non-zero"
            )));
        }
        let slot = out.entry(token).or_insert(0u128);
        *slot = slot
            .checked_add(amount)
            .ok_or_else(|| err(format!("MIP-0006 {label} amount overflow for token")))?;
    }
    Ok(out)
}

/// Positive delta = maker spends (gives); negative = maker receives (wants).
fn deltas_to_gives_wants(
    offer: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> (BTreeMap<String, u128>, BTreeMap<String, u128>) {
    let mut gives = BTreeMap::new();
    let mut wants = BTreeMap::new();
    for delta in offer.deltas.iter_deref() {
        let token = shielded_token_wire(delta.token_type);
        if delta.value > 0 {
            *gives.entry(token).or_insert(0) += delta.value as u128;
        } else if delta.value < 0 {
            *wants.entry(token).or_insert(0) += delta.value.unsigned_abs();
        }
    }
    (gives, wants)
}

fn compare_token_maps(
    advertised: &BTreeMap<String, u128>,
    actual: &BTreeMap<String, u128>,
    label: &str,
) -> Result<(), PayError> {
    if advertised == actual {
        return Ok(());
    }
    Err(err(format!(
        "MIP-0006 {label} does not match offer deltas (advertised={advertised:?}, actual={actual:?})"
    )))
}

fn offers_from_maker_bytes(
    maker_bytes: &[u8],
) -> Result<Vec<ZswapOffer<ZswapProof, InMemoryDB>>, PayError> {
    const TAG_PROVEN: &[u8] = b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";
    const TAG_SEALED: &[u8] =
        b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";

    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofMarker, Transaction};
    use transient_crypto::commitment::PedersenRandomness;

    if maker_bytes.starts_with(TAG_PROVEN) {
        let mut r: &[u8] = maker_bytes;
        let tx: Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> =
            tagged_deserialize(&mut r)
                .map_err(|e| err(format!("failed to parse proven maker tx: {e}")))?;
        return offers_from_standard_tx(&tx);
    }
    if maker_bytes.starts_with(TAG_SEALED) {
        type PedSealed =
            <ProofMarker as midnight_ledger::structure::ProofKind<InMemoryDB>>::Pedersen;
        let mut r: &[u8] = maker_bytes;
        let tx: Transaction<MnSig, ProofMarker, PedSealed, InMemoryDB> = tagged_deserialize(&mut r)
            .map_err(|e| err(format!("failed to parse sealed maker tx: {e}")))?;
        return offers_from_standard_tx(&tx);
    }

    Err(err(
        "MIP-0006 transaction must be zswapoffer bech32 or a sealed/proven Midnight transaction",
    ))
}

fn offers_from_standard_tx<B>(
    tx: &midnight_ledger::structure::Transaction<
        midnight_base_crypto::signatures::Signature,
        midnight_ledger::structure::ProofMarker,
        B,
        InMemoryDB,
    >,
) -> Result<Vec<ZswapOffer<ZswapProof, InMemoryDB>>, PayError>
where
    B: midnight_storage::Storable<InMemoryDB> + Clone,
{
    use midnight_ledger::structure::Transaction;
    let Transaction::Standard(stx) = tx else {
        return Err(err("expected Standard transaction"));
    };
    let mut offers = Vec::new();
    if let Some(gc) = stx.guaranteed_coins.as_ref() {
        offers.push(gc.deref().clone());
    }
    for pair in stx.fallible_coins.iter() {
        offers.push(pair.deref().1.deref().clone());
    }
    if offers.is_empty() {
        return Err(err("maker transaction has no Zswap offers to validate"));
    }
    Ok(offers)
}

fn aggregate_gives_wants(
    offers: &[ZswapOffer<ZswapProof, InMemoryDB>],
) -> (BTreeMap<String, u128>, BTreeMap<String, u128>) {
    let mut gives = BTreeMap::new();
    let mut wants = BTreeMap::new();
    for offer in offers {
        let (g, w) = deltas_to_gives_wants(offer);
        for (token, amount) in g {
            *gives.entry(token).or_insert(0) += amount;
        }
        for (token, amount) in w {
            *wants.entry(token).or_insert(0) += amount;
        }
    }
    (gives, wants)
}

/// True when a bare Zswap offer should be placed in `guaranteed_coins` (segment 0), matching
/// [`super::dapp_connector::build_make_intent_unsealed_tx`] maker placement for relay solvers.
pub fn zswap_offer_belongs_in_guaranteed(offer: &ZswapOffer<ZswapProof, InMemoryDB>) -> bool {
    let has_inputs = offer.inputs.iter_deref().next().is_some();
    let has_outputs = offer.outputs.iter_deref().next().is_some();
    let shielded_swap = has_inputs && has_outputs;
    has_outputs && (shielded_swap || !has_inputs)
}

/// Infer Zswap segment when wrapping bare `zswapoffer` into a proven tx.
pub fn infer_zswap_segment_from_maker_bytes(maker_bytes: &[u8]) -> u16 {
    const TAG_PROVEN: &[u8] = b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";
    const TAG_SEALED: &[u8] =
        b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";

    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofMarker, Transaction};
    use transient_crypto::commitment::PedersenRandomness;

    let parse_stx = |bytes: &[u8]| -> Option<
        midnight_ledger::structure::StandardTransaction<
            MnSig,
            ProofMarker,
            PedersenRandomness,
            InMemoryDB,
        >,
    > {
        let mut r: &[u8] = bytes;
        let tx: Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> =
            tagged_deserialize(&mut r).ok()?;
        let Transaction::Standard(stx) = tx else {
            return None;
        };
        Some(stx)
    };

    if maker_bytes.starts_with(TAG_PROVEN) || maker_bytes.starts_with(TAG_SEALED) {
        if let Some(stx) = parse_stx(maker_bytes) {
            if stx.guaranteed_coins.is_some() {
                return super::dapp_connector::GUARANTEED_ZSWAP_SEGMENT;
            }
            let mut segments: Vec<u16> = stx
                .fallible_coins
                .iter()
                .map(|p| *p.deref().0.deref())
                .collect();
            segments.sort_unstable();
            segments.dedup();
            if segments.len() == 1 {
                return segments[0];
            }
        }
    }
    DEFAULT_ZSWAP_OFFER_SEGMENT
}

fn verify_auth(payload: &serde_json::Value, auth: &Mip6AuthJson) -> Result<(), PayError> {
    if auth.scheme != "schnorr-bip340" {
        return Err(err(format!(
            "unsupported MIP-0006 auth scheme {:?} (expected schnorr-bip340)",
            auth.scheme
        )));
    }
    let mut unsigned = payload.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("auth");
    }
    let canonical = serde_json_canonicalizer::to_string(&unsigned)
        .map_err(|e| err(format!("MIP-0006 auth canonical JSON failed: {e}")))?;
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();

    let pk_hex = auth
        .signer_public_key
        .strip_prefix("0x")
        .unwrap_or(&auth.signer_public_key);
    let pk_bytes =
        hex::decode(pk_hex).map_err(|e| err(format!("invalid auth signerPublicKey hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(err(format!(
            "auth signerPublicKey must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let pk: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| err("auth signerPublicKey must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|e| err(format!("invalid auth signerPublicKey: {e}")))?;

    let sig_hex = auth.signature.strip_prefix("0x").unwrap_or(&auth.signature);
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| err(format!("invalid auth signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(err(format!(
            "auth signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let sig = SchnorrSignature::try_from(sig_bytes.as_slice())
        .map_err(|e| err(format!("invalid auth signature: {e}")))?;

    vk.verify(&digest, &sig)
        .map_err(|_| err("MIP-0006 auth signature verification failed"))?;
    Ok(())
}

/// Validate MIP-0006 metadata and return maker transaction bytes for balancing.
pub fn materialize_validated_offer(
    chain_id: &str,
    v: &serde_json::Value,
) -> Result<Vec<u8>, PayError> {
    let _ = chain_id;
    let payload: Mip6OfferPayloadJson = serde_json::from_value(v.clone())
        .map_err(|e| err(format!("invalid MIP-0006 offer JSON: {e}")))?;
    if payload.version != 1 {
        return Err(err(format!(
            "unsupported MIP-0006 version {} (expected 1)",
            payload.version
        )));
    }
    if payload.transaction.trim().is_empty() {
        return Err(err("MIP-0006 offer requires a non-empty transaction field"));
    }

    let transaction = payload.transaction.trim();
    if !transaction.starts_with("zswapoffer") {
        return Err(err(
            "MIP-0006 transaction field must be a zswapoffer… bech32 string per MIP-0005; \
             use balanceSealedTransaction with sealed/proven hex for the OWS swap path",
        ));
    }
    let offer = decode_zswap_offer_bech32(transaction)?;
    let expected_segment = if zswap_offer_belongs_in_guaranteed(&offer) {
        super::dapp_connector::GUARANTEED_ZSWAP_SEGMENT
    } else {
        DEFAULT_ZSWAP_OFFER_SEGMENT
    };
    let bytes = super::balance_sealed::wrap_zswap_offer_as_proven_tx(chain_id, transaction)?;
    if infer_zswap_segment_from_maker_bytes(&bytes) != expected_segment {
        return Err(err(
            "internal error: wrapped zswap offer segment does not match expected zswap segment",
        ));
    }
    let maker_bytes = bytes;
    let offers = vec![offer];
    let (actual_gives, actual_wants) = aggregate_gives_wants(&offers);
    let advertised_gives = advertised_token_map(&payload.gives, "gives")?;
    let advertised_wants = advertised_token_map(&payload.wants, "wants")?;
    compare_token_maps(&advertised_gives, &actual_gives, "gives")?;
    compare_token_maps(&advertised_wants, &actual_wants, "wants")?;

    if let Some(auth) = &payload.auth {
        verify_auth(v, auth)?;
    }

    Ok(maker_bytes)
}

/// Serialize a proven Zswap offer per MIP-0005 (raw ledger bytes, no tag prefix).
pub fn serialize_zswap_offer_raw(
    offer: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> Result<Vec<u8>, PayError> {
    let mut buf = Vec::new();
    offer
        .serialize(&mut buf)
        .map_err(|e| err(format!("failed to serialize zswap offer: {e}")))?;
    Ok(buf)
}

/// Deserialize a proven Zswap offer from MIP-0005 raw ledger bytes (no tag prefix).
pub fn deserialize_zswap_offer_raw(
    bytes: &[u8],
) -> Result<ZswapOffer<ZswapProof, InMemoryDB>, PayError> {
    let mut r: &[u8] = bytes;
    ZswapOffer::<ZswapProof, InMemoryDB>::deserialize(&mut r, 0)
        .map_err(|e| err(format!("failed to parse zswap offer: {e}")))
}

/// Encode a proven Zswap offer as MIP-0005 `zswapoffer…` bech32.
///
/// Uses the primitives encoder without the crate-level [`bech32::encode`] length cap so proven
/// offers (~10k+ raw bytes) fit per MIP-0005 ("MUST NOT enforce bech32's 90-character limit").
pub fn encode_zswap_offer_bech32(
    offer: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> Result<String, PayError> {
    use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};
    let buf = serialize_zswap_offer_raw(offer)?;
    let hrp = Hrp::parse(ZSWAP_OFFER_BECH32_HRP)
        .map_err(|e| err(format!("invalid zswap offer HRP: {e}")))?;
    Ok(buf
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .chars()
        .collect())
}

/// Decode a MIP-0005 `zswapoffer…` bech32 string into a proven Zswap offer.
pub fn decode_zswap_offer_bech32(s: &str) -> Result<ZswapOffer<ZswapProof, InMemoryDB>, PayError> {
    use bech32::primitives::checksum;
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Bech32m, Checksum, Fe32};

    let unchecked = UncheckedHrpstring::new(s.trim())
        .map_err(|e| err(format!("invalid zswap offer bech32: {e}")))?;
    if unchecked.hrp().as_str() != ZSWAP_OFFER_BECH32_HRP {
        return Err(err(format!(
            "expected zswapoffer bech32 HRP, got {}",
            unchecked.hrp().as_str()
        )));
    }
    if Bech32m::CHECKSUM_LENGTH > 0 {
        if unchecked.data_part_ascii().len() < Bech32m::CHECKSUM_LENGTH {
            return Err(err(
                "invalid zswap offer bech32: data too short for checksum",
            ));
        }
        let mut eng = checksum::Engine::<Bech32m>::new();
        eng.input_hrp(unchecked.hrp());
        for &b in unchecked.data_part_ascii() {
            eng.input_fe(Fe32::from_char_unchecked(b));
        }
        if eng.residue() != &Bech32m::TARGET_RESIDUE {
            return Err(err("invalid zswap offer bech32 checksum"));
        }
    }
    let checked = unchecked.remove_checksum::<Bech32m>();
    let bytes: Vec<u8> = checked.byte_iter().collect();
    deserialize_zswap_offer_raw(&bytes)
}

fn token_map_to_mip6_entries(map: &BTreeMap<String, u128>) -> Vec<serde_json::Value> {
    map.iter()
        .map(|(token, amount)| {
            let wire = if token.starts_with("0x") {
                token.clone()
            } else {
                format!("0x{token}")
            };
            serde_json::json!({ "token": wire, "amount": amount.to_string() })
        })
        .collect()
}

/// Build MIP-0006 offer JSON (`version`, `transaction`, `gives`, `wants`) from maker sealed/proven bytes.
pub fn export_mip6_offer_json_from_maker_bytes(
    maker_bytes: &[u8],
) -> Result<serde_json::Value, PayError> {
    let offers = offers_from_maker_bytes(maker_bytes)?;
    if offers.len() != 1 {
        return Err(err(format!(
            "MIP-0006 export expects exactly one Zswap offer in the maker transaction, found {}",
            offers.len()
        )));
    }
    let offer = &offers[0];
    let transaction = encode_zswap_offer_bech32(offer)?;
    let (gives_map, wants_map) = deltas_to_gives_wants(offer);
    if gives_map.is_empty()
        && offer.inputs.iter_deref().next().is_some()
        && offer.outputs.iter_deref().next().is_some()
    {
        return Err(err(
            "MIP-0006 export: maker offer has shielded inputs and outputs but empty gives — \
             do not send tokens you are giving to the counterparty in the maker transaction; \
             include only your spend inputs plus outputs for tokens you want back to your \
             shielded address (see MIP-0006 and docs/midnight/swap-intent.md)",
        ));
    }
    Ok(serde_json::json!({
        "version": 1,
        "transaction": transaction,
        "gives": token_map_to_mip6_entries(&gives_map),
        "wants": token_map_to_mip6_entries(&wants_map),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::signature::Signer;
    use k256::schnorr::SigningKey;
    use midnight_storage::storage::Array;
    use midnight_zswap::{Delta, Offer as ZswapOffer};
    use rand::rngs::OsRng;

    fn sample_offer(gives: i128, wants: i128) -> ZswapOffer<ZswapProof, InMemoryDB> {
        let token_give = ShieldedTokenType(midnight_base_crypto::hash::HashOutput([1u8; 32]));
        let token_want = ShieldedTokenType(midnight_base_crypto::hash::HashOutput([2u8; 32]));
        let mut delta_vec = Vec::new();
        if gives != 0 {
            delta_vec.push(Delta {
                token_type: token_give,
                value: gives,
            });
        }
        if wants != 0 {
            delta_vec.push(Delta {
                token_type: token_want,
                value: -wants,
            });
        }
        ZswapOffer {
            inputs: Array::new(),
            outputs: Array::new(),
            transient: Array::new(),
            deltas: delta_vec.into(),
        }
    }

    #[test]
    fn zswap_offer_belongs_in_guaranteed_matches_io_shape() {
        let deltas_only = sample_offer(100, 50);
        assert!(!zswap_offer_belongs_in_guaranteed(&deltas_only));
    }

    #[test]
    fn gives_wants_match_deltas() {
        let offer = sample_offer(100, 50);
        let (gives, wants) = deltas_to_gives_wants(&offer);
        assert_eq!(gives.get(&hex::encode([1u8; 32])), Some(&100));
        assert_eq!(wants.get(&hex::encode([2u8; 32])), Some(&50));
    }

    #[test]
    fn mismatched_gives_rejected() {
        let offer = sample_offer(100, 50);
        let advertised_gives = BTreeMap::from([(hex::encode([1u8; 32]), 99u128)]);
        let (actual_gives, actual_wants) = deltas_to_gives_wants(&offer);
        assert!(compare_token_maps(&advertised_gives, &actual_gives, "gives").is_err());
        let advertised_wants = BTreeMap::from([(hex::encode([2u8; 32]), 50u128)]);
        assert!(compare_token_maps(&advertised_wants, &actual_wants, "wants").is_ok());
    }

    #[test]
    fn encode_decode_zswapoffer_bech32_round_trip() {
        let offer = sample_offer(100, 50);
        let bech32 = encode_zswap_offer_bech32(&offer).expect("encode");
        assert!(bech32.starts_with("zswapoffer1"));
        let decoded = decode_zswap_offer_bech32(&bech32).expect("decode");
        assert_eq!(
            decoded.deltas.iter_deref().count(),
            offer.deltas.iter_deref().count()
        );
    }

    #[test]
    fn materialize_rejects_full_tx_hex_in_transaction_field() {
        let json = serde_json::json!({
            "version": 1,
            "transaction": "0x010203",
            "gives": [],
            "wants": [],
        });
        let err = materialize_validated_offer("midnight:preview", &json).unwrap_err();
        assert!(err.message.contains("zswapoffer"));
    }

    #[test]
    fn export_mip6_round_trip_from_bech32() {
        let offer = sample_offer(100, 50);
        let bech32 = encode_zswap_offer_bech32(&offer).expect("encode");
        let token_give = format!("0x{}", hex::encode([1u8; 32]));
        let token_want = format!("0x{}", hex::encode([2u8; 32]));
        let json = serde_json::json!({
            "version": 1,
            "transaction": bech32,
            "gives": [{"token": token_give, "amount": "100"}],
            "wants": [{"token": token_want, "amount": "50"}],
        });
        let bytes = materialize_validated_offer("midnight:preview", &json).expect("materialize");
        let exported = export_mip6_offer_json_from_maker_bytes(&bytes).expect("export");
        assert_eq!(exported["transaction"], json["transaction"]);
        assert_eq!(exported["gives"], json["gives"]);
        assert_eq!(exported["wants"], json["wants"]);
    }

    #[test]
    fn materialize_validated_zswapoffer_bech32() {
        let offer = sample_offer(100, 50);
        let bech32_str = encode_zswap_offer_bech32(&offer).expect("bech32 encode");

        let token_give = hex::encode([1u8; 32]);
        let token_want = hex::encode([2u8; 32]);
        let json = serde_json::json!({
            "version": 1,
            "transaction": bech32_str,
            "gives": [{"token": token_give, "amount": "100"}],
            "wants": [{"token": token_want, "amount": "50"}],
        });
        let bytes =
            materialize_validated_offer("midnight:preview", &json).expect("materialize offer");
        assert!(super::super::balance_sealed::is_proven_midnight_payload(
            &bytes
        ));
        assert_eq!(
            infer_zswap_segment_from_maker_bytes(&bytes),
            DEFAULT_ZSWAP_OFFER_SEGMENT
        );
    }

    #[test]
    fn auth_round_trip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let mut payload = serde_json::json!({
            "version": 1,
            "transaction": "zswapoffer1qq",
            "gives": [{"token": hex::encode([1u8; 32]), "amount": "1"}],
            "wants": [],
        });
        let canonical = serde_json_canonicalizer::to_string(&payload).unwrap();
        let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        let sig: SchnorrSignature = signing_key.sign(&digest);
        payload["auth"] = serde_json::json!({
            "signerPublicKey": hex::encode(vk.to_bytes()),
            "signature": hex::encode(sig.to_bytes()),
            "scheme": "schnorr-bip340",
        });
        let auth: Mip6AuthJson = serde_json::from_value(payload["auth"].clone()).unwrap();
        verify_auth(&payload, &auth).expect("auth should verify");
    }
}
