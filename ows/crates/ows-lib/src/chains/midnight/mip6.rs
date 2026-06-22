//! [MIP-0006](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mips/mip-0006-p2p-atomic-swaps.md)
//! offer payload validation and optional authentication.

use super::error::{PayError, PayErrorCode};
use super::parse_token_type;
use k256::schnorr::{signature::Verifier, Signature as SchnorrSignature, VerifyingKey};
use midnight_coin_structure::coin::ShieldedTokenType;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
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

/// MIP-0005 bech32 human-readable part for a bare Zswap offer.
pub const ZSWAP_OFFER_BECH32_HRP: &str = "zswapoffer1";

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

/// Infer fallible segment when wrapping bare `zswapoffer` into a proven tx.
pub fn infer_zswap_segment_from_maker_bytes(maker_bytes: &[u8]) -> u16 {
    const TAG_PROVEN: &[u8] = b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";
    if !maker_bytes.starts_with(TAG_PROVEN) {
        return DEFAULT_ZSWAP_OFFER_SEGMENT;
    }
    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofMarker, Transaction};
    use transient_crypto::commitment::PedersenRandomness;

    let mut r: &[u8] = maker_bytes;
    let Ok(tx): Result<Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>, _> =
        tagged_deserialize(&mut r)
    else {
        return DEFAULT_ZSWAP_OFFER_SEGMENT;
    };
    let Transaction::Standard(stx) = tx else {
        return DEFAULT_ZSWAP_OFFER_SEGMENT;
    };
    let mut segments: Vec<u16> = stx
        .fallible_coins
        .iter()
        .map(|p| *p.deref().0.deref())
        .collect();
    segments.sort_unstable();
    segments.dedup();
    if segments.len() == 1 {
        segments[0]
    } else {
        DEFAULT_ZSWAP_OFFER_SEGMENT
    }
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
    let (maker_bytes, offers) = if transaction.starts_with("zswapoffer") {
        let offer = super::balance_sealed::decode_zswap_offer_bech32_public(transaction)?;
        let segment = DEFAULT_ZSWAP_OFFER_SEGMENT;
        let bytes = super::balance_sealed::wrap_zswap_offer_as_proven_tx_public(
            chain_id,
            transaction,
            segment,
        )?;
        if infer_zswap_segment_from_maker_bytes(&bytes) != segment {
            return Err(err(
                "internal error: wrapped zswap offer segment does not match fallible segment",
            ));
        }
        (bytes, vec![offer])
    } else {
        let maker_bytes =
            super::balance_sealed::decode_maker_tx_hex_or_offer_public(chain_id, transaction)?;
        let offers = offers_from_maker_bytes(&maker_bytes)?;
        (maker_bytes, offers)
    };
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

/// Encode a proven Zswap offer as MIP-0005 `zswapoffer…` bech32.
///
/// Fails with [`PayError`] when the serialized offer exceeds bech32 capacity (common for proven
/// offers with full spend proofs). Use [`export_mip6_offer_json_from_maker_bytes`] for automatic
/// hex fallback.
pub fn encode_zswap_offer_bech32(
    offer: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> Result<String, PayError> {
    use bech32::Bech32m;
    let mut buf = Vec::new();
    tagged_serialize(offer, &mut buf)
        .map_err(|e| err(format!("failed to serialize zswap offer: {e}")))?;
    let hrp = bech32::Hrp::parse(ZSWAP_OFFER_BECH32_HRP)
        .map_err(|e| err(format!("invalid zswap offer HRP: {e}")))?;
    bech32::encode::<Bech32m>(hrp, &buf).map_err(|e| {
        err(format!(
            "zswap offer bech32 encode failed ({e}); offer may be too large — use sealed/proven hex in MIP-0006 transaction field"
        ))
    })
}

fn mip6_transaction_field(
    maker_bytes: &[u8],
    offer: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> String {
    encode_zswap_offer_bech32(offer).unwrap_or_else(|_| format!("0x{}", hex::encode(maker_bytes)))
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
    let transaction = mip6_transaction_field(maker_bytes, offer);
    let (gives_map, wants_map) = deltas_to_gives_wants(offer);
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
    fn mip6_transaction_field_prefers_bech32_for_compact_offers() {
        let offer = sample_offer(100, 50);
        let tx = mip6_transaction_field(b"sealed-bytes", &offer);
        assert!(tx.starts_with("zswapoffer"));
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
        use bech32::Bech32m;
        use midnight_serialize::tagged_serialize;

        let offer = sample_offer(100, 50);
        let mut buf = Vec::new();
        tagged_serialize(&offer, &mut buf).expect("serialize offer");
        let hrp = bech32::Hrp::parse(ZSWAP_OFFER_BECH32_HRP).expect("hrp");
        let bech32_str = bech32::encode::<Bech32m>(hrp, &buf).expect("bech32 encode");

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
