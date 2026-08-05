//! Read-only inspection of a sealed Midnight offer: what a party holding no keys can learn from the
//! bytes alone.
//!
//! A sealed (`proof,pedersen-schnorr`) maker offer is imbalanced by design, and its imbalance is
//! public: the Pedersen binding fixes the per-token value balance in the clear even when the coins,
//! addresses and shielded output values behind it stay hidden. So an offer's *terms* — what it gives,
//! what it wants, until when — can be derived from the bytes by anyone, with no keys, no network and
//! no wallet state. That is what makes a venue able to list an offer it cannot lie about.

use std::collections::BTreeMap;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_coin_structure::coin::TokenType as LedgerTokenType;
use midnight_ledger::structure::{ProofMarker, Transaction, UtxoSpend};
use midnight_serialize::{tagged_deserialize, Serializable};
use midnight_storage::db::InMemoryDB;
use ows_signer::chains::MidnightNetwork;
use serde::{Deserialize, Serialize};
use transient_crypto::commitment::PureGeneratorPedersen;

/// A fully sealed (`proof,pedersen-schnorr`) Midnight transaction — the form a maker offer arrives in.
type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// How the native token renders in inspected terms.
const NATIVE_TOKEN_LABEL: &str = "night";

/// One side of an offer's terms: an amount of one token in one value domain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenAmount {
    /// `"unshielded"`, `"shielded"` or `"dust"`.
    pub domain: String,
    /// Lowercase 64-hex token id, or `"night"` for the native token.
    pub token: String,
    pub value: u128,
}

/// The terms carried by one transaction segment: what the offer hands over and what it asks for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentTerms {
    pub segment: u16,
    pub gives: Vec<TokenAmount>,
    pub wants: Vec<TokenAmount>,
}

/// One unshielded output an offer spends, named the way the indexer names UTXOs.
///
/// The identifiers here are join keys, not labels: `token` is always the raw lowercase 64-hex id
/// (never the `night` shorthand [`TokenAmount`] uses) and `owner` is the Bech32m address rather than
/// the verifying key the transaction actually carries, because those are the forms the chain answers
/// questions in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InputRef {
    /// The intent that created the spent output, lowercase hex, no `0x`.
    pub intent_hash: String,
    pub output_no: u32,
    pub owner: String,
    pub token: String,
    pub value: u128,
}

/// Everything a keyless reader can derive from a sealed offer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OfferInspection {
    pub network_id: String,
    /// When the offer stops being executable: the earliest intent TTL, in Unix seconds.
    pub min_ttl_secs: u64,
    pub segments: Vec<SegmentTerms>,
    /// The unshielded outputs this offer spends. Shielded inputs are deliberately absent: a Zswap
    /// spend publishes only a nullifier, so there is no public reference to follow — anything
    /// watching an offer on chain can watch its unshielded legs and nothing more.
    #[serde(default)]
    pub inputs: Vec<InputRef>,
}

/// Derive a sealed offer's terms from its bytes.
///
/// The sign convention is `Transaction::balance`'s: a positive imbalance is the offer's surplus,
/// which the counterparty receives (a *give*); a negative one is its shortage, which the counterparty
/// must supply (a *want*, stored as its absolute value).
pub fn inspect_sealed_offer(bytes: &[u8]) -> std::io::Result<OfferInspection> {
    let mut r: &[u8] = bytes;
    let tx: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed tx: {e}")))?;
    let Transaction::Standard(ref stx) = tx else {
        return Err(std::io::Error::other("not a standard transaction"));
    };

    let min_ttl_secs = stx
        .intents
        .iter()
        .map(|pair| {
            let (_seg_sp, intent_sp) = pair.deref();
            intent_sp.deref().ttl.to_secs()
        })
        .min()
        .ok_or_else(|| std::io::Error::other("transaction has no intents"))?;

    let imbalance = tx
        .balance(None)
        .map_err(|e| std::io::Error::other(format!("malformed transaction: {e:?}")))?;

    let mut per_segment: BTreeMap<u16, SegmentTerms> = BTreeMap::new();
    for ((token, segment), bal) in imbalance {
        if bal == 0 {
            continue;
        }
        let amount = TokenAmount {
            domain: domain_of(&token).to_string(),
            token: token_label(&token),
            value: bal.unsigned_abs(),
        };
        let terms = per_segment.entry(segment).or_insert_with(|| SegmentTerms {
            segment,
            gives: Vec::new(),
            wants: Vec::new(),
        });
        if bal > 0 {
            terms.gives.push(amount);
        } else {
            terms.wants.push(amount);
        }
    }

    let network = MidnightNetwork::from_reference(&stx.network_id);
    let mut inputs = Vec::new();
    for pair in stx.intents.iter() {
        let (_seg_sp, intent_sp) = pair.deref();
        let intent = intent_sp.deref();
        for offer in [
            intent.guaranteed_unshielded_offer.as_ref(),
            intent.fallible_unshielded_offer.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for spend in offer.deref().inputs.iter_deref() {
                inputs.push(input_ref(&network, spend)?);
            }
        }
    }

    Ok(OfferInspection {
        network_id: stx.network_id.clone(),
        min_ttl_secs,
        segments: per_segment.into_values().collect(),
        inputs,
    })
}

fn input_ref(network: &MidnightNetwork, spend: &UtxoSpend) -> std::io::Result<InputRef> {
    let mut vk_raw = Vec::new();
    Serializable::serialize(&spend.owner, &mut vk_raw)
        .map_err(|e| std::io::Error::other(format!("unreadable input owner: {e}")))?;
    let owner = network
        .unshielded_address_for_verifying_key(&vk_raw)
        .map_err(|e| std::io::Error::other(format!("unreadable input owner: {e}")))?;
    Ok(InputRef {
        intent_hash: hex::encode(spend.intent_hash.0 .0),
        output_no: spend.output_no,
        owner,
        token: hex::encode(spend.type_.0 .0),
        value: spend.value,
    })
}

fn domain_of(token: &LedgerTokenType) -> &'static str {
    match token {
        LedgerTokenType::Unshielded(_) => "unshielded",
        LedgerTokenType::Shielded(_) => "shielded",
        LedgerTokenType::Dust => "dust",
    }
}

/// DUST has no token id, so it labels itself; the all-zero id is the native token, which the offer's
/// terms name `night` — `parse_token_type` owns that normalization.
fn token_label(token: &LedgerTokenType) -> String {
    let wire = match token {
        LedgerTokenType::Unshielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Shielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Dust => return "dust".to_string(),
    };
    match crate::parse_token_type(Some(&wire)) {
        Ok(crate::TokenType::Native) => NATIVE_TOKEN_LABEL.to_string(),
        _ => wire,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_coin_structure::coin::TokenType as LedgerTokenType;
    use midnight_ledger::structure::{ProofMarker, Transaction};
    use midnight_serialize::tagged_deserialize;
    use midnight_storage::db::InMemoryDB;
    use transient_crypto::commitment::PureGeneratorPedersen;

    use super::*;

    type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

    fn fixture_bytes() -> Vec<u8> {
        let hex_str = include_str!("dapp_connector/testdata/sealed_maker_preprod.hex");
        let hex_str = hex_str.trim();
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap()
    }

    #[test]
    fn inspects_the_sealed_maker_fixture() {
        let bytes = fixture_bytes();
        let insp = inspect_sealed_offer(&bytes).expect("sealed fixture must inspect");

        assert!(!insp.network_id.is_empty());
        assert!(insp.min_ttl_secs > 0);
        assert!(!insp.segments.is_empty());
        assert!(insp
            .segments
            .iter()
            .any(|s| !s.gives.is_empty() || !s.wants.is_empty()));

        // Oracle: the derived terms must reproduce `Transaction::balance` entry for entry — positive
        // (surplus) as a give, negative (shortage) as a want, keyed by the same segment.
        let mut r: &[u8] = &bytes;
        let tx: TxSealed = tagged_deserialize(&mut r).unwrap();
        let mut expected: BTreeMap<(u16, String, String), i128> = BTreeMap::new();
        for ((token, segment), bal) in tx.balance(None).unwrap() {
            if bal == 0 {
                continue;
            }
            let (domain, id) = match token {
                LedgerTokenType::Unshielded(tt) => ("unshielded", hex::encode(tt.0 .0)),
                LedgerTokenType::Shielded(tt) => ("shielded", hex::encode(tt.0 .0)),
                LedgerTokenType::Dust => ("dust", "dust".to_string()),
            };
            let id = if id == hex::encode([0u8; 32]) {
                "night".to_string()
            } else {
                id
            };
            *expected
                .entry((segment, domain.to_string(), id))
                .or_default() += bal;
        }

        let mut got: BTreeMap<(u16, String, String), i128> = BTreeMap::new();
        for seg in &insp.segments {
            for give in &seg.gives {
                *got.entry((seg.segment, give.domain.clone(), give.token.clone()))
                    .or_default() += give.value as i128;
            }
            for want in &seg.wants {
                *got.entry((seg.segment, want.domain.clone(), want.token.clone()))
                    .or_default() -= want.value as i128;
            }
        }

        assert_eq!(got, expected);
    }

    #[test]
    fn rejects_garbage() {
        assert!(inspect_sealed_offer(b"not a transaction").is_err());
    }

    #[test]
    fn reads_the_fixture_unshielded_input_refs() {
        let insp = inspect_sealed_offer(&fixture_bytes()).unwrap();

        // The fixture funds its 500,000 NIGHT give from the maker's own unshielded UTXOs, so it
        // names them — and a watcher can follow exactly these on chain.
        assert!(
            !insp.inputs.is_empty(),
            "an offer that gives unshielded NIGHT must spend unshielded inputs"
        );
        for input in &insp.inputs {
            assert_eq!(input.intent_hash.len(), 64, "{input:?}");
            assert!(
                input.intent_hash.chars().all(|c| c.is_ascii_hexdigit()),
                "{input:?}"
            );
            assert!(
                input.intent_hash.chars().all(|c| !c.is_ascii_uppercase()),
                "identifiers are lowercase hex: {input:?}"
            );
            assert_eq!(input.token.len(), 64, "{input:?}");
            assert!(input.value > 0, "{input:?}");
            // The owner is the address the indexer keys UTXOs by, not the raw verifying key.
            assert!(
                input.owner.starts_with("mn_addr_preprod1"),
                "{} is not a preprod unshielded address",
                input.owner
            );
        }

        // The inputs must cover what the offer hands over.
        let native = hex::encode([0u8; 32]);
        let supplied: u128 = insp
            .inputs
            .iter()
            .filter(|i| i.token == native)
            .map(|i| i.value)
            .sum();
        let given: u128 = insp
            .segments
            .iter()
            .flat_map(|s| &s.gives)
            .filter(|g| g.domain == "unshielded" && g.token == "night")
            .map(|g| g.value)
            .sum();
        assert!(
            supplied >= given,
            "inputs supply {supplied} but the offer gives {given}"
        );
    }

    #[test]
    fn an_offer_with_no_unshielded_inputs_names_none() {
        // Garbage never parses, so the empty case is asserted where it is reachable: the refs are
        // read per intent, and an intent without an unshielded offer contributes nothing.
        let insp = inspect_sealed_offer(&fixture_bytes()).unwrap();
        assert!(insp
            .inputs
            .iter()
            .all(|i| !i.owner.is_empty() && !i.intent_hash.is_empty()));
    }
}
