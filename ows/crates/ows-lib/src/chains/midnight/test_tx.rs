//! Minimal tagged Midnight transaction bytes for integration tests.

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::structure::{
    Intent, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction,
};
use midnight_serialize::tagged_serialize;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use rand::rngs::OsRng;
use transient_crypto::commitment::PedersenRandomness;

type TxPreimage = Transaction<MnSig, ProofPreimageMarker, PedPre, InMemoryDB>;
type TxProvenUnsealed = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;
type PedPre = <ProofPreimageMarker as midnight_ledger::structure::ProofKind<InMemoryDB>>::Pedersen;

fn empty_intent() -> Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
    let ttl = Timestamp::from_secs(1_700_000_000);
    let mut rng = OsRng;
    Intent::new(&mut rng, None, None, vec![], vec![], vec![], None, ttl)
}

fn standard_tx(
    network_id: &str,
    segment: u16,
) -> StandardTransaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
    let intents = MnHashMap::new().insert(segment, empty_intent());
    let mut stx = StandardTransaction {
        network_id: network_id.to_string(),
        intents,
        guaranteed_coins: None,
        fallible_coins: MnHashMap::new(),
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    stx
}

/// `proof-preimage,embedded-fr` payload with a single empty intent segment.
pub fn minimal_preimage_tx_bytes(network_id: &str) -> Vec<u8> {
    let tx: TxPreimage = Transaction::Standard(standard_tx(network_id, 1));
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).expect("serialize preimage tx");
    out
}

/// `proof,embedded-fr` payload with no intents (valid proven Standard tx shell).
pub fn minimal_proven_tx_bytes(network_id: &str) -> Vec<u8> {
    let stx = StandardTransaction {
        network_id: network_id.to_string(),
        intents: MnHashMap::new(),
        guaranteed_coins: None,
        fallible_coins: MnHashMap::new(),
        binding_randomness: Default::default(),
    };
    let tx: TxProvenUnsealed = Transaction::Standard(stx);
    let mut out = Vec::new();
    tagged_serialize(&tx, &mut out).expect("serialize proven tx");
    out
}

/// Sealed `proof,pedersen-schnorr` payload (direct sign-and-encode path).
pub fn minimal_sealed_tx_bytes(network_id: &str) -> Vec<u8> {
    use midnight_ledger::structure::ProofKind;
    use rand::{rngs::StdRng, SeedableRng as _};

    type PedSealed = <ProofMarker as ProofKind<InMemoryDB>>::Pedersen;
    type TxSealed = Transaction<MnSig, ProofMarker, PedSealed, InMemoryDB>;

    let stx = StandardTransaction {
        network_id: network_id.to_string(),
        intents: MnHashMap::new(),
        guaranteed_coins: None,
        fallible_coins: MnHashMap::new(),
        binding_randomness: Default::default(),
    };
    let tx: TxProvenUnsealed = Transaction::Standard(stx);
    let sealed: TxSealed = tx.seal(StdRng::from_entropy());
    let mut out = Vec::new();
    tagged_serialize(&sealed, &mut out).expect("serialize sealed tx");
    out
}

pub fn assert_network_mismatch(err: &impl std::fmt::Display) {
    let msg = err.to_string();
    assert!(
        msg.contains("does not match"),
        "expected network mismatch error, got: {msg}"
    );
}
