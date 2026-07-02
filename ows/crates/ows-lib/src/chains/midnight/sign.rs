//! Sign (and, for the preimage flow, prove) a balanced Midnight transaction so
//! it can be submitted to a Midnight node.
//!
//! Two entry points share the same intent-signing core:
//!
//! - [`sign_prove_and_seal`] consumes a balanced `proof-preimage,embedded-fr`
//!   payload (as produced by [`super::balance::balance_unsealed_preimage_standard_tx`]).
//! - [`sign_and_seal`] consumes a balanced `proof,embedded-fr` payload (as
//!   produced by [`super::balance::balance_unsealed_proven_standard_tx`]); the
//!   ZK proofs are already in place so we only need to sign + seal.

use super::error::{PayError, PayErrorCode};
use midnight_base_crypto::signatures::{Signature, SigningKey as MidnightSigningKey};
use midnight_ledger::structure::{
    ProofKind, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction,
};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use rand::rngs::OsRng;
use std::ops::Deref as _;
use transient_crypto::commitment::PedersenRandomness;

fn err(msg: impl Into<String>) -> PayError {
    PayError::new(PayErrorCode::InvalidInput, msg)
}

type PedPre = <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen;
type PedSealed = <ProofMarker as ProofKind<InMemoryDB>>::Pedersen;
type TxPreimage = Transaction<Signature, ProofPreimageMarker, PedPre, InMemoryDB>;
type TxProvenUnsealed = Transaction<Signature, ProofMarker, PedersenRandomness, InMemoryDB>;
type TxSealed = Transaction<Signature, ProofMarker, PedSealed, InMemoryDB>;

/// Inline helper for both flows: build the signing-key vectors that `Intent::sign(...)`
/// expects (one entry per guaranteed unshielded input / per dust registration), and
/// verify that every guaranteed input is owned by the signing key.
macro_rules! signing_key_vectors {
    ($intent:expr, $signing_key:expr) => {{
        let vk = $signing_key.verifying_key();
        for inp in &$intent.guaranteed_inputs() {
            if inp.owner != vk {
                return Err(err(
                    "all guaranteed unshielded inputs must be owned by the signing key",
                ));
            }
        }
        let n_g = $intent.guaranteed_inputs().len();
        let g_keys = vec![$signing_key.clone(); n_g];
        let n_regs = $intent
            .dust_actions
            .as_ref()
            .map(|da| da.registrations.len())
            .unwrap_or(0);
        let reg_keys = vec![$signing_key.clone(); n_regs];
        (g_keys, reg_keys)
    }};
}

pub(super) fn sign_prove_and_seal(
    chain_id: &str,
    indexer_url: &str,
    tx_bytes: &[u8],
    sender_private_key: &[u8; 32],
) -> Result<Vec<u8>, PayError> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxPreimage = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse balanced tx bytes: {e}")))?;
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
    let intent = intent_sp.deref().clone();

    let signing_key = MidnightSigningKey::from_bytes(sender_private_key)
        .map_err(|e| err(format!("invalid midnight signing key: {e}")))?;
    let (g_keys, reg_keys) = signing_key_vectors!(intent, signing_key);

    let mut rng = OsRng;
    let intent_signed = intent
        .sign(&mut rng, seg_id, &g_keys, &[], &reg_keys)
        .map_err(|e| err(format!("intent signing failed: {e:?}")))?;

    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_signed);
    // Preserve any shielded zswap offers + binding randomness from the inbound tx; the unshielded
    // offer doesn't contribute to the Pedersen binding, so the existing sum is still correct.
    let stx_unproven = StandardTransaction {
        network_id: super::ledger_network_id(chain_id).map_err(err)?,
        intents,
        guaranteed_coins: stx.guaranteed_coins.clone(),
        fallible_coins: stx.fallible_coins.clone(),
        binding_randomness: stx.binding_randomness,
    };
    let tx_unproven: TxPreimage = Transaction::Standard(stx_unproven);

    let ledger_params = super::block_on(super::fetch_indexer_ledger_parameters(indexer_url))
        .map_err(|e| err(format!("ledger params: {e}")))?;

    let prover = super::OwsProver::from_env().map_err(|e| err(format!("prover: {e}")))?;

    let proven =
        super::block_on(tx_unproven.prove(prover, &ledger_params.cost_model.runtime_cost_model))
            .map_err(|e| err(format!("prove tx failed: {e:?}")))?;

    let sealed: TxSealed = {
        use rand::{rngs::StdRng, SeedableRng as _};
        proven.seal(StdRng::from_entropy())
    };

    let mut out = Vec::new();
    tagged_serialize(&sealed, &mut out).map_err(|e| err(format!("serialize sealed tx: {e}")))?;
    Ok(out)
}

/// Sign + seal a balanced proven transaction (`proof,embedded-fr`).
///
/// The dapp has already proven the contract calls / zswap offers, so this skips
/// the `prove(...)` step entirely and goes straight from signed intents to a
/// sealed `proof,pedersen-schnorr` payload.
pub(super) fn sign_and_seal(
    chain_id: &str,
    tx_bytes: &[u8],
    sender_private_key: &[u8; 32],
) -> Result<Vec<u8>, PayError> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProvenUnsealed = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse balanced proven tx bytes: {e}")))?;
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
    let intent = intent_sp.deref().clone();

    let signing_key = MidnightSigningKey::from_bytes(sender_private_key)
        .map_err(|e| err(format!("invalid midnight signing key: {e}")))?;
    let (g_keys, reg_keys) = signing_key_vectors!(intent, signing_key);

    let mut rng = OsRng;
    let intent_signed = intent
        .sign(&mut rng, seg_id, &g_keys, &[], &reg_keys)
        .map_err(|e| err(format!("intent signing failed: {e:?}")))?;

    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_signed);
    let stx_signed = StandardTransaction {
        network_id: stx.network_id.clone(),
        intents,
        guaranteed_coins: stx.guaranteed_coins.clone(),
        fallible_coins: stx.fallible_coins.clone(),
        binding_randomness: stx.binding_randomness,
    };
    let tx_signed: TxProvenUnsealed = Transaction::Standard(stx_signed);

    let sealed: TxSealed = {
        use rand::{rngs::StdRng, SeedableRng as _};
        tx_signed.seal(StdRng::from_entropy())
    };

    let mut out = Vec::new();
    tagged_serialize(&sealed, &mut out).map_err(|e| err(format!("serialize sealed tx: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod network_id_tests {
    use super::{sign_and_seal, sign_prove_and_seal};
    use crate::chains::midnight::test_tx::{
        assert_network_mismatch, minimal_preimage_tx_bytes, minimal_proven_tx_bytes,
    };

    const INDEXER: &str = "https://indexer.example/graphql";
    const KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn sign_prove_and_seal_rejects_network_mismatch() {
        let tx = minimal_preimage_tx_bytes("preview");
        let err = sign_prove_and_seal("midnight:mainnet", INDEXER, &tx, &KEY).unwrap_err();
        assert_network_mismatch(&err);
    }

    #[test]
    fn sign_and_seal_rejects_network_mismatch() {
        let tx = minimal_proven_tx_bytes("preview");
        let err = sign_and_seal("midnight:mainnet", &tx, &KEY).unwrap_err();
        assert_network_mismatch(&err);
    }
}
