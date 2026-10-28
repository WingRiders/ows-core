//! The verifier keys a transaction's calls will be checked against, read from the contracts' state on
//! chain. A call's proof is verified against the key its contract holds for that entry point when the
//! transaction is applied — not against anything in the transaction — and a contract's maintenance
//! authority can replace that key at the same address. So the key a policy pins has to come from the
//! chain, read before the policy pass, and the call's proof is checked against that same key before the
//! wallet signs: a proof that verifies under the key the policy saw cannot verify under another, so the
//! transaction lands only while the contract still holds it.

use std::collections::{BTreeMap, BTreeSet};

use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::structure::{
    ContractAction, PedersenDowngradeable, ProofKind, ProofMarker, SignatureKind,
    StandardTransaction,
};
use midnight_ledger::verify::ProofVerificationMode;
use midnight_serialize::{tagged_deserialize, tagged_serialize, Serializable, Tagged};
use midnight_storage::db::InMemoryDB;
use midnight_storage::Storable;
use onchain_runtime::state::{ContractOperation, ContractState, EntryPointBuf};
use sha2::{Digest as _, Sha256};

use super::{entry_point_label, OperationKeys};

/// Every operation of each contract in `addresses`, verifier keys included, from the indexer's current
/// view of its state. A contract the indexer holds no state for contributes nothing.
pub(crate) async fn fetch_operations(
    indexer_url: &str,
    addresses: &BTreeSet<ContractAddress>,
) -> Result<BTreeMap<(ContractAddress, EntryPointBuf), ContractOperation>, std::io::Error> {
    let mut operations = BTreeMap::new();
    for address in addresses {
        let Some(state_hex) = fetch_contract_state_hex(indexer_url, address).await? else {
            continue;
        };
        operations.extend(contract_operations(*address, &state_hex)?);
    }
    Ok(operations)
}

async fn fetch_contract_state_hex(
    indexer_url: &str,
    address: &ContractAddress,
) -> Result<Option<String>, std::io::Error> {
    let q = r#"query ContractState($address: HexEncoded!) { contractAction(address: $address) { state } }"#;
    let resp = crate::ledger_params::indexer_http_client()
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "address": hex::encode(address.0 .0) },
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        std::io::Error::other(format!(
            "indexer contract-state response is not JSON: {}",
            e.without_url()
        ))
    })?;
    if let Some(errors) = body.get("errors") {
        return Err(std::io::Error::other(format!(
            "indexer refused the contract-state query: {errors}"
        )));
    }
    Ok(body["data"]["contractAction"]["state"]
        .as_str()
        .map(str::to_string))
}

/// Each operation out of a contract state the indexer returned (the hex of its tagged serialization).
pub(super) fn contract_operations(
    address: ContractAddress,
    state_hex: &str,
) -> Result<BTreeMap<(ContractAddress, EntryPointBuf), ContractOperation>, std::io::Error> {
    let bytes = hex::decode(state_hex.strip_prefix("0x").unwrap_or(state_hex))
        .map_err(|e| std::io::Error::other(format!("contract state is not hex: {e}")))?;
    let state: ContractState<InMemoryDB> = tagged_deserialize(&mut &bytes[..]).map_err(|e| {
        std::io::Error::other(format!(
            "contract state of {} does not parse: {e}",
            hex::encode(address.0 .0)
        ))
    })?;
    Ok(state
        .operations
        .clone()
        .into_iter()
        .map(|(entry_point, operation)| ((address, entry_point), operation))
        .collect())
}

/// The hash of each operation's verifier keys, as a call's record names them.
pub(crate) fn operation_keys(
    operations: &BTreeMap<(ContractAddress, EntryPointBuf), ContractOperation>,
) -> Result<BTreeMap<(ContractAddress, EntryPointBuf), OperationKeys>, std::io::Error> {
    operations
        .iter()
        .map(|(id, operation)| {
            let keys = OperationKeys {
                v2: operation.v2.as_ref().map(key_hash).transpose()?,
                v3: operation.v3.as_ref().map(key_hash).transpose()?,
            };
            Ok((id.clone(), keys))
        })
        .collect()
}

/// Check every call's proof against the key its contract holds in `operations`, exactly as the ledger
/// does when it applies the transaction: the key the proof's version selects, over the call's public
/// inputs bound to its intent's binding commitment. A call to a contract absent from `operations` has
/// no key here to check against; the ledger refuses it (`ContractNotPresent`).
pub(crate) fn verify_call_proofs<S, B>(
    tx: &StandardTransaction<S, ProofMarker, B, InMemoryDB>,
    operations: &BTreeMap<(ContractAddress, EntryPointBuf), ContractOperation>,
) -> Result<(), std::io::Error>
where
    S: SignatureKind<InMemoryDB>,
    B: Storable<InMemoryDB> + PedersenDowngradeable<InMemoryDB>,
{
    for (_, intent) in tx.intents.clone() {
        let binding_commitment = intent.binding_commitment.downgrade();
        for action in Vec::from(&intent.actions) {
            let ContractAction::Call(call) = action else {
                continue;
            };
            let Some(operation) = operations.get(&(call.address, call.entry_point.clone())) else {
                continue;
            };
            <ProofMarker as ProofKind<InMemoryDB>>::proof_verify(
                operation,
                &call.proof,
                call.public_inputs(binding_commitment),
                &call,
                ProofVerificationMode::Real,
            )
            .map_err(|e| {
                std::io::Error::other(format!(
                    "the proof of the call to {} on contract {} does not verify against the \
                     verifier key the contract holds on chain, so the transaction cannot land as \
                     the policy would see it: {e}",
                    entry_point_label(&call.entry_point),
                    hex::encode(call.address.0 .0)
                ))
            })?;
        }
    }
    Ok(())
}

/// SHA-256 of a verifier key's tagged serialization — the bytes Compact writes to `<circuit>.verifier`.
fn key_hash<T: Serializable + Tagged>(key: &T) -> Result<String, std::io::Error> {
    let mut bytes = Vec::new();
    tagged_serialize(key, &mut bytes)
        .map_err(|e| std::io::Error::other(format!("serialize verifier key: {e}")))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}
