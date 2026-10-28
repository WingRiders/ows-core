//! The verifier keys a transaction's calls will be checked against, read from the contracts' state on
//! chain. A call's proof is verified against the key its contract holds for that entry point when the
//! transaction is applied — not against anything in the transaction — and a contract's maintenance
//! authority can replace that key at the same address. So the key a policy pins has to come from the
//! chain, read before the policy pass.

use std::collections::{BTreeMap, BTreeSet};

use midnight_coin_structure::contract::ContractAddress;
use midnight_serialize::{tagged_deserialize, tagged_serialize, Serializable, Tagged};
use midnight_storage::db::InMemoryDB;
use onchain_runtime::state::{ContractState, EntryPointBuf};
use sha2::{Digest as _, Sha256};

use super::OperationKeys;

/// The verifier-key hashes of every operation of each contract in `addresses`, from the indexer's
/// current view of its state. A contract the indexer holds no state for contributes nothing.
pub(crate) async fn fetch_operation_keys(
    indexer_url: &str,
    addresses: &BTreeSet<ContractAddress>,
) -> Result<BTreeMap<(ContractAddress, EntryPointBuf), OperationKeys>, std::io::Error> {
    let mut keys = BTreeMap::new();
    for address in addresses {
        let Some(state_hex) = fetch_contract_state_hex(indexer_url, address).await? else {
            continue;
        };
        keys.extend(operation_keys(*address, &state_hex)?);
    }
    Ok(keys)
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

/// Hash each operation's verifier keys out of a contract state the indexer returned (the hex of its
/// tagged serialization).
pub(super) fn operation_keys(
    address: ContractAddress,
    state_hex: &str,
) -> Result<BTreeMap<(ContractAddress, EntryPointBuf), OperationKeys>, std::io::Error> {
    let bytes = hex::decode(state_hex.strip_prefix("0x").unwrap_or(state_hex))
        .map_err(|e| std::io::Error::other(format!("contract state is not hex: {e}")))?;
    let state: ContractState<InMemoryDB> = tagged_deserialize(&mut &bytes[..]).map_err(|e| {
        std::io::Error::other(format!(
            "contract state of {} does not parse: {e}",
            hex::encode(address.0 .0)
        ))
    })?;
    let mut keys = BTreeMap::new();
    for (entry_point, operation) in state.operations.clone() {
        keys.insert(
            (address, entry_point),
            OperationKeys {
                v2: operation.v2.as_ref().map(key_hash).transpose()?,
                v3: operation.v3.as_ref().map(key_hash).transpose()?,
            },
        );
    }
    Ok(keys)
}

/// SHA-256 of a verifier key's tagged serialization — the bytes Compact writes to `<circuit>.verifier`.
fn key_hash<T: Serializable + Tagged>(key: &T) -> Result<String, std::io::Error> {
    let mut bytes = Vec::new();
    tagged_serialize(key, &mut bytes)
        .map_err(|e| std::io::Error::other(format!("serialize verifier key: {e}")))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}
