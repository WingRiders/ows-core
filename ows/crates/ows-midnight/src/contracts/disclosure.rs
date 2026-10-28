//! What the tooling that built a transaction discloses about its calls, and the check that makes a
//! disclosure safe to show a policy.
//!
//! A call's arguments are private inputs to its proof, so the transaction's bytes do not carry them.
//! They are bound to it all the same: every Compact circuit proves that the call's communication
//! commitment — public, in the transaction — is `transient_commit(input ‖ output, rand)`. The tooling
//! holds `input`, `output` and `rand` (it built the call), so it can hand them over, and the wallet
//! recomputes the commitment: a disclosure that opens a call's commitment *is* that call's arguments,
//! one that opens none is refused outright.

use std::collections::BTreeMap;

use midnight_base_crypto::fab::{AlignedValue, Alignment, Value, ValueAtom};
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::communication_commitment;
use midnight_ledger::structure::{ContractAction, ProofKind};
use midnight_serialize::Deserializable;
use midnight_storage::db::DB;
use serde::Deserialize;
use transient_crypto::curve::Fr;

use super::{atoms, entry_point_label, fr_hex, CallArguments};

/// The `disclose` member of a `balanceUnsealedTransaction` request: the calls whose arguments the
/// tooling reveals. Every entry must match the transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosures {
    #[serde(default)]
    pub calls: Vec<CallDisclosure>,
}

/// One call's `input` (its arguments) and `output` (its result) as the ledger's `ContractCallPrototype`
/// took them, and the randomness its communication commitment was drawn with — the hex string the JS
/// ledger API's `communicationCommitmentRandomness()` returned. `address` and `entryPoint` are optional
/// cross-checks: when given, they must name the call the disclosure opens.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallDisclosure {
    pub input: WireAlignedValue,
    pub output: WireAlignedValue,
    pub communication_commitment_rand: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub entry_point: Option<String>,
}

/// An aligned value on the wire: its atoms as hex strings (each the ledger's little-endian bytes) and
/// its alignment exactly as the JS ledger API shapes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireAlignedValue {
    pub value: Vec<String>,
    pub alignment: Alignment,
}

/// Check every disclosure against the transaction's calls. Returns each opened call's arguments, keyed
/// by its communication commitment. A disclosure that opens nothing in the transaction is an error: the
/// tooling claimed something about this transaction that is not true of it, and a policy must not see
/// the claim.
pub(crate) fn verify_disclosures<P: ProofKind<D>, D: DB>(
    actions: impl Iterator<Item = (u16, ContractAction<P, D>)>,
    disclosures: &Disclosures,
) -> Result<BTreeMap<Fr, CallArguments>, std::io::Error> {
    let mut calls: BTreeMap<Fr, (ContractAddress, String)> = BTreeMap::new();
    for (_, action) in actions {
        let ContractAction::Call(call) = action else {
            continue;
        };
        calls.insert(
            call.communication_commitment,
            (call.address, entry_point_label(&call.entry_point)),
        );
    }

    let mut arguments = BTreeMap::new();
    for (i, disclosure) in disclosures.calls.iter().enumerate() {
        let input = aligned(&disclosure.input)
            .map_err(|e| invalid(format!("disclose.calls[{i}].input: {e}")))?;
        let output = aligned(&disclosure.output)
            .map_err(|e| invalid(format!("disclose.calls[{i}].output: {e}")))?;
        let rand = parse_fr(&disclosure.communication_commitment_rand).map_err(|e| {
            invalid(format!(
                "disclose.calls[{i}].communicationCommitmentRand: {e}"
            ))
        })?;
        let commitment = communication_commitment(input.clone(), output.clone(), rand);
        let Some((address, entry_point)) = calls.get(&commitment) else {
            return Err(invalid(format!(
                "disclose.calls[{i}] opens no call in the transaction (communication commitment {})",
                fr_hex(&commitment)
            )));
        };
        let named_address = disclosure
            .address
            .as_deref()
            .map(|a| a.strip_prefix("0x").unwrap_or(a));
        if named_address.is_some_and(|a| !a.eq_ignore_ascii_case(&hex::encode(address.0 .0))) {
            return Err(invalid(format!(
                "disclose.calls[{i}] names address {}, but opens a call to {}",
                disclosure.address.as_deref().unwrap_or_default(),
                hex::encode(address.0 .0)
            )));
        }
        if disclosure
            .entry_point
            .as_deref()
            .is_some_and(|ep| ep != entry_point)
        {
            return Err(invalid(format!(
                "disclose.calls[{i}] names entry point {}, but opens a call to {entry_point}",
                disclosure.entry_point.as_deref().unwrap_or_default()
            )));
        }
        arguments.insert(
            commitment,
            CallArguments {
                input: atoms(&input),
                output: atoms(&output),
            },
        );
    }

    Ok(arguments)
}

fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

fn aligned(wire: &WireAlignedValue) -> Result<AlignedValue, String> {
    let atoms = wire
        .value
        .iter()
        .map(|h| {
            hex::decode(h.strip_prefix("0x").unwrap_or(h))
                .map(ValueAtom)
                .map_err(|e| format!("atom {h:?} is not hex: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    AlignedValue::new(Value(atoms), wire.alignment.clone())
        .ok_or_else(|| "the value does not fit its alignment".to_string())
}

/// A field element from the hex of its ledger serialization, the whole input consumed.
fn parse_fr(hex_str: &str) -> Result<Fr, String> {
    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|e| format!("not hex: {e}"))?;
    let mut reader: &[u8] = &bytes;
    let fr = <Fr as Deserializable>::deserialize(&mut reader, 0)
        .map_err(|e| format!("not a field element: {e}"))?;
    if !reader.is_empty() {
        return Err("trailing bytes after the field element".into());
    }
    Ok(fr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::fab::{AlignmentAtom, AlignmentSegment};
    use midnight_base_crypto::hash::HashOutput;
    use midnight_ledger::structure::ContractCall;
    use midnight_storage::arena::Sp;
    use midnight_storage::db::InMemoryDB;
    use onchain_runtime::context::Effects;
    use onchain_runtime::state::EntryPointBuf;
    use onchain_runtime::transcript::Transcript;

    use crate::contracts::Atom;

    type Action = ContractAction<(), InMemoryDB>;

    fn address(byte: u8) -> ContractAddress {
        ContractAddress(HashOutput([byte; 32]))
    }

    fn amount(value: u64) -> AlignedValue {
        AlignedValue::new(
            Value(vec![ValueAtom(value.to_le_bytes().to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 8,
            })]),
        )
        .unwrap()
    }

    fn nothing() -> AlignedValue {
        AlignedValue::new(Value(vec![]), Alignment(vec![])).unwrap()
    }

    fn wire(value: &AlignedValue) -> WireAlignedValue {
        WireAlignedValue {
            value: value.value.0.iter().map(|a| hex::encode(&a.0)).collect(),
            alignment: value.alignment.clone(),
        }
    }

    fn call(
        contract: u8,
        entry_point: &str,
        commitment: Fr,
        effects: Effects<InMemoryDB>,
    ) -> Action {
        ContractAction::Call(Sp::new(ContractCall {
            address: address(contract),
            entry_point: EntryPointBuf(entry_point.as_bytes().to_vec()),
            guaranteed_transcript: Some(Sp::new(Transcript {
                gas: Default::default(),
                effects,
                program: vec![].into(),
                version: None,
            })),
            fallible_transcript: None,
            communication_commitment: commitment,
            proof: (),
        }))
    }

    /// A call to `withdraw(1000)` on contract 0xAA, built the way the ledger builds one: its commitment
    /// is `communication_commitment(input, output, rand)`.
    fn withdraw_call(rand: Fr) -> (Action, CallDisclosure) {
        let commitment = communication_commitment(amount(1000), nothing(), rand);
        let disclosure = CallDisclosure {
            input: wire(&amount(1000)),
            output: wire(&nothing()),
            communication_commitment_rand: fr_hex(&rand),
            address: None,
            entry_point: None,
        };
        (
            call(0xAA, "withdraw", commitment, Effects::default()),
            disclosure,
        )
    }

    #[test]
    fn a_disclosure_that_opens_a_call_yields_its_arguments() {
        let (action, disclosure) = withdraw_call(Fr::from(4242u64));
        let commitment = match &action {
            ContractAction::Call(c) => c.communication_commitment,
            _ => unreachable!(),
        };
        let arguments = verify_disclosures(
            [(1u16, action)].into_iter(),
            &Disclosures {
                calls: vec![disclosure],
            },
        )
        .unwrap();

        assert_eq!(
            arguments[&commitment].input,
            vec![Atom::Bytes {
                length: 8,
                hex: "e803000000000000".into(),
                uint: Some("1000".into()),
            }]
        );
        assert!(arguments[&commitment].output.is_empty());
    }

    #[test]
    fn a_disclosure_of_other_arguments_opens_nothing_and_is_refused() {
        let (action, mut disclosure) = withdraw_call(Fr::from(4242u64));
        // The tooling claims the call withdraws 10, not the 1000 it was proven with.
        disclosure.input = wire(&amount(10));
        let e = verify_disclosures(
            [(1u16, action)].into_iter(),
            &Disclosures {
                calls: vec![disclosure],
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("opens no call"), "{e}");
    }

    #[test]
    fn a_disclosure_must_name_the_call_it_opens() {
        let (action, mut disclosure) = withdraw_call(Fr::from(4242u64));
        disclosure.entry_point = Some("deposit".into());
        let e = verify_disclosures(
            [(1u16, action.clone())].into_iter(),
            &Disclosures {
                calls: vec![disclosure.clone()],
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("names entry point deposit"), "{e}");

        disclosure.entry_point = Some("withdraw".into());
        disclosure.address = Some(format!("0x{}", hex::encode([0xBBu8; 32])));
        let e = verify_disclosures(
            [(1u16, action)].into_iter(),
            &Disclosures {
                calls: vec![disclosure],
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("names address"), "{e}");
    }

    #[test]
    fn the_wire_shape_is_the_js_ledger_apis() {
        // `input` exactly as the JS ledger API shapes an AlignedValue, its atoms hex-encoded.
        let json = r#"{
            "calls": [{
                "input": {
                    "value": ["e803"],
                    "alignment": [{ "tag": "atom", "value": { "tag": "bytes", "length": 8 } }]
                },
                "output": { "value": [], "alignment": [] },
                "communicationCommitmentRand": "00",
                "entryPoint": "withdraw"
            }]
        }"#;
        let parsed: Disclosures = serde_json::from_str(json).unwrap();
        assert_eq!(aligned(&parsed.calls[0].input).unwrap(), amount(1000));
        assert_eq!(parsed.calls[0].entry_point.as_deref(), Some("withdraw"));
        assert!(serde_json::from_str::<Disclosures>(r#"{"calls":[],"extra":1}"#).is_err());
    }
}
