//! The contract records of real proven transactions, built and proven on stagenet (ledger 9, compactc
//! 0.34.0) against the test contracts in `e2e/contract-calls/contracts/`. Each fixture is the proven,
//! unbalanced transaction a dapp hands `balanceUnsealedTransaction`, with the `disclose` member its
//! tooling sent: every call's input, output and communication-commitment randomness exactly as the JS
//! ledger API's `ContractCallPrototype` took them (the randomness of a root call is drawn inside
//! midnight-js, so the harness reads it there). A fresh build of each was funded by OWS and landed:
//!
//! - `single`: `Single.record(12345, 0x0102…20)`, which returns 12345.
//! - `composed`: `Caller.write_then_read(42)`, which calls `Tally.set(42)` then `Tally.get()`.
//! - `value`: `Payer.pay_from_wallet(NIGHT, 1)`: takes 1 NIGHT in, pays it to the Till and drives
//!   `Till.take_unshielded`, which claims it.
//! - `value_forward`: `Payer.forward_from_wallet(NIGHT, 1)`: only the sub-call takes NIGHT in.

use midnight_ledger::structure::{
    ProofMarker, Signature as MnSig, StandardTransaction, Transaction,
};
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;
use transient_crypto::commitment::PedersenRandomness;

use super::*;

type Base = StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

fn fixture(name: &str) -> (Base, Disclosures) {
    let (tx_hex, disclose) = match name {
        "single" => (
            include_str!("../testdata/contract_calls/single.tx.hex"),
            include_str!("../testdata/contract_calls/single.disclose.json"),
        ),
        "composed" => (
            include_str!("../testdata/contract_calls/composed.tx.hex"),
            include_str!("../testdata/contract_calls/composed.disclose.json"),
        ),
        "value" => (
            include_str!("../testdata/contract_calls/value.tx.hex"),
            include_str!("../testdata/contract_calls/value.disclose.json"),
        ),
        "value_forward" => (
            include_str!("../testdata/contract_calls/value_forward.tx.hex"),
            include_str!("../testdata/contract_calls/value_forward.disclose.json"),
        ),
        other => panic!("no fixture {other}"),
    };
    let bytes = hex::decode(tx_hex.trim()).unwrap();
    let tx: Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> =
        tagged_deserialize(&mut &bytes[..]).unwrap();
    let Transaction::Standard(base) = tx else {
        panic!("the fixture is a Standard transaction");
    };
    (base, serde_json::from_str(disclose).unwrap())
}

/// The records of a fixture with its disclosures verified, as the policy pass sees them, for a wallet
/// none of the calls pays.
fn records(name: &str) -> Vec<ContractInteraction> {
    let (base, disclosures) = fixture(name);
    let facts = CallFacts {
        arguments: verify_disclosures(base.actions(), &disclosures).unwrap(),
        ..Default::default()
    };
    contract_interactions(base.actions(), &UserAddress(HashOutput([0; 32])), &facts)
}

fn record<'a>(records: &'a [ContractInteraction], entry_point: &str) -> &'a ContractInteraction {
    records
        .iter()
        .find(|r| r.entry_point.as_deref() == Some(entry_point))
        .unwrap_or_else(|| panic!("no record for {entry_point}"))
}

fn uint(n: u128, length: u32) -> Atom {
    let mut bytes = n.to_le_bytes().to_vec();
    bytes.resize(length as usize, 0);
    Atom::Bytes {
        length,
        hex: hex::encode(bytes),
        uint: Some(n.to_string()),
    }
}

#[test]
fn every_call_of_every_real_transaction_opens_with_its_disclosure() {
    for name in ["single", "composed", "value", "value_forward"] {
        let out = records(name);
        let (_, disclosures) = fixture(name);
        assert_eq!(
            out.len(),
            disclosures.calls.len(),
            "{name}: one record per call"
        );
        for r in &out {
            assert!(
                r.arguments.is_some(),
                "{name}: {:?} has no arguments",
                r.entry_point
            );
            // A root call's commitment is as real as a sub-call's: midnight-js draws its randomness
            // when it builds the call, and the circuit binds it like any other.
            assert_ne!(r.call, Some(fr_hex(&Fr::from(0u64))), "{name}");
        }
    }
}

#[test]
fn a_real_calls_arguments_and_result_are_the_ones_it_was_proven_with() {
    let out = records("single");
    let args = out[0].arguments.as_ref().unwrap();
    assert_eq!(
        args.input,
        vec![
            uint(12345, 8),
            Atom::Bytes {
                length: 32,
                hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
                uint: None,
            },
        ]
    );
    assert_eq!(args.output, vec![uint(12345, 8)]);
}

#[test]
fn a_disclosure_of_a_different_argument_is_refused_for_a_real_call() {
    let (base, mut disclosures) = fixture("composed");
    // The tooling claims Caller.write_then_read(43) — the transaction was proven with 42.
    let root = disclosures
        .calls
        .iter_mut()
        .find(|c| c.entry_point.as_deref() == Some("write_then_read"))
        .unwrap();
    root.input.value[0] = "2b".into();
    let e = verify_disclosures(base.actions(), &disclosures).unwrap_err();
    assert!(e.to_string().contains("opens no call"), "{e}");
}

#[test]
fn a_real_composed_transaction_is_a_tree_each_call_names_its_place_in() {
    let out = records("composed");
    let root = record(&out, "write_then_read");
    assert_eq!(root.caller, None);
    assert_eq!(root.arguments.as_ref().unwrap().input, vec![uint(42, 8)]);
    for callee in ["set", "get"] {
        assert_eq!(record(&out, callee).caller, root.call, "{callee}");
    }
    // Tally.set(42) takes the argument the root forwarded, and Tally.get() returns what it stored.
    assert_eq!(
        record(&out, "set").arguments.as_ref().unwrap().input,
        vec![uint(42, 8)]
    );
    assert_eq!(
        record(&out, "get").arguments.as_ref().unwrap().output,
        vec![uint(42, 8)]
    );
}
