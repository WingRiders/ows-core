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
//! - `shielded`: `Vault.deposit_shielded(coin)`: the dapp outputs a 1000-unit coin to the contract,
//!   which claims it.

use midnight_ledger::structure::{
    ProofMarker, Signature as MnSig, StandardTransaction, Transaction,
};
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;
use transient_crypto::commitment::PedersenRandomness;

use super::*;

type Base = StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

const NIGHT: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PAYER: &str = "6af1a747a98ebaa9bb2d7914177cfa6dc075a0f5f8ceae5916dd60a72e545050";
const TILL: &str = "da2172e0aef2418711220fada839e87e98dfecf4688832b2eb685c8a4ddf2ad6";

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
        "shielded" => (
            include_str!("../testdata/contract_calls/shielded.tx.hex"),
            include_str!("../testdata/contract_calls/shielded.disclose.json"),
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
    let (arguments, coins) = verify_disclosures(base.actions(), &disclosures).unwrap();
    let facts = CallFacts {
        arguments,
        coins,
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
    for name in ["single", "composed", "value", "value_forward", "shielded"] {
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

/// The payer takes 1 NIGHT in and pays it to the Till; the Till takes it in. Each contract's record
/// says so, and the payer's payout names the Till — so a policy can tell the value that stays inside
/// the tree from the value that comes from outside it (the 1 NIGHT the wallet funds, once, in the
/// effects).
#[test]
fn a_real_payment_between_contracts_shows_on_both_and_names_the_payee() {
    let out = records("value");
    let payer = record(&out, "pay_from_wallet");
    let till = record(&out, "take_unshielded");
    let one = vec![(NIGHT.to_string(), "1000000".to_string())];

    assert_eq!(payer.address, PAYER);
    assert_eq!(payer.sent_to, one);
    assert_eq!(payer.received_from, one);
    assert_eq!(
        payer.payouts,
        vec![Payout {
            token: NIGHT.into(),
            amount: "1000000".into(),
            recipient: TILL.into(),
            recipient_kind: RecipientKind::Contract,
            to_wallet: false,
        }]
    );
    assert_eq!(till.address, TILL);
    assert_eq!(till.caller, payer.call);
    assert_eq!(till.sent_to, one);
    assert!(till.received_from.is_empty() && till.payouts.is_empty());
}

#[test]
fn a_real_forwarded_payment_shows_only_on_the_callee() {
    let out = records("value_forward");
    let payer = record(&out, "forward_from_wallet");
    let till = record(&out, "take_unshielded");
    assert!(payer.sent_to.is_empty() && payer.payouts.is_empty());
    assert_eq!(
        till.sent_to,
        vec![(NIGHT.to_string(), "1000000".to_string())]
    );
    assert_eq!(till.caller, payer.call);
}

/// The vault claims the 1000-unit coin the dapp sends it. Its commitment is all the transaction shows;
/// the tooling's coin opening — checked against that commitment — is what puts the value on the record.
#[test]
fn a_real_shielded_deposit_shows_the_coin_the_contract_claims() {
    let out = records("shielded");
    let vault = record(&out, "deposit_shielded");
    assert_eq!(vault.shielded.sent_to.len(), 1);
    let coin = &vault.shielded.sent_to[0];
    assert_eq!(
        coin.token.as_deref(),
        Some("1ff34b30e33b5a3e69037149ba1c787bed7dfd25274594e1ec8b391ff29fac93")
    );
    assert_eq!(coin.value.as_deref(), Some("1000"));
    assert!(vault.sent_to.is_empty(), "nothing unshielded");

    // Without the opening the record still names the coin, by commitment only.
    let (base, _) = fixture("shielded");
    let bare = contract_interactions(
        base.actions(),
        &UserAddress(HashOutput([0; 32])),
        &CallFacts::default(),
    );
    assert_eq!(bare[0].shielded.sent_to[0].commitment, coin.commitment);
    assert_eq!(bare[0].shielded.sent_to[0].value, None);
}
