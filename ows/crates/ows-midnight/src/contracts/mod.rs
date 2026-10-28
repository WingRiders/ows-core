//! The contract actions a transaction carries, read off the ledger structure for the policy seam.
//!
//! The companion of the wallet-relative effects, and deliberately disjoint from them: the effects say
//! how much *the wallet* moves, these say *who* the transaction talks to, *what* it asks of them and
//! how much value each contract declares it takes in and pays out. Identity and counterparty amounts
//! live only here.
//!
//! Everything a record says comes from the transaction's bytes or is checked against them. A call's
//! arguments are not in the bytes — they are private inputs to its proof — so they appear only when
//! the tooling that built the call discloses them and they open the call's communication commitment
//! ([`disclosure`]). The verifier key a call's proof is checked against lives in the contract's state
//! on chain, read before the policy pass ([`onchain`]).

use std::collections::BTreeMap;

use midnight_base_crypto::fab::{AlignedValue, AlignmentAtom, AlignmentSegment, ValueAtom};
use midnight_base_crypto::hash::HashOutput;
use midnight_coin_structure::coin::{PublicAddress, TokenType as LedgerTokenType, UserAddress};
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::structure::{
    ContractAction, ContractCall, ContractOperationVersion, ProofKind,
};
use midnight_serialize::Serializable as _;
use midnight_storage::db::DB;
use midnight_storage::storage::HashMap as MnHashMap;
use onchain_runtime::context::{ClaimedUnshieldedSpendsKey, Effects};
use onchain_runtime::state::EntryPointBuf;
use transient_crypto::curve::Fr;

mod disclosure;
mod onchain;
#[cfg(test)]
mod real_calls;

pub(crate) use disclosure::verify_disclosures;
pub use disclosure::Disclosures;
pub(crate) use onchain::fetch_operation_keys;

/// The guaranteed section, executed before every fallible one. A call's guaranteed transcript runs
/// here whichever intent carried it; only its fallible transcript runs in that intent's own segment.
const GUARANTEED_SEGMENT: u16 = 0;

/// What a transaction does to a contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractActionKind {
    /// Invokes an entry point on an already-deployed contract.
    Call,
    /// Deploys a new contract.
    Deploy,
    /// Applies a maintenance update (authority / verifier keys) to an existing contract.
    Maintain,
}

/// One contract action a transaction performs, keyed by the segment it executes in — `0` guaranteed
/// (always executed), non-zero fallible (executed in segment order, allowed to fail). A call declaring
/// both a guaranteed and a fallible transcript yields one entry per transcript, each at its own
/// segment, so a policy reads a single record's segment rather than inferring it from where the record
/// sits. A fallible segment id is whatever `u16` the transaction's author picked for that intent — it
/// is an identifier, not a sequence number, so guaranteed-versus-fallible is `== 0` versus `!= 0`.
///
/// A call names itself (`call`) and, when another call in the transaction claims it, that call
/// (`caller`): a composed transaction is a tree of calls, and each record carries its own place in it,
/// so a policy judges the tree by reading every record rather than by where a record sits in the list.
///
/// The amounts are the ones the **contract's transcript declares**, not proven wallet movement: they
/// equal what the wallet sends and receives only when the wallet is the contract's sole counterparty
/// in that segment (the normal shape for a single wallet-funded call), and they are only as
/// trustworthy as the transcript is — meaningful for a proven or sealed transaction. For what the
/// wallet itself moves, read the effects.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContractInteraction {
    pub segment: u16,
    pub kind: ContractActionKind,
    /// The contract's hex-encoded address (a deploy's is derived from its initial state).
    pub address: String,
    /// The entry point a call invokes, as its UTF-8 name (hex when the name is not UTF-8). Absent for
    /// a deploy or a maintenance update, neither of which targets one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    /// A call's identity: its communication commitment, hex-encoded as the ledger serializes it (the
    /// form the JS ledger API returns). Both records of a call that declares two transcripts carry the
    /// same value. Absent for a deploy or a maintenance update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<String>,
    /// The `call` of the call whose transcript claims this one — the contract that called it, in a
    /// composed transaction. Absent for a root call (one the transaction makes directly).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// SHA-256 of the verifier key the ledger checks this call's proof against, as the contract's
    /// on-chain state holds it — equal to `sha256sum` of the compiled `<circuit>.verifier` file. A
    /// contract's maintenance authority can replace it at the same address, so a policy pins this
    /// rather than trusting the address and entry point alone. Absent for a deploy or maintenance
    /// update, and when the indexer holds no state for the contract — a call the ledger refuses
    /// (`ContractNotPresent`), since it checks every call against the state before the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_key: Option<String>,
    /// The call's arguments and result, present only when the tooling disclosed them and they open
    /// the call's communication commitment — the ledger's own binding of a proof to its inputs and
    /// outputs. Without a disclosure a policy knows whom the call targets, not what it asks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<CallArguments>,
    /// Per token, the total value the contract declares it takes in, from every party to the
    /// transaction together. The wallet sends this only when it is the contract's sole counterparty.
    pub sent_to: Vec<(String, String)>,
    /// Per token, the total value the contract declares it pays out, to every recipient together.
    /// `payouts` says to whom; this is not what the wallet receives.
    pub received_from: Vec<(String, String)>,
    /// The unshielded payouts the call declares, one per token and recipient.
    pub payouts: Vec<Payout>,
}

/// Who a contract's declared unshielded payout goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipientKind {
    /// A user's unshielded address.
    User,
    /// Another contract.
    Contract,
}

/// One recipient of a call's declared unshielded payout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Payout {
    /// The token, as the same wire string `sent_to` and `received_from` use.
    pub token: String,
    /// The amount, as a decimal string.
    pub amount: String,
    /// The recipient's hex-encoded address: a user's address hash or a contract's address.
    pub recipient: String,
    pub recipient_kind: RecipientKind,
    /// Whether the recipient is the wallet's own unshielded address.
    pub to_wallet: bool,
}

/// A call's disclosed arguments (`input`) and result (`output`), each flattened into the atoms the
/// ledger lays them out as, in declaration order. A Compact `Uint<64>` is one 8-byte atom, a
/// `Bytes<32>` one 32-byte atom, a struct its fields' atoms in order, and a `Maybe`/enum a 2-byte
/// variant atom followed by that variant's atoms — the canonical vector a policy constrains.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CallArguments {
    pub input: Vec<Atom>,
    pub output: Vec<Atom>,
}

/// One atom of a disclosed value. Byte atoms carry their full declared width in `hex` (the ledger's
/// little-endian bytes, zero-padded), and — up to 16 bytes — the same bytes read as an unsigned
/// integer in `uint`, so a policy caps an amount by comparing a decimal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Atom {
    Bytes {
        length: u32,
        hex: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        uint: Option<String>,
    },
    /// A native field element, little-endian.
    Field { hex: String },
    /// A value the ledger represents by its hash.
    Compress { hex: String },
}

/// What the wallet established about a transaction's calls beyond what the bytes say, before the
/// policy pass: the verifier keys on chain, and the arguments the tooling disclosed, each checked
/// against the transaction.
#[derive(Debug, Clone, Default)]
pub struct CallFacts {
    /// Per contract and entry point, the hash of each verifier-key version its state holds.
    pub(crate) operation_keys: BTreeMap<(ContractAddress, EntryPointBuf), OperationKeys>,
    /// Per call (its communication commitment), its verified arguments.
    pub(crate) arguments: BTreeMap<Fr, CallArguments>,
}

/// The SHA-256 of an operation's verifier keys, one per proof system the ledger supports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OperationKeys {
    /// The key for ZKIR v2 proofs (the ledger's `ContractOperationVersion::V3`).
    pub v2: Option<String>,
    /// The key for ZKIR v3 proofs (`ContractOperationVersion::V4`).
    pub v3: Option<String>,
}

impl OperationKeys {
    /// The key a proof of `version` is verified against — mirroring the ledger's own choice when it
    /// prices and verifies a call (`validation_cost_with_state`): the latest key when the version is
    /// unknown.
    fn for_version(&self, version: Option<ContractOperationVersion>) -> Option<&String> {
        match version {
            Some(ContractOperationVersion::V3) => self.v2.as_ref(),
            Some(ContractOperationVersion::V4) => self.v3.as_ref(),
            _ => self.v3.as_ref().or(self.v2.as_ref()),
        }
    }
}

/// The contract actions of a transaction's intents, one entry per executing segment. Pure over the
/// ledger structure and the established `facts` (no key, no network), so it is the unit-tested core
/// behind every plan's `contracts()`; callers pass `StandardTransaction::actions()`, whose `u16` is
/// the intent's segment, and the wallet's unshielded address, to mark the payouts that reach it.
pub(crate) fn contract_interactions<P: ProofKind<D>, D: DB>(
    actions: impl Iterator<Item = (u16, ContractAction<P, D>)>,
    wallet: &UserAddress,
    facts: &CallFacts,
) -> Vec<ContractInteraction> {
    let actions: Vec<(u16, ContractAction<P, D>)> = actions.collect();
    let callers = callers_by_claim(&actions);
    let mut out = Vec::new();
    for (intent_segment, action) in &actions {
        match action {
            ContractAction::Call(call) => {
                let id = CallId::of(call);
                let identity = CallIdentity {
                    address: &call.address,
                    entry_point: entry_point_label(&call.entry_point),
                    call: fr_hex(&call.communication_commitment),
                    caller: callers.get(&id).map(fr_hex),
                    verifier_key: facts
                        .operation_keys
                        .get(&(call.address, call.entry_point.clone()))
                        .and_then(|keys| {
                            keys.for_version(P::proof_version_to_operation_version(&call.proof))
                        })
                        .cloned(),
                    arguments: facts.arguments.get(&call.communication_commitment).cloned(),
                };
                let guaranteed = call.guaranteed_transcript.as_ref();
                let fallible = call.fallible_transcript.as_ref();
                if let Some(transcript) = guaranteed {
                    out.push(call_interaction(
                        GUARANTEED_SEGMENT,
                        &identity,
                        &transcript.effects,
                        wallet,
                    ));
                }
                if let Some(transcript) = fallible {
                    out.push(call_interaction(
                        *intent_segment,
                        &identity,
                        &transcript.effects,
                        wallet,
                    ));
                }
                if guaranteed.is_none() && fallible.is_none() {
                    // A call declaring no transcript moves nothing, but a policy keyed on which
                    // contracts a transaction touches still has to see it.
                    out.push(call_interaction(
                        *intent_segment,
                        &identity,
                        &Effects::<D>::default(),
                        wallet,
                    ));
                }
            }
            // A deploy and a maintenance update carry no transcript — the ledger skips both in the
            // guaranteed pass — so they declare no value movement and ride their intent's segment.
            ContractAction::Deploy(deploy) => out.push(non_call_interaction(
                *intent_segment,
                ContractActionKind::Deploy,
                deploy.address(),
            )),
            ContractAction::Maintain(update) => out.push(non_call_interaction(
                *intent_segment,
                ContractActionKind::Maintain,
                update.address,
            )),
        }
    }
    out
}

/// A call as another call's transcript claims it: the callee's address, entry-point hash and
/// communication commitment — exactly the triple the ledger matches a claim against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CallId {
    address: ContractAddress,
    entry_point: HashOutput,
    commitment: Fr,
}

impl CallId {
    fn of<P: ProofKind<D>, D: DB>(call: &ContractCall<P, D>) -> Self {
        CallId {
            address: call.address,
            entry_point: call.entry_point.ep_hash(),
            commitment: call.communication_commitment,
        }
    }
}

/// For every call another call claims, the claiming call's communication commitment — the edges of
/// the transaction's call tree. The ledger admits a claim only when the claimed call is in the same
/// transaction and claimed once, so each callee has exactly one caller.
fn callers_by_claim<P: ProofKind<D>, D: DB>(
    actions: &[(u16, ContractAction<P, D>)],
) -> BTreeMap<CallId, Fr> {
    let mut callers = BTreeMap::new();
    for (_, action) in actions {
        let ContractAction::Call(call) = action else {
            continue;
        };
        let transcripts = call
            .guaranteed_transcript
            .iter()
            .chain(call.fallible_transcript.iter());
        for transcript in transcripts {
            for claim in transcript.effects.claimed_contract_calls.iter() {
                let (_seq, address, entry_point, commitment) = (*claim).into_inner();
                callers.insert(
                    CallId {
                        address,
                        entry_point,
                        commitment,
                    },
                    call.communication_commitment,
                );
            }
        }
    }
    callers
}

/// What every record of one call shares, whichever transcript it reports.
struct CallIdentity<'a> {
    address: &'a ContractAddress,
    entry_point: String,
    call: String,
    caller: Option<String>,
    verifier_key: Option<String>,
    arguments: Option<CallArguments>,
}

fn call_interaction<D: DB>(
    segment: u16,
    identity: &CallIdentity<'_>,
    effects: &Effects<D>,
    wallet: &UserAddress,
) -> ContractInteraction {
    ContractInteraction {
        segment,
        kind: ContractActionKind::Call,
        address: hex::encode(identity.address.0 .0),
        entry_point: Some(identity.entry_point.clone()),
        call: Some(identity.call.clone()),
        caller: identity.caller.clone(),
        verifier_key: identity.verifier_key.clone(),
        arguments: identity.arguments.clone(),
        sent_to: token_amounts(&effects.unshielded_inputs),
        received_from: token_amounts(&effects.unshielded_outputs),
        payouts: payouts(&effects.claimed_unshielded_spends, wallet),
    }
}

fn non_call_interaction(
    segment: u16,
    kind: ContractActionKind,
    address: ContractAddress,
) -> ContractInteraction {
    ContractInteraction {
        segment,
        kind,
        address: hex::encode(address.0 .0),
        entry_point: None,
        call: None,
        caller: None,
        verifier_key: None,
        arguments: None,
        sent_to: Vec::new(),
        received_from: Vec::new(),
        payouts: Vec::new(),
    }
}

/// A transcript's claimed unshielded spends — what it pays out, keyed by token and recipient — sorted
/// by token and then recipient, with zeros dropped.
fn payouts<D: DB>(
    claimed: &MnHashMap<ClaimedUnshieldedSpendsKey, u128, D>,
    wallet: &UserAddress,
) -> Vec<Payout> {
    let mut out: Vec<Payout> = claimed
        .clone()
        .into_iter()
        .filter(|(_, amount)| *amount != 0)
        .map(|(ClaimedUnshieldedSpendsKey(token, recipient), amount)| {
            let (recipient, recipient_kind, to_wallet) = match recipient {
                PublicAddress::User(user) => {
                    (hex::encode(user.0 .0), RecipientKind::User, user == *wallet)
                }
                PublicAddress::Contract(contract) => {
                    (hex::encode(contract.0 .0), RecipientKind::Contract, false)
                }
            };
            Payout {
                token: wire_token_type(token),
                amount: amount.to_string(),
                recipient,
                recipient_kind,
                to_wallet,
            }
        })
        .collect();
    out.sort_by(|a, b| (&a.token, &a.recipient).cmp(&(&b.token, &b.recipient)));
    out
}

/// A transcript's declared per-token amounts on the wire, sorted by token and with zeros dropped. The
/// amounts are decimal strings, like an effect's, so a JSON reader never rounds one.
fn token_amounts<D: DB>(amounts: &MnHashMap<LedgerTokenType, u128, D>) -> Vec<(String, String)> {
    let mut by_token: BTreeMap<String, u128> = BTreeMap::new();
    for (token, value) in amounts.clone() {
        let total = by_token.entry(wire_token_type(token)).or_default();
        *total = total.saturating_add(value);
    }
    by_token
        .into_iter()
        .filter(|(_, v)| *v != 0)
        .map(|(token, v)| (token, v.to_string()))
        .collect()
}

/// A ledger token type as the wire string the policy context uses elsewhere: the 32-byte hex of the
/// token (all-zeros for NIGHT), or `dust` for the DUST dimension. The transcript fields these come
/// from are unshielded, so the hex is never ambiguous in practice; the shielded arm only keeps the
/// mapping total.
fn wire_token_type(token: LedgerTokenType) -> String {
    match token {
        LedgerTokenType::Unshielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Shielded(tt) => hex::encode(tt.0 .0),
        LedgerTokenType::Dust => "dust".to_string(),
    }
}

/// A call's entry point as its UTF-8 name — how Compact declares them — falling back to hex for a name
/// that is not valid UTF-8.
fn entry_point_label(entry_point: &[u8]) -> String {
    std::str::from_utf8(entry_point)
        .map(str::to_string)
        .unwrap_or_else(|_| hex::encode(entry_point))
}

/// A field element as the ledger serializes it, hex-encoded — the form the JS ledger API renders a
/// communication commitment in, so a call's id reads the same on both sides.
pub(crate) fn fr_hex(fr: &Fr) -> String {
    let mut bytes = Vec::new();
    fr.serialize(&mut bytes)
        .expect("serializing a field element into memory cannot fail");
    hex::encode(bytes)
}

/// Flatten an aligned value into its atoms, in order, following the alignment: an option segment
/// contributes its 2-byte variant atom, then the chosen variant's atoms. The value is already known to
/// fit its alignment (an [`AlignedValue`] cannot be built otherwise).
pub(crate) fn atoms(value: &AlignedValue) -> Vec<Atom> {
    let mut out = Vec::new();
    let mut rest: &[ValueAtom] = &value.value.0;
    flatten(&value.alignment.0, &mut rest, &mut out);
    out
}

fn flatten(segments: &[AlignmentSegment], rest: &mut &[ValueAtom], out: &mut Vec<Atom>) {
    for segment in segments {
        let Some((first, tail)) = rest.split_first() else {
            return;
        };
        match segment {
            AlignmentSegment::Atom(atom) => {
                out.push(atom_of(*atom, first));
                *rest = tail;
            }
            AlignmentSegment::Option(variants) => {
                let variant = AlignmentAtom::Bytes { length: 2 };
                out.push(atom_of(variant, first));
                *rest = tail;
                let index = first
                    .0
                    .iter()
                    .rev()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
                if let Some(chosen) = variants.get(index) {
                    flatten(&chosen.0, rest, out);
                }
            }
        }
    }
}

fn atom_of(alignment: AlignmentAtom, value: &ValueAtom) -> Atom {
    match alignment {
        AlignmentAtom::Bytes { length } => {
            let mut bytes = value.0.clone();
            bytes.resize(length as usize, 0);
            let uint = (length <= 16).then(|| {
                bytes
                    .iter()
                    .rev()
                    .fold(0u128, |acc, b| (acc << 8) | u128::from(*b))
                    .to_string()
            });
            Atom::Bytes {
                length,
                hex: hex::encode(&bytes),
                uint,
            }
        }
        AlignmentAtom::Field => Atom::Field {
            hex: hex::encode(&value.0),
        },
        AlignmentAtom::Compress => Atom::Compress {
            hex: hex::encode(&value.0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::UnshieldedTokenType;
    use midnight_coin_structure::contract::ContractAddress;
    use midnight_ledger::structure::{ContractDeploy, MaintenanceUpdate};
    use midnight_storage::arena::Sp;
    use midnight_storage::db::InMemoryDB;
    use onchain_runtime::state::{
        ContractMaintenanceAuthority, ContractState, EntryPointBuf, StateValue,
    };
    use onchain_runtime::transcript::Transcript;

    /// The proof-free marker instantiation: the extraction reads only addresses and transcripts, both
    /// proof-independent, so a test never needs a prover.
    type Call = midnight_ledger::structure::ContractCall<(), InMemoryDB>;
    type Action = ContractAction<(), InMemoryDB>;

    fn address(byte: u8) -> ContractAddress {
        ContractAddress(HashOutput([byte; 32]))
    }

    fn token(byte: u8) -> LedgerTokenType {
        LedgerTokenType::Unshielded(UnshieldedTokenType(HashOutput([byte; 32])))
    }

    fn wallet() -> UserAddress {
        UserAddress(HashOutput([0x77; 32]))
    }

    /// A transcript declaring `inputs` taken in and `outputs` paid out by the contract.
    fn transcript(
        inputs: &[(LedgerTokenType, u128)],
        outputs: &[(LedgerTokenType, u128)],
    ) -> Sp<Transcript<InMemoryDB>, InMemoryDB> {
        let mut effects = Effects::<InMemoryDB>::default();
        for (token, value) in inputs {
            effects.unshielded_inputs = effects.unshielded_inputs.insert(*token, *value);
        }
        for (token, value) in outputs {
            effects.unshielded_outputs = effects.unshielded_outputs.insert(*token, *value);
        }
        Sp::new(Transcript {
            gas: Default::default(),
            effects,
            program: vec![].into(),
            version: None,
        })
    }

    fn call(
        contract: u8,
        entry_point: &str,
        guaranteed: Option<Sp<Transcript<InMemoryDB>, InMemoryDB>>,
        fallible: Option<Sp<Transcript<InMemoryDB>, InMemoryDB>>,
    ) -> Action {
        ContractAction::Call(Sp::new(Call {
            address: address(contract),
            entry_point: EntryPointBuf(entry_point.as_bytes().to_vec()),
            guaranteed_transcript: guaranteed,
            fallible_transcript: fallible,
            communication_commitment: Default::default(),
            proof: (),
        }))
    }

    #[test]
    fn a_call_yields_one_entry_per_transcript_at_its_own_segment() {
        // One call carried by intent segment 3, declaring both transcripts: the guaranteed one runs in
        // segment 0, the fallible one in the intent's segment.
        let action = call(
            0xAB,
            "swap",
            Some(transcript(&[(token(0x11), 100)], &[])),
            Some(transcript(&[], &[(token(0x22), 250)])),
        );

        let out = contract_interactions(
            [(3u16, action)].into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].segment, GUARANTEED_SEGMENT);
        assert_eq!(out[0].kind, ContractActionKind::Call);
        assert_eq!(out[0].address, hex::encode([0xABu8; 32]));
        assert_eq!(out[0].entry_point.as_deref(), Some("swap"));
        assert_eq!(
            out[0].sent_to,
            vec![(hex::encode([0x11u8; 32]), "100".to_string())]
        );
        assert!(out[0].received_from.is_empty());

        assert_eq!(out[1].segment, 3);
        assert_eq!(out[1].address, hex::encode([0xABu8; 32]));
        assert!(out[1].sent_to.is_empty());
        assert_eq!(
            out[1].received_from,
            vec![(hex::encode([0x22u8; 32]), "250".to_string())]
        );
    }

    #[test]
    fn a_call_declaring_no_transcript_is_still_reported() {
        let out = contract_interactions(
            [(1u16, call(0x07, "noop", None, None))].into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].segment, 1);
        assert_eq!(out[0].entry_point.as_deref(), Some("noop"));
        assert!(out[0].sent_to.is_empty());
        assert!(out[0].received_from.is_empty());
    }

    #[test]
    fn a_deploy_and_a_maintenance_update_ride_their_intent_segment_with_no_amounts() {
        let deploy = ContractDeploy::<InMemoryDB> {
            initial_state: ContractState::new(
                StateValue::Null,
                Default::default(),
                ContractMaintenanceAuthority::default(),
            ),
            nonce: HashOutput([0x42; 32]),
        };
        // A deploy names no address of its own — the ledger derives it from the deploy itself.
        let deployed_address = hex::encode(deploy.address().0 .0);
        let update = MaintenanceUpdate::<InMemoryDB> {
            address: address(0x99),
            updates: vec![].into(),
            counter: 0,
            signatures: vec![].into(),
        };

        let out = contract_interactions(
            [
                (2u16, Action::Deploy(Sp::new(deploy))),
                (5u16, Action::Maintain(update)),
            ]
            .into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, ContractActionKind::Deploy);
        assert_eq!(out[0].segment, 2);
        assert_eq!(out[0].address, deployed_address);
        assert_eq!(out[0].entry_point, None);
        assert!(out[0].sent_to.is_empty() && out[0].received_from.is_empty());

        assert_eq!(out[1].kind, ContractActionKind::Maintain);
        assert_eq!(out[1].segment, 5);
        assert_eq!(out[1].address, hex::encode([0x99u8; 32]));
        assert_eq!(out[1].entry_point, None);
    }

    /// A real, settled stagenet contract call, read from the bytes the chain actually carries.
    ///
    /// Fixture: tx `bbe2acc327f072605403eede4d640d7cae0d47cb9b98a5319a8066aa82f0142d`, block
    /// 975946 on `midnight:stagenet` (ledger 9), status SUCCESS — refetch with
    /// `{ transactions(offset:{hash:"bbe2ac…"}) { raw } }` against
    /// `https://indexer.stagenet.shielded.tools/api/v4/graphql`.
    ///
    /// The indexer reports this call independently as address
    /// `f973e22e0a15c1c4ef9dd5d6d6c87f6c60728b6277e09421de8f780644477421`, entry point
    /// `deposit_unshielded` — so the address and entry point below are cross-checked against a
    /// source other than our own decoding, and the amount is what a real dapp's transcript declares.
    #[test]
    fn a_real_stagenet_contract_call_is_read_from_the_chain_bytes() {
        use midnight_ledger::structure::Signature as MnSig;
        use midnight_ledger::structure::{ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use transient_crypto::commitment::PureGeneratorPedersen;

        let hex_str = include_str!("../testdata/contract_call_stagenet.hex").trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let mut reader: &[u8] = &bytes;
        let tx: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut reader).unwrap();
        let Transaction::Standard(base) = &tx else {
            panic!("the fixture is a Standard transaction");
        };

        let out = contract_interactions(base.actions(), &wallet(), &CallFacts::default());

        assert_eq!(
            out.len(),
            1,
            "the fixture carries exactly one contract action"
        );
        let call = &out[0];
        assert_eq!(call.kind, ContractActionKind::Call);
        assert_eq!(
            call.address,
            "f973e22e0a15c1c4ef9dd5d6d6c87f6c60728b6277e09421de8f780644477421"
        );
        assert_eq!(call.entry_point.as_deref(), Some("deposit_unshielded"));
        assert!(call.payouts.is_empty());

        // The deposit declares only a guaranteed transcript, so it is keyed by the guaranteed segment.
        assert_eq!(call.segment, GUARANTEED_SEGMENT);

        // A deposit pays value IN and takes none out: 10 NIGHT into the account contract.
        assert_eq!(
            call.sent_to,
            vec![(hex::encode([0u8; 32]), "10000000".to_string())]
        );
        assert!(call.received_from.is_empty());
    }

    /// A call's payout total does not say who is paid: the payouts name each recipient, so one that
    /// pays a third party is not mistaken for income to the wallet.
    #[test]
    fn a_calls_payouts_name_each_recipient() {
        let dapp = UserAddress(HashOutput([0x44; 32]));
        let other_contract = address(0x55);
        let mut effects = Effects::<InMemoryDB>::default();
        effects.unshielded_outputs = effects.unshielded_outputs.insert(token(0x22), 175);
        for (recipient, amount) in [
            (PublicAddress::User(dapp), 100),
            (PublicAddress::User(wallet()), 50),
            (PublicAddress::Contract(other_contract), 25),
        ] {
            effects.claimed_unshielded_spends = effects
                .claimed_unshielded_spends
                .insert(ClaimedUnshieldedSpendsKey(token(0x22), recipient), amount);
        }
        let transcript = Sp::new(Transcript {
            gas: Default::default(),
            effects,
            program: vec![].into(),
            version: None,
        });

        let out = contract_interactions(
            [(1u16, call(0x0C, "swap", Some(transcript), None))].into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        let tok = hex::encode([0x22u8; 32]);
        assert_eq!(out[0].received_from, vec![(tok.clone(), "175".to_string())]);
        assert_eq!(
            out[0].payouts,
            vec![
                Payout {
                    token: tok.clone(),
                    amount: "100".to_string(),
                    recipient: hex::encode([0x44u8; 32]),
                    recipient_kind: RecipientKind::User,
                    to_wallet: false,
                },
                Payout {
                    token: tok.clone(),
                    amount: "25".to_string(),
                    recipient: hex::encode([0x55u8; 32]),
                    recipient_kind: RecipientKind::Contract,
                    to_wallet: false,
                },
                Payout {
                    token: tok,
                    amount: "50".to_string(),
                    recipient: hex::encode([0x77u8; 32]),
                    recipient_kind: RecipientKind::User,
                    to_wallet: true,
                },
            ]
        );
    }

    #[test]
    fn dust_and_zero_amounts_render_as_the_policy_expects() {
        let action = call(
            0x01,
            "fee",
            Some(transcript(
                &[(LedgerTokenType::Dust, 42), (token(0x33), 0)],
                &[],
            )),
            None,
        );

        let out = contract_interactions(
            [(1u16, action)].into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        // The DUST dimension keeps the `dust` wire name the effects use; a zero amount is dropped.
        assert_eq!(out[0].sent_to, vec![("dust".to_string(), "42".to_string())]);
    }

    fn call_with(
        contract: u8,
        entry_point: &str,
        commitment: Fr,
        guaranteed: Option<Sp<Transcript<InMemoryDB>, InMemoryDB>>,
    ) -> Action {
        ContractAction::Call(Sp::new(Call {
            address: address(contract),
            entry_point: EntryPointBuf(entry_point.as_bytes().to_vec()),
            guaranteed_transcript: guaranteed,
            fallible_transcript: None,
            communication_commitment: commitment,
            proof: (),
        }))
    }

    fn with_effects(
        effects: Effects<InMemoryDB>,
    ) -> Option<Sp<Transcript<InMemoryDB>, InMemoryDB>> {
        Some(Sp::new(Transcript {
            gas: Default::default(),
            effects,
            program: vec![].into(),
            version: None,
        }))
    }

    fn claiming(callee: u8, entry_point: &str, commitment: Fr) -> Effects<InMemoryDB> {
        use onchain_runtime::context::ClaimedContractCallsValue;
        let mut effects = Effects::<InMemoryDB>::default();
        effects.claimed_contract_calls =
            effects
                .claimed_contract_calls
                .insert(ClaimedContractCallsValue(
                    0,
                    address(callee),
                    EntryPointBuf(entry_point.as_bytes().to_vec()).ep_hash(),
                    commitment,
                ));
        effects
    }

    #[test]
    fn a_composed_call_names_its_caller_and_the_root_names_none() {
        // caller.write_then_read claims tally.set — the shape of a two-contract call tree.
        let (root, callee) = (Fr::from(22u64), Fr::from(11u64));
        let out = contract_interactions(
            [
                (
                    1u16,
                    call_with(
                        0xAA,
                        "write_then_read",
                        root,
                        with_effects(claiming(0xBB, "set", callee)),
                    ),
                ),
                (
                    1u16,
                    call_with(0xBB, "set", callee, Some(transcript(&[], &[]))),
                ),
            ]
            .into_iter(),
            &wallet(),
            &CallFacts::default(),
        );

        assert_eq!(out[0].call, Some(fr_hex(&root)));
        assert_eq!(out[0].caller, None);
        assert_eq!(out[1].call, Some(fr_hex(&callee)));
        assert_eq!(out[1].caller, Some(fr_hex(&root)));
    }

    #[test]
    fn a_claim_names_a_caller_only_when_address_entry_point_and_commitment_all_match() {
        // The ledger admits a claim only on the full triple, so a near miss is no edge.
        let callee = Fr::from(11u64);
        for claim in [
            claiming(0xBB, "get", callee),
            claiming(0xCC, "set", callee),
            claiming(0xBB, "set", Fr::from(12u64)),
        ] {
            let out = contract_interactions(
                [
                    (
                        1u16,
                        call_with(0xAA, "root", Fr::from(22u64), with_effects(claim)),
                    ),
                    (
                        1u16,
                        call_with(0xBB, "set", callee, Some(transcript(&[], &[]))),
                    ),
                ]
                .into_iter(),
                &wallet(),
                &CallFacts::default(),
            );
            assert_eq!(out[1].caller, None);
        }
    }

    #[test]
    fn the_verifier_key_follows_the_proof_version_the_ledger_checks_against() {
        let keys = OperationKeys {
            v2: Some("v2-key".into()),
            v3: Some("v3-key".into()),
        };
        assert_eq!(
            keys.for_version(Some(ContractOperationVersion::V3))
                .map(String::as_str),
            Some("v2-key")
        );
        assert_eq!(
            keys.for_version(Some(ContractOperationVersion::V4))
                .map(String::as_str),
            Some("v3-key")
        );
        assert_eq!(keys.for_version(None).map(String::as_str), Some("v3-key"));
        let v2_only = OperationKeys {
            v2: Some("v2-key".into()),
            v3: None,
        };
        assert_eq!(
            v2_only.for_version(None).map(String::as_str),
            Some("v2-key")
        );
        assert_eq!(
            v2_only.for_version(Some(ContractOperationVersion::V4)),
            None,
            "a v3 proof against a contract holding only a v2 key has no key to pin"
        );
    }

    /// The real stagenet call fixture, with the verifier keys its contract holds on chain: the call's
    /// record pins the key its proof is checked against, and that key is byte for byte the one Compact
    /// compiled — `sha256sum contracts/managed/account/keys/deposit_unshielded.verifier` in the passport
    /// playground (compactc 0.34.0) prints `b8b29aca…`.
    ///
    /// Fixture: `testdata/acc_state_stagenet.hex` is `contractAction(address:
    /// "f973e22e0a15c1c4ef9dd5d6d6c87f6c60728b6277e09421de8f780644477421") { state }` on the stagenet
    /// indexer, as of tx `b8078ee3b84895dfcf55dff0842124bc8e8016c5d2d7f8f1fe2f1e0abc14d241` (block
    /// 975950).
    #[test]
    fn a_real_call_pins_the_verifier_key_its_contract_holds_on_chain() {
        use midnight_ledger::structure::Signature as MnSig;
        use midnight_ledger::structure::{ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use transient_crypto::commitment::PureGeneratorPedersen;

        let contract = ContractAddress(HashOutput(
            hex::decode("f973e22e0a15c1c4ef9dd5d6d6c87f6c60728b6277e09421de8f780644477421")
                .unwrap()
                .try_into()
                .unwrap(),
        ));
        let state = include_str!("../testdata/acc_state_stagenet.hex").trim();
        let facts = CallFacts {
            operation_keys: onchain::operation_keys(contract, state).unwrap(),
            ..Default::default()
        };
        let deposit =
            &facts.operation_keys[&(contract, EntryPointBuf(b"deposit_unshielded".to_vec()))];
        assert_eq!(deposit.v3, None, "the account contract compiles to ZKIR v2");

        let hex_str = include_str!("../testdata/contract_call_stagenet.hex").trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let tx: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut &bytes[..]).unwrap();
        let Transaction::Standard(base) = &tx else {
            panic!("the fixture is a Standard transaction");
        };
        let out = contract_interactions(base.actions(), &wallet(), &facts);

        assert_eq!(
            out[0].verifier_key.as_deref(),
            Some("b8b29aca1d6a86f57efc504ad9bf348a2ef7dd643cdd2be08810ee4412050d23")
        );
        assert_eq!(out[0].caller, None, "a direct call has no caller");
        assert!(out[0].call.is_some());
    }

    #[test]
    fn atoms_lay_out_a_value_in_declaration_order() {
        use midnight_base_crypto::fab::{Alignment, Value};
        let bytes = |length| AlignmentSegment::Atom(AlignmentAtom::Bytes { length });
        // (amount: Uint<64> = 1000, recipient: Bytes<32>, memo: a two-variant option holding Uint<8> 7)
        let value = AlignedValue::new(
            Value(vec![
                ValueAtom(vec![0xe8, 0x03]),
                ValueAtom(vec![0xAB; 32]),
                ValueAtom(vec![1]),
                ValueAtom(vec![7]),
            ]),
            Alignment(vec![
                bytes(8),
                bytes(32),
                AlignmentSegment::Option(vec![Alignment(vec![]), Alignment(vec![bytes(1)])]),
            ]),
        )
        .expect("the value fits its alignment");

        assert_eq!(
            atoms(&value),
            vec![
                Atom::Bytes {
                    length: 8,
                    hex: "e803000000000000".into(),
                    uint: Some("1000".into()),
                },
                Atom::Bytes {
                    length: 32,
                    hex: hex::encode([0xABu8; 32]),
                    uint: None,
                },
                Atom::Bytes {
                    length: 2,
                    hex: "0100".into(),
                    uint: Some("1".into()),
                },
                Atom::Bytes {
                    length: 1,
                    hex: "07".into(),
                    uint: Some("7".into()),
                },
            ]
        );
    }
}
