# Pluggability seams — and the load-bearing claim Midnight may falsify

## The core claim

`docs/07-supported-chains.md:135-143`:

> ## Adding a New Chain
>
> 1. Define a canonical chain identifier, preferably using CAIP-2.
> 2. Specify the derivation path and coin type, if applicable.
> 3. Specify the address encoding and checksum behavior.
> 4. Define the signing and message-signing behavior required by `02-signing-interface.md`.
> 5. Document any transaction serialization rules needed to produce deterministic signatures.
>
> **No changes to OWS core, the signing interface, or the policy engine are needed.**

This is a **strong load-bearing claim.** All 11 currently-supported chains conform to it. Midnight is a candidate to **falsify** it, on multiple axes simultaneously.

## What the claim is true for today

The 11 existing chains all share:

- **One signing curve per chain** — `Curve::Secp256k1` or `Curve::Ed25519`. (`curve.rs:3-6`)
- **One private-key derivation per logical account** — `HdDeriver::derive() -> SecretBytes`. (`hd.rs:30-40`)
- **One address per logical account per chain** — `ChainSigner::derive_address(private_key) -> String`. (`traits.rs:30`)
- **One signature per signing request** — `SignOutput { signature, recovery_id, public_key }`. (`traits.rs:5-13`)
- **Transaction model uniform via `raw_hex`** — `TransactionContext.raw_hex: String` swallows arbitrary serialization. (`policy.rs:67`)
- **Stateless signers** — zero-sized impls (or near-zero, e.g., Bitcoin's HRP). No prover keys, no sync state, no per-call cache beyond the global 5-second LRU.
- **No proving** — signatures only.

## Where Midnight is expected to break the claim

| Axis | OWS today | Midnight (per scope + raw-context index) | Verdict |
|---|---|---|---|
| Curves | secp256k1, ed25519 | + JubJub, + BLS12-381 | **falsifies** — `Curve` enum closed-extension |
| Keys per account | 1 | 3 (shielded, unshielded, dust); IOHK's 8.4.2026 update floats a single-address proposal that may collapse this | **falsifies** until the single-address proposal lands and is adopted |
| Addresses per account | 1 | 3 today; same caveat | **falsifies** under current contract |
| Tx model | account ish (`to`/`value`/`data` + `raw_hex`) | hybrid: UTxO unshielded + shielded notes (Zswap) + dust + intents | **likely falsifies** for policy engine — Bitcoin gets away with `raw_hex`-only because policies don't deserialize, but the scope's "Policy Engine support" section explicitly requires deserialized tx + wallet-state context |
| Signing | 1 signature per tx | binding signature + per-input spend authorizations on shielded txs (TBC during 2b) | **likely falsifies** — `SignOutput` is single-sig |
| Proving | none | required for shielded txs | **falsifies** — no equivalent in `ChainSigner` |
| Sync state | none in OWS surface | required between calls per IOHK 8.4.2026 update | **falsifies** — no `WalletSyncState` in OWS today |
| Stateless signer | yes | depends on prover route — in-process Rust port = stateful, hosted proof-server = stateless w.r.t. proving | **conditional** |
| Indexer | not in OWS surface | required (whether public or self-hosted is open) | **falsifies** if surfaced; could be deferred to executable policies otherwise |

## What seams the trait *does* offer

These places allow extension without trait change:

- `extract_signable_bytes<'a>(&self, &'a [u8]) -> Result<&'a [u8], _>` (`traits.rs:60-62`) — Solana overrides for envelope stripping (`solana.rs:80-99`).
- `encode_signed_transaction` (`traits.rs:68-78`) — opt-in via override; default errors.
- `default_derivation_path(index)` — chain-specific path layout.
- Per-chain-signer state — `BitcoinSigner::mainnet()/testnet()`, `CosmosSigner::cosmos_hub()` show non-zero-sized signers are accepted by the dispatcher.
- `signer_for_chain` in `chains/mod.rs:29-43` — adding a chain just adds an arm.
- Executable policies (`policy.rs:34-38`) — pipe `PolicyContext` JSON to a user-provided binary; the binary can do anything.

## What seams Midnight will need that don't exist

- **Multi-key derivation API.** `HdDeriver::derive_account(seed, account_index, chain) -> MidnightAccount { shielded, unshielded, dust }` or three separate calls with three derivation paths.
- **Curve enum extension.** Add `Curve::Bls12_381`, `Curve::JubJub` (or a generic "extended" variant). Affects `Curve::private_key_len`, `public_key_len`, `HdDeriver::derive`, the signer trait, the cache key.
- **Multi-signature-shape return.** Either widen `SignOutput` to carry multiple signatures, or introduce a parallel trait method (e.g., `sign_shielded_tx → ShieldedSigOutput { binding_sig, spend_auths: Vec<...> }`).
- **Prover-state-bearing signers.** Either let the signer own prover state (stateful), or add a separate `Prover` trait that the signer composes. Either way, this breaks the "all signers are zero-sized" pattern.
- **Wallet-sync-state surface.** In FFI: a typed object the binding can serialize/deserialize. In `ows-lib`: a vault-format extension or a session/cache layer.
- **Policy-engine extension.** Add a `MidnightTransactionContext` variant (or extend `TransactionContext` with optional fields) carrying parsed effects from the deserialized tx + wallet sync state.
- **CAIP-2 namespace registration.** `chain.rs::ChainType::Midnight` + `KNOWN_CHAINS` entry + `from_namespace` arm + `default_coin_type` (TBD which SLIP-44 — see [topic 08-caip2](../topics/08-caip2.md)).

## Posture for phase 3

The claim "no changes to OWS core, signing interface, or policy engine are needed" is the load-bearing assumption. Phase 3 should make a **principled decision** for each axis:

- **Strict adherence:** force Midnight into the existing surface (e.g., one signer per domain, executable-policy-only deserialization). Possible but ugly; the three-domain wallet shape would be hidden behind three sibling chains (`midnight-shielded`, `midnight-unshielded`, `midnight-dust`).
- **Targeted extension:** widen specific seams (curve enum, multi-key HD, optional `MidnightTransactionContext`) while keeping the trait shape. Most-likely outcome.
- **New parallel surface:** introduce `MidnightSigner` (separate trait) and reuse `ChainSigner` only for unshielded operations. Minimum disruption to existing chains; maximum complexity in `ows-lib` to multiplex.

Phase 2 (this knowledge base) does not pick. Phase 3 does, with this baseline as the LHS.
