# Midnight Open Wallet Standard Scope

Midnight-only extract of the joint Cardano/Midnight OWS scope. Cross-cutting items (project setup, bindings, testing) that apply to both chains are kept here for completeness.

## Project setup

We will familiarize ourselves with the OWS codebase, set up the build and testing pipelines, and gain a solid understanding of the system architecture and existing abstractions.

## CAIP-2 abstraction

In line with the current OWS setup which lists only mainnets, the initial version will support Midnight mainnet using the namespace `midnight:mainnet`. We will integrate this namespace across all required components and configure the respective endpoints.

As the indexer service we plan to use the public midnight indexer. As the proving service/solution, for the sake of security (exposure of private key) and better user experience, we plan to explore and port a solution for built-in prover, implementations of which have already started appearing in the ecosystem (e.g. WASM-based provers). Alternatively, we would explore the usage of a locally hosted prover server.

> **Update 8.4.2026:** Exact approach to design/implement OWS ↔ Midnight interface TBD; dapp connector specs <https://github.com/midnightntwrk/midnight-dapp-connector-api/blob/main/src/api.ts> seem like a good starting point given that OWS and AI agent are in a similar relation as wallets and dapps. IOHK stated that the CAIP-2 for Midnight is in progress and might not be finalized before the implementation concludes. WingRiders and IOHK agreed that a built-in prover should be a viable approach and WASM prover seems like a good starting point — just make sure to integrate directly the underlying Rust libraries rather than the WASM bindings, as that would be just extra performance/architectural overhead.

## Key derivation and cryptography

Midnight logical accounts consist of multiple keys/addresses (namely unshielded, dust and shielded), therefore we will need to adjust the existing OWS abstractions accordingly.

For unshielded address derivation, OWS already supports the secp256k1 curve. For the dust and shielded addresses, we plan to port the JubJub and BLS12-381 curve implementations (<https://github.com/midnightntwrk/midnight-zk/tree/next/curves>) which don't seem to be supported by OWS yet.

> **Update 8.4.2026:** IOHK will share a proposal for a single address capturing unshielded, shielded and dust addresses, which should simplify OWS abstractions.

## Implementing the Chain Plugin Interface

To implement signing of transactions/arbitrary data (messages) we plan to use as reference the `midnight-wallet` library which, while made in TypeScript, uses Rust bindings to the `midnight-ledger` libraries for the lower-level logic. Our plan is to import the relevant `midnight-ledger` Rust crates into OWS (also Rust) and port the relevant logic from the `midnight-wallet` TypeScript SDK into OWS.

We expect that extra effort will be needed to accommodate shielded transactions in OWS, as well as the whole concept of three separate addresses (shielded, unshielded, dust) per logical account. To prevent private key exposure, we plan to explore built-in proving as outlined in the "CAIP-2 abstraction" section.

Moreover, the Midnight wallet requires significant time to synchronize its state before being able to perform transactions; therefore we also plan to explore the integration of storage and retrieval of the sync state for a smoother experience, similarly as the `midnight-wallet` library already does.

> **Update 8.4.2026:** IOHK agreed that the state synchronization needs to be hooked into the API and state needs to be persisted between calls to keep latencies low.

## Policy Engine support

To support custom executable policies in the OWS Policy Engine and analyze transactions to be signed, we plan to leverage the deserialization functionality available in the `midnight-ledger` (`midnight-wallet`) repository. Provided we have the synced wallet state (UTxOs) from the indexer, we should be able to determine the effect of the transaction on the wallet to give information to the Policy Engine.

As a reference for the format of data to exchange we plan to use the Midnight dapp connector API reference, which outlines how external parties (for the purpose of this project, AI agents) are supposed to exchange data (transactions) with wallets: <https://github.com/midnightntwrk/midnight-docs/api-reference/dapp-connector>

## Cross-Language Bindings

We will extend the TypeScript and Python bindings to expose the newly implemented Midnight functionality.

## Testing

Each component will include comprehensive unit tests covering edge cases and failure scenarios. In addition, we will conduct thorough end-to-end testing of both successful (happy path) and failure (unhappy path) flows.

## Invoicing Milestones — Midnight

| Milestone | When | Amount | Scope |
|-----------|------|--------|-------|
| Milestone 1 | Month 2 | €37,981 | Analysis, Architecture and setup; CAIP-2/CAIP-10 abstraction; Key Derivation and Cryptography (Rust Core) |
| Milestone 2 | Month 3 | €26,083 | Implementing the Chain Plugin Interface |
| Milestone 3 | Month 4 | €30,166 | Policy Engine Support; Cross-Language Bindings |
| **Total**  |         | **€94,230** | |

Payment address in USDC (ERC20): `0x27Eb0B0955D3Fb0181f43288F1c64dd3c0D605fE`

---

## Appendix: Repo extension points (Midnight-relevant)

From local survey of `ows-core-internal`:

- **Chain registry / CAIP namespaces:** `ows/crates/ows-core/src/chain.rs` — add a `Midnight` variant to `ChainType`, append a `KNOWN_CHAINS` entry for `midnight:mainnet`, and wire `namespace()`, `default_coin_type()`, `from_namespace()` match arms.
- **Chain Plugin / Signer trait:** `ows/crates/ows-signer/src/traits.rs` — `ChainSigner` defines `sign`, `sign_message`, `sign_transaction`, `extract_signable_bytes`, `encode_signed_transaction`, `default_derivation_path`, `coin_type`. Add `ows/crates/ows-signer/src/chains/midnight.rs`, register in `chains/mod.rs` and `signer_for_chain()` dispatch.
- **Curves:** `Curve` enum currently lacks JubJub and BLS12-381 needed for dust/shielded keys. Port from `midnightntwrk/midnight-zk`.
- **Key derivation:** `ows/crates/ows-signer/src/hd.rs` — current `HdDeriver` covers BIP-32 (secp256k1) and SLIP-10 (ed25519). The single-derivation-path-per-address assumption needs to be lifted so one logical account can carry unshielded + dust + shielded keys.
- **Pre-signing policy engine:** `ows/crates/ows-core/src/policy.rs` — `TransactionContext` is account-model (`raw_hex`). Extend with shielded/unshielded UTxO context fed from the indexer's synced wallet state, and integrate `midnight-ledger` deserialization to compute net effect on the agent's wallet.
- **State sync persistence:** new — sync state must persist between calls (per IOHK 8.4.2026 update); design where this lives in the OWS keystore/session layer.
- **Built-in prover:** new — import `midnight-ledger` Rust crates directly (not WASM bindings) so proving runs in-process without leaking the private key.
- **FFI bindings:** `bindings/node/src/lib.rs` (NAPI) and `bindings/python/src/lib.rs` (PyO3) — new `ChainType::Midnight` flows through automatically once registered; verify TypeScript/Python type hints.
- **CLI:** `ows/crates/ows-cli/src/main.rs` — `--chain midnight` accepted automatically once `KNOWN_CHAINS` is updated.
- **Contributor docs:** `docs/07-supported-chains.md`, `CONTRIBUTING.md`.
