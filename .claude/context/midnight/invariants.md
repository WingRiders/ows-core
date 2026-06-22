# System invariants (assertions)

> Artifact (c) per `task.md` step 2. Each invariant is phrased as an assertion (something a property test could check). Tagged by source.
>
> Status: first-pass populated by 2a (OWS), 2b (ledger), 2c (wallet). **Second-pass appended** — 2d (WalletEngine, license-pending — user override 2026-04-29), 2e (connector v4.0.0), 2f (Lace). Each invariant carries a citation. **Append-only across passes.** Wider X-1 sweep (curve-related signature invariants) **deferred** to a true 2g plan.

## OWS-side invariants currently enforced (from 2a)

These are the load-bearing assumptions the existing code makes. Midnight integration must preserve or explicitly violate them.

| # | Assertion | Enforced where |
|---|-----------|----------------|
| OWS-I-1 | `Curve::private_key_len() == 32` for every supported curve | `ows-signer/src/curve.rs:11-14` |
| OWS-I-2 | `HdDeriver::derive(seed, path, curve)` returns a `SecretBytes` of length 32 (when seed length ∈ [16, 64]) | `ows-signer/src/hd.rs:30-40` |
| OWS-I-3 | `HdDeriver::derive_ed25519(...)` rejects any path component without a `'` (hardened-only) | `ows-signer/src/hd.rs:148` |
| OWS-I-4 | `HdDeriver::derive(seed, path, curve)` with same `(seed, path, curve)` is deterministic | `ows-signer/src/hd.rs:572-577` (test) |
| OWS-I-5 | `signer_for_chain(chain).chain_type() == chain` for every `ChainType` variant | `ows-signer/src/chains/mod.rs:29-43`; tested at `lib.rs:255-271` |
| OWS-I-6 | `EvmSigner::sign(key, msg)` requires `msg.len() == 32` | `ows-signer/src/chains/evm.rs:232-237` |
| OWS-I-7 | `EvmSigner::sign(...)` returns 65-byte signature (`r ‖ s ‖ v`) with `recovery_id ∈ {0, 1}` | `ows-signer/src/chains/evm.rs:240-256` |
| OWS-I-8 | `parse_chain(chain.name)` round-trips for every entry in `KNOWN_CHAINS` (when `name` is unique) | `ows-core/src/chain.rs:200-260`; tests `chain.rs:459-474` |
| OWS-I-9 | `ChainType::namespace()` is total (covers all 11 variants) and matches `from_namespace().unwrap().namespace()` for every recognised CAIP-2 namespace | `ows-core/src/chain.rs:269-318` |
| OWS-I-10 | `TransactionContext.raw_hex` is non-empty for transaction-signing requests; empty otherwise (with `typed_data` carrying the signable payload for EIP-712) | `ows-core/src/policy.rs:65-67` (doc-comment) |
| OWS-I-11 | `Policy.action == Deny` for every policy in storage (no other variant exists) | `ows-core/src/policy.rs:6-7` |
| OWS-I-12 | All `ChainSigner` impls are `Send + Sync` | `ows-signer/src/traits.rs:19` |
| OWS-I-13 | The global key cache evicts entries after 5s and holds at most 32 | `ows-signer/src/lib.rs:31-33` |

## Midnight ledger invariants (from 2b §C — assertion form)

| # | Assertion | Source |
|---|-----------|--------|
| MN-I-1 | Every Zswap input produces exactly one nullifier added to ledger state, distinct from prior nullifiers: `∀ tx, ∀ input ∈ tx.zswap_inputs: nullifier ∉ state.nullifiers_before ∧ nullifier ∈ state.nullifiers_after` | `zswap.md::apply_input` |
| MN-I-2 | Every Zswap output produces exactly one commitment, with unique index in Merkle tree: `∀ tx, ∀ output ∈ tx.zswap_outputs: commitment ∉ state.commitments_before ∧ commitment ∈ state.commitments_after` | `zswap.md::apply_output` |
| MN-I-3 | No transaction is valid without covering all declared fees in Dust: `∀ tx: dust_balance ≥ 0` after spends and registrations applied | `intents-transactions.md::balance`, `dust.md` |
| MN-I-4 | Transaction binding randomness equals the sum of all per-component Pedersen randomnesses: `∑ intent_commitments + ∑ zswap_value_commitments == embedded::GENERATOR * tx.binding_randomness` | `preliminaries.md::Fiat-Shamir Pedersen` |
| MN-I-5 | Every Dust spend's output value = input value updated minus fee paid, and is non-negative: `∀ dust_spend: new_commitment_value == updated_value(old_output, gen_info, tnow) - v_fee ∧ v_fee ≤ updated_value` | `dust.md::dust_spend_valid` |
| MN-I-6 | Segment 0 is atomic for the entire tx; if it fails, the entire tx fails: `segment_0_success ∨ result == FailEntirely`. Fallible segment failures revert only that segment | `intents-transactions.md::application` |
| MN-I-7 | Every unshielded UTXO input has a valid Schnorr signature from the owner: `∀ utxo_spend: signature_verify((segment_id, ErasedIntent), utxo_spend.owner_verifying_key, signature) == Ok` | `night.md::well_formed` |
| MN-I-8 | Causal precedence: if A calls B, A precedes B in the segment order: `A.fallible_transcript.is_none() ∨ B.guaranteed_transcript.is_none()` when A calls B | `intents-transactions.md::sequencing_check`; properties.md Theorem 4 |
| MN-I-9 | Every intent has a TTL in the valid window: `∀ intent: intent.ttl ≥ tblock ∧ intent.ttl ≤ tblock + global_ttl` | `intents-transactions.md::ttl_check_weak` |
| MN-I-10 | Dust generation per Star is bounded by `night_dust_ratio` and decays after backing Night spent: `Dust_value(t) ≤ Night_value * night_dust_ratio` while Night unspent | `dust.md::updated_value` |
| MN-I-11 | Every contract call proof is bound to its parent intent's binding commitment: `zk_verify(circuit, program_execution, (segment_id, intent.binding_commitment), proof) == Ok` | `contracts.md::well_formed` |
| MN-I-12 | Zswap input proves against a Merkle root in the (TTL-windowed) history: `∀ input: input.merkle_tree_root ∈ state.commitment_tree_history.get(tblock)` | `zswap.md::apply_input` |
| MN-I-13 | Per-token-type, per-segment balance is non-negative (zero or positive remainder to treasury): `∀ (token_type, segment_id): balance[(token_type, segment_id)] ≥ 0` | `intents-transactions.md::balancing_check` |

## Midnight wallet invariants (from 2c §H)

| # | Assertion | Source |
|---|-----------|--------|
| WL-I-1 | Facade exposes consistent address per role per account index: derived address from same HD account is reproducible across wallet types | `packages/hd/src/HDWallet.ts` |
| WL-I-2 | Balancing produces at minimum one output per imbalance plus a fee output: `BalanceRecipe.balancingTransaction.outputs ≥ baseTransaction.imbalances.size + 1` | `packages/capabilities/src/balancer/` |
| WL-I-3 | Transaction imbalances are zero after finalization: `∀ segment ∈ finalizedTx: finalizedTx.imbalances(segment) == empty` | `packages/facade/src/index.ts` |
| WL-I-4 | Pending transaction set is monotonically growing during submission window: `pendingTransactions(t1) ⊆ pendingTransactions(t2)` for `t1 < t2` until tx finalizes/expires | `packages/capabilities/src/pendingTransactions/` |
| WL-I-5 | Sync progress monotonically narrows gaps: `sourceGap(t1) ≥ sourceGap(t2) ∧ applyGap(t1) ≥ applyGap(t2)` for `t1 < t2`, until both reach 0 | `packages/abstractions/src/SyncProgress.ts` |
| WL-I-6 | Wallet state serialization round-trips: `deserialize(serialize(state)) == state` | `packages/abstractions/src/InMemoryTransactionHistoryStorage.ts` |
| WL-I-7 | Address derivation uses distinct HD roles for distinct domains: shielded address (role 3) ≠ unshielded address (role 0) ≠ dust address (role 2) for same `(seed, account)` | `packages/hd/src/HDWallet.ts` (Roles enum) |
| WL-I-8 | Secret keys are not logged or returned via public observables: only secrets passed *into* `start()` are seen by the wallet; never exposed back | `packages/facade/src/index.ts` (signature shape) |
| WL-I-9 | Coin selection is deterministic for given state: `chooseCoin(S.coins, T, A)` returns same coin across calls for same `(state, token_type, amount)` | `packages/capabilities/src/balancer/chooseCoin.ts` |
| WL-I-10 | Recipe finalization is idempotent within a sync cycle: `finalizeRecipe(recipe)` produces same `FinalizedTransaction` for same recipe in same block window | `packages/facade/src/index.ts::finalizeRecipe` |

## OWS↔Midnight integration invariants we want to preserve (synthesized)

These are not yet enforced; they are *targets* for phase 5+ tests.

| # | Assertion | Why |
|---|-----------|-----|
| INT-I-1 | OWS `derive_address(midnight, ...)` returns one of the three Midnight addresses *or* a structured object — never silently picks one without disclosure | Avoids ambiguous defaults |
| INT-I-2 | OWS Midnight HD derivation uses path `m/44'/2400'/<account>'/<role>/<index>` — same as `midnight-wallet/packages/hd` | Cross-wallet recovery interop |
| INT-I-3 | Bech32m HRPs (`mn_shield-addr`, `mn_addr`, `mn_dust`, plus subtypes) match `midnight-wallet/packages/address-format` exactly | Address compatibility with Lace, 1AM, third-party tools |
| INT-I-4 | OWS sync state file is encrypted at rest with the same scrypt + AES-GCM scheme as the vault | Defense-in-depth — sync state reveals UTxOs/balances |
| INT-I-5 | Sync state file carries a schema version tag, and OWS refuses to load a version it doesn't know how to migrate | Avoid silent corruption on schema drift |
| INT-I-6 | OWS never queries the indexer for "does commitment X exist?" — uses stochastic prefix queries only | Privacy hygiene per `dust.md` |
| INT-I-7 | OWS Midnight tx signing path returns `SignerError::InvalidTransaction(...)` if the indexer URL is unset and a shielded operation is requested | Avoid silent failures |
| INT-I-8 | OWS ledger crate vendoring (`midnight-ledger` Rust crates) pin SHA from `raw-context/CLONES.md` — no transitive `cargo update` re-pulls during builds | Reproducibility |
| INT-I-9 | OWS adds `ChainType::Midnight` to `ALL_CHAIN_TYPES` array in `chain.rs:23-34` only if cross-chain mnemonic-derivation should produce a Midnight account by default | Cross-chain wallet UX consistency |
| INT-I-10 | If the single-address proposal lands and OWS adopts it, OWS preserves the three-address API as a **read-only diagnostic** for the migration window | Backwards-compat for users on the three-address model |
| INT-I-11 | OWS Midnight policy engine evaluates `AllowedChains` on the deserialized `chain_id` (whether `midnight:mainnet` or whatever upstream finalizes) — does not match `raw_hex` content | Avoid confused-deputy |
| INT-I-12 | OWS sync state never contains private key material — only commitments, public keys, balances, sync progress | Layer separation; vault holds the keys |

## Connector API invariants (from 2e — Apache-2.0)

| # | Assertion | Tag | Source |
|---|-----------|-----|--------|
| CN-I-1 | For every successful `connect(networkId)`, the returned `ConnectedAPI` is a frozen object whose all methods are callable (or return `PermissionRejected`) | OWS-side (must enforce on AI-agent side) | `SPECIFICATION.md:56-68`, `api.ts:58, 70-204` |
| CN-I-2 | Wallet must validate that `networkId` passed to `connect()` matches the wallet's actual connection; rejects with `Disconnected` if cannot reach | Midnight-side | `SPECIFICATION.md:72`; `errors.ts:26` |
| CN-I-3 | Every `InitialAPI` has unique semver `apiVersion` field; multiple incompatible versions coexist as separate `window.midnight[uuid]` entries | Midnight-side | `SPECIFICATION.md:68`; `api.ts:42-46` |
| CN-I-4 | Every `signData()` call must prefix `data` with `midnight_signed_message:<size>:` before signing | Midnight-side **(critical security)** | `SPECIFICATION.md:359` |
| CN-I-5 | All transactions returned from `balance{Un,}sealedTransaction()` are cryptographically bound, signed, and proved — ready for `submitTransaction` without further work | Midnight-side | `SPECIFICATION.md:343-355`; `api.ts:115, 128` |
| CN-I-6 | Every `APIError` carries `type === 'DAppConnectorAPIError'` and one of 5 codes (`InternalError`, `Rejected`, `InvalidRequest`, `PermissionRejected`, `Disconnected`) | Midnight-side | `errors.ts:16-48` |
| CN-I-7 | `getDustBalance()` returns object `{ cap: bigint; balance: bigint }` per `api.ts:84` (de-facto contract; `SPECIFICATION.md:95-97` is stale — X-5) | Midnight-side, **OWS-side must match `api.ts`** | `api.ts:84`; X-5 in `open-questions.md` |
| CN-I-8 | Three address methods are mandatory; absence is signalled via `PermissionRejected` not method-missing | Midnight-side | `api.ts:88-103` |
| CN-I-9 | Every `getProvingProvider()` returns an object whose `prove()` method computes proofs that pass on-chain verification | Midnight-side **(end-to-end)** | `SPECIFICATION.md:362-373`; `api.ts:179, 348-365` |
| CN-I-10 | `Configuration.networkId` is a plain string (not CAIP-2) | Midnight-side | `api.ts:220`; `SPECIFICATION.md:70-71` |

## WalletEngine invariants (from 2d — license-pending, user override 2026-04-29)

| # | Assertion | Tag | Source |
|---|-----------|-----|--------|
| WE-I-1 | Tx state transitions are driven by exactly one operation: `pending ← spend/watch_for`; `confirmed ← apply_transaction`; `final ← finalize_transaction`; `rejected ← discard_transaction` | OWS-side | `Specification.md:456-465`; `tx-lifecycle.puml` |
| WE-I-2 | For every transaction in `final` state, coins booked during `spend()` do not overlap with coins booked by any other pending/confirmed tx | OWS-side | `Specification.md:496-510` (booking semantics) |
| WE-I-3 | Tx result must be one of: `Success`, `PartialSuccess(intent_ids)`, `Failure`. Result with successful fallible segments but failed segment 0 is invalid | OWS-side | `Specification.md:410-427` |
| WE-I-4 | Coin lifecycle: `pending → confirmed → final → booked → spent`, with rollback edges; `discarded` is terminal | OWS-side | `coin-lifecycle.puml` |
| WE-I-5 | `available_balance = sum of final coins not booked-or-spent`; `pending_balance = pending + confirmed`; `total_balance = available + pending` | OWS-side | `Specification.md:476-487` (balance accounting) |
| WE-I-6 | For every shielded coin commitment Merkle tree state after block N, root must match the root provided by `apply_transaction(tx_N, ...)` | OWS-side | `Specification.md:491-621` |
| WE-I-7 | `m/44'/2400'/<account>'/<role>/<index>` derivation is deterministic; same `(seed, account, role, index)` produces same key | OWS-side; tested by `test-vectors/keyDerivation.json` | `Specification.md:189-214` |
| WE-I-8 | Bech32m address roundtrip: `decode(encode(hex, ctx)) == hex`; same hex on different networks produces different bech32m strings (HRP differs); identical hex payloads | OWS-side; tested by `test-vectors/addresses.json` | `Specification.md:309-377` |
| WE-I-9 | Binding randomness composition is linear: `commitment(s1, r1) ⊕ commitment(s2, r2) == commitment(s1 ∪ s2, r1 ∘ r2)` (sparse homomorphic) | Midnight-side | `Specification.md:153-167` |
| WE-I-10 | Transaction binding randomness equals the sum of all per-component Pedersen randomnesses | Midnight-side | `Specification.md:773, 881-885` |
| WE-I-11 | Fallible sections cannot be balanced after the transaction is bound | OWS-side; runtime check or compile-time type-state | `Specification.md:924-927` |

## X-1-related invariants (from X-1 closure, 2g 2026-04-29)

| # | Assertion | Tag | Source |
|---|-----------|-----|--------|
| MN-I-14 | Unshielded signature scheme is **Schnorr over secp256k1, BIP-340**; no Ed25519 path exists in the ledger | Midnight-side | `midnight-ledger/base-crypto/src/signatures.rs:14-18`; `Specification.md:218`; `night.md` |
| MN-I-15 | Schnorr verifying key serialized as 32 bytes (BIP-340 field encoding); Schnorr signature serialized as 64 bytes | Midnight-side | `signatures.rs:122-126, 264-272` |
| MN-I-16 | Wallet's `SignatureVerifyingKey` / `SignatureSecretKey` types are imports of `@midnight-ntwrk/ledger-v8` ledger types — wallet does not redefine the curve at TypeScript layer | Midnight-side | `midnight-wallet/packages/unshielded-wallet/src/v1/Keys.ts:15`; `KeyStore.ts:14-21` |

## Lace operational invariants (from 2f)

| # | Assertion | Tag | Source |
|---|-----------|-----|--------|
| LC-I-1 | Lace registers `apiVersion: '4.0.1'` — one minor bump above v4.0.0 spec | Reference | `lace/packages/module/dapp-connector-midnight/src/midnight-wallet-api.ts:32` |
| LC-I-2 | Lace persists redux-persist version 9; migrations defined as reducer-shaped pure functions (v3, v5, v7, v8, v9) | Reference | `lace/packages/contract/midnight-context/src/store/init.ts:28-90` |
| LC-I-3 | Lace's tx TTL is hardcoded at 1 hour; spec is silent on TTL default | Reference | `lace/packages/contract/midnight-context/src/const.ts:14` |
| LC-I-4 | Lace does not persist Midnight wallet sync state across sessions; rehydrates from SDK each session | Reference (**OWS diverges per IOHK 8.4.2026 update**) | `lace/packages/contract/midnight-context/src/store/init.ts:26-93` (no sync-state in whitelist) |
| LC-I-5 | Lace dapp-connector is feature-flag-gated with no graceful degradation; module unloads when flag toggled off | Reference | `lace/packages/module/dapp-connector-midnight/src/index.ts:54-55` |

## Updated INT (integration) invariants

(Existing INT-I-1 through INT-I-12 stand; the following added or refined.)

| # | Assertion | Why |
|---|-----------|-----|
| INT-I-13 (NEW) | OWS Midnight `signData` path **always prefixes** input with `midnight_signed_message:<size>:` regardless of caller — no opt-out | Spec mandate `SPECIFICATION.md:359`; closes potential X-7-style bug for OWS |
| INT-I-14 (NEW) | OWS Midnight `make_transfer` path **always validates** the calling agent's authorization — no shortcut | Closes X-6-style bug; consistent with spec's permission model intent |
| INT-I-15 (NEW) | OWS sync state **persists across sessions** (per IOHK 8.4.2026 update); explicit divergence from Lace's "rehydrate each session" pattern | Latency requirement from scope |
| INT-I-16 (NEW) | OWS Midnight `getDustBalance`-equivalent FFI returns `{ cap, balance }` shape (matching `api.ts:84`, not stale spec text) | Closes X-5-driven inconsistency at the OWS boundary |
| INT-I-17 (NEW) | OWS Midnight FFI exposes all three address types via either three methods or one method returning all three; **never silently picks one** as default | Avoids ambiguous-default UX |
| INT-I-18 (NEW) | OWS Midnight FFI changes to user-supplied node/indexer/proof-server URLs warn the user about server-trust implications | Closes X-8-style UX gap from Lace's pattern |

## What's still not asserted

To be added in true-2g and beyond:
- Wider X-1 sweep effects on signature-related invariants throughout the ledger and wallet path.
- Cost-model invariants (L-3 deferred).
- midnight-js (dapp-side SDK) invariants (H-6 partial).
- Cross-chain mnemonic-derivation invariants (one mnemonic → all chains' accounts; verify Midnight slots in cleanly).
- Cardano partner-chain bridge invariants if OWS surfaces them.

## True-2g additions (2026-04-30, plan `2026-04-30-true-2g`)

### Cost-model invariants (from G2 — `cost-model.md`, `storage-io-cost-modeling.md`)

| # | Assertion | Source |
|---|---|---|
| CM-I-1 | 5-D normalized cost is evaluated as the **maximum** over dimensions, not the sum (read_time, compute_time, block_usage especially) | `cost-model.md:348` |
| CM-I-2 | All normalized dimension costs satisfy `[0, 1]` before block ingestion; out-of-range tx is rejected at well-formedness | `cost-model.md:247-251` |
| CM-I-3 | Each dimension's price ≥ 0.25 × max-dimension price (price floor prevents under-pricing of underutilized dimensions) | `cost-model.md:208-209, 261, 291` |
| CM-I-4 | Guaranteed-segment costs must be tight enough for sub-second block validation | `cost-model.md:506-508` |
| CM-I-5 | Charged key set `K` (write/churn) remains child-closed and ref-counts stay accurate across all transactions | `storage-io-cost-modeling.md:95-97, 154-194` |
| CM-I-6 | Synchronous reads cost both `read_time` AND `compute_time` (asymmetric to async batched reads) | `cost-model.md:135-136` |

### Runtime / migration invariants (from G3 — `midnight-wallet/packages/runtime/`)

| # | Assertion | Source |
|---|---|---|
| RT-I-1 | Every `Variant` implements `migrateState(previousState): Effect<TState>` — type-system enforced; no opt-out | `Variant.ts:41` |
| RT-I-2 | `ProtocolState<TState> = { version, state }`; version is tracked OUTSIDE `TState`, in the runtime wrapper | `Runtime.ts:20-21, 260, 279-289` |
| RT-I-3 | Migration triggers iff target version is outside current variant's `validVersionRange` | `Runtime.ts:284-286` |
| RT-I-4 | `validVersionRange` = `[sinceVersion, nextVariant.sinceVersion)` (or `[sinceVersion, MaxSupportedVersion]` if final) | `Runtime.ts:212-215` |
| RT-I-5 | Old variant's `variantScope` closes BEFORE next variant runs (no concurrent variants) | `Runtime.ts:292` |
| RT-I-6 | `migrateToNextVariant` receives `lastState` from the previous variant, not state-at-request-time | `Runtime.ts:295` |
| RT-I-7 | OWS vault must include a top-level `schema_version` field — midnight-wallet leaves persistence to consumers | OWS-derived; see [topic 09](topics/09-state-persistence.md) |

### Wider X-1 sweep — verification only (no new entries)

The X-1 sweep verified that all signature-related invariants and failure-modes across topic files use Schnorr-secp256k1 (BIP-340) framing consistently. No `Ed25519` references remain in Midnight-side topic files (existing OWS-baseline references to `Curve::Ed25519` describe OWS's existing curve enum, not Midnight). Existing entries MN-I-7 and MN-I-14..16 capture the Schnorr discipline; no propagation edits needed.

### Lace-side invariants (LC-I-6, LC-I-7 — confirmed bugs from G5)

| # | Assertion | Tag | Source |
|---|---|---|---|
| LC-I-6 | `signData` must wrap input data with `midnight_signed_message:<size>:<data>` (CIP-8/Midnight structured prefix) before hashing/signing — Lace **does not**, escalated as bug X-7 | Reference (negative — what NOT to replicate) | `midnight-dapp-connector-api.ts:555-579, 715-733`; tests `:1053-1055, 1081-1083, 1109-1111` |
| LC-I-7 | All transaction-initiating methods (`makeTransfer`, `makeIntent`, `balanceSealedTransaction`, `balanceUnsealedTransaction`) must receive and validate sender/origin context, and pass it to user confirmation — Lace `makeTransfer`/`makeIntent` pass empty `{}`, escalated as bug X-6 | Reference (negative — what NOT to replicate) | `midnight-dapp-connector-api.ts:348-402, 365, 512-523, 244-292, 630-648` |

### midnight-js boundary invariants (BD-I-1..3 — from G4 H-6 closure)

| # | Assertion | Tag | Source |
|---|---|---|---|
| BD-I-1 | midnight-js never owns signing keys; signing happens exclusively at `WalletProvider.balanceTx()` in the wallet runtime | Midnight-side | `midnight-js/AGENTS.md:50-56`; `wallet-provider.ts:35-39` |
| BD-I-2 | Tx flow is strictly `UnprovenTransaction → ProofProvider.proveTx() → UnboundTransaction → WalletProvider.balanceTx() → FinalizedTransaction → MidnightProvider.submitTx() → TransactionId` | Midnight-side | `midnight-js/AGENTS.md:50-56` |
| BD-I-3 | Boundary point is the `WalletProvider` interface; midnight-js calls it, midnight-wallet implements it; no code crosses this boundary | Midnight-side | `wallet-provider.ts`; `midnight-js/AGENTS.md` (`MidnightProviders.walletProvider`) |
