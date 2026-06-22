# Topic 03 — Transaction model

> **Status:** first-pass populated by 2b + 2c. **Second-pass augmented** by 2d (WalletEngine spec, license-pending — user override 2026-04-29), 2e (connector v4.0.0), 2f (Lace) — see "Second-pass refinements" section. **True-2g (2026-04-30):** cost-model deep read added; closes L-3, L-8 — see "True 2g — cost model details" section.

## Transaction structure (per 2b — `midnight-ledger/spec/intents-transactions.md`)

```
Transaction = {
    intents: Map<u16, Intent>,                    // segment_id → intent
    guaranteed_offer: Option<ZswapOffer>,         // shielded inputs/outputs that always run
    fallible_offer: Map<u16, ZswapOffer>,         // segment_id → shielded offer (per-segment fallible)
    binding_randomness: Fr,                       // sum of per-component Pedersen randomness
}

Intent = {
    guaranteed_unshielded_offer,                  // unshielded inputs/outputs (always)
    fallible_unshielded_offer,                    // unshielded inputs/outputs (segmented)
    actions: Vec<ContractAction>,                 // contract calls
    dust_actions,                                 // dust spends/registrations
    ttl,                                          // time-to-live
    binding_commitment,                           // commitment to randomness
}
```

### Segments

- **Segment 0 = guaranteed.** Always executes. If it fails, the entire transaction fails.
- **Segments 1..65535 = fallible.** Execute in segment-id order. Each may fail independently with rollback only of that segment.

This is a major divergence from generic chains — most chains are tx-atomic (Cardano UTxO) or call-atomic (Ethereum reverts). Midnight's segment model means a single tx can carry mixed effects with partial-success semantics.

### Tx state types (per 2b §A — crate analysis)

`Transaction<S, P, B>` is parameterized by three type axes:

| Axis | Variants | Meaning |
|---|---|---|
| `S` (Signaturish) | `Signature`, `PreSignature` | unshielded signatures present? |
| `P` (Provingish) | `Proof`, `PreProof` | ZK proofs present? |
| `B` (Bindingish) | `FiatShamirPedersen`, `PedersenRandomness` | binding finalized via Fiat-Shamir? |

Lifecycle (per 2c §B — wallet recipes):

```
Construction              → Transaction<PreSignature, PreProof, PedersenRandomness>
   ↓ balancing (capabilities/balancer)
Balanced                  → Transaction<PreSignature, PreProof, PedersenRandomness>
   ↓ proving (prover-client → external proof-server)
Proven                    → Transaction<PreSignature, Proof, PedersenRandomness>
   ↓ binding (Fiat-Shamir)
Bound                     → Transaction<PreSignature, Proof, FiatShamirPedersen>
   ↓ signing (per-input Schnorr-secp256k1)
Signed                    → Transaction<Signature, Proof, FiatShamirPedersen>
   ↓ submission to node
```

Wallet's `BalancingRecipe` (`facade/src/index.ts`) tags each state:
- `FINALIZED_TRANSACTION` — fully signed/proven/bound
- `UNBOUND_TRANSACTION` — needs binding + signing
- `UNPROVEN_TRANSACTION` — needs proving + binding + signing

## Balancing (per 2b — `intents-transactions.md` + 2c — `capabilities/balancer`)

Per-segment, per-token-type balance:
- **Shielded:** Pedersen commitment opening proves balance. Zswap `deltas` (signed imbalances per token) sum to zero across `(token_type, segment_id)`.
- **Unshielded:** sum of inputs - sum of outputs = 0 per `(token_type, segment_id)` (or non-negative, with positive remainder going to treasury per 2b §C invariant 13).
- **Dust:** spend value computed by `updated_value(old_output, gen_info, tnow)` on the prover side, with the proof asserting `v_fee ≤ updated_value`.

Wallet implementation (per 2c §B):
- `capabilities::chooseCoin` — pure functional coin selection.
- `capabilities::getBalanceRecipe` — produces `BalancingRecipe { baseTransaction, balancingTransaction }` where `balancingTransaction` includes the change/fee outputs.
- Three balancing passes interleave (shielded, unshielded, dust); each can produce its own counter-offer that gets merged via `tx.merge(other)`.

## Fee model (per 2b — `dust.md` + `cost-model.md`)

Fees are paid in **Dust**, not in Night and not in shielded tokens. Dust is non-transferable, non-tradable; it's a fee-payment resource.

### Dust generation

Dust is generated from Night UTxOs at a per-Star rate up to a cap:

> "5 DUST/NIGHT max, ~1 week generation time, 3-hour grace period for spends."

`updated_value(old_output, gen_info, tnow)` is the in-circuit function that computes current dust value. After backing Night is spent, dust decays (3-hour grace period to spend before zero).

### 5-dimensional cost model (per 2b §B-03)

Costs charge across:
- `read_time` — circuit/storage read latency
- `compute_time` — circuit compute steps
- `block_usage` — fraction of block consumed
- `bytes_written` — storage writes
- `bytes_churned` — storage rewrites

Spec defers exact rates to `cost-model.md` and `storage-io-cost-modeling.md` (not deeply read in 2b first pass — held for 2g).

## Replay protection (per 2b — `intents-transactions.md`)

- **Intent hash + time-filtered map.** Each intent has a unique hash; nodes maintain a TimeFilterMap with ~1-week TTL. Transactions whose intent hash is in the map are rejected as replays.
- **No per-account nonce counter.** This is a major divergence from account-model chains (Ethereum's `tx.nonce`). Midnight is UTxO-based for replay, not nonce-based.
- **Per-intent TTL** — each intent has its own `ttl` field; valid range `[tblock, tblock + global_ttl)`. Transactions composed of multiple intents may have different TTLs per intent.

## Cross-domain composition

A single transaction can carry:
- One or more unshielded UTXO spends (Night, custom unshielded tokens)
- One or more shielded inputs/outputs (Zswap)
- Zero or more dust spends/registrations
- Zero or more contract calls (each with a ZK execution proof)

All bound by a single `binding_randomness: Fr` that sums per-component Pedersen randomness — proven via Fiat-Shamir at the transaction level.

### ZswapTransient

Per 2b §H surprise 6: a shielded output can be **spent within the same transaction** via `ZswapTransient`. Mechanism: prove `output_valid` as usual, then prove `input_valid` against an ephemeral size-1 Merkle tree containing only the new output. Allows in-tx atomic shield-spend-shield flows. The Merkle tree of committed outputs is only updated at block end.

## Effects matching (per 2b — `contracts.md`)

Contract calls carry **pre-declared `Effects`** — claimed nullifiers, claimed shielded receives/spends, claimed contract calls, mints, etc. The ZK proof asserts that program execution matches the declared effects. Validators compare claimed vs declared effects in parallel without re-running the program.

This is unusual: most chains derive effects *from* execution. Midnight requires effects to be declared *first* and proved consistent.

## Cardano partner-chain (per 2b — `cardano-system-transactions.md`)

NIGHT bridges between Cardano and Midnight via system transactions. Per 2b §G open question:
- Cardano oracle consensus (who validates cNight balance against Cardano?) is unspecified in the spec.
- Conflict resolution if Cardano and Midnight ledgers diverge is unspecified.

For OWS scope: probably out of scope for v1 (the wallet doesn't need to construct cross-chain transactions; the system transactions are produced by validators). HANDOVER §7 question 8 tracks this.

## Wallet-side recipe API (per 2c — `facade/`)

User-facing flow:
1. **Build recipe:** `facade.transferTransaction(outputs, secrets, options) -> UnprovenTransactionRecipe`.
2. **Balance:** `facade.balanceUnprovenTransaction(tx, secrets, options) -> UnprovenTransactionRecipe` (with balancing tx attached).
3. **Sign:** `facade.signRecipe(recipe, signSegment) -> BalancingRecipe`.
4. **Finalize (prove + bind):** `facade.finalizeRecipe(recipe) -> FinalizedTransaction`.
5. **Submit:** `facade.submitTransaction(tx) -> TransactionIdentifier`.

Each call is a Promise. The internal Effect/RxJS plumbing is hidden behind the public API.

Other top-level methods (per 2c §B-06):
- `initSwap(inputs, outputs, secrets, options)` — for Zswap-style swaps.
- `registerNightUtxosForDustGeneration(utxos, vk, signFn, dustAddr)` — registers Night UTxOs for dust generation.

## What this means for OWS

- **`TransactionContext.raw_hex` is insufficient.** Midnight transactions are heterogeneous structures. Either we widen `raw_hex` semantics (treat it as opaque canonical bytes; let executable policies parse) or we extend `TransactionContext` with Midnight-specific fields.
- **No nonce-based replay protection.** OWS's `PolicyRule::ExpiresAt` is the existing TTL escape; it could map cleanly to Midnight's per-intent TTL via the executable-policy path.
- **Multi-step lifecycle.** OWS today has `sign_message` / `sign_transaction` — single-shot. Midnight's recipe lifecycle (build → balance → sign → finalize) doesn't fit. Likely OWS needs to expose the wallet API as a stateful object or as multiple composable functions.
- **Segment-aware signing.** `signSegment` is part of the wallet API per 2c. OWS must surface segment IDs.
- **Effects as first-class.** Policy engine could leverage pre-declared effects to evaluate transaction safety without running the program. Maps cleanly to executable-policy stdin.

## Second-pass refinements (2d / 2e / 2f)

**2d (WalletEngine `Specification.md`) — recipe lifecycle, refined:** the spec describes **3 major phases** (each containing multiple operations), not 5 sequential steps. The 5-step framing in the first pass is an aggregate view; the spec's view:

1. **Building** (steps 1-5): create shielded/unshielded inputs/outputs, transients (output-immediately-spent), intents, and the transaction skeleton.
2. **Balancing** (steps 6-8): per-segment, per-token-type coin selection until imbalances clear; cover dust fees iteratively; merge balancing tx with base tx.
3. **Finalization** (steps 9-11): submit to external prover → bind via Fiat-Shamir Pedersen on binding randomness → sign unshielded inputs (Schnorr-secp256k1 per input) over erased intent → ready for submission.

**Coin lifecycle (per `coin-lifecycle.puml`):** `[*] → pending → confirmed → final → booked → spent`, plus `rollback` edges and a `discarded` sink. Balance accounting uses `available_balance = sum of final coins not booked-or-spent` and `pending_balance = pending + confirmed`. Booked/spent excluded from both. **OWS must model these states or accept that pending balances are stale.**

**Tx lifecycle (per `tx-lifecycle.puml`):** `pending → confirmed → final → rejected` with substates Success / PartialSuccess / Failure under confirmed/final. Driven by `apply_transaction`, `finalize_transaction`, `rollback_last_transaction`, `discard_transaction`. **No nonce-based replay protection** (UTxO-based, intent-hash + TimeFilterMap).

**Six atomic state operations** (`Specification.md:456-465`): `apply_transaction(tx, status, ts, roots, dust_update)`, `apply_system_transaction(tx)`, `finalize_transaction(tx)`, `rollback_last_transaction()`, `discard_transaction(tx)`, `spend(coins, outputs)`. These bracket the wallet's state machine.

**Fallible-section binding constraint (`Specification.md:924-927`):** "Balancing fallible sections will only be possible when the provided transaction is not yet bound." Rationale unclear (sig dependency or cost-model instability). OWS must respect this functional constraint when surfacing the recipe lifecycle.

**Pre-declared `Effects`** confirmed as policy primitive: contracts declare effects (claimed nullifiers, claimed receives, mints) before execution; ZK proof asserts execution matches declaration; validators compare in parallel without re-running circuits. Implication for OWS [topic 07](07-policy.md).

**2e (connector v4.0.0) — connector hides the recipe.** Transactions are **opaque hex strings** in both directions; `Transaction<S,P,B>` type-state never crosses the dapp boundary. Five tx methods (`makeTransfer`, `makeIntent`, `balanceUnsealedTransaction`, `balanceSealedTransaction`, `submitTransaction`) cover the lifecycle. `options.payFees?: boolean` defaults to `true`. Sealed vs unsealed split: sealed = signatures + binding present; unsealed = preimage data for binding still present. Implication: **OWS↔AI-agent boundary inherits opacity if it mirrors the connector.** Policy engine wanting to inspect declared effects must deserialize `raw_hex` itself.

**2f (Lace) — TTL hardcoded at 1 hour** (`lace/packages/contract/midnight-context/src/const.ts:14`). Spec is silent on TTL default; this is Lace UX. Lace also adds:

- **`MidnightTxParameters`** — Lace-internal serialized JSON shape that survives between UI and signing layers (`signing/midnight-in-memory-transaction-signer.ts:17, 75-77`). Not part of connector spec; Lace's UX/IPC concern.
- **Dust designation as a separate tx flow** (`'dust-designation'` type, `signing/midnight-in-memory-transaction-signer.ts:79-88`) — registers Night UTxOs for dust generation. Not in connector spec; Lace's UX extension for a Midnight-specific operation.
- **Sender context overload** on tx methods (`midnight-dapp-connector-api.ts:244-248`) — Lace appends a third `senderContext?` parameter for origin authorization, hidden from spec. Internal middleware concern.

## True 2g — cost model details (closes L-3, partial L-6 / L-8)

> Source: deep read of `raw-context/midnight-ledger/spec/cost-model.md` and `storage-io-cost-modeling.md`, cross-referenced with `intents-transactions.md` and `dust.md`.

### The 5-D rate components

The cost model tracks five resource dimensions in the `SyntheticCost` struct (`cost-model.md:56-76`):

| Dimension | Unit | Notes / examples |
|---|---|---|
| `read_time` | Duration (picoseconds) | I/O read latency. Batched 4K reads ~2 µs; synchronous 4K reads ~85 µs (`cost-model.md:460-461`). |
| `compute_time` | Duration (picoseconds) | Single-threaded at tx level, multi-threaded at block level. Baseline 100 µs (`cost-model.md:479`). Proof verification: constant 3,382 µs + linear 3,352 ns/input (`cost-model.md:463-464`). |
| `block_usage` | bytes | Serialized tx size. Block cap 200,000 bytes (`cost-model.md:154-160`). |
| `bytes_written` | bytes | Persistent storage appends. Limit 20,000 bytes/block (`cost-model.md:158`). |
| `bytes_churned` | bytes | Temporary writes pending GC. `churn = positive_delta − persistent_bytes_written` (`cost-model.md:98`). Limit 1,000,000 bytes/block (`cost-model.md:159`). |

Write/churn are computed globally post-tx via reference-counted Merkle DAG closure (`storage-io-cost-modeling.md:7-9, 23-27`), not incrementally. **Synchronous reads cost both `read_time` AND `compute_time`** (`cost-model.md:135-136`) — "we will count as both compute and read time, because they stall compute." Asymmetric pricing favors batched/async patterns.

### Sourcing — genesis defaults + dynamic per-block adjustment

- **Genesis defaults:** block limits, initial price factors, baseline cost, performance benchmarks, parallelism factor 4 — hardcoded at genesis (`cost-model.md:154-160, 255-262, 477-482, 450-471, 476`).
- **Dynamic per-block adjustment:** `FeePrices` updated each block via `update()` based on normalized dimension fullness, targeting 50% block utilization (`cost-model.md:164-170, 277-301`).
- **Wallet-supplied estimation:** transaction authors pre-compute costs from a snapshot of the cost model at submission time.
- **Stored on-chain as parameters:** block limits and prices are part of `LedgerParameters` (`cost-model.md:524-528`), adjustable at runtime per `cost-model.md:148-150`.

### Authority — distributed and multi-layered

| Role | Authoritative for | Citation |
|---|---|---|
| Ledger spec | cost-model structure + semantics | `cost-model.md` (whole); `intents-transactions.md:386-387` defers fee computation to spec |
| Wallet | fee estimation at tx-construction time | `intents-transactions.md:385-391, 459-461` |
| Node / validator | cost-model application + dynamic price update + block-fullness book-keeping | `cost-model.md:186-203` ("the node will need to do its own book-keeping") |
| Chain consensus | rejection of over-limit txs | `cost-model.md:239-252` (`normalize()` returns `None` if any dimension > 1) |

**Drift between wallet estimation and chain pricing is structural** — the wallet sees a snapshot; the chain may have repriced before the tx lands. This is the cost-model-authority open question (W-6) made concrete: no entity is solely authoritative; the node enforces but the wallet must keep up.

### Failure modes (added to `failure-modes.md` as CM-1..6)

The spec explicitly addresses three failure scenarios:

1. **Pre-validation rejection (drift):** if any normalized dimension exceeds 1.0, well-formedness fails and `normalize()` returns `None`. **No Dust burn** — well-formedness is not execution (`intents-transactions.md:185-216`). Wallet retries with refreshed cost model.
2. **Mid-execution fallible failure:** guaranteed-segment costs commit before fallible segments execute; fallible failures localize per `intents-transactions.md:720-741, 822-856`. **The spec is silent on whether validators precharge fallible execution from Dust** — open question worth tracking.
3. **Hard-fork repricing:** cost-model parameters are NOT consensus-locked across forks. `dust.md:13-17` explicitly: "Dust is not persistent, the system may redistribute it on hardforks." A fork may invalidate past cost assumptions.

### Zero-value transient semantics (closes L-8)

- **Zero-value Dust UTXOs are created and charged normally:** when `v_pre − v_fee == 0`, a new UTXO is still created (`dust.md:54, 519, 527`).
- **Cost model does not distinguish zero-value:** `bytes_written = sum of node sizes added` regardless of value (`storage-io-cost-modeling.md:119-131`). Zero-value outputs occupy storage.
- **Garbage collection is best-effort:** `gc_rcmap` is resource-bounded and may quit early (`storage-io-cost-modeling.md:199-239, 257-259`). A zero-value transient may persist indefinitely if GC doesn't run — "okay, as it is costed as persistent storage."

**OWS implication:** zero-value transients are valid, not malformed-tx. OWS validators (if implementing) treat them normally; surfacing a "stays at 0" warning may help users.

### Implications for OWS

- **OWS Midnight signing path must accept dynamic fee parameters.** Either query the chain at sign time (cost-model snapshot ages out fast) or accept a wallet-supplied snapshot via the policy/context. Hardcoded fees will drift.
- **Cost-model authority resolution:** if OWS wraps a cost model from indexer / node / fallback, surface which one and let policy reject mismatches.
- **Pre-compute requires one of:** (a) live chain access, (b) wallet-supplied cost-model snapshot, (c) tolerance margin built into the wallet's recipe step.

## Open questions

- **Q-tx-1:** Does OWS need to surface `Transaction<S,P,B>`'s state-type axis to the FFI, or hide it behind one opaque `MidnightTransaction` blob? **Status: leans toward opaque (matches connector v4 pattern).** Phase 3 confirms.
- **Q-tx-2:** ZswapTransient — does the wallet API allow constructing in-tx spend-and-respend, or is that contract-only? **Status: 2d confirms transient is in the building-phase ops; producible by the wallet itself.** [L-8](../open-questions.md) tracks zero-value transient semantics.
- **Q-tx-3:** Cardano partner-chain — does OWS surface NIGHT bridge txs, or treat the bridge as transparent at signing layer? See [open-questions.md](../open-questions.md) H-8.
- **Q-tx-4:** Cost model — does OWS need to query the indexer for current cost-model parameters, or hardcode? Per 2b §G open question, cost model is dynamic.
- **Q-tx-5 (NEW from 2d):** Fallible-section binding constraint — at what API surface does OWS enforce that fallible sections aren't balanced after binding? Static type-state in Rust traits (compile-time) vs runtime check (clearer error).
