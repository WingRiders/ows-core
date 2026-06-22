# Topic 09 — Sync state persistence across calls

> **Status:** first-pass populated by 2c (wallet `runtime/`, `abstractions/`) + scope. 2b ledger spec gave the structural reason. **True-2g (2026-04-30):** runtime/state-schema deep read added; closes W-3 — see "True 2g — runtime / migration discipline" section.

## Why state must persist (per IOHK 8.4.2026 update)

`scope/midnight-scope.md`:
> The Midnight wallet requires significant time to synchronize its state before being able to perform transactions; therefore we also plan to explore the integration of storage and retrieval of the sync state for a smoother experience.
>
> **Update 8.4.2026:** IOHK agreed that the state synchronization needs to be hooked into the API and state needs to be persisted between calls to keep latencies low.

Without persistence, every signing operation re-syncs from a checkpoint (or genesis), taking minutes. With persistence, sync is incremental from the last persisted height.

## What needs persisting (per 2c §G + §B)

1. **Block height (`safe_height`)** — the height at which the wallet's local state is consistent. Reorgs may invalidate tip-height; safe-height is one some-finality-depth back.
2. **Per-variant wallet state**:
   - **Shielded:** owned coin set (commitments + secrets), Merkle tree snapshots needed for input proofs, pending shielded receives.
   - **Unshielded:** UTxO set, pending tx, last seen Schnorr nonces (none, since UTxO model).
   - **Dust:** generation records (tied to specific Night UTxOs), accrual state, last spend timestamps.
3. **Pending transaction set** — submitted but not yet finalized tx, with their TTLs.
4. **Sync progress** (`sourceGap`, `applyGap`) — diagnostic, derivable but cheap to persist.
5. **Optional: transaction history** — `TransactionHistoryStorage<T>` interface in `abstractions/`. Implementations: `InMemory` (single-string serialized), `NoOp`. User can supply persistent impl.

## What does NOT need persisting

- Mnemonic / seed — never persisted (per 2c §G; user supplies on each `start()` call).
- Secret keys — stored in `~/.ows/wallets/<wallet_id>.json` already (encrypted via scrypt + AES-GCM per CLAUDE.md), separate from sync state.
- Indexer connection state (auth tokens, subscription IDs) — re-established on restart.
- Prover-server URL — config, not state.

## Wallet's serialization story (per 2c §G)

- `WalletState` is a branded Effect type. Pure-functional updates via `capabilities/`.
- `SyncProgress` has `serialize()` / `isStrictlyComplete()`.
- Tx history: `TransactionHistoryStorage` interface, implementations expose `serialize()` returning a single string (human-unreadable).
- Variant state migration: `RuntimeVariant.migrateFromPrevious(previousState) -> TState` — handles hard-forks. `runtime/` orchestrates via `StateChange::VersionChange` events.

The serialized state is **not** documented in a human-readable spec; it's whatever the impl produces. For OWS, this means we either:
- Vendor `midnight-wallet`'s state types directly (and their serialization).
- Define our own serialization and translate in/out at the wallet API boundary (extra work).

## Suspend / resume / hot reload (per 2c §G)

- **Suspend** (`facade.stop()`): closes indexer subscriptions; stops sync; in-memory state can be cleared. Seed not cleared (user owns it).
- **Resume** (`facade.start(shieldedSecretKeys, dustSecretKey)`): restarts sync from last block height; re-fetches recent blocks (in case of reorg); re-applies tx.
- **Hot reload** (account switch): `stop()`, derive different account, `init()` with new keys, `start()`.

User is responsible for safe storage of seed (hardware wallet, encrypted keystore). Wallet only handles derived state.

## What this means for OWS

### Vault format extension

Today: `~/.ows/wallets/<wallet_id>.json` holds encrypted mnemonic / private keys (CLAUDE.md "Vault" section). For Midnight, we add a separate state path:

```
~/.ows/wallets/<wallet_id>.json              # existing: encrypted seed/keys
~/.ows/midnight/<wallet_id>/sync-state.bin   # new: sync state per chain, encrypted-at-rest
~/.ows/midnight/<wallet_id>/tx-history.bin   # new: tx history per chain, encrypted-at-rest
```

Why per-chain: future Midnight side-deployments (testnet/preview/devnet) will share a vault but have separate sync states. Keying by chain_id avoids collisions.

Encryption: same scrypt + AES-GCM scheme as the vault. Sync state has the same secrecy class as transaction history (i.e., reveals UTxOs, balances). Worth encrypting at rest.

### API surface

Two shapes:
- **Implicit:** `sign_transaction(...)` reads/writes sync state from `~/.ows/midnight/...` automatically. Caller never sees state. Simplest UX; hardest to reason about.
- **Explicit:** OWS exposes `load_state(wallet_id, chain_id) -> SyncState` and `save_state(wallet_id, chain_id, state)`. Callers must thread state through. More flexibility; matches scope's "hooked into the API" language.

Phase 3 picks. Implicit is closer to existing OWS UX (`derive_address(chain, ...)` is implicit-stateful via the vault); explicit better for AI-agent / multi-process callers.

### Versioning

State format will change as the wallet evolves (variant migrations per `runtime/`). OWS must:
- Tag state files with a schema version.
- Implement `migrate_from_v1_to_v2` paths or re-sync from genesis on schema mismatch.
- Never silently corrupt state on version skew.

### State size

Spec doesn't quote. From wallet behavior: per-account state grows with the user's tx history. A long-term active wallet might accumulate Mb to Gb of state. OWS should:
- Cap or compact state where possible (Merkle tree snapshots can be pruned to recent roots).
- Provide a `compact_state(wallet_id, chain_id)` operation.

## True 2g — runtime / migration discipline (closes W-3)

> Source: deep read of `raw-context/midnight-wallet/packages/runtime/src/{Runtime.ts, WalletBuilder.ts, abstractions/*}.ts` plus `test/{runtime, walletBuilder, walletState, walletBuilderType}.test.ts`. Caveat: the runtime defines the migration **mechanism**; OWS must add the **persistence** discipline that midnight-wallet leaves to consumers.

### Variant migration mechanism

The interface is `migrateState`, not `migrateFromPrevious` (despite first-pass shorthand):

```typescript
interface Variant<TState, TPreviousState> {
  migrateState(previousState: TPreviousState): Effect<TState>;
  // + sinceVersion, validVersionRange, etc.
}
```
(`Variant.ts:33-42`)

Migration triggers in two paths:
- **Initial startup:** `startEmpty` calls `migrateState(null)` on the head variant (`WalletBuilder.ts:104-106`).
- **Version-boundary crossing:** when a variant emits `StateChange.VersionChange` with a version outside its `validVersionRange`, `migrateToNextVariant` runs (`Runtime.ts:153-171`); the next variant's `migrateState` runs over the previous variant's *last* state (`Runtime.ts:163, 295`).

**`migrateState` is mandatory** — every variant must implement it. The type system enforces this (`Variant.ts:41`); there is no opt-out, no default pass-through, no skip.

### `VersionChangeType` enum + `StateChange` flow

```typescript
type VersionChangeType =
  | { Version: { version: ProtocolVersion } }   // explicit target
  | { Next: {} };                                // step to next (used in tests)

type StateChange<TState> =
  | { State: { state: TState } }                            // normal state update
  | { ProgressUpdate: { sourceGap: bigint; applyGap: bigint } }   // sync diagnostics
  | { VersionChange: { change: VersionChangeType } };       // protocol version change
```
(`VersionChangeType.ts:25-31`, `StateChange.ts:24-38`)

Branch on `VersionChange`:
- **In-range** (`validVersionRange` covers it): only the protocol-version annotation updates; **no migration**, state preserved (`Runtime.ts:221-263` test case).
- **Out-of-range**: trigger migration. Old variant's scope closes (`Runtime.ts:292`); new variant runs `migrateState(previousState)` (`Runtime.ts:163`).

### Version-tag scheme — important absence

**The wallet does NOT embed a version tag in serialized state.** State payloads are opaque `TState`. Version tracking lives in the `Runtime` layer via a separate `ProtocolState` wrapper:

```typescript
ProtocolState<TState> = { version: ProtocolVersion; state: TState }
```
(`Runtime.ts:20-21`)

When a variant emits `VersionChange`, the Runtime updates its `protocolVersion` accumulator (`Runtime.ts:260, 279-289`) and attaches it to every subsequent state emission (`Runtime.ts:270-272`). Neither `Runtime.ts` nor `Variant.ts` defines how state is persisted — serialization is left entirely to the consumer.

> **OWS implication:** OWS vault MUST include an explicit `schema_version` field at the top level of its serialized state, separately from the state payload. Adopt during phase 5.

### Integration-test patterns

`runtime.test.ts` covers:
- Variant lifecycle and migration via `VersionChangeType.Version` (`runtime.test.ts:30`).
- Custom starting (`startEmpty`, `startFirst`, mid-chain) (`runtime.test.ts:76, 110, 144`).
- `ProgressUpdate` propagation (`runtime.test.ts:170`).
- **In-range version change without migration** (`runtime.test.ts:221-263`) — explicitly tested that intra-variant version annotation updates do NOT migrate.
- Edge case: `VersionChangeType.Next` ignored if no successor (`runtime.test.ts:265`).

`walletBuilder.test.ts` covers:
- Single-variant wallets (`:63`).
- **Two-variant migration** (`:90-122`) — `migrateState` applied at the boundary.
- **Three-variant sequential migration** (`:124-181`) — explicitly traces state shape through all migrations (lines 165-167 comment block).
- Strict-ascending `sinceVersion` enforcement (`:44-60`).

**Critical absence:** there is **no serialize/deserialize round-trip test with a version change in the middle.** Tests exercise migration on in-memory state but never persist+reload across a version change. OWS must add this — see RT-I-7 in `invariants.md`.

### Discipline OWS should adopt

1. **Explicit `schema_version` field at the top level of serialized vault state.** Numeric, monotonic, recognized at deserialization. Reject unknown values rather than silently accepting.
2. **Total order of schema versions.** Mirror `WalletBuilder`'s strict-ascending check (`WalletBuilder.ts:55-57`); refuse to register a schema with `sinceVersion ≤ previous`.
3. **Mandatory `migrate_from_previous` per schema.** Match `Variant.migrateState`'s signature. Compile-time enforcement (Rust trait method without default).
4. **Round-trip tests on every consecutive schema-version pair.** Serialize → reload → migrate → check shape and content. Midnight has no such test; OWS must.
5. **Runtime version-mismatch detection.** Vault loader compares persisted `schema_version` against compiled-in supported range; trigger migration if older, error if newer (analogous to `Runtime.ts:284-286`).
6. **Structured migration errors.** Model on `WalletRuntimeError` (`WalletRuntimeError.ts:15`) — distinguish "missing migration" / "migration failed" / "version unknown" / "version newer than code".
7. **Type-level distinct schemas.** Branded types or sealed structs per schema version; prevent accidental cross-version state use (make illegal states unrepresentable).

### Status of W-3

**closed by-finding** — runtime mechanism is well-specified (mandatory `migrateState`, range-driven boundary detection), but **persistence discipline is delegated to the consumer**. OWS fills the gap with the seven-item discipline above.

## Open questions

- **Q-state-1:** implicit vs explicit API surface. Phase 3 decision.
- **Q-state-2:** does OWS vendor `midnight-wallet`'s state types + serialization, or roll its own translator? Tied to vendoring strategy in [04-proving](04-proving.md).
- **Q-state-3:** state size in practice — need to quantify by running a Lace wallet for a while and measuring `~/.local/share/lace/midnight/...` (if accessible) or `~/.cache/midnight-proving/` etc.
- **Q-state-4:** state reset / recovery — what's the UX when state is corrupted? Re-sync from genesis with a config flag?
- **Q-state-5:** Cardano partner-chain state — is the wallet expected to track Cardano-side state (NIGHT bridge UTxOs) too, or only Midnight-side? See [03-tx-model](03-tx-model.md) Q-tx-3.
