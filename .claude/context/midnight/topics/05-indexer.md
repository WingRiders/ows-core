# Topic 05 — Indexer and sync

> **Status:** first-pass populated by 2c (wallet packages). 2b ledger spec gave background on what state needs syncing. 2e (connector API) and 2f (Lace) may add detail.

## Indexer's role (per 2c §F)

The indexer is the wallet's **mandatory source of sync state.** Without it, the wallet cannot know:
- Which Zswap commitments are owned (it must scan).
- What the Merkle tree state looks like for input proofs.
- Which dust generation events apply to its Night UTxOs.

There are two transports:
- **GraphQL HTTP queries** — for blockhash lookups, terms-and-conditions, ledger parameters.
- **GraphQL WebSocket subscriptions** — for real-time event streams (new blocks, tx, events).

Wallet client: `midnight-wallet/packages/indexer-client`. Underlying `midnight-indexer` repo (Rust microservices or single-binary SQLite per `raw-context/index.md`).

## Query / subscription surface (per 2c §F)

Queries:
- `Connect` — establish session.
- `Disconnect` — tear down.
- `BlockHash` — block info (height, hash, timestamp).
- `FetchTermsAndConditions` — service ToS.
- (cost-model parameters and other ledger parameters per `midnight-indexer/indexer-api/`)

Subscriptions:
- `ShieldedTransactions` — Zswap-related events (new commitments, nullifiers).
- `UnshieldedTransactions` — Night UTXO events.
- `ZswapEvents` — custom shielded token events.
- `DustLedgerEvents` — dust generation/spend events.

## Sync flow

Per 2c §F:
1. Wallet calls `indexerClient.subscribe(fromHeight, filters)` (one stream per event kind).
2. Indexer streams events as the chain advances.
3. Wallet capability layer (`capabilities/`) processes each event into pure state updates.
4. Wallet emits `state()` Observable updates.

**Stochastic prefix queries** (per 2b — `dust.md § Wallet recovery`):
> "To find owned Night UTXOs, search for commitments with matching owner. For Dust, follow chains from Night UTXO nonces."
>
> "Use stochastic prefix queries instead of 'does commitment X exist?' — query commitments starting with N-bit prefix, filter locally. Anonymity set size ∝ 2^(14 − 7) ≈ 128 if 2^14 total commitments."

The privacy-preserving discovery pattern (prefix queries) is enforced by the *wallet* (not the indexer). This means a naïve indexer client that asks "does commitment X exist?" leaks ownership.

## Sync state shape (per 2c §G)

Wallet maintains in-memory:

```typescript
type WalletState = {
    coins: Array<{ coin: Coin; meta: { ctime: Date; ... } }>;
    balances: { available: bigint; pending: bigint; total: bigint };
    syncProgress: SyncProgress;
}

type SyncProgress = {
    sourceGap: bigint;   // indexer-tip minus wallet-applied
    applyGap: bigint;    // queued-but-not-applied within the wallet
    isStrictlyComplete(): boolean;  // both === 0n
}
```

Plus per-variant state (shielded coin sets, Merkle tree snapshots for input proofs, dust accrual records, pending tx).

State lives in a `SubscriptionRef` (RxJS-flavored mutable atomic ref); updates are pure functional via capabilities layer.

## State persistence (transition into [`09-state-persistence.md`](09-state-persistence.md))

In-memory by default. Optional persistence via `TransactionHistoryStorage<T>` interface:
- `InMemoryTransactionHistoryStorage` — serializes to a single string.
- `NoOpTransactionHistoryStorage` — discards.
- User can supply custom impl.

Per IOHK 8.4.2026 update (scope): "the state synchronization needs to be hooked into the API and state needs to be persisted between calls to keep latencies low." This is a hard requirement for OWS — without persistence between calls, every signing operation re-syncs from genesis or last-checkpoint, taking minutes.

## Public hosted indexer status

**Open question (HANDOVER §7 question 2).** The OWS scope says:

> As the indexer service we plan to use the public midnight indexer.

`midnight-indexer/README.md` only documents self-hosted deployment (microservices + PostgreSQL or single-binary + SQLite). **No public hosted instance documented.**

Plausible reads:
1. IOHK runs an internal hosted indexer that's not documented.
2. The scope statement is aspirational and OWS users will need to self-host.
3. The Lace blog or production reference-wallets mention a public indexer URL we missed.

Plan 2g should reconcile. Until then, OWS architecture should be **agnostic** to indexer location — accept a configurable URL.

## Cardano partner-chain in indexer

Per 2c §F: not in the wallet. The wallet treats Midnight as standalone. Cardano-side state (NIGHT bridging events) presumably surfaces through `UnshieldedTransactions` once they land on Midnight, but that's after the bridge oracles run — not the wallet's concern.

## What this means for OWS

- **OWS needs an indexer-client surface.** Either:
  - Bundled (OWS ships a Rust GraphQL client + WS subscription client for `midnight-indexer/indexer-api`).
  - Pluggable (caller provides a `WalletState` payload pre-fetched).
  - Side-process (OWS spawns a local indexer process).
- **State must persist.** OWS today has `~/.ows/wallets/<wallet_id>.json` for encrypted vault. Sync state needs a separate path (probably `~/.ows/midnight/sync/<wallet_id>/`).
- **`PolicyContext` extension.** Per `../ows-baseline/policy-context.md`: to evaluate Midnight policies, the engine needs *deserialized tx + wallet sync state*. Either we extend `PolicyContext` with `wallet_state: Option<MidnightWalletState>`, or executable policies fetch it themselves.
- **Privacy hygiene.** OWS must not query for specific commitments — must use the prefix-query pattern. Code review hazard.
- **Reorgs.** Wallet replays from a safe block height on reorg. OWS must persist the "safe height" rather than the tip height to avoid corrupting state on a deep reorg.

## Open questions

- **Q-indexer-1:** does a public hosted indexer exist? HANDOVER §7 question 2.
- **Q-indexer-2:** does OWS bundle a GraphQL/WS client, or pull the existing Rust crates from `midnight-indexer/`? The repo is Apache-2.0; no license issue.
- **Q-indexer-3:** sync-state storage location and format. New OWS surface required (per scope's "State sync persistence" extension point).
- **Q-indexer-4:** how does the wallet authenticate to the indexer? GraphQL connection management likely uses tokens; OWS must surface this.
