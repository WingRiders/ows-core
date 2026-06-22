# Failure-mode inventory

> Artifact (b) per `task.md` step 2. What can go wrong, where, and what catches it.
>
> Status: first-pass populated by 2a (OWS), 2b (ledger spec), 2c (wallet packages). **Second-pass appended** — 2d (WalletEngine, license-pending — user override 2026-04-29), 2e (connector v4.0.0), 2f (Lace). Each entry tagged with the source sub-phase that surfaced it. **Append-only across passes.**

## OWS-side (from 2a)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| OWS-1 | Non-32-byte private key passed to `EvmSigner::sign` | Caller corrupted key bytes | `evm.rs:232-237` returns `SignerError::InvalidMessage` if `message.len() != 32`; key parsing returns `InvalidPrivateKey` |
| OWS-2 | Ed25519 path with non-hardened component | Caller passed `m/44'/501'/0'/0` (no `'` on last index) | `hd.rs:148` returns `HdError::Ed25519NonHardened` |
| OWS-3 | Seed length outside [16, 64] bytes | Caller fed wrong-length input | `hd.rs:31-33` returns `HdError::InvalidSeedLength(n)` |
| OWS-4 | Unknown chain identifier | User typo | `chain.rs:251-259` returns `Err` with help text |
| OWS-5 | `encode_signed_transaction` called on a chain that didn't override the default | User-friendly error path | `traits.rs:73-77` default impl returns `SignerError::InvalidTransaction("encode_signed_transaction not implemented for {chain_type}")` |
| OWS-6 | Cache-key collision in `derive_from_mnemonic_cached` | Hash collision (negligible) or future cache-key change | `hd.rs:62-76`. Unlikely in practice; would manifest as wrong key returned. No automated check. |
| OWS-7 | Vault file corrupted / decryption fails | Disk corruption or wrong password | `ows-lib/src/vault.rs` (per CLAUDE.md scrypt + AES-GCM) returns decrypt error |

## Midnight ledger-level (from 2b)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| MN-1 | Double-spend via replay | Attacker resubmits old intent | Replay protection: intent hash in TimeFilterMap with ~1-week TTL (`intents-transactions.md`) |
| MN-2 | Zswap nullifier collision | Attacker proves two inputs with same nullifier | `assert!(!state.nullifiers.contains(nullifier))` in `apply_input` (`zswap.md`) |
| MN-3 | Forged Zswap output commitment | Attacker creates output with wrong coin info or value | Output proof verification: `zk_verify(output_valid, ...)` validates commitment derivation (`zswap.md`) |
| MN-4 | Stale Merkle tree root in input proof | Reorg or chain advance after wallet built tx | Root history validation: `input.merkle_tree_root ∈ state.commitment_tree_history.get(tblock)` (`zswap.md`) |
| MN-5 | Unshielded UTXO without signature | Attacker spends user's UTxOs without private key | Schnorr signature verification: `signature_verify((segment_id, intent), owner_key, sig)` per input (`night.md`) |
| MN-6 | Dust spend exceeds backing amount | Attacker claims more fees than dust balance | Constraint in proof that `updated_value ≥ v_fee` (`dust.md`) |
| MN-7 | Contract call without matching effect | Program produces state change but claims false effects | Effects matching check: claimed nullifiers/commitments/mints must match actual program effects (`intents-transactions.md`) |
| MN-8 | Segment sequencing violation | Attacker places fallible call before guaranteed call that depends on it | Causal precedence check: `fallible_transcript.is_none() ∨ guaranteed_transcript.is_none()` (`intents-transactions.md`) |
| MN-9 | Binding commitment malleability | Attacker modifies tx after Fiat-Shamir binding sealed | Binding check: Fiat-Shamir commitment covers intent hash; recompute mismatch (`preliminaries.md`) |
| MN-10 | TTL expiry | Tx accepted past its TTL window | Validation: `ttl ≥ tblock ∧ ttl ≤ tblock + global_ttl` (`intents-transactions.md`) |
| MN-11 | Dust grace-period violation | Dust spend references stale Merkle root outside grace period | Dust root history lookup: root must exist in history at `tnow - dust_grace_period` (`dust.md`) |
| MN-12 | Contract state overflow | Malicious contract mints unbounded tokens | Token minting balance check: unshielded mints added to contract balance; must not exceed state value limit (`contracts.md`) |
| MN-13 | Imbalance in segment-token pair | Inputs ≠ outputs + fee for some `(segment_id, token_type)` | `balancing_check`: `balance[(token_type, segment_id)] ≥ 0` (`intents-transactions.md`) |
| MN-14 | Tx well-formedness failure | Wrong segment ordering, missing binding, etc. | `Transaction::well_formed()` (`ledger/src/transaction.rs`) — comprehensive structural check |

## Midnight wallet-level (from 2c)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| WL-1 | Insufficient funds for transfer | Wallet coins < requested output + fees | `InsufficientFundsError` from `getBalanceRecipe()` in `capabilities/balancer/`; facade propagates |
| WL-2 | Prover server unavailable | Server down, network unreachable, or misconfigured URL | `ClientError`/`ServerError` from `HttpProverClient.proveTransaction()`; facade calls `revertTransaction()` to undo booking |
| WL-3 | Indexer sync lag / chain reorganization | Indexer has latency gap, or reorg invalidates blocks | `VersionChange` / `ProgressUpdate` events; wallet replays state from safe block height |
| WL-4 | Invalid seed / wrong length | User-supplied seed not 32 bytes or corrupted | `{ type: 'seedError'; error }` from `HDWallet.fromSeed()` |
| WL-5 | Address parsing failure (Bech32m invalid) | Bad checksum, wrong HRP, non-ASCII chars | `MidnightBech32m.parse()` throws `Error` |
| WL-6 | Pending tx TTL exceeded | User delays submission beyond TTL (default ~1 hour) | Prover or node rejection; facade auto-reverts via pending service |
| WL-7 | Hard-fork variant migration failure | New variant can't migrate from old state | `runtime/`'s `migrateFromPrevious(oldState)` returns error; wallet falls back to fresh-sync from safe height |
| WL-8 | State serialization round-trip failure | Schema drift between save and load | Variant state migration; OWS will need explicit version tag |

## OWS↔Midnight integration failure modes (synthesized)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| INT-1 | Curve enum doesn't recognize JubJub/BLS12-381 | OWS port hasn't extended `Curve` yet | Compile error (good) — unmatched arm in `match curve {}` in `hd.rs:36-39` |
| INT-2 | Multi-key derivation API not exposed at FFI | Caller can't get all 3 addresses for a Midnight account | TS/Python type-system: missing function. **Risk:** caller falls back to per-domain calls and forgets one. |
| INT-3 | Sync state corrupted across version skew | OWS upgraded; sync state file format changed | Versioned schema with explicit migration; on mismatch, fall back to fresh-sync. **Risk:** silent corruption if version tag missing. |
| INT-4 | Indexer URL not configured | Caller didn't set indexer URL before sign | Explicit error from sync layer; **risk:** confusing if wrapped inside opaque "sync failed" |
| INT-5 | Prover unreachable on shielded sign | Network issue or hosted-prover down | Sync error from `HttpProverClient`; **risk:** OWS must distinguish from indexer errors so caller can retry or switch route |
| INT-6 | Privacy leak via naïve indexer query | OWS implements "does commitment X exist?" instead of stochastic prefix query | Code review hazard. **No automated catch.** Must be enforced by review + integration tests against a real indexer. |
| INT-7 | CAIP-2 namespace skew | OWS ships with `midnight:mainnet`; upstream picks different form | OWS-internal namespace string change; one-line update if isolated; **risk:** wallets created before vs after will have different `chain_id` strings |
| INT-8 | Policy engine misses Midnight-specific check because `TransactionContext` doesn't expose deserialized intents | Built-in rules can only see `raw_hex`; can't enforce "no minting" without parsing | Either widen `TransactionContext` or rely on executable policies. **Risk:** quiet bypass if both paths missed |
| INT-9 | Vault file format mismatch on multi-key Midnight accounts | OWS upgraded vault schema; old wallets unreadable | Schema version field + migration; **risk:** wallets imported as raw keys (3 keys, not mnemonic) need explicit multi-key support |
| INT-10 | Cardano partner-chain bridge tx accidentally signed | If OWS exposes generic `sign_transaction(midnight, raw_hex)` and a bridge tx slips through | Need policy-level check that bridges aren't user-initiated, or surface bridge txs as a separate operation |
| INT-11 | Network confusion (mainnet vs preview) | User signs a mainnet tx with a preview address | Bech32m suffix mismatch in address parsing; **but** if address-format is permissive and we strip the suffix, the check is lost. Needs explicit `network_id` validation in OWS sign path. |
| INT-12 | Long-running prover blocks signing UX | Caller expects sub-second sign; prover takes many seconds | Timeouts + progress reporting at FFI; **risk:** synchronous `sign_transaction()` stalls UI |

## Categories

- **Validation (OWS-side, defensive):** OWS-1 through OWS-7 catch user/caller errors at OWS boundaries.
- **Consensus (Midnight ledger):** MN-1 through MN-14 are enforced by node validators and proof verifiers — OWS only needs to construct *valid* transactions; the ledger rejects invalid ones.
- **Wallet operational (Midnight):** WL-1 through WL-8 surface in normal user flows; OWS must surface them through the FFI without leaking implementation details.
- **Integration (OWS↔Midnight):** INT-1 through INT-12 are *new failure modes* introduced by adding Midnight to OWS. These are the ones phase 5 (implementation) must explicitly test for.

## Connector API failures (from 2e — `errors.ts:16-27` + `SPECIFICATION.md`)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| CN-1 | `connect(networkId)` rejects (Disconnected) | Wallet cannot reach the specified network | `errors.ts:26` `Disconnected` code; promise rejected |
| CN-2 | `connect(networkId)` rejects (Rejected) | User denied connection in wallet UI | `errors.ts:23` `Rejected` |
| CN-3 | `getXxxBalance` returns `PermissionRejected` | User denied per-method permission during connect | `errors.ts:23`; persistent for session per `SPECIFICATION.md:321` |
| CN-4 | `balance{Un,}sealedTransaction` returns `InvalidRequest` | Malformed tx hex; cannot deserialize; imbalance unsolvable | `errors.ts:21-22`; wallet validates before signing |
| CN-5 | `balance{Un,}sealedTransaction` returns `Rejected` | User rejects signing in confirmation dialog | `errors.ts:23` |
| CN-6 | Disconnection mid-call | Wallet process killed / crashed mid-balance | `errors.ts:26` `Disconnected` |
| CN-7 | Version mismatch | Dapp filtered for `^3.0` but wallet only has `^4.0` | Discovery-time: `Object.values(window.midnight).filter(...)` returns empty — caller's logic |
| CN-8 | Wallet missing on `window.midnight` | No wallet extension installed | Caller's `Object.values(window.midnight ?? {})` is empty array |
| CN-9 | Hard-fork window: dapp picks wrong version | Two `InitialAPI` entries side-by-side; dapp picks the deprecated one | Caller's semver filter; if wrong version is picked, runtime type errors at first method call |
| CN-10 | Configuration mismatch (`networkId`) | Dapp connected to mainnet; expects testnet | `getConfiguration().networkId` check by dapp; spec doesn't auto-validate |
| CN-11 | TTL-exceeded tx submission | Dapp submits tx past per-intent TTL | Network rejection; dapp sees via `getTxHistory()` status `discarded` (`api.ts:254`) |
| CN-12 | Segment ID collision | Dapp specifies `intentId: 1` in two `makeIntent()` calls in same tx | Wallet may auto-adjust or reject; spec ambiguous |
| CN-13 | Proof preimage privacy leak | DApp passes preimage to `getProvingProvider().prove()`; wallet sees it | **No mitigation** — `SPECIFICATION.md:370-372` notes this is an accepted privacy boundary |
| CN-14 | Connector spec self-inconsistency on `getDustBalance` shape | `SPECIFICATION.md:95-97` says `Promise<bigint>`; `api.ts:84` says `Promise<{cap, balance}>` (X-5) | **No automated catch** — caller may destructure incorrectly. OWS port should target `api.ts` shape. |

## WalletEngine spec failures (from 2d — license-pending, user override 2026-04-29)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| WE-1 | Segment 0 failure | Tx rejected by ledger rules (inputs invalid, proofs don't verify, double-spend) | Tx state → `Failure`; coins remain unchanged; `apply_transaction` records but doesn't apply state changes |
| WE-2 | Partial segment failure | Some fallible segments fail (contract revert, balance check) | Tx state → `PartialSuccess` with successful intent IDs returned; failed intents' coins remain booked; user decides resubmit/accept |
| WE-3 | Merkle tree desynchronization (reorg) | Chain reorg detected; competing block | `rollback_last_transaction()` reverts roots and coin states |
| WE-4 | Dust output expired (grace period) | Wallet didn't sync dust state within grace window | Spend fails during balancing — generation no longer in tree |
| WE-5 | Orphaned coin (predicted, never confirmed) | Multi-party tx never broadcast | Coin in `pending` state indefinitely; user's `discard_transaction()` removes |
| WE-6 | WalletBackend lies about sync state | Malicious or corrupted backend reports wrong roots | `apply_transaction` verifies roots against known state; mismatch aborts |
| WE-7 | Proving server timeout / unavailable | Proof-server down | HTTP timeout/error; tx remains unproven; pending pool recovery |
| WE-8 | ZK proof verification fails | Wallet generated incorrect proof | Tx → Failed; no coin state changes (proof prevents corruption) |
| WE-9 | Private key lost / corrupted | Storage corruption, password forgotten | All operations requiring signing fail; restore from backup |
| WE-10 | State Merkle trees out-of-sync | Wallet missed block; corrupt storage | `apply_transaction` root verification fails; flag for recovery → resync from trusted source |
| WE-11 | Fallible-section binding constraint violation | Caller balances fallible section after binding | `Specification.md:924-927` constraint; OWS port enforces with type-state or runtime check (Q-tx-5) |
| WE-12 | Pending tx pool unbounded growth | No GC policy in spec; long-running wallet | OWS port must add TTL/size cap (W-8) |

## Lace integration failures (from 2f)

| # | Failure | Source / cause | Caught by |
|---|---------|----------------|-----------|
| LC-1 | `makeTransfer` invoked from unauthorized origin | Lace bypasses origin authorization for this method (`midnight-dapp-connector-api.ts:348-371`) | **No catch** — security gap (X-6) |
| LC-2 | `signData` data not prefixed with `midnight_signed_message:<size>:` | Lace implementation may not apply prefix (X-7, unverified) | Spec mandate `SPECIFICATION.md:359`; if Lace skips, dapp could trick wallet into signing tx-shaped bytes |
| LC-3 | User-overridable indexer URL points at malicious server | Lace `store/slice.ts:62-100` no UI warning | **No catch** at Lace level (X-8); OWS port should ship stricter default + warning |
| LC-4 | Stale dust balance cache after clock drift | Lace persists `maxCapReachedAt`; client clock differs | `dust-utils.ts:68` clamps to 0 safely; UX shows stale until sync resolves |
| LC-5 | Connector module unloads when feature flag toggled | Lace has no graceful degradation; module simply unloads | Caller-visible: dapp connector disappears mid-session if user toggles flag |
| LC-6 | Mobile dapp-connector unsupported | `dapp-connector-midnight` is `lace-extension` only | Caller cannot use connector from mobile; UX must surface this |

## Categories (updated)

- **Validation (OWS-side, defensive):** OWS-1 through OWS-7.
- **Consensus (Midnight ledger):** MN-1 through MN-14 (validators enforce).
- **Wallet operational (Midnight):** WL-1 through WL-8 + **WE-1 through WE-12** (WalletEngine spec).
- **Connector boundary:** **CN-1 through CN-14** (dapp-connector v4.0.0).
- **Production wallet integration:** **LC-1 through LC-6** (Lace specifics; some are bugs OWS port should not replicate).
- **Integration (OWS↔Midnight):** INT-1 through INT-12.

## Still not inventoried

To be added in true-2g and beyond:
- Reorg-recovery edge cases crossing dust grace period (deep reorg).
- Cross-tx race conditions (two Wallet processes signing concurrently against same vault).
- Side-channel timing leaks in prover (especially route A in-process).
- Cost-model failure modes (L-3 deferred from 2g-lite).
- midnight-js dapp-side failure catalog (H-6 partial).

## True-2g additions (from G2 + G3 deep reads)

### Cost-model failure modes (CM-1..6, from G2)

| # | Failure | Source / cause | Caught by |
|---|---|---|---|
| CM-1 | Drift rejection without burn | Cost model has dynamically repriced between wallet's snapshot and chain ingestion; tx cost exceeds limits | `normalize()` returns `None` at well-formedness; **no Dust burn** because pre-validation is not execution. Wallet retries with refreshed cost model. (`cost-model.md:239-252`, `intents-transactions.md:185-216`) |
| CM-2 | Fallible execution waste | Fallible segment fails mid-execution (contract revert, balance check) | Spec localizes failure to that segment; **silent on whether validators precharge fallible exec from Dust.** Open question. (`intents-transactions.md:720-741, 822-856`) |
| CM-3 | GC incompleteness | `gc_rcmap` step budget exhausts before completion; zero-value or negative-rc nodes persist | "Okay, as it is costed as persistent storage" (`storage-io-cost-modeling.md:257-259`). Storage bloat permanent until subsequent tx triggers further GC. |
| CM-4 | Dust grace-period cliff | Tx's timestamp falls outside `dust_grace_period` (3 hours, `dust.md:248`); fee payment fails | Spend fails at well-formedness; user gets typed error, must rebalance. **Risk:** wallets that don't refresh `tnow` before sign get cliff-edge failures. |
| CM-5 | Hard-fork cost repricing | Forks may invalidate past cost assumptions; Dust may be redistributed (`dust.md:13-17`) | **No forward-compat guarantee.** Wallet's cost-model snapshot becomes invalid post-fork; must refetch. |
| CM-6 | Synchronous-IO double-cost | Sync reads cost both `read_time` AND `compute_time` (`cost-model.md:135-136`) | Caller may underestimate fee if assuming reads are "I/O only." Asymmetric pricing favors batched/async patterns. |

### Runtime / migration failure modes (RT-1..5, from G3)

| # | Failure | Source / cause | Caught by |
|---|---|---|---|
| RT-1 | Empty variants array on `initHeadVariant` | builder misconfigured | `WalletRuntimeError` "No variant to init" (`Runtime.ts:206-207`) |
| RT-2 | `VersionChangeType.Next` with no successor | edge case at end of variant chain | **Silent no-op** (`Runtime.ts:281-282`, tested at `runtime.test.ts:265`). **Risk:** caller may assume migration occurred. |
| RT-3 | `migrateState` throws / returns `Effect.fail` | new variant cannot interpret old state | Runtime stream halts; `WalletRuntimeError`. Wallet must restart from earlier checkpoint. |
| RT-4 | Out-of-order variant registration | builder bug — `sinceVersion ≤ previousVariant.sinceVersion` | `Error('ProtocolMismatch: sinceVersion is prior to previously registered version')` at `WalletBuilder.ts:55-57`; tested at `walletBuilder.test.ts:44-60` |
| RT-5 | Persisted state lacks `schema_version` field | upstream wallet leaves persistence discipline to consumer | **Not caught upstream.** OWS must add the version field and validate at load. **Risk:** silent corruption on schema drift. |

### Lace bugs confirmed (from G5 — LC-X-6, LC-X-7)

| # | Failure | Source / cause | Caught by |
|---|---|---|---|
| LC-X-7 | Lace `signData` does NOT prefix data with `midnight_signed_message:<size>:` before signing | Implementation gap; tests confirm raw-bytes pass-through (`midnight-dapp-connector-api.ts:574-575, 1053-1055`) | **No catch** — escalated as bug X-7. Severity: **CRITICAL.** Allows malicious dapp to craft bytes that sign as valid txs. Violates spec `SPECIFICATION.md:359` (CN-I-4). |
| LC-X-6 | Lace `makeTransfer` and `makeIntent` pass empty sender `{}` to confirmation callback; no origin attribution | Implementation gap (looks intentional); contrast with `balanceSealedTransaction`'s `resolveSenderAndOptions` (`midnight-dapp-connector-api.ts:365, 512-523, 630-648`) | **No catch** — escalated as bug X-6. Severity: **HIGH.** User-facing dialog has no origin; no per-dapp permission scope. |
