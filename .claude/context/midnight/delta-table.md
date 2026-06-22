# Delta table — OWS today vs Midnight

> Artifact (a) per `task.md` step 2. Each row marks **kept / changed / new** vs the closest prior art (existing OWS chain implementations). LHS column cites OWS source via `ows-baseline/`. RHS column cites Midnight source via topic files.
>
> Status: first-pass populated by 2a (OWS) + 2b (ledger spec) + 2c (wallet packages). Second-pass adds 2d (WalletEngine, license-pending — user override), 2e (connector v4.0.0), 2f (Lace's three Midnight packages), and X-1 (curve verification). Append-only across passes.

## Index

| Dimension | OWS today | Midnight target | Verdict |
|-----------|-----------|-----------------|---------|
| Chain identifier shape | CAIP-2 string ([chain-registry.md](ows-baseline/chain-registry.md)) | `midnight:mainnet` provisional ([08-caip2.md](topics/08-caip2.md)) | **kept** (registry shape unchanged); namespace string is **new** |
| `ChainType` registry | 11 unit variants ([chain-registry.md](ows-baseline/chain-registry.md)) | + `Midnight` variant | **changed** (one new arm) |
| `KNOWN_CHAINS` | 23 entries | + `midnight` entry | **changed** (one new entry) |
| SLIP-44 coin type | hardcoded per chain ([chain-registry.md](ows-baseline/chain-registry.md)) | 2400 (per midnight-wallet `m/44'/2400'/...`) | **new** (verify SLIP-44 status) |
| Curves supported | secp256k1, ed25519 ([hd-deriver.md](ows-baseline/hd-deriver.md)) | + JubJub, + BLS12-381 ([02-curves.md](topics/02-curves.md)) | **changed** (`Curve` enum extension) |
| HD derivation | BIP-32 + SLIP-10, returns 1 key per call ([hd-deriver.md](ows-baseline/hd-deriver.md)) | BIP-32 + 5 role sub-trees per account, 3 keys derived per logical account ([01-addresses.md](topics/01-addresses.md)) | **new** (multi-output API needed) |
| Keys per logical account | 1 ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | 3 (shielded, unshielded, dust); single-address proposal pending | **new** until proposal lands |
| Addresses per logical account | 1 ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | 3, Bech32m HRPs `mn_shield-addr`, `mn_addr`, `mn_dust` ([01-addresses.md](topics/01-addresses.md)) | **new** |
| Address encoding | per-chain (EIP-55 hex / Base58 / Bech32 / etc.) ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | Bech32m with `mn_<type>[_<network>]` prefix | **new** but mechanically familiar (Bitcoin/Cosmos use Bech32) |
| Network in address | not in OWS address shape (chain_id is separate) | encoded as suffix in Bech32m address (`mn_addr_preview1...` for testnet) | **new** |
| `ChainSigner` trait | 9 methods, single-sig output ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | 9 methods insufficient: shielded path needs proving + multi-sig output | **changed** (extension or new parallel trait) |
| Signing curve per chain | 1 ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | 1 for unshielded (Schnorr-secp256k1, BIP 340), but shielded path uses ZK not signature ([04-proving.md](topics/04-proving.md)) | **changed** |
| Signature primitive | secp256k1 ECDSA / ed25519 EdDSA ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | Schnorr-secp256k1 (BIP 340) for unshielded; ZK proofs replace signatures for shielded/dust/contract | **new** (Schnorr) |
| `SignOutput` | one signature per call ([chain-signer-trait.md](ows-baseline/chain-signer-trait.md)) | tx can carry many Schnorr sigs (per unshielded input) + many ZK proofs + 1 Fiat-Shamir Pedersen proof per intent | **new** structure |
| Proving | none ([pluggability-seams.md](ows-baseline/pluggability-seams.md)) | required for Zswap inputs/outputs, dust spends, contract calls ([04-proving.md](topics/04-proving.md)) | **new** |
| Stateless signers | yes ([pluggability-seams.md](ows-baseline/pluggability-seams.md)) | shielded path is stateful (prover keys, CRS) unless route C (hosted) ([04-proving.md](topics/04-proving.md)) | **changed** depending on prover route |
| Transaction model | account-ish; `raw_hex` swallows arbitrary serialization ([policy-context.md](ows-baseline/policy-context.md)) | hybrid: UTxO unshielded + Zswap shielded notes + dust + contract intents + segments + per-intent TTL ([03-tx-model.md](topics/03-tx-model.md)) | **changed** for policy engine; **new** structure |
| Replay protection | implicit (chain-specific; nonce on EVM, UTxO-uniqueness on Bitcoin) | intent-hash + time-filtered map (~1 week TTL); no nonce ([03-tx-model.md](topics/03-tx-model.md)) | **new** |
| Tx atomicity | tx-atomic (most chains) | segment-based: segment 0 atomic; segments 1+ fallible-with-rollback ([03-tx-model.md](topics/03-tx-model.md)) | **new** |
| Tx lifecycle | 1-shot sign | 5 steps: build → balance → sign → finalize (prove + bind) → submit ([03-tx-model.md](topics/03-tx-model.md)) | **changed** (multi-step) |
| `PolicyContext` | flat, account-model fields + `raw_hex` ([policy-context.md](ows-baseline/policy-context.md)) | needs deserialized intents + wallet sync state for net-effect computation ([07-policy.md](topics/07-policy.md)) | **changed** (extension required) |
| Pre-declared effects | not in OWS today | first-class in Midnight; policy can check effects without running program ([07-policy.md](topics/07-policy.md)) | **new** primitive available |
| Policy actions | `Deny` only ([policy-context.md](ows-baseline/policy-context.md)) | same scope for v1 (refuse to sign on violation) | **kept** |
| Indexer / sync | not in OWS surface | required (GraphQL queries + WebSocket subscriptions) ([05-indexer.md](topics/05-indexer.md)) | **new** |
| Sync state persistence | not in OWS today | required between calls (IOHK 8.4.2026) ([09-state-persistence.md](topics/09-state-persistence.md)) | **new** |
| Vault format | encrypted mnemonic OR encrypted private key, single-key per chain ([ffi-bindings.md](ows-baseline/ffi-bindings.md)) | needs three encrypted private keys per logical account when imported as raw keys ([10-bindings.md](topics/10-bindings.md)) | **changed** (vault schema) |
| Wallet location | `~/.ows/wallets/<wallet_id>.json` (CLAUDE.md) | + sync state and tx history per chain in new path | **changed** (new sub-paths) |
| FFI surface | string pass-through for chain id ([ffi-bindings.md](ows-baseline/ffi-bindings.md)) | + `derive_midnight_account`, recipe-lifecycle methods, sync state plumbing | **changed** (new functions) |
| CLI | `ows --chain <id>` works for any registered chain ([chain-registry.md](ows-baseline/chain-registry.md)) | + sync, balance, recipe-step subcommands needed | **changed** (new subcommands) |
| CAIP-2 namespace | hardcoded `match` in `chain.rs::namespace()` | `"midnight"` arm pending CAIP-2 finalization | **new** |
| Hash primitives | per-chain inline (Keccak256, SHA-256, RIPEMD-160, Blake2b) | + Poseidon (ZK-friendly), + SHA-256 (already there), + Pedersen ([02-curves.md](topics/02-curves.md)) | **new** (Poseidon) |
| Trusted setup | none | required for ZK proofs (CRS via `midnight-proofs`) ([02-curves.md](topics/02-curves.md), [04-proving.md](topics/04-proving.md)) | **new** |
| Cardano partner-chain | n/a | NIGHT bridges Cardano↔Midnight via system transactions; out-of-scope at signing layer for v1 ([03-tx-model.md](topics/03-tx-model.md)) | **deferred** |

## Rows added by second pass (2d / 2e / 2f / X-1)

| Dimension | OWS today | Midnight target | Verdict |
|-----------|-----------|-----------------|---------|
| Unshielded signature scheme (X-1 closed) | ECDSA over secp256k1 (`ows-signer/src/chains/evm.rs`) | **Schnorr over secp256k1, BIP-340** — `k256::schnorr` per `midnight-ledger/base-crypto/src/signatures.rs:14-18` | **new scheme** (existing `Curve::Secp256k1` enum kept) |
| Dapp connector API | none in OWS | `midnight-dapp-connector-api` v4.0.0 — type-based, hex-string tx, three address methods, granular permissions ([06-connector.md](topics/06-connector.md)) | **new** (closest reference for OWS↔AI-agent boundary per scope §8.4.2026) |
| Wallet discovery mechanism | n/a | `window.midnight[uuidv4]` per draft CAIP-372 (`SPECIFICATION.md:44-54`) | **new** |
| Hard-fork API coexistence | n/a | multiple `InitialAPI` entries side-by-side in `window.midnight`, distinguished by `apiVersion` semver (`SPECIFICATION.md:68`) | **new** discipline |
| Connector network identifier | OWS uses CAIP-2 throughout | bare string (`"mainnet"`, `"preview"`); `Configuration.networkId: string \| NetworkId` with `NetworkId` undefined ([06-connector.md](topics/06-connector.md)) | **changed** (boundary translation required) |
| Connector tx encoding | n/a | hex-encoded `Transaction<S,P,B>` strings; recipe lifecycle hidden from dapp | **new** (opaque-blob discipline) |
| Connector tx methods | n/a | 5 methods: `makeTransfer`, `makeIntent`, `balanceUnsealedTransaction`, `balanceSealedTransaction`, `submitTransaction` ([06-connector.md](topics/06-connector.md)) | **new** |
| Connector signing | n/a | `signData(data, options)` — only `keyType: "unshielded"`; mandatory prefix `midnight_signed_message:<size>:` (`SPECIFICATION.md:359`) | **new** |
| Connector proving delegation | n/a | `getProvingProvider(keyMaterialProvider): Promise<ProvingProvider>` — dapp passes `KeyMaterialProvider` (ZKIR + prover key + verifier key) ([06-connector.md](topics/06-connector.md)) | **new** seam (closest match for OWS pluggable proving) |
| Permission model | OWS `Policy.action == Deny` (binary) | per-method `PermissionRejected` + advisory `hintUsage(methodNames)` ([06-connector.md](topics/06-connector.md)) | **changed** (more fine-grained) |
| Transaction history surface | n/a | `getTxHistory(pageNumber, pageSize): Promise<HistoryEntry[]>` (`SPECIFICATION.md:231-237`) — txHash + status + per-segment ExecutionStatus | **new** |
| Connector error catalog | OWS `SignerError` enum | 5 codes: `InternalError`, `Rejected`, `InvalidRequest`, `PermissionRejected`, `Disconnected`; `APIError` is type alias not class (`errors.ts:16-48`) | **new** |
| WalletEngine state ops (per 2d) | n/a in OWS | 6 atomic ops: `apply_transaction`, `apply_system_transaction`, `finalize_transaction`, `rollback_last_transaction`, `discard_transaction`, `spend` (`Specification.md:456-465`) | **new** lifecycle vocabulary |
| Coin lifecycle states (per 2d) | n/a | 6 states: pending → confirmed → final → booked → spent + discarded; rollback edges (`coin-lifecycle.puml`) | **new** |
| Tx lifecycle states (per 2d) | tx-atomic | pending → confirmed → final + rejected; substates Success/PartialSuccess/Failure (`tx-lifecycle.puml`) | **new** |
| Test vectors (per 2d) | per-chain inline tests in OWS | `WalletEngine/test-vectors/{addresses.json (2,281 lines), keyDerivation.json (400 lines)}` — directly portable to OWS Rust tests | **new resource** (port directly) |
| Lace persistence (per 2f) | n/a | persists dust balance cache, network URL overrides, UX dismissals; **does not persist** wallet sync state — IOHK 8.4.2026 update reverses this for OWS | **new — OWS diverges from Lace** on sync-state persistence |
| Lace network override (per 2f) | n/a | user-overridable indexer/proof-server URLs without UI warning (`store/slice.ts:62-100`) | **risk** (OWS port should ship stricter default + warning, X-8) |
| Reference Schnorr-secp256k1 impl | OWS has ECDSA via `secp256k1` crate; `evm.rs` not reusable | upstream Midnight uses `k256::schnorr` (BIP-340) | **decision** — vendor `k256::schnorr` or implement in OWS (P-4) |

## Summary verdict

**Falsifies the load-bearing claim** in `docs/07-supported-chains.md:135-143` ("No changes to OWS core, the signing interface, or the policy engine are needed") on at least the following axes:

1. **Curve enum** (`Curve::Secp256k1 | Ed25519`) — must extend.
2. **HD deriver** (single-key-per-call) — must add multi-output API.
3. **`ChainSigner` trait** — must extend (proving + multi-sig output).
4. **`PolicyContext`** — must extend (deserialized intents + wallet state).
5. **`SignOutput` shape** — must extend (multi-signature).
6. **FFI surface** — must add (multi-address derivation, recipe lifecycle, sync state).
7. **Vault format** — must version-bump (multi-key entries).
8. **New subsystems** — indexer client, prover (route TBD), sync state persistence.

**Kept:** chain registry shape, CAIP-2 discipline (namespace string is new), policy action enum (`Deny`-only), `git`-tracked OWS folder structure (`ows/`, `bindings/`, `docs/`).

## Rows added by true-2g pass (2026-04-30)

| Dimension | OWS today | Midnight target | Verdict |
|-----------|-----------|-----------------|---------|
| Cost model — dimensionality | n/a (single-fee on EVM; not surfaced elsewhere) | 5-D synthetic cost: read_time, compute_time, block_usage, bytes_written, bytes_churned ([topic 03](topics/03-tx-model.md), `cost-model.md:56-76`) | **new** |
| Cost model — sourcing | n/a | hybrid: genesis defaults + dynamic per-block adjustment + wallet snapshot at submission (`cost-model.md:148-150, 277-301`) | **new** |
| Cost model — block limits | per-chain block size only | 5-D limits: 200K bytes total, 20K bytes_written, 1M bytes_churned (others time-bound) (`cost-model.md:154-160`) | **new** |
| Cost model — sync-read asymmetry | n/a | sync reads cost both `read_time` AND `compute_time` (`cost-model.md:135-136`) | **new** |
| Cost model — authority | n/a | distributed: ledger spec defines, wallet estimates, node enforces, consensus rejects (`cost-model.md:186-203`) | **new** |
| Schema-version persistence | none in OWS today | midnight-wallet leaves persistence to consumers; OWS must add explicit `schema_version` ([topic 09](topics/09-state-persistence.md)) | **new** (OWS-side discipline gap) |
| Variant migration mechanism | none in OWS today | mandatory `migrateState` on every Variant; type-system enforced (`Variant.ts:41`) | **new** (pattern to mirror) |
| Version range vs migration boundary | n/a | in-range version change: annotation only; out-of-range: variant swap (`Runtime.ts:284-286, 221-263`) | **new** distinction |
| Round-trip migration tests | n/a | midnight has in-memory migration tests but **no serialize/reload across version change**; OWS must add | **new gap to fill** |
| Connector signData prefix discipline | n/a | spec mandates `midnight_signed_message:<size>:` wrap; **Lace skips, escalated bug X-7** ([topic 06](topics/06-connector.md)) | **gap to enforce** in OWS — apply unconditionally |
| Connector make* origin auth | n/a | spec implies origin scoping; **Lace skips for makeTransfer/makeIntent, escalated bug X-6** ([topic 06](topics/06-connector.md)) | **gap to enforce** in OWS — validate every method |
| midnight-js vs midnight-wallet | n/a | clean boundary at `WalletProvider`; midnight-js (14 packages) = dapp SDK; midnight-wallet = wallet runtime; H-6 closed | **clarified** boundary |
| midnight-js modular layout | n/a | 14 packages: `types`, `network-id`, `contracts`, `protocol`, `indexer-public-data-provider`, `level-private-state-provider`, `dapp-connector-proof-provider`, `http-client-proof-provider`, `fetch-zk-config-provider`, `node-zk-config-provider`, `logger-provider`, `compact`, `utils`, `midnight-js` (barrel) | **reference** for OWS-Node SDK shape (phase 5+) |
| Proving routes by package | n/a | A: `dapp-connector-proof-provider` (wallet-delegated); C: `http-client-proof-provider` (remote server); B: not implemented | **clarifies** route definitions |
| ZK config split | n/a | `fetch-zk-config-provider` (browser HTTPS) + `node-zk-config-provider` (Node.js filesystem) — independent of proving route | **reference** for OWS ZK config trait shape |
