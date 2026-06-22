# Open questions ledger

> Status of every open question that blocks phase-3 (or downstream) decisions. Seeded with HANDOVER §7's 8 questions, plus questions surfaced during 2a/2b/2c reads. Each entry has a status: **open** / **partial** / **closed by-finding** / **closed-as-bug**.
>
> This file is **append-only**: status changes are recorded, not overwritten.

## From HANDOVER §7 (phase-1 carryover)

| # | Question | Status | Notes |
|---|----------|--------|-------|
| H-1 | Prover route: in-process Rust port (no precedent), in-WASM (1AM), or local proof-server (Lace)? | **partial — narrowed by 2d** | 2d (WalletEngine spec) confirms proving boundary is **HTTP-only, external-only**: `apis-and-common-types/proving-server/README.md` documents POST `/prove-tx` with Borsh; **no in-process prover specified anywhere in the architecture.** 2f confirms Lace consumes `httpClientProvingProvider`. Routes A/B require OWS to pioneer (no upstream precedent). Route C matches Lace exactly. Scope's 8.4.2026 lean is route B (WASM from upstream Rust). Phase-3 commits. |
| H-2 | Public hosted indexer — does it exist? | **open** | `midnight-indexer/README.md` documents only self-hosted. 2c ledger spec doesn't require any specific indexer location. Need IOHK confirmation. |
| H-3 | `midnight-architecture` license clarification | **deferred — user override 2026-04-29** | Repo has no `LICENSE`. User explicitly authorized reading this material on 2026-04-29 ("i dont care, run another parallel agent"). 2d sub-phase ran. **Do not paste verbatim** from this repo into published artifacts; cite by `path:line`. Track upstream license clarification — outstanding for any quoted material in OWS source. |
| H-4 | Single-address proposal (8.4.2026) — has IOHK shared it? | **open** | Not surfaced in the cloned repos as of 2026-04-29. Phase-2 records the three-address model as current contract. v4.0.0 connector spec **structurally enforces three address types** (X-4 detail). Single-address would be a v5+ change. |
| H-5 | `zkir` vs `zkir-v3` migration story | **partial — closed by 2b** | Both crates exist. `zkir` (v2.1.0) is legacy; `zkir-v3` (v3.0.0-rc.1) is current. Production has shifted to v3. OWS should target v3. Open for: hard-fork gate that switches networks from v2 to v3 — when, and what's the wallet's role. |
| H-6 | midnight-js vs midnight-wallet responsibility split | **closed by-finding (true-2g, 2026-04-30)** | Closed: clean boundary at `WalletProvider` interface. midnight-js (14 packages) = dapp SDK only — proof generation, ZK config, indexer client, contract syntax, network ID; zero wallet-side code. midnight-wallet = wallet runtime — key custody, signing, tx finalization, blockchain sync. Tx flow stops at `Unproven → ProofProvider.proveTx → Unbound → wallet.balanceTx (signs/finalizes) → submit`. Two proving routes: `dapp-connector-proof-provider` (wallet-delegated) and `http-client-proof-provider` (remote server). See [topic 06 §midnight-js boundary](topics/06-connector.md). Boundary invariants BD-I-1..3 in `invariants.md`. |
| H-7 | CAIP-2 finalization for `midnight:mainnet` | **open** | IOHK said "in progress; might not finalize before implementation concludes." OWS uses `midnight:mainnet` provisionally. Track upstream PRs at https://github.com/ChainAgnostic/CAIPs. Connector v4.0.0 doesn't adopt CAIP-2 — bare strings only. |
| H-8 | Cardano↔Midnight bridge txs — does OWS need to model these? | **deferred** | 2b confirmed `cardano-system-transactions.md` exists; bridge oracles run on validators, not in user wallets. Likely transparent at OWS layer; phase-3 confirms. |

## Surfaced by 2a (OWS baseline)

(No new questions — 2a is descriptive of existing OWS code; design decisions for OWS extension belong to phase 3.)

## Surfaced by 2b (Midnight ledger spec)

| # | Question | Status | Notes |
|---|----------|--------|-------|
| L-1 | CRS / proving keys: size, distribution, trusted-setup ceremony | **open** | Spec defers to `midnight-proofs` library docs. Important for binary size + first-run UX on route A/B. 2d cross-check: WalletEngine spec also defers — no CRS distribution mechanism in architecture docs. |
| L-2 | Cardano oracle consensus for cNight ↔ Night bridge | **open** | Spec says system transactions handle bridging but doesn't detail oracle agreement. Probably out of scope for OWS unless bridges become user-initiated. |
| L-3 | Cost model dynamics — precisely what determines fees? | **closed by-finding (true-2g, 2026-04-30)** | Closed: 5-D synthetic cost (`SyntheticCost`: read_time/compute_time/block_usage/bytes_written/bytes_churned, `cost-model.md:56-76`). Genesis defaults + dynamic per-block adjustment via `FeePrices.update()` targeting 50% block utilization (`cost-model.md:148-150, 277-301`). Authority distributed: ledger spec → wallet estimates → node enforces → consensus rejects. Pre-validation drift = rejection without burn. Sync reads cost both `read_time` AND `compute_time` (`cost-model.md:135-136`). Hard-fork repricing not consensus-locked. See [topic 03 §True 2g](topics/03-tx-model.md). Invariants CM-I-1..6 in `invariants.md`; failure modes CM-1..6 in `failure-modes.md`. |
| L-4 | Indexer query privacy — optimal prefix length for anonymity | **open** | Spec sketches stochastic prefix queries (anonymity set ∝ 2^(14-7) = 128 for example). Practical recommendations not in spec. |
| L-5 | Intent composition lifecycle — when can wallet finalize? | **open** | Spec allows external parties to compose intents before binding. Wallet must be careful not to sign before composition is complete. Not formalized; UX concern. |
| L-6 | Fallible-transcript abort semantics — gas burn from forced fallible failures | **open** | Cost model presumably charges for attempted execution; deterministic-failure attacks need scrutiny. **True-2g update:** spec is silent on whether validators precharge fallible execution from Dust (see CM-2 in `failure-modes.md`). Still open. |
| L-7 | Field-aligned binary (FAB) edge cases — who validates? | **open** | `field-aligned-binary.md` specifies alignment but consensus consequences of malformed FAB unclear. |
| L-8 | NEW (2d): ZswapTransient zero-value semantics | **closed by-finding (true-2g, 2026-04-30)** | Closed via L-3 deep read: zero-value Dust UTXOs are created and charged normally per `dust.md:54, 519, 527`. Cost model does not distinguish zero-value (`storage-io-cost-modeling.md:119-131`); GC best-effort, may persist indefinitely (`storage-io-cost-modeling.md:199-239, 257-259`). Not a malformed-tx case. |

## Surfaced by 2c (Midnight wallet packages)

| # | Question | Status | Notes |
|---|----------|--------|-------|
| W-1 | In-process proving fallback in `prover-client/` | **closed by-finding (2c, reaffirmed by 2d/2f)** | 2c: `WasmProver` namespace exists but no implementation. 2d: WalletEngine spec assumes external HTTP proving via `apis-and-common-types/proving-server/`. 2f: Lace consumes `httpClientProvingProvider`. **No in-process or WASM fallback exists in any production wallet or in the architecture spec.** Routes A/B in OWS would be upstream-firsts. |
| W-2 | Cardano partner-chain interaction at the wallet layer | **closed by-finding** | 2c confirmed: not in the wallet. Wallet treats Midnight as standalone. Bridge state surfaces only after validators land it. |
| W-3 | Variant state schema versioning | **closed by-finding (true-2g, 2026-04-30)** | Closed: mechanism is mandatory `Variant.migrateState(previousState)` (type-system enforced, `Variant.ts:41`). Version tracked OUTSIDE state in `ProtocolState<TState> = { version, state }` (`Runtime.ts:20-21`). Migration triggers iff target version is outside current variant's `validVersionRange` (`Runtime.ts:284-286`). **Persistence discipline delegated to consumers** — neither runtime nor architecture spec mandates a serialization format. **OWS must add explicit `schema_version` field at top level.** Round-trip serialize+migrate tests are ABSENT in midnight-wallet; OWS must add. See [topic 09 §True 2g](topics/09-state-persistence.md). Invariants RT-I-1..7; failure modes RT-1..5. |
| W-4 | Transaction history storage pruning | **open** | `InMemoryTransactionHistoryStorage` serializes everything to one string with no GC. Long-running wallets bloat. OWS should add TTL or size cap. |
| W-5 | Cross-wallet address derivation consistency on partial recovery | **open** | If user imports only an unshielded key (without the others), can the wallet still function? Or must all three be present? Test required. |
| W-6 | Cost model authority — node vs prover vs wallet | **open** | All three reference cost model. **True-2g update:** L-3 closure documents authority is distributed (ledger spec → wallet estimates → node enforces → consensus rejects). The W-6 specific question — "if they diverge, what wins?" — answers as: node enforces at ingestion; wallet must keep up via refresh. Still open in the design sense: which layer is OWS authoritative for? |
| W-7 | NEW (2d): Merkle tree snapshot persistence granularity | **open** | WalletEngine spec requires consistency checks against provided roots per `apply_transaction`, but doesn't mandate storing full intermediate trees. Roots-only vs full-tree changes state-file size and reorg-recovery speed. Phase 3 picks. |
| W-8 | NEW (2d): Pending transaction pool TTL / GC | **open** | Spec mentions pending tx pool but no TTL or GC policy. Long-running wallets accumulate stale failed tx. Couples with W-4. Lace bounds via 1-hour hardcoded TTL (`lace/packages/contract/midnight-context/src/const.ts:14`); spec is silent. |

## Surfaced cross-source

| # | Question | Status | Notes |
|---|----------|--------|-------|
| X-1 | Unshielded signature scheme — Schnorr-secp256k1 (BIP 340) per 2b ledger spec, vs Ed25519 per 2c wallet API names | **closed by-finding (2g, 2026-04-29)** | **Outcome a:** 2c misnamed Ed25519 from a generic API name. Ledger source-of-truth `midnight-ledger/base-crypto/src/signatures.rs:14-18` declares "Schnorr over secp256k1, conforming to BIP340" and wraps `k256::schnorr::{VerifyingKey, SigningKey, Signature}` directly. Wallet `midnight-wallet/packages/unshielded-wallet/src/v1/Keys.ts:15` and `KeyStore.ts:14-21` import `SignatureVerifyingKey` and `signData` from `@midnight-ntwrk/ledger-v8` — no wallet-layer redefinition. WalletEngine spec `Specification.md:218` confirms. **Wider X-1 sweep verified consistent (true-2g 2026-04-30):** no Ed25519 references remain in Midnight-side topic files; existing entries MN-I-7 and MN-I-14..16 capture the Schnorr discipline. |
| X-2 | SLIP-44 coin type 2400 status | **open** | midnight-wallet's `m/44'/2400'/...` uses 2400. Public SLIP-44 registry doesn't currently allocate 2400 to Midnight (verify). Either IOHK has a private allocation, or coin type may change before public registry. OWS needs to track. |
| X-3 | OWS↔connector boundary shape | **closed by-finding (partial, 2e/2f)** | Connector v4.0.0 uses bare `networkId` strings (`"mainnet"`, `"preview"`, etc.) at every API boundary; **no CAIP-2** anywhere in the surface. `Configuration.networkId: string \| NetworkId` per `SPECIFICATION.md:169` references undefined `NetworkId` type — Q-conn-new-1 below. OWS must translate at its boundary. **Phase 3** picks where the translation lives (OWS-internal CAIP-2 vs adopt bare strings vs strict CAIP-2 with reverse-translation). |
| X-4 | One chain or three sibling chains in `KNOWN_CHAINS` | **closed by-finding (strong bias toward single chain, 2d/2e)** | 2d (WalletEngine `Specification.md:189-214`) models Midnight as **one ledger with three address types per account** via 5 hardcoded HD roles. 2e (connector v4) **structurally enforces three address types per account** with three separate methods on `WalletConnectedAPI`. Three-address cohesion is stronger than sibling-chain modeling: addresses share one mnemonic + one account; HD divergence is at role level, not coin_type level. Sibling-chain modeling would require separate `m/44'/2400a/...`-style coin_types not in spec. **Single-chain with multi-address derivation trait** is the upstream-aligned shape. Phase 3 confirms. |
| X-5 | NEW (2e): `getDustBalance` shape — connector spec self-inconsistency | **open** | `SPECIFICATION.md:95-97` says `type DustBalance = { getDustBalance(): Promise<bigint>; }` — bare bigint. `src/api.ts:84` says `getDustBalance(): Promise<{ cap: bigint; balance: bigint }>` — object with both fields. Lace's implementation (`midnight-dapp-connector-api.ts:169-192`) follows `api.ts`. **`api.ts` is de-facto authoritative; SPECIFICATION.md text is stale.** OWS port should target `api.ts` shape. Flag upstream — possibly worth a PR to `midnight-dapp-connector-api/SPECIFICATION.md`. |
| X-6 | NEW (2f): Lace `makeTransfer` skips origin authorization | **closed-as-bug (true-2g, 2026-04-30) — escalate upstream** | **CONFIRMED BUG.** Full read of `midnight-dapp-connector-api.ts:348-402`: `makeTransfer` (`:365`) explicitly casts `{} as Runtime.MessageSender` to confirmation callback — no origin attribution. **`makeIntent` shows the same pattern** (`:512-523`). Compare `balanceSealedTransaction` (`:244-292`) which uses `resolveSenderAndOptions` (`:630-648`) and **throws** `APIError(ErrorCodes.InternalError, 'Missing sender context')`. Pattern looks intentional but creates a security hole: confirmation dialog has no dapp origin. **OWS port must validate origin on every method, no exceptions.** Severity: HIGH. Closed-as-bug invariant LC-I-7; failure mode LC-X-6. |
| X-7 | NEW (2f): Lace `signData` prefix application unverified | **closed-as-bug (true-2g, 2026-04-30) — escalate upstream** | **CONFIRMED BUG.** Full read of `midnight-dapp-connector-api.ts:555-579, 715-733`: `signData` decodes input encoding (hex/base64/text via `decodeSignData`) and passes raw bytes directly to `wallet.signData(dataBytes)` (`:574-575`). **No `midnight_signed_message:<size>:` prefix is applied.** Test expectations confirm pass-through: `expect(mockSignData).toHaveBeenCalledWith(new Uint8Array(...))` (`:1053-1055, 1081-1083, 1109-1111`). **Severity: CRITICAL** — allows a malicious dapp to craft bytes that, when signed, encode a valid transaction. Violates spec `SPECIFICATION.md:359` (CN-I-4). **OWS port must apply the prefix unconditionally before passing to the wallet's signing primitive.** Closed-as-bug invariant LC-I-6; failure mode LC-X-7. |
| X-8 | NEW (2f): Lace user-overridable indexer/proof-server URLs without UI warning | **open — UX concern for OWS port** | Lace `lace/packages/contract/midnight-context/src/store/slice.ts:62-100` allows user to override node/indexer/proof-server URLs per network; persisted with no UI warning about malicious-server risk. OWS port should ship with stricter defaults and explicit warning on URL change. |

## Process / phase-execution questions

| # | Question | Status | Notes |
|---|----------|--------|-------|
| P-1 | Should we read `midnight-architecture/` despite missing license? | **closed by user override (2026-04-29)** | User ("i dont care, run another parallel agent") explicitly authorized reading on 2026-04-29. 2d ran. Citation discipline: cite by `path:line`, paraphrase rather than verbatim quote, label sections derived from the no-LICENSE source. **Open for any code that would ship in OWS source — verbatim derivations into `ows/` source require license clarification.** |
| P-2 | Is the OWS scope's "use the public midnight indexer" assumption load-bearing for v1? | **open** | If no public indexer, OWS must ship with self-hosting docs. Affects scope of phase 5 deliverables. |
| P-3 | Do we ship a vendored copy of `midnight-ledger` Rust crates, or depend on crates.io / git tags? | **open** | License is Apache-2.0; either way works. Vendoring + SHA-pinning gives reproducibility; depending on git tag is simpler maintenance. Phase-3 decision. |
| P-4 | NEW (2g): Schnorr-secp256k1 (BIP-340) — vendor `k256::schnorr` directly or implement in OWS? | **open** | Per Q-curves-4. OWS's `evm.rs` ECDSA can't be reused for Midnight's BIP-340 Schnorr. Vendoring shrinks surface area; depending on `k256` adds a public dep. Phase-3 decision. |

## Status summary (after true-2g pass, 2026-04-30)

- **open:** 20 (was 24 after 2d/2e/2f/X-1; -4 from true-2g closures: L-3, L-8, X-6, X-7)
- **partial:** 2 (H-1 narrowed by 2d; H-5 zkir migration story)
- **closed by-finding:** 9 (W-1, W-2, X-1, X-3, X-4 prior + L-3, L-8, W-3, H-6 from true-2g)
- **closed-as-bug (escalate upstream):** 2 (X-6, X-7 — confirmed Lace bugs from true-2g)
- **deferred / closed by override:** 3 (H-3 closed by user override; H-8 deferred; P-1 closed by user override)
- **Total:** 36 questions tracked; **no new questions in true-2g** (the pass closed without surfacing new ones).

**Largest deltas in true-2g (2026-04-30):**

- **L-3 closed by-finding** — full 5-D cost model documented; genesis defaults + dynamic per-block adjustment; authority distributed; sync reads cost both `read_time` and `compute_time`; pre-validation drift = rejection without Dust burn.
- **L-8 closed by-finding (via L-3 deep read)** — zero-value Dust UTXOs are created and charged normally; not a malformed-tx case; GC best-effort.
- **W-3 closed by-finding** — runtime mechanism (`Variant.migrateState` mandatory; range-driven boundary detection) is well-specified; **persistence delegated to consumers**; OWS must add explicit `schema_version` field. Round-trip serialize+migrate tests absent upstream.
- **H-6 closed by-finding** — clean boundary at `WalletProvider` interface; midnight-js (14 packages) = dapp SDK only, zero wallet-side code; tx flow stops at `Unbound → wallet.balanceTx` (signs).
- **X-6 closed-as-bug** — Lace `makeTransfer`/`makeIntent` pass empty sender `{}`; no origin attribution. **OWS must validate origin on every method.** Severity: HIGH. Escalate upstream.
- **X-7 closed-as-bug** — Lace `signData` does NOT apply `midnight_signed_message:<size>:` prefix. **OWS must apply unconditionally.** Severity: CRITICAL. Escalate upstream.

**Carryover from prior passes (largest deltas before true-2g):**

- **X-1 closed (2g X-1 scoped, 2026-04-29)** — Schnorr-secp256k1 (BIP-340) confirmed via direct read.
- **X-3 closed-partial (2026-04-29)** — connector boundary uses bare strings, no CAIP-2.
- **X-4 closed-partial (2026-04-29)** with strong bias toward single chain.
- **H-1 narrowed (2026-04-29)** — proving boundary is HTTP-only across spec, architecture, and Lace.
- **H-3 closed by user override (2026-04-29).**

**The remaining open questions cluster around:**

- **Architecture decisions** (H-1 prover route, H-7 CAIP-2 namespace, X-4 single-vs-sibling confirmation, P-4 vendor-vs-implement Schnorr) — phase 3 with user.
- **Upstream coordination** (H-2 public indexer, H-4 single-address proposal, X-2 SLIP-44 allocation, W-6 cost-model authority design, L-6 fallible burn) — needs IOHK input.
- **Lace bug escalations** (X-6, X-7) — confirmed bugs; **OWS must NOT replicate**; escalate upstream.
- **Connector spec drift** (X-5 dust balance shape; Q-conn-new-1 `NetworkId` type; Q-conn-new-5 shielded-key signing) — possibly worth upstream PRs.
