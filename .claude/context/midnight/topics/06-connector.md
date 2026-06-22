# Topic 06 — Dapp connector API

> **Status:** populated by 2e (`midnight-dapp-connector-api/` v4.0.0, Apache-2.0) and 2f (Lace's three Midnight packages, MIT) in second pass. 2d (`midnight-architecture/components/WalletEngine`, license-pending — user override) confirms the connector lives outside WalletEngine and is normative for the dapp-facing surface only. **True-2g (2026-04-30):** Lace verification added — X-6 and X-7 confirmed as bugs (escalate upstream); midnight-js boundary documented (closes H-6). See "True 2g — Lace verification" section. Cross-cutting cells in `delta-table.md`, `failure-modes.md`, `invariants.md`, and `open-questions.md` carry the per-axis detail.

## Discovery and connection

Per 2e — `midnight-dapp-connector-api/SPECIFICATION.md`:

- **Discovery:** wallets install a frozen `InitialAPI` object at `window.midnight[uuidv4]` (one UUID per wallet/version pair), per [draft CAIP-372](https://github.com/ChainAgnostic/CAIPs/pull/372/files). Multiple wallets can coexist; multiple versions of the same wallet can coexist. Spec §2 normative.
- **`InitialAPI`** carries `rdns`, `name`, `icon`, `apiVersion` (semver string), and `connect(networkId): Promise<ConnectedAPI>`. `src/api.ts:21-51`.
- **Hard-fork coexistence** is achieved purely at discovery time: no negotiation step. Each version is a separate `window.midnight[uuid]` entry; dapps filter by `apiVersion` semver match before calling `connect()`. `SPECIFICATION.md:68`. There is no version parameter inside `connect()`; if a dapp picks the wrong version it fails at call time with type/runtime errors.

Per 2f — Lace registers `apiVersion: '4.0.1'` (`lace/packages/module/dapp-connector-midnight/src/midnight-wallet-api.ts:32`), one minor bump above v4.0.0 spec. Real-world spec drift; OWS port should target v4.0+ semver compatibility, not pin to exact `4.0.0`.

## ConnectedAPI surface

```
ConnectedAPI = WalletConnectedAPI & HintUsage
```

Per 2e — `src/api.ts:58, 70-204`:

| Group | Method | Returns |
|---|---|---|
| **Balances** | `getShieldedBalances()` | `Promise<Record<TokenType, bigint>>` |
| | `getUnshieldedBalances()` | `Promise<Record<TokenType, bigint>>` |
| | `getDustBalance()` | `Promise<{ cap: bigint; balance: bigint }>` per `api.ts:84`. **See spec contradiction below.** |
| **Addresses** | `getShieldedAddresses()` | `Promise<{ shieldedAddress, shieldedCoinPublicKey, shieldedEncryptionPublicKey }>` (all Bech32m strings) |
| | `getUnshieldedAddress()` | `Promise<{ unshieldedAddress: string }>` |
| | `getDustAddress()` | `Promise<{ dustAddress: string }>` |
| **Tx construction** | `makeTransfer(desiredOutputs, options?)` | `Promise<{ tx: string }>` (hex) |
| | `makeIntent(desiredInputs, desiredOutputs, options)` | `Promise<{ tx: string }>` (hex) |
| **Tx balancing** | `balanceUnsealedTransaction(tx, options?)` | `Promise<{ tx: string }>` |
| | `balanceSealedTransaction(tx, options?)` | `Promise<{ tx: string }>` |
| **Submission** | `submitTransaction(tx)` | `Promise<void>` |
| **Signing** | `signData(data, options)` | `Promise<Signature>` (only `keyType: "unshielded"` per `api.ts:308`) |
| **Proving delegation** | `getProvingProvider(keyMaterialProvider)` | `Promise<ProvingProvider>` |
| **History** | `getTxHistory(pageNumber, pageSize)` | `Promise<HistoryEntry[]>` |
| **Status** | `getConfiguration()` | `Promise<Configuration>` (carries `networkId: string`, `indexerUri`, `indexerWsUri`, optional deprecated `proverServerUri`) |
| | `getConnectionStatus()` | `Promise<ConnectionStatus>` |
| **Permissions** | `hintUsage(methodNames)` | `Promise<void>` (advisory) |

Errors are typed unions; `errors.ts:16-27` defines five codes — `InternalError`, `Rejected`, `InvalidRequest`, `PermissionRejected`, `Disconnected`. The error shape is `APIError = Error & { type: 'DAppConnectorAPIError'; code: ErrorCode; reason: string }` (`errors.ts:41-48`). Per v4 release notes, `APIError` is a **type alias, not a class** — `instanceof APIError` checks no longer work; dapps must check `error.type === 'DAppConnectorAPIError'`.

## Address-type handling — three separate methods, no bundle

Per 2e: the connector exposes **three separate getters**, not a single bundled address object. Dapps must call all three (subject to permission rejection per method) and compose. Each address type is **mandatory on `WalletConnectedAPI`**; wallets cannot omit any without rejecting the call. The single-address proposal (scope §8.4.2026, H-4 in `open-questions.md`) is **not present in v4.0.0** — the spec enforces three addresses structurally.

Implication: settles X-4 partially. WalletEngine spec (2d) treats Midnight as **one ledger with three address types per account** (per `Specification.md:189-214` 5-role HD enum). Connector API enforces this. Modeling Midnight as three sibling chains in OWS's `KNOWN_CHAINS` would break the logical-account boundary; one-chain-with-multi-address-derivation is the upstream-compatible shape. Phase 3 still picks; this finding strongly biases toward single chain.

## Networking and `networkId`

Per 2e — `api.ts:50, 220, 333` and `SPECIFICATION.md:70-71, 169`:

- `networkId` is a **bare string** at every API boundary: `connect(networkId)`, `Configuration.networkId`, `ConnectionStatus.networkId`. Examples in spec: `"mainnet"`, `"preview"`, `"preprod"`, `"undeployed"`, `"my-private-net"` (test-vectors).
- **No CAIP-2** anywhere in the v4.0.0 surface. CAIP-372 (discovery) is referenced; CAIP-2 (chain naming) is not adopted.
- **`SPECIFICATION.md:169` declares the type as `string | NetworkId`** but `NetworkId` is not defined anywhere in the spec or `src/`. This appears to be an unfinished forward-compat placeholder.

Per 2f — Lace `lace/packages/contract/midnight-context/src/value-objects/midnight-network-id.vo.ts` wraps the bare string in a branded value object for type safety. Lace also exposes user-overridable URLs per network (node, indexer, proof-server) in `store/slice.ts:62-100`.

X-3 status: **closed by-finding (partial).** Connector boundary is clear: bare strings. OWS must translate at its boundary if it adopts CAIP-2 internally. The translation is straightforward (`midnight:mainnet` ↔ `mainnet`) but must be explicit; auto-stripping on input and re-prefixing on output. Open question: which side owns canonicalisation (OWS-internal `midnight:mainnet` vs upstream-style `mainnet`).

## Transaction methods and recipe mapping

Per 2e — `api.ts:115-160`:

| Method | Input | Returns | Wallet-visible intent |
|---|---|---|---|
| `makeTransfer(desiredOutputs, options?)` | structured outputs (`DesiredOutput[]` with `kind: "shielded"\|"unshielded"`, `address`, `tokenType`, `amount`) | hex tx | "I want to send these tokens; pick coins and balance" |
| `makeIntent(desiredInputs, desiredOutputs, options)` | structured I/O + `intentId: number \| "random"` | hex tx | "I want a swap-shaped intent; segment-id assigned" |
| `balanceUnsealedTransaction(tx, options?)` | hex `Transaction<SignatureEnabled, Proof, PreBinding>` | hex balanced tx | "Contract call; finalize binding + signatures + balance" |
| `balanceSealedTransaction(tx, options?)` | hex `Transaction<SignatureEnabled, Proof, Binding>` | hex balanced tx | "Sealed (signed/bound) tx with imbalances; rebalance only" |
| `submitTransaction(tx)` | hex finalized tx | `void` | submit to network |

`options.payFees?: boolean` defaults to `true`. When `false`, the wallet does not pay dust fees (intent must include a fee output some other way). Per spec §"Transaction methods".

**Connector hides the recipe lifecycle.** The internal `Transaction<S,P,B>` type-state machine (per topic 03) is not surfaced to dapps. Transactions are **opaque hex strings** at the connector boundary in both directions. Implication for OWS: if the OWS↔AI-agent boundary mirrors the connector, it inherits the same opacity — the agent never sees structured tx data, only hex blobs. If OWS wants the policy engine to inspect declared effects (per topic 07), the policy engine must deserialize `raw_hex` itself; the connector won't pre-parse for it.

Per 2f — Lace adds `MidnightTxParameters` (a Lace-internal serialized JSON shape) that survives between UI and signing layers (`lace/packages/module/blockchain-midnight/src/signing/midnight-in-memory-transaction-signer.ts:17, 75-77`). This is a Lace UX concern, not part of the connector spec.

## Proving delegation (`getProvingProvider`)

Per 2e — `api.ts:179-180, 348-365` and `SPECIFICATION.md:362-373`:

- Dapp passes a `KeyMaterialProvider` interface (`getZKIR(circuitKeyLocation): Promise<Uint8Array>`, `getProverKey(...)`, `getVerifierKey(...)`).
- Wallet returns a `ProvingProvider` (`check(serializedPreimage, keyLocation): Promise<boolean>`, `prove(serializedPreimage, keyLocation, overwriteBindingInput?): Promise<...>`).
- The wallet is **trusted** to see proof preimages — privacy boundary: dapps that mind preimage exposure must use a different proving stack (none provided by spec).
- Note: prover keys may be 10–80MB+ (`SPECIFICATION.md:368`) — transport limits matter on browser channels.

Per 2f — Lace's `DappZkConfigProvider` wraps the dapp's `KeyMaterialProvider` to adapt to the SDK's `ZKConfigProvider` interface (`lace/packages/module/dapp-connector-midnight/src/store/dependencies/midnight-dapp-connector-api.ts:69-87`). Lace passes proofs through to `httpClientProvingProvider` (`@midnight-ntwrk/midnight-js-http-client-proof-provider`) — i.e., **HTTP to a proof-server**, not in-process. Confirms W-1 (HTTP-only proving in the field) for a third source.

This is the closest analogue OWS has for the route C (hosted proof-server) shape. Routes A (in-process Rust) and B (in-WASM Rust) per the scope's 8.4.2026 lean both go beyond what either Lace or `prover-client` offers today.

## Permission model

- Permissions are **opaque to dapps**. Methods reject with `PermissionRejected` (`errors.ts:23`); dapps cannot proactively ask "do I have permission for X?".
- `hintUsage(methodNames)` is **advisory** (`api.ts:203`) — wallets may use it to batch permission prompts; no return value, no guarantee. Dapps cannot tell which hints were honoured.
- Per 2f — Lace uses `hintUsage` plus a manual authorize-on-first-call flow with origin whitelist (`lace/packages/module/dapp-connector-midnight/src/store/dependencies/dapp-connector.ts:43-155`). Sender context is appended to method args via a Lace-internal overload (`balanceSealedTransaction(tx, optionsOrSender?, senderContext?)` at `:244-248`); spec is unaware. Internal middleware hides the third parameter.

## v4 vs v3 vs current source — drift checks

Per 2e — RELEASE_NOTES_v4.0.0.md vs `src/api.ts` v4.0.0:

- **Zero drift** between release-notes line items and `src/api.ts`. All 16 documented v4 changes appear in source.

Per 2e/2f — **One real spec contradiction inside v4.0.0** (X-5, new):

| Spec evidence | api.ts evidence |
|---|---|
| `SPECIFICATION.md:95-97`: `type DustBalance = { getDustBalance(): Promise<bigint>; }` — single bigint | `api.ts:84`: `getDustBalance(): Promise<{ cap: bigint; balance: bigint }>` — object with both fields |

Lace follows `api.ts` (`{cap, balance}`), not the SPECIFICATION.md text. Conclusion: `api.ts` is the de-facto contract; `SPECIFICATION.md:95-97` is stale prose. OWS port should target the `{cap, balance}` shape and treat `api.ts` as the source of truth for the wire format. Recorded as X-5 in `open-questions.md`.

## Lace as production reference (per 2f)

The three Lace packages stack as:

```
dapp-connector-midnight (lace-extension only)  ← injects window.midnight[uuid]
   └─ midnight-context (shared)
        └─ blockchain-midnight (lace-extension + lace-mobile)  ← signing, sync, tx-executor
              └─ @midnight-ntwrk/wallet-sdk-* (the 2c packages)
```

**Notable lace-internal extensions** beyond the connector spec:

- **Branded value objects** (`midnight-address.vo.ts`, `midnight-network-id.vo.ts`) — wrap SDK types for compile-time safety. OWS Rust port has the equivalent in newtypes.
- **Deferred sync** (`store/deferred-sync-service.ts`) — lazy `WalletFacade` initialization per account; only spin up when needed.
- **Reactive watch pattern** (`store/side-effects/watch.ts`) — multi-account state stream.
- **Dust as a synthetic UI token** (`dust-token.ts`) — Lace creates a UI-only `DustToken` wrapper with `decimals=2` for display; not backed by indexer rows. Reinforces "dust is a fee resource, not a token" naming hygiene from `midnight-wallet/CLAUDE.md`.
- **Dust designation flow** as a separate tx type (`dust-designation`) — Lace UX for registering NIGHT UTxOs to generate dust. Not in connector spec.
- **TTL hard-coded at 1 hour** — `lace/packages/contract/midnight-context/src/const.ts:14`. Connector spec doesn't mandate; this is Lace's UX choice.
- **Network config user-overridable** (`store/slice.ts:62-100`) — user can point Lace at any node/indexer/proof-server URL. **Security note:** no UI warning; user could be tricked into a malicious indexer. OWS should ship with a stricter default and explicit warning on URL change.

**Likely Lace bugs / divergences worth recording** (X-6, X-7, X-8 in `open-questions.md`):

- **`makeTransfer` skips origin authorization** in Lace (`midnight-dapp-connector-api.ts:348-371`) — it passes empty sender `{}` to the confirmation callback (`:365`) instead of validating the origin. Other tx methods do validate. This may be a real security bug or a deliberate design choice for read-after-connect; either way it's a divergence from how Lace treats the other methods. **Recorded as X-6 — needs upstream check.**
- **`signData` data prefix unverified** — spec mandates the wallet must prefix `data` with `midnight_signed_message:<size>:` before signing (`SPECIFICATION.md:359`). The Lace `signData` body wasn't fully visible in the 2f read window; if absent, this is a security bug that lets a dapp trick the wallet into signing transaction-shaped bytes. **Recorded as X-7 — needs full read of Lace's signing path.**
- **Persistence asymmetry**: Lace persists dust balance cache and network configs but **does not persist the wallet sync state itself** — sync state hydrates from the SDK on each session. The IOHK 8.4.2026 update for OWS pushes the opposite direction (persist sync state to keep latencies low). OWS will diverge from Lace on this axis.

## What this means for OWS

- **OWS↔AI-agent boundary can mirror the connector shape closely.** The scope's 8.4.2026 framing ("OWS and AI agent are in a similar relation as wallets and dapps") aligns with v4: hex-only tx blobs, three separate address methods, granular permission model. The OWS port can lift method names and types directly with minor renaming.
- **OWS cannot lift `connect(networkId)` semantics** without translation. CAIP-2 vs bare string. OWS chooses: adopt bare strings internally (consistent with Midnight; breaks OWS's CAIP-2 discipline) or wrap the connector (extra layer; preserves CAIP-2 contract). Phase 3 picks.
- **Permission model is more fine-grained than OWS today.** OWS's existing `Policy.action == Deny` is binary; the connector exposes per-method `PermissionRejected`. If OWS surfaces a Midnight policy primitive, it can map cleanly to per-method permission via executable policies — but the existing `AllowedChains`-style rule is too coarse.
- **Proving delegation is a useful seam.** Dapps can pass their own `KeyMaterialProvider`; wallet returns a `ProvingProvider`. OWS can use the same shape as a pluggability seam between OWS-core (Rust) and a higher-level orchestrator that supplies CRS / prover keys.

## True 2g — Lace verification (closes X-6, X-7) + midnight-js boundary (closes H-6)

> Source: deep read of `raw-context/lace/.../midnight-dapp-connector-api.ts` (full file) and `raw-context/midnight-js/{AGENTS.md, CLAUDE.md, packages/}`.

### X-7: signData prefix — **CONFIRMED BUG** (escalate)

Lace's `signData` method body (`midnight-dapp-connector-api.ts:555-579`) decodes the input encoding (hex/base64/text via `decodeSignData`, `:715-733`) and passes raw bytes directly to `wallet.signData(dataBytes)` (`:574-575`). **No `midnight_signed_message:<size>:` prefix is applied.**

Test expectations confirm the wallet receives unwrapped bytes (`midnight-dapp-connector-api.ts:1053-1055, 1081-1083, 1109-1111`):

```typescript
expect(mockSignData).toHaveBeenCalledWith(new Uint8Array(Buffer.from('48656c6c6f', 'hex')))
```

— a direct decode, no wrapping.

**Severity: CRITICAL.** A malicious dapp can craft bytes that, when signed, encode a valid transaction. Violates connector spec `SPECIFICATION.md:359` (the prefix mandate). **OWS port must apply the prefix unconditionally before passing to the wallet's signing primitive.** Existing invariant CN-I-4 captures the spec mandate; LC-I-6 (new) captures the Lace gap.

### X-6: makeTransfer origin authorization — **CONFIRMED BUG** (escalate)

Lace's `makeTransfer` method (`midnight-dapp-connector-api.ts:348-402`) explicitly casts an empty object to `Runtime.MessageSender`:

```typescript
{} as Runtime.MessageSender,
```
(`midnight-dapp-connector-api.ts:365`)

**`makeIntent` shows the same pattern** (`:512-523`). Compare with `balanceSealedTransaction` (`:244-292`) which calls `resolveSenderAndOptions` (`:630-648`) and **throws** `APIError(ErrorCodes.InternalError, 'Missing sender context')` if sender is missing.

**Severity: HIGH.** The user-facing confirmation dialog has no origin attribution — the user can't tell which dapp initiated the transfer. A malicious dapp can submit `makeTransfer` calls and the wallet has no per-dapp permission scope for them.

**Attack scenario:** dappX calls `makeTransfer(amount, dappX_recipient)`. The wallet's confirmation UI shows the action but no origin. dappY (legitimate, concurrent) calls `balanceSealedTransaction` and shows "dappY requests a transaction." A user approving both could not have intended to authorize dappX, but the wallet has no way to surface the discrepancy.

**Pattern looks intentional** (both `make*` methods, no test expectations for sender context) — it's a deliberate choice with the wrong tradeoff. **OWS port must validate origin on every method, no exceptions.**

### midnight-js vs midnight-wallet boundary (closes H-6)

The boundary is clean and zero-overlap:

| Concern | Owner | Boundary point |
|---|---|---|
| Key custody | midnight-wallet | `WalletProvider` interface |
| Signing | midnight-wallet | `WalletProvider.balanceTx()` (`wallet-provider.ts:35`) |
| Tx finalization (binding + signing) | midnight-wallet | `WalletProvider.balanceTx()` returns `FinalizedTransaction` |
| Blockchain state sync | midnight-wallet | wallet-internal |
| Proof generation | midnight-js (logic) ↔ wallet (in-process route A) | `ProofProvider.proveTx()` (`proof-provider.ts:22`) |
| ZK config (proving keys) | midnight-js | `ZKConfigProvider` interface (`fetch-zk-config-provider`, `node-zk-config-provider`) |
| Public-data indexer client | midnight-js | `PublicDataProvider` (`indexer-public-data-provider`) |
| Private state storage | midnight-js (abstraction) ↔ wallet (impl) | `PrivateStateProvider` interface |
| Contract calls | midnight-js | `@midnight-ntwrk/midnight-js-contracts` |
| Network ID handling | midnight-js | `network-id` package |

**Tx flow** (`midnight-js/AGENTS.md:50-56`):
```
UnprovenTransaction → ProofProvider.proveTx() → UnboundTransaction
  → WalletProvider.balanceTx() → FinalizedTransaction  ← SIGNING HAPPENS IN WALLET
  → MidnightProvider.submitTx() → TransactionId
```

**Verdict: CLOSED.** midnight-js is unambiguously a dapp SDK with no wallet runtime code. midnight-wallet is unambiguously a wallet runtime with no dapp SDK code. The boundary is `WalletProvider`: midnight-js calls it, midnight-wallet implements it. Zero exceptions.

**Implication for OWS:** if OWS-core is the wallet runtime in this layering, OWS provides the `WalletProvider` impl + the in-process proving provider (route A). midnight-js (or its OWS-side analogue) lives outside OWS and orchestrates the contract/proof/balance flow on the dapp side.

### Proving topology (refined)

| Route | midnight-js package | Wallet involvement |
|---|---|---|
| **Route A (wallet-delegated proving)** | `dapp-connector-proof-provider` | Wallet runs prover via `getProvingProvider()` |
| **Route C (remote proof server)** | `http-client-proof-provider` | Wallet not involved; dapp calls server (Lace-style: local Docker `localhost:6300`) |

(Route B "in-WASM Rust" — neither package supports today; an OWS pioneer.) Combined with the ZK config split (`fetch-zk-config-provider` for browser HTTPS, `node-zk-config-provider` for Node.js filesystem), midnight-js's pluggability is fine-grained: ZK artifacts are independent of the proving route.

## Open questions refined / closed

- **X-3 (OWS↔connector boundary shape):** **closed by-finding (partial)** — bare strings, not CAIP-2. Translation layer required; Phase 3 picks where to put it.
- **X-4 (one chain or three sibling chains):** **closed by-finding (strong bias toward single chain)** — connector enforces three address types per account; WalletEngine spec models Midnight as one ledger. Sibling-chain modeling would deviate from upstream and break logical-account unity. Phase 3 confirms.
- **X-5 (NEW): connector spec self-inconsistency on `getDustBalance` shape** — `SPECIFICATION.md:95-97` says `Promise<bigint>`; `src/api.ts:84` says `Promise<{cap, balance}>`. Lace + 2e source-of-truth read agree on `{cap, balance}`. OWS targets `api.ts` shape; flag upstream.
- **X-6 (NEW): Lace `makeTransfer` skips origin authorization.** Security review needed.
- **X-7 (NEW): Lace `signData` prefix application unverified** for the v4.0.1 implementation. Full read of Lace's signing path needed.
- **X-8 (NEW): user-overridable indexer URL in Lace without UI warning.** OWS port should make this stricter.
- **Q-connector-1 (OWS↔AI-agent message envelope):** **partial — the connector itself is async-Promise; multi-process OWS may need an envelope, not part of v4 spec.** Defer to phase 3.
- **Q-connector-2 (wallet must be online):** **partial — spec doesn't address sync state at the API boundary; Lace defers all queries until SDK is ready (deferred-sync-service).** OWS should require explicit sync-state guarantees.
- **Q-connector-3 (address-type per-method or per-domain):** **closed by-finding — per-method.** `kind: "shielded" | "unshielded"` on `DesiredOutput` / `DesiredInput`. No domain-scoping in v4.
- **Q-connector-4 (NEW): Configuration `networkId: string | NetworkId` — `NetworkId` undefined.** Forward-compat placeholder or stale type? Confirm with upstream.
- **Q-connector-5 (NEW): `signData` only supports `keyType: "unshielded"`.** Shielded-key signing intentional out-of-scope or v4 limitation? Affects policy authorization scope.
- **Q-connector-6 (NEW): `hintUsage` carries no return data on which hints were honoured.** Intentional opacity, or missing feedback channel?

See `open-questions.md` for the canonical ledger of statuses across all topics.
