# Topic 07 — Policy engine integration

> **Status:** first-pass populated by 2b + 2c. **Second-pass augmented** by 2d (WalletEngine, license-pending — user override 2026-04-29), 2e (connector v4.0.0), 2f (Lace) — see "Second-pass refinements" section at the bottom.

## What the OWS Policy engine sees today

Per `../ows-baseline/policy-context.md`:
- `TransactionContext { to, value, raw_hex, data }` — flat, account-model.
- Built-in rules: `AllowedChains`, `ExpiresAt`, `AllowedTypedDataContracts`.
- Executable policies receive `PolicyContext` JSON via stdin; can do anything the user's binary supports.
- Single `PolicyAction = Deny`.

OWS today does **not** deserialize transaction bytes inside the policy engine — that's the executable policy's job. The built-in rules see only top-level metadata strings.

## What the Midnight scope demands

`scope/midnight-scope.md § Policy Engine support`:

> To support custom executable policies in the OWS Policy Engine and analyze transactions to be signed, we plan to leverage the deserialization functionality available in the `midnight-ledger` (`midnight-wallet`) repository. Provided we have the synced wallet state (UTxOs) from the indexer, we should be able to determine the effect of the transaction on the wallet to give information to the Policy Engine.

I.e., the policy engine needs:
1. **Deserialization** of Midnight transactions (intents + effects + per-segment offers + balancing). Available via `midnight-ledger::transaction` types + FAB serialization.
2. **Wallet sync state** to compute the *net effect* of a transaction on the agent's wallet (which UTxOs are spent, which created, which dust consumed).

Without (2), the engine can read what the tx claims to do but not what it *means* for this wallet.

## What's deserializable from the tx alone (per 2b)

From `intents-transactions.md`:
- All intents, their segment IDs, TTLs, binding commitments.
- Per-intent `dust_actions` (spend amounts, registrations).
- Per-intent `actions` — contract calls with **pre-declared `Effects`** (claimed nullifiers, claimed shielded receives/spends, mints, unshielded inputs/outputs).
- Top-level `guaranteed_offer` (Zswap inputs/outputs, always executes).
- Top-level `fallible_offer` map (segment → ZswapOffer for fallible parts).
- The per-input unshielded UTXO addresses and amounts (in the unshielded offers).

From `dust.md` + `night.md`:
- Token type per Zswap input/output (segregated by `token_type` for balance proofs).
- Unshielded sender/recipient pubkey hashes (Schnorr verifying-key hashes).

The pre-declared-effects model is a gift to policy engines: validators (and policies) can check what a tx *claims* to do without running the contract.

## What requires wallet state to compute

- "What's the net change in MY balance?" — needs the wallet's UTXO + shielded coin set + dust accruals to identify which inputs are mine vs which outputs come back to me as change.
- "Is this tx draining my unshielded UTxOs to a non-allowlisted address?" — needs the wallet's address.
- "Does this tx spend a Zswap commitment my dust depended on?" — needs the wallet's dust generation map.

Per scope: the *deserialized tx* gives the structural view; the *wallet state* turns it into ownership semantics.

## Policy-relevant invariants (selected from 2b §C)

- "every Zswap input produces exactly one nullifier claimed and added to ledger state" — a built-in rule could enforce "this nullifier must match an unspent commitment in *my* coin set, otherwise this tx isn't mine to sign."
- "every Intent has a valid TTL within `[tblock, tblock + global_ttl]`" — `PolicyRule::ExpiresAt` already handles per-intent TTLs as long as the engine can read the smallest TTL across intents.
- "transaction balance per token per segment is zero" — balance check ensures we're not signing a tx that takes more than it gives. A built-in `ChainSpecificBalanceCheck` rule could enforce this without executable policies, given deserialization.

## What this means for OWS

Two design forks:

### Fork PA: extend `TransactionContext`

Add optional Midnight-specific fields to `TransactionContext`:

```rust
pub struct TransactionContext {
    pub to: Option<String>,
    pub value: Option<String>,
    pub raw_hex: String,                                       // FAB-encoded Midnight tx
    pub data: Option<String>,
    // new (Midnight)
    pub midnight_intents: Option<Vec<MidnightIntent>>,         // deserialized
    pub midnight_balance_changes: Option<Vec<BalanceDelta>>,   // computed using wallet state
}
```

Pros: built-in rules can directly inspect intents. Cons: bloats `TransactionContext` for non-Midnight chains; Midnight-specific fields in shared struct.

### Fork PB: parallel `PolicyContext` variant

Add a `PolicyContextV2` or `MidnightPolicyContext` shape that wraps the existing `PolicyContext` and adds Midnight-specific fields. Built-in rules for Midnight know how to consume it; the shared `PolicyContext` stays clean.

Pros: clean separation. Cons: more types; rule dispatch must be chain-aware.

### Fork PC: defer to executable policies

Keep `PolicyContext` flat. Provide `MidnightHelper::deserialize(raw_hex)` to executable policies. Engine itself stays Midnight-agnostic.

Pros: minimal core change. Cons: relies on every Midnight-aware policy author to call the helper consistently; built-in `AllowedChains`-style rules can't enforce Midnight-specific constraints.

The scope leans toward PA or PB by virtue of demanding "give information to the Policy Engine" — i.e., the engine itself becomes Midnight-aware. Phase 3 picks.

## Pre-declared effects as a policy primitive

If we build a Midnight-aware engine, **pre-declared `Effects`** become a powerful primitive. A rule like "deny if this tx mints a non-allowlisted token type" can check `effects.unshielded_mints` directly without running any program. This is a gift unique to Midnight; OWS should exploit it.

## Open questions

- **Q-policy-1:** which fork (PA/PB/PC) does OWS pick? Phase 3 decision.
- **Q-policy-2:** does the engine need *reverted* effects too (i.e., what happens if a fallible segment fails)? Probably yes, to avoid signing tx where the user-intended segment is fallible and the attacker's segment is guaranteed.
- **Q-policy-3:** how is wallet sync state passed to executable policies? Via stdin (alongside `PolicyContext`), or via env vars / a side file?
- **Q-policy-4:** does the policy engine need access to the indexer at evaluation time to fetch Merkle proofs for input-validity checks? Probably no — the prover already does that — but a paranoid policy might want to double-check.

## Second-pass refinements (2d / 2e / 2f)

**2d (WalletEngine `Specification.md`):** policy is **explicitly out of WalletEngine scope** — delegated to application layer and consensus rules. Intent TTL (`ttl` field per intent) provides replay protection per `Specification.md:843`. WalletEngine produces transactions; doesn't authorize them. **OWS owns the policy/authorization layer entirely** — no upstream pattern to follow on this axis.

**2e (connector v4.0.0):** the connector exposes a granular permission model that is structurally finer-grained than OWS's binary `Policy.action == Deny`:

- Per-method permission rejection via `PermissionRejected` error code (`errors.ts:23`).
- Advisory `hintUsage(methodNames)` (`api.ts:203`) lets dapps pre-declare expected method usage so wallet can batch-prompt for permissions.
- **No proactive permission inspection** — dapps cannot ask "do I have permission for X?" before calling. Try-and-catch is the only path. Permissions are opaque to the dapp.
- **Effects are not exposed to the dapp.** The connector hides declared `Effects`; dapps construct intents, wallet internalizes effect analysis. **Implication for OWS:** the connector boundary cannot expose pre-declared effects to a policy engine sitting on the other side; the policy engine must run *inside* the wallet (or have privileged access to the wallet's deserialized intents). Pre-declared effects as a policy primitive only works at the wallet layer, not the dapp ↔ wallet boundary.
- Wallet **may** prompt user for permissions during `connect(networkId)` (`SPECIFICATION.md:73`); MAY not MUST.
- Wallet **may** ask user for permission scope per `SPECIFICATION.md:322-323`. Spec implies all transaction methods should enforce authorization, but doesn't make it a MUST in all cases — see X-6 below for the resulting Lace behavior.

**2f (Lace) — production permission patterns:**

- **Origin whitelist** with sender-context middleware (`lace/packages/module/dapp-connector-midnight/src/store/dependencies/dapp-connector.ts:43-155`). Each request goes through: lock check → authenticator check → origin whitelist check → fee-payment option transform.
- **Authorization not persisted across sessions** for Midnight in Lace — the dapp-connector store has no persist config. User re-authorizes each session. (Different from how Lace handles Cardano dapp authorization.)
- **`makeTransfer` skips origin authorization** (Lace bug or design choice; X-6 in [open-questions.md](../open-questions.md)). Other tx methods validate via `handleRequestValidation`. If this is a bug, OWS port must not replicate.
- **`signData` prefix application** — spec `SPECIFICATION.md:359` mandates `midnight_signed_message:<size>:` prefix; Lace's full implementation wasn't visible in 2f's read window. X-7 — needs verification. **OWS port must enforce this prefix unconditionally.** Without it, a dapp can trick the wallet into signing transaction-shaped bytes.

## Second-pass open questions

- **Q-policy-5 (NEW from 2e):** OWS↔AI-agent policy boundary — does the policy engine sit inside OWS (sees deserialized intents and pre-declared effects) or outside OWS (only sees hex-blob `raw_hex`)? Phase 3 architectural decision. Cross-references topic 06 Q-connector-1.
- **Q-policy-6 (NEW from 2f):** Does OWS persist agent authorization across sessions, or re-authorize each session like Lace does for Midnight? Tradeoff: persistence = better UX, fresh authorization = better security. Phase 3.
- **Q-policy-7 (NEW from 2f X-7):** Should OWS expose a `signMessage` method at all for shielded keys, or restrict signing to unshielded only (matching the v4 connector's `keyType: "unshielded"`)? Q-conn-new-5 in [topic 06](06-connector.md) tracks the upstream side.
