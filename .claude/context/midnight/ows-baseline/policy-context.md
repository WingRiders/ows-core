# Policy context — `ows-core::policy`

## Definitions

`ows/crates/ows-core/src/policy.rs:1-131`

```rust
pub enum PolicyAction { Deny }                      // policy.rs:6-7

pub enum PolicyRule {                                // policy.rs:13-23
    AllowedChains { chain_ids: Vec<String> },
    ExpiresAt { timestamp: String },
    AllowedTypedDataContracts { contracts: Vec<String> },
}

pub struct Policy {                                  // policy.rs:27-40
    pub id, name, version, created_at: ...,
    pub rules: Vec<PolicyRule>,
    pub executable: Option<String>,                  // path to executable policy program
    pub config: Option<serde_json::Value>,           // opaque
    pub action: PolicyAction,
}

pub struct PolicyContext {                           // policy.rs:44-54
    pub chain_id: String,                            // CAIP-2
    pub wallet_id: String,
    pub api_key_id: String,
    pub transaction: TransactionContext,             // ← key model assumption
    pub spending: SpendingContext,                   // opaque, future
    pub timestamp: String,                           // ISO-8601
    pub typed_data: Option<TypedDataContext>,        // EIP-712 only
}

pub struct TransactionContext {                      // policy.rs:58-71
    pub to: Option<String>,
    pub value: Option<String>,                       // string-encoded smallest unit
    pub raw_hex: String,                             // ← signable payload (or empty)
    pub data: Option<String>,                        // EVM calldata
}

pub struct SpendingContext {                         // policy.rs:75-80
    pub daily_total: String,                         // reserved for future use
    pub date: String,                                // YYYY-MM-DD
}

pub struct TypedDataContext {                        // policy.rs:84-101
    pub verifying_contract, domain_chain_id, primary_type, domain_name, domain_version, raw_json,
}

pub struct PolicyResult {                            // policy.rs:105-112
    pub allow: bool,
    pub reason: Option<String>,
    pub policy_id: Option<String>,
}
```

## Model assumptions

1. **Account model.** `TransactionContext` has `to`/`value`/`data` — single sender → single recipient. UTxO chains today flatten into this (Bitcoin/Cosmos/Tron's whole tx serializes into `raw_hex`; the `to`/`value` slots are best-effort).
2. **One transaction per signing request.** `PolicyContext.transaction` is singular. No batch.
3. **`raw_hex` is the signable payload string.** The doc-comment says: "Empty for non-transaction signing requests such as typed data, which is instead exposed via `TypedDataContext::raw_json`."
4. **Decoupled from chain semantics.** Built-in rules see only `chain_id`, `to`, `value`, `raw_hex`, `data` strings. They don't deserialize tx bytes — that's left to executable policies.
5. **Executable policies are opaque-extension points.** A policy can carry `executable` (path) + `config` (opaque JSON), and the rule engine pipes `PolicyContext` JSON to the executable's stdin. This is the only escape hatch for chain-specific policy logic.
6. **`PolicyAction` = `Deny` only.** No "Approve", "Modify", "Forward".

## Built-in rules

Three rules (`policy.rs:13-23`):
- `AllowedChains` — chain-id allowlist.
- `ExpiresAt` — time-based denial.
- `AllowedTypedDataContracts` — verifying-contract allowlist for EIP-712. Pass-through for non-typed-data.

Rule-evaluation logic isn't in this file (it's in `ows-lib`). The struct shape constrains what's *visible* to evaluation.

## Tests

`policy.rs:133-352` — 11 tests cover serde roundtrips for each rule, full `Policy` with executable, full `PolicyContext` with and without typed-data, `PolicyResult` allowed/denied, optional-field omission.

## Salient facts for delta vs. Midnight

- **`raw_hex` is one string.** Midnight transactions are heterogeneous (intents bundling unshielded + shielded + dust effects). Either we widen `raw_hex` semantics to "the canonical signable bytes" and let the executable policy parse, or we add a Midnight-specific extension to `TransactionContext`.
- **No UTxO context.** No `inputs[]`/`outputs[]`. Bitcoin already swallows this in `raw_hex`. Midnight wallet layer needs the *deserialized* tx (intents + their effects on the wallet's UTxO + shielded notes), not just the wire bytes — the scope's "Policy Engine support" section calls this out explicitly. Plausibly this requires a new `MidnightTransactionContext` (or extending `TransactionContext` with optional `Vec<Effect>`).
- **No sync state in `PolicyContext`.** Midnight wallet must consume the indexer's synced wallet state to compute the *net effect* of a tx. Either we extend `PolicyContext` with a `wallet_state: Option<...>` field, or we expect executable policies to fetch state themselves.
- **No CAIP-2 vs OWS-internal disambiguation.** `chain_id: String` accepts whatever — including `midnight:mainnet` while CAIP-2 finalization is pending. Built-in `AllowedChains` matches by string equality, so OWS-internal namespaces work for now.
- **`PolicyAction = Deny` is sufficient for the v1 Midnight scope** (just enforce policies, refuse to sign on violation). If Midnight needs "auto-rebalance" or "transform" policies later, `PolicyAction` must grow.
