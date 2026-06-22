# OWS baseline (LHS of the delta table)

Existing OWS chain abstractions, characterized for comparison against Midnight. All claims cite OWS source as `path:line`.

## Files

| File | Covers |
|------|--------|
| `chain-registry.md` | `ows-core::ChainType`, `KNOWN_CHAINS`, `parse_chain`, CAIP-2 mapping |
| `chain-signer-trait.md` | `ows-signer::ChainSigner` — 9 methods, defaults, invariants |
| `hd-deriver.md` | `ows-signer::HdDeriver` — BIP-32/SLIP-10, single-key-per-path |
| `policy-context.md` | `ows-core::policy` — `PolicyContext`, `TransactionContext`, account-model assumption |
| `ffi-bindings.md` | NAPI/PyO3 string pass-through; ChainType not enumerated across FFI |
| `pluggability-seams.md` | What new chains can extend without touching trait/core/policy |

## Source snapshot

Captured 2026-04-29, OWS workspace version 1.3.2 (per `ows/Cargo.toml` workspace members).
