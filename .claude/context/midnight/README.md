# Midnight knowledge base

Curated material distilled from `../../../.local/tasks/add-midnight-to-ows/raw-context/`. **Source of truth** for Midnight integration into OWS, organized along two axes:

- **Source axis** (sub-phases that produced the content) — see `../../../.local/tasks/add-midnight-to-ows/phases/phase-2-build-knowledge-base/`.
- **Topic axis** (output organization) — see `topics/`.

## Layout

| Path | Purpose |
|------|---------|
| `delta-table.md` | (a) artifact: dimension × {OWS today, Midnight, kept/changed/new} |
| `failure-modes.md` | (b) artifact: failure-mode inventory |
| `invariants.md` | (c) artifact: assertions in property-test shape |
| `open-questions.md` | open questions blocking phase-3 decisions; status per item |
| `topics/01-addresses.md` | shielded vs unshielded vs dust; Bech32m HRPs; single-address proposal |
| `topics/02-curves.md` | JubJub, BLS12-381, hash primitives, key shapes |
| `topics/03-tx-model.md` | UTxO + shielded notes + dust + intents; lifecycle; balancing; fee |
| `topics/04-proving.md` | ZK proving stack; the route fork (in-process / WASM / hosted); `zkir`/`zkir-v3` |
| `topics/05-indexer.md` | sync state, GraphQL surface, public-indexer status |
| `topics/06-connector.md` | dapp connector API; `balanceTransaction`; `networkId="mainnet"` |
| `topics/07-policy.md` | what extra `PolicyContext` data Midnight needs |
| `topics/08-caip2.md` | `midnight:mainnet` namespace; CAIP-2 finalization |
| `topics/09-state-persistence.md` | sync state across calls; storage |
| `topics/10-bindings.md` | multi-key/multi-address surface across NAPI/PyO3 |
| `ows-baseline/` | LHS material: existing OWS chain abstractions (citations to OWS source) |

## What this is and isn't

**Is:**
- Snapshot of facts as of the source-axis sub-phases populated below. Each fact carries a citation.
- Distilled from raw-context — pinned SHAs in `../../../.local/tasks/add-midnight-to-ows/raw-context/CLONES.md`.
- Living: amended as 2d–2g land. Each amend updates `progress.md` in the phase folder.

**Isn't:**
- Authoritative on contested claims — `open-questions.md` tracks anything under-evidence or contradicted by sources.
- A design proposal — phase 3 (per `task.md`) iterates with the user; phase 5 lists deliverables.
- A replacement for raw-context. When in doubt, check the cited source file.

## Population status

| Sub-phase | Source | Pass | Status | Date |
|-----------|--------|------|--------|------|
| 2a | OWS internals | first | populated | 2026-04-29 |
| 2b | midnight-ledger spec + crates | first | populated | 2026-04-29 |
| 2c | midnight-wallet 17 packages | first | populated | 2026-04-29 |
| 2d | midnight-architecture WalletEngine spec | second | populated (license-pending — user override 2026-04-29) | 2026-04-29 |
| 2e | midnight-dapp-connector-api v4.0.0 | second | populated | 2026-04-29 |
| 2f | lace Midnight packages | second | populated | 2026-04-29 |
| 2g (X-1 only) | curve verification reads | scoped | populated — X-1 closed by-finding (Outcome a) | 2026-04-29 |
| 2g (full synthesis) | L-3 cost model, W-3 state schema, wider X-1 sweep, midnight-js (H-6), Lace verification (X-6/X-7) | last | populated 2026-04-30 (closes L-3, L-8, W-3, H-6; X-6/X-7 confirmed-as-bugs) | 2026-04-30 |

Topic files now have second-pass refinements (01, 02, 03, 06, 07, 10) marked at the file headers. Topic 06-connector replaced placeholder with full content. Cross-cutting files (`delta-table.md`, `failure-modes.md`, `invariants.md`) are append-only — second-pass entries appended in dedicated sections; first-pass content unchanged.

## Scope

The Midnight-only scope extract lives at [`scope/midnight-scope.md`](scope/midnight-scope.md).
