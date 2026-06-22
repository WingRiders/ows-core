# Topic 04 — ZK proving

> **Status:** first-pass populated by 2b (ledger spec) + 2c (wallet packages). 2f (Lace) and reference-wallet snapshots will further constrain the route fork. **True-2g X-1 sweep (2026-04-30):** verified Schnorr-secp256k1 (BIP-340) framing throughout; Fiat-Shamir Pedersen for binding vs Schnorr for per-input UTXO signing distinction is correct; no edits required.

## What needs proving (per 2b — `midnight-ledger/spec`)

Five proof kinds, all consensus-required:

| Proof | Source spec | What it proves |
|---|---|---|
| `input_valid` | `zswap.md` | Shielded input is in Merkle tree, nullifier correctly derived from secret, value commitment correct. **Public:** `ZswapInput`, segment. **Private:** sk/contract, Merkle tree, coin, randomness. |
| `output_valid` | `zswap.md` | Shielded output commitment correctly derived from coin info + recipient pubkey + randomness; value commitment correct. **Binding input:** ciphertext (if present). |
| `dust_spend_valid` | `dust.md` | Dust input in commitment tree; secret-key ownership; output value = `updated_value(old, gen_info, tnow) - v_fee`; new commitment derivation. **Public:** `DustSpend`, `tnow`, params, commitment_root, generation_root. **Private:** dust, sk, gen, Merkle trees, initial nonce, seq_no. |
| Contract-call execution | `contracts.md` | Program execution against current contract state matches pre-declared effects. **Binding input:** segment + intent.binding_commitment. |
| Intent binding (Fiat-Shamir Pedersen) | `preliminaries.md` | Knowledge-of-exponent over JubJub for the Pedersen sum: `g*s == g*R + C*c` where `c = H(intent_hash, C, T)`. |

## What gets signed (per 2b §E)

Signature primitives are scoped to **unshielded UTXO spends** and the (deferred) Cardano bridge:

| Signing primitive | Used for | Curve / scheme |
|---|---|---|
| **Schnorr (BIP 340) over secp256k1** | Per-input signatures on unshielded UTXO spends; signature payload is `(segment_id: u16, ErasedIntent)` where `ErasedIntent = Intent<(), (), Pedersen>` (signatures + ZK proofs erased). | secp256k1 / BIP 340. |
| (none) | Shielded inputs/outputs, Dust spends, contract calls — all proved by ZK, no traditional signature. | — |

So a single Midnight transaction can carry: 0..N Schnorr signatures (one per unshielded input) + 0..M ZK proofs (one per shielded input/output, dust spend, contract call) + 1 Fiat-Shamir Pedersen proof (per intent).

`SignOutput` (`ows-signer::traits::SignOutput`) carrying a single signature does not match this surface. See [`../delta-table.md`](../delta-table.md).

## Crate stack (per 2b §A)

`midnight-ledger` workspace's ZK-related crates:
- **`zkir` (v2.1.0)** — legacy IR-to-circuit compiler. Still functional; used in tests. Production has shifted to `zkir-v3`.
- **`zkir-v3` (v3.0.0-rc.1)** — current IR compiler. Imports:
  - `midnight-curves` (v0.2.0) — BLS12-381 + JubJub.
  - `midnight-proofs` (v0.7.0+) — proving keys, CRS, prover/verifier.
  - `midnight-circuits` (v6.0.0+) — circuit definitions (`input_valid`, `output_valid`, `dust_spend_valid`, contract-call circuits).
  - `midnight-zk-stdlib` (v1.0.0+) — Poseidon, field arithmetic.
- **`zkir-wasm`, `zkir-v3-wasm`** — WASM bindings for browser / WASM proving.
- **`proof-server/`** — HTTP service crate. Wraps `zkir` for proving.
- **`wasm-proving-demos/zkir-mt`** — browser-WASM proving demos. Per 2b §F not the consensus path.

Minimum-vendor set for **transaction signing only (no proving)**: `ledger`, `zswap`, `onchain-runtime`, `base-crypto`, `transient-crypto`, `serialize`, `coin-structure`, `storage` with non-proving feature flags. Plus `midnight-curves` for cryptographic primitives.

Minimum-vendor set for **in-process proving**: above + `zkir-v3`, `midnight-proofs`, `midnight-circuits`, `midnight-zk-stdlib`.

## The route fork (forks shown, not picked)

Three production-precedent routes for proof generation in OWS Midnight:

| Route | Precedent | Pros | Cons |
|---|---|---|---|
| **A. In-process Rust port** | None upstream (per HANDOVER §6 finding 3 — `midnight-wallet/packages/prover-client/` is a *client*, not in-process) | No external dependency at runtime; private key never leaves the wallet process; matches scope's 8.4.2026 update preference ("WASM prover but use the underlying Rust libraries directly"). | Largest implementation cost; CRS / proving keys must be shipped or downloaded; binary size grows substantially. |
| **B. WASM proving (in-WASM Rust)** | 1AM (closed-source, per `raw-context/reference-wallets/index.md`); also `midnight-ledger/wasm-proving-demos/`. | Browser-targeted; works in WASM-restricted environments; **same Rust libraries as route A** but compiled to WASM. | Slower than native; still ships CRS / proving keys; OWS Node/Python bindings would call WASM rather than native. |
| **C. Hosted proof-server** | Lace + `midnight-ledger/proof-server/` (production default; Lace forwards to local Docker `localhost:6300` v8.0.3). | Production-tested; smallest binary; CRS managed externally. | Private key material must be sent to the prover (or the prover must be co-located with the wallet); operational dependency on a side-process or remote service; prover server may diverge in version. |

**Per scope's 8.4.2026 update:** "built-in WASM prover, but use the underlying Rust libraries directly" — i.e., a hybrid leaning toward route A (Rust libs) but compiled to WASM for distribution to web targets.

## What `prover-client` actually does (per 2c §E)

`midnight-wallet/packages/prover-client/`:

```typescript
class HttpProverClient {
  constructor(config: ServerConfig)  // { serverUrl: string }
  proveTransaction<S, B>(tx: Transaction<S, PreProof, B>, costModel?: CostModel): Promise<Transaction<S, Proof, B>>
}
```

Exclusively HTTP POST to an external proof-server (e.g., `http://localhost:6300`). No WebSocket, no streaming. Errors: `ClientError`, `ServerError`, `InvalidProtocolSchemeError`. **No in-process proving fallback.**

There is a `WasmProver` namespace under `prover-client/src/effect/` (per 2c §E) but no implementation visible. It's a hint at intended future work, not a working route.

So 2c confirms the architecture from §3.

## What gets sent to the prover

Per 2b §F + 2c §E:
- The unproven `Transaction<S, PreProof, B>` (FAB-encoded).
- Optional `CostModel` for fee calculation.

The prover returns `Transaction<S, Proof, B>` with all ZK proofs filled in. **Secret keys never sent** — the prover only needs public data + the prover's own circuit-specific witnesses (which the circuit constructs from the unproven tx; the wallet supplies private witnesses for input/output proofs by including them in the unproven tx structure).

This contradicts a naive worry that "in-process prover keeps the secret key safer than hosted prover." The witness inputs are already present in the unproven tx going to the prover; the secret key isn't. **The `proof-server` route does not expose the user's secret key.**

What it does expose: transaction *content* (recipient, amount). Lace's local Docker prover keeps this on-host. A *remote* hosted prover would leak content to the operator. So the privacy concern is content-level, not key-level.

## CRS / proving keys

Per 2b §G — spec doesn't document:
- CRS size on disk.
- Trusted-setup ceremony details.
- Verifier-key embedding mechanism.

These are deferred to `midnight-proofs` library docs. Plausible OWS questions for phase 3:
- Do we ship CRS in the binary?
- Download on first use? From which URL?
- Cache it where (`~/.ows/midnight/crs/`)?

## Performance

Spec doesn't quote proving times. Lace forwards to a Docker proof-server because in-browser Rust-native proving is impractical (long enough to choke a UI thread). 1AM uses WASM proving in production but also uses Halo2 and Noble Curves — diverges from `midnight-zk` (per HANDOVER §6 finding 4); not directly comparable.

## What this means for OWS

- **`ChainSigner` trait is insufficient** for Midnight's shielded path. Either:
  - Add a separate `Prover` trait that the chain signer composes.
  - Add a `prove_transaction` method to a parallel `MidnightSigner` trait.
  - Hide proving behind `sign_transaction` and silently call the prover (but then `sign_transaction` becomes async or long-running, which is a behavioral break).
- **State carry.** Whichever route is picked, the prover (or proof-server client) needs to carry state: configuration (URL or in-process keys), connection pool, cost model. Stateless `ChainSigner` impls won't do.
- **Per 8.4.2026 scope:** the ramp toward route A (Rust libs directly, WASM-compiled when needed) is the user-stated preference. Phase 3 should commit to that with an explicit OWS task to vendor `zkir-v3` + `midnight-proofs` + `midnight-circuits` + `midnight-zk-stdlib` (estimate substantial).

## Open questions

- **Q-prove-1:** which route does OWS commit to? HANDOVER §7 question 1.
- **Q-prove-2:** if route A — where do CRS/proving keys live? In binary? Downloaded? Per-network?
- **Q-prove-3:** if route C — does OWS bundle a `proof-server` binary (acceptable since it's Apache-2.0), or assume the user runs one separately?
- **Q-prove-4:** `zkir` vs `zkir-v3` — both exist in the workspace. HANDOVER §7 question 5. Pick one; understand the migration story (cost model? hard-fork gate?).
