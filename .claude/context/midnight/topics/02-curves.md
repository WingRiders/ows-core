# Topic 02 — Curves and cryptography

> **Status:** first-pass populated by 2b (ledger spec). 2c (wallet) confirmed wallet-layer treats curves as opaque ledger types. **Second-pass refinement by scoped 2g X-1 verification (2026-04-29):** X-1 closed by-finding — see "Curve disagreement (X-1) — closed" below. 2d (WalletEngine) confirms Schnorr-secp256k1 (BIP-340) for unshielded. 2f (Lace) consumes ledger types unchanged. Wider X-1 sweep (effects on `invariants.md`, `topics/04-proving.md`) **deferred** to a future 2g plan.

## Curves used by Midnight

Per 2b — `midnight-ledger/spec/preliminaries.md` and crate dependencies:

| Curve | Where | What for |
|---|---|---|
| **secp256k1** | `base-crypto` (depends on `k256`) | Schnorr signatures (BIP 340) for unshielded UTXO spends and Dust registration intents |
| **JubJub** (over BLS12-381 scalar field) | `transient-crypto`, `midnight-zk/curves` | Embedded curve for Pedersen commitments; binding randomness; `embedded::CurvePoint` |
| **BLS12-381** | `midnight-zk/curves`, via `midnight-curves` (v0.2.0) | Outer pairing-friendly curve for KZG commitments / proof system; CRS lives here |
| (none EdDSA) | — | **No Ed25519.** X-1 closed by-finding (2g, 2026-04-29) — see below. |

Heritage (per `raw-context/index.md`): `midnight-zk/curves` forks `blstrs` (Filecoin) for BLS12-381 and `jubjub` (Zcash) for JubJub, then diverged. Dual licensed Apache-2.0 OR MIT for `curves/` only — favorable for vendoring.

## Hash functions

Per 2b — `preliminaries.md`:

| Hash | Use |
|---|---|
| **SHA-256** | Coin commitments, nullifiers, contract addresses, transaction-level metadata. Standard Merkle-Damgård; `sha2` crate. |
| **Poseidon** | ZK-friendly hash in field `Fr`. Used for embedded-curve hash (Pedersen base selection: `hash_to_curve(coin.type_, segment)`), Dust nonces (`field::hash((InitialNonce, seq, sk))`), and internal circuit constraints. Provided by `midnight-circuits` / `midnight-zk-stdlib`. |
| **HMAC-SHA512** (caller side) | BIP-32 HD derivation only. Not part of consensus. |
| **Field-aligned** | `serialize/spec/field-aligned-binary.md` — alignment-aware FAB encoding. Not a hash. |

Important: Poseidon parameters (number of rounds, S-box constants) are inherited from `midnight-circuits`; not re-specified in the ledger spec. Spec defers to the trusted implementation.

## Key shapes

| Domain | Secret key | Public key | Notes |
|---|---|---|---|
| Unshielded (Night) | secp256k1 scalar (32 B) | secp256k1 verifying key | Per 2b — Schnorr (BIP 340). Address = `Hash<VerifyingKey>` (`night.md`). |
| Shielded (Zswap) | Random 256-bit `ZswapCoinSecretKey` | `ZswapCoinPublicKey = SHA-256(ZswapCoinSecretKey)` | Per 2b — `preliminaries.md`. Plus separate "encryption" pubkey for `ShieldedAddress` (full address = coin pk ‖ enc pk, 64 B). |
| Dust | `DustSecretKey ∈ Fr` (256-bit field elt) | `DustPublicKey = field::Hash<DustSecretKey>` (Poseidon-in-field) | Per 2b — `dust.md`. ZK-friendly. |

All private keys are 32 bytes by byte-width (fits in OWS's `Curve::private_key_len = 32`). Structurally, dust keys are field elements (not raw bytes) and need canonical reduction; OWS must not assume "any 32 bytes is a valid private key" for dust.

## Trusted setup

Per 2b §G — `midnight-proofs` (v0.7.0+) provides the proving keys / CRS. **Spec does not document:**
- CRS size on disk.
- MPC ceremony details (was there a Powers-of-Tau-style multi-party computation, or a trusted dealer?).
- Verifier-key embedding mechanism in shipped binaries.

These are deferred to `midnight-proofs` library docs. Open question for any in-process Rust port — vendoring `midnight-proofs` requires shipping or downloading the CRS.

## Zeroization

Per 2b — all crypto crates depend on `zeroize = "^1.8.0"`. Implicit requirement: secret-key types implement `Zeroize` on drop. OWS already enforces this via `SecretBytes` (`ows-signer/src/zeroizing.rs`). Compatible — we'd wrap Midnight key bytes the same way.

## What this means for OWS

- **`Curve` enum extension required.** OWS's `Curve` enum (`ows-signer/src/curve.rs:3-6`) is `Secp256k1 | Ed25519`. Adding Midnight needs `JubJub` and `Bls12_381` (or generalized variants). Affects `private_key_len`/`public_key_len` arithmetic — JubJub/BLS12-381 fr fits in 32 bytes; pairing-curve points are larger but typically not stored as private keys.
- **HD derivation needs a route for JubJub.** Neither BIP-32 (secp256k1) nor SLIP-10 (ed25519, hardened-only) cover JubJub directly. Midnight's `hd/` package uses BIP-32 secp256k1 for *derivation*, then curve-specific *transformation* per role. Plausibly OWS does the same: derive 32-byte material via BIP-32, then per-role transform to JubJub fr / dust fr / secp256k1 sk.
- **Hash registry.** `ows-signer` doesn't currently expose Poseidon or SHA-256 as named primitives — it uses Keccak256/SHA-256 inline in chain signers. Midnight's hash discipline (Poseidon for Pedersen, SHA-256 for commitments) needs to be preserved by any port.
- **Vendoring strategy.** `midnight-zk/curves` is dual-licensed Apache-2.0 OR MIT, favorable. The minimum vendor is `curves/` (BLS12-381 + JubJub). For proving (out of scope for 2a–2c) we'd need `midnight-proofs`, `midnight-circuits`, `midnight-zk-stdlib` per 2b.

## Curve disagreement (X-1) — closed

Outcome **a** of the three outcomes anticipated in the plan: **2c misnamed Ed25519 from a generic API name; the wallet wraps the ledger's Schnorr-secp256k1 (BIP-340) primitive directly.** No translation layer.

Evidence:

- **Ledger source-of-truth:** `midnight-ledger/base-crypto/src/signatures.rs:14-18` says verbatim "Schnorr over secp256k1, conforming to BIP340." The module imports `k256::schnorr` and wraps `schnorr::VerifyingKey`, `schnorr::SigningKey`, `schnorr::Signature` directly. Key length is 32 bytes (BIP340 field encoding); signature is 64 bytes (`signatures.rs:125, 270`). License Apache-2.0.
- **Wallet does not redefine the type:** `midnight-wallet/packages/unshielded-wallet/src/v1/Keys.ts:15` imports `SignatureVerifyingKey` from `@midnight-ntwrk/ledger-v8`. `KeyStore.ts:14-21` imports `signatureVerifyingKey`, `signData`, `addressFromKey` from the same package. The wallet provides a `UnshieldedKeystore` interface (`KeyStore.ts:40-46`) that delegates `signData`, `getPublicKey` to ledger functions; no curve choice happens at the wallet layer.
- **WalletEngine spec confirms:** `midnight-architecture/components/WalletEngine/Specification.md:218` says verbatim "Unshielded tokens use Schnorr signature over secp256k1 curve" and §B-02 of the 2d agent's structured report cites the same.

The Ed25519 confusion in the 2c first-pass report came from the type **name** `SignatureVerifyingKey` — a generic name in the SDK that, without context, suggests EdDSA. The 2c agent did not look at the implementation source, only the TypeScript imports.

**Implication for OWS:**

- Use Schnorr-over-secp256k1 (BIP-340) for the unshielded path, not Ed25519. OWS's current `Curve::Secp256k1` is the right enum variant; what changes is the **scheme** — OWS chains today use ECDSA over secp256k1 (e.g., EVM); Midnight uses Schnorr (BIP-340). OWS's `evm.rs` ECDSA implementation is **not reusable**; a new Schnorr implementation is needed, or OWS vendors `k256::schnorr` directly.
- The 32-byte private key length and 32-byte public key length match OWS's `Curve::private_key_len = 32` invariant. No length-arithmetic changes needed.
- Key caching shape (`hd.rs:62-76`) is curve+seed+path keyed; adding "Schnorr-secp256k1" as a separate cache key (vs. ECDSA-secp256k1) is required.

## Open questions (remaining)

- **Q-curves-2:** OWS's `Curve` is currently 2 variants. Should new variants be `Bls12_381`, `JubJub` (specific) or a more generic shape (e.g., `Curve::Custom(name)` with per-curve trait)? Affects key-cache key derivation in `hd.rs:72-75` (string match). **Open.**
- **Q-curves-3:** Trusted setup distribution — does OWS need to ship CRS bytes? Or download on first use? Or rely on hosted prover? Tied to [04-proving](04-proving.md)'s route fork. **Open.**
- **Q-curves-4 (NEW from 2g X-1 read):** OWS's `evm.rs` ECDSA implementation cannot be reused for Midnight's Schnorr-secp256k1 (BIP-340). Decide: vendor `k256::schnorr` directly (same dependency Midnight uses), or implement Schnorr-secp256k1 inside OWS. Vendoring trims surface area but adds a public dep to OWS. **Open — phase 3 decision.**
