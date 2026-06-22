# HD deriver — `ows-signer::hd`

## API

`ows/crates/ows-signer/src/hd.rs:24-193`

```rust
pub struct HdDeriver;

impl HdDeriver {
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> { ... }
    pub fn derive_from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, path: &str, curve: Curve) -> Result<SecretBytes, HdError> { ... }
    pub fn derive_from_mnemonic_cached(mnemonic: &Mnemonic, passphrase: &str, path: &str, curve: Curve) -> Result<SecretBytes, HdError> { ... }
    pub fn validate_path(path: &str) -> Result<(), HdError> { ... }
}
```

Stateless; all methods are static. Returns `SecretBytes` (a zeroize-on-drop wrapper over `Vec<u8>`).

## Curve enum

`ows/crates/ows-signer/src/curve.rs:1-24`

```rust
pub enum Curve { Secp256k1, Ed25519 }

impl Curve {
    pub fn private_key_len(&self) -> usize { 32 }   // both
    pub fn public_key_len(&self) -> usize { ... }   // 33 (compressed) for secp256k1, 32 for ed25519
}
```

**Closed at 2 variants.** No JubJub, BLS12-381, Pasta, ristretto, etc.

## HdError

`hd.rs:8-21` — four variants:
- `InvalidPath(String)` — malformed path
- `DerivationFailed(String)` — wrapped from `coins-bip32`
- `Ed25519NonHardened` — explicit, structured
- `InvalidSeedLength(usize)` — checks 16–64 bytes

## Derivation routes

### secp256k1 — BIP-32

`hd.rs:116-134`. Uses `coins_bip32::derived::DerivedXPriv::root_from_seed` then `derive_path`. Outputs a `k256::ecdsa::SigningKey` whose 32-byte serialization is wrapped as `SecretBytes`.

Allows non-hardened indices (per BIP-32).

### ed25519 — SLIP-10

`hd.rs:137-192`. Inline implementation (no external crate). HMAC-SHA512 master key with `ed25519 seed` constant; per-component HMAC-SHA512 over `0x00 || key || (index + 0x80000000)`. Splits the 64-byte HMAC output into 32-byte key + 32-byte chain code; zeroizes intermediate buffers.

**Hardened-only.** Non-hardened indices (path components without `'`) return `HdError::Ed25519NonHardened` (`hd.rs:148`).

## Cache

`hd.rs:55-86` — `derive_from_mnemonic_cached`:
- Computes cache key as SHA-256 of `phrase ‖ ":" ‖ passphrase ‖ ":" ‖ path ‖ ":" ‖ curve_name`.
- Looks up in `crate::global_key_cache()` — 5-second TTL, 32-entry LRU (`lib.rs:31-33`).
- On miss: derives uncached, inserts, returns.

## Tests

`hd.rs:195-586` — 18 tests covering:
- Per-chain derivation paths (EVM, Solana, Bitcoin, Cosmos, Tron) — `hd.rs:206-240`.
- BIP-32 spec test vectors v1, v2 (`hd.rs:280-362`).
- SLIP-10 spec test vectors v1, v2 (`hd.rs:368-447`).
- Seed-length validation (16–64 byte boundaries) — `hd.rs:451-475`.
- Determinism + characterization tests (`hd.rs:479-585`) including the well-known "abandon" mnemonic → known EVM address `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`.

## Salient facts for delta vs. Midnight

- **Single derivation path per call.** API is `derive(seed, path, curve) → SecretBytes`. Midnight's three-keys-per-account model needs 3× this surface or a new multi-output API.
- **Two curves, exhaustive matched.** `derive`'s match (`hd.rs:36-39`) is `Curve::Secp256k1 | Curve::Ed25519`. Adding JubJub or BLS12-381 requires extending `Curve` and adding a new derivation route. JubJub is a Schnorr-friendly Edwards curve over the BLS12-381 scalar field — typical wallet HD schemes for it use ZIP-32 (Zcash) or a Midnight-specific variant; not addressed by SLIP-10 directly.
- **32-byte private keys, always.** `Curve::private_key_len() = 32` for both supported curves (`curve.rs:11-14`). BLS12-381 fr fits in 32 bytes; JubJub fr fits in 32 bytes. So the byte width is fine; the structure isn't.
- **Cache key includes curve_name as a string.** `hd.rs:72-75` matches on `secp256k1` / `ed25519`. Adding curves needs the cache-key formula updated.
- **Validation is path-shape-only.** `validate_path` (`hd.rs:89-113`) checks "starts with m/" and parsable u32 indices. It doesn't enforce any chain-specific path discipline (e.g., "Solana paths must be all-hardened" is enforced *during* `derive_ed25519`, not at validation).
