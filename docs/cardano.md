# Cardano Support — Technical Specification

> Status: work in progress. This document specifies the Cardano integration parts
> that are **implemented** in this fork, and flags the parts that are still
> **planned**. It is scoped to three deliverables that are complete:
>
> 1. **Analysis, architecture, and setup** — codebase familiarization, build/test
>    pipeline, and a map of where Cardano fits into the existing abstractions (see
>    [Analysis, Architecture, and Setup](#analysis-architecture-and-setup)).
> 2. **CAIP-2 / CAIP-10 addressing abstraction**
> 3. **Key derivation and cryptography — Ed25519-BIP32**
>
> Transaction building, message/transaction signing, and Shelley address
> encoding are explicitly out of scope for these deliverables and are
> tracked separately.

## Abstract

This specification adds Cardano mainnet support to the Open Wallet Standard (OWS)
reference implementation while preserving OWS's chain-agnostic, local-first design.
It introduces the `cip34` CAIP-2 namespace and registers Cardano mainnet, preprod,
and preview networks with canonical chain identifiers, a coin type, and default
(keyless) Koios RPC endpoints. On the cryptographic side, it adds a new
`Ed25519Bip32` curve (Ed25519-V2 / BIP32-Ed25519) implemented generically via the
`ed25519-bip32` crate, together with the Cardano Icarus master-key scheme and
CIP-1852 hierarchical derivation. Cardano accounts are derived from two credentials
— a payment credential (`role = 0`) and a stake credential (`role = 2`) — which
diverges from OWS's prior assumption that one account maps to a single derivation
path; the key-storage and derivation layers were extended to carry the two
96-byte extended private keys required to later assemble a Shelley base address.

## Motivation

OWS already supports Ed25519 chains (Solana, TON, NEAR) using SLIP-10 derivation,
and secp256k1 chains using BIP-32. Cardano cannot reuse either path:

- **Curve / derivation scheme.** Cardano uses BIP32-Ed25519 ("Ed25519-V2"),
  which extends a 64-byte Ed25519 extended secret key with a 32-byte chain code
  (96 bytes total) and supports both hardened and **non-hardened** child
  derivation. SLIP-10 ed25519 (used by Solana et al.) is hardened-only and is not
  compatible with Cardano wallets.
- **Master key generation.** Cardano (Icarus) derives the root key from the raw
  BIP-39 **entropy** via PBKDF2-HMAC-SHA512, not from the BIP-39 _seed_ used by
  BIP-32 / SLIP-10.
- **Multi-credential addresses.** A Cardano Shelley address is built from two
  independent credentials at two different CIP-1852 derivation paths (payment and
  stake). OWS previously assumed a single derivation path produces a single
  address.
- **Identifier namespace.** Cardano is not an EVM/`eip155`, `solana`, `cosmos`,
  etc. chain; it needs its own CAIP-2 namespace and a deterministic chain
  identifier.

The existing abstractions (`Curve`, `HdDeriver`, `ChainType`, `Chain`,
`ChainSigner`) therefore had to be extended rather than reused as-is.

## Analysis, Architecture, and Setup

### Cryptographic stack

OWS already ships a broad cryptographic toolkit in `ows-signer`. The relevant
existing primitives and the libraries that provide them:

| Concern                       | Library (crate)                          | Used by / notes                                   |
| ----------------------------- | ---------------------------------------- | ------------------------------------------------- |
| secp256k1 ECDSA               | `k256`                                   | EVM, Bitcoin, Cosmos, Tron, XRPL, Spark, Filecoin |
| BIP-32 derivation (secp256k1) | `coins-bip32`                            | all secp256k1 families                            |
| Ed25519 signatures            | `ed25519-dalek`                          | Solana, TON, Sui, NEAR                            |
| SLIP-10 ed25519 derivation    | in-house (HMAC-SHA512 over `hmac`/`sha2`)| hardened-only ed25519 families                    |
| BIP-39 mnemonics              | `coins-bip39`                            | seed + entropy extraction                         |
| Hashing                       | `sha2`, `sha3`, `ripemd`, `blake2`       | address + tx hashing across families              |
| Address encodings             | `bech32`, `bs58` (+check), `base64`      | segwit/bech32, base58check, etc.                  |
| At-rest encryption            | `aes-gcm` + `scrypt`/`hkdf` (`CryptoEnvelope`) | encrypted wallet files                      |
| Secret hygiene                | `zeroize` (`SecretBytes`)                | all key material is zeroized on drop              |

Cardano introduces two additional, Cardano-specific dependencies:

- **`ed25519-bip32` (0.4.1)** — BIP32-Ed25519 ("Ed25519-V2") key derivation:
  96-byte extended private keys (`XPRV_SIZE`), `DerivationScheme::V2`, hardened
  **and** non-hardened children, and `normalize_bytes_force3rd` for valid root
  keys. Chosen so derivation stays in the generic `HdDeriver`, rather than pulling
  a full chain SDK into the key path.
- **`cardano-serialization-lib` (CSL, 14.1.1)** — the canonical Cardano library
  for network parameters (`NetworkInfo`), address construction, and CBOR
  transaction encoding. In the completed deliverables it is used only for
  `NetworkInfo`; later deliverables will use it for Shelley address encoding and
  transaction (de)serialization. Note CSL also pulls in `pbkdf2`, which we use
  directly for the Icarus master-key step.

### Peculiarities of Cardano vs. other OWS chains

Several ways Cardano departs from chains already supported in OWS, each of which
drove a specific design decision later in this document:

1. **Extended-key derivation (96 bytes, V2).** Unlike SLIP-10 ed25519
   (32-byte keys, hardened-only) or BIP-32 secp256k1, Cardano uses BIP32-Ed25519
   with 64-byte extended secret keys + a 32-byte chain code, and allows
   **non-hardened** derivation. This is a new `Curve`, not a tweak to an existing
   one.
2. **Master key from entropy, not seed.** Most chains derive from the BIP-39
   *seed* (PBKDF2 over the mnemonic phrase). Cardano's Icarus scheme derives the
   root key from the raw BIP-39 **entropy** (PBKDF2-HMAC-SHA512, empty password,
   entropy as salt, 4096 iterations). Reusing the seed would yield addresses no
   other Cardano wallet could reproduce.
3. **Two credentials per address.** A Shelley **base** address combines a payment
   credential (CIP-1852 `role = 0`) and a stake credential (`role = 2`), each at
   its own derivation path. OWS's "one path → one address" assumption does not
   hold; the key-storage layer carries 192 bytes (payment ‖ stake).
4. **CIP-1852 purpose, not BIP-44.** Cardano uses purpose `1852'` (not `44'`)
   with coin type `1815'`, and a `role` segment between account and index.
5. **CAIP-2 via CIP-34.** The chain identifier encodes both a network id and a
   network magic (`cip34:<networkId>-<networkMagic>`), rather than a single
   numeric/string reference.
6. **CBOR transactions + keyless RPC.** Transactions are CBOR (handled by CSL
   later); the default RPC provider is keyless Koios, with submission via a binary
   `POST /submittx`.

General specifications worth reading alongside this section:
[CIP-1852](https://cips.cardano.org/cip/CIP-1852),
[CIP-3 (Icarus master key)](https://cips.cardano.org/cip/CIP-3),
[CIP-19 (addresses)](https://cips.cardano.org/cip/CIP-19),
[CIP-34 (chain identification)](https://cips.cardano.org/cip/CIP-34),
the [BIP32-Ed25519 paper](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf),
and the in-repo [`docs/07-supported-chains.md`](07-supported-chains.md).

## Specification

### 1. CAIP-2 / CAIP-10 addressing

#### 1.1 Namespace and chain identifiers

Cardano is identified with the **`cip34`** CAIP-2 namespace, following
[CIP-34](https://cips.cardano.org/cip/CIP-34). The CIP-34 reference encodes the
network as `<networkId>-<networkMagic>`:

| Network | OWS name          | CAIP-2 chain id     | networkId | networkMagic |
| ------- | ----------------- | ------------------- | --------- | ------------ |
| Mainnet | `cardano`         | `cip34:1-764824073` | 1         | 764824073    |
| Preprod | `cardano-preprod` | `cip34:0-1`         | 0         | 1            |
| Preview | `cardano-preview` | `cip34:0-2`         | 0         | 2            |

A new `ChainType::Cardano` variant is added to the chain-family enum
(`ows-core/src/chain.rs`). The namespace mapping is wired in both directions:

- `ChainType::Cardano.namespace()` → `"cip34"`
- `ChainType::from_namespace("cip34")` → `Some(ChainType::Cardano)`
- `ChainType::Cardano.default_coin_type()` → `1815` (SLIP-44 coin type for ADA)

The three networks above are registered in `KNOWN_CHAINS`, so `parse_chain`
resolves both friendly names (`cardano`, `cardano-preprod`, `cardano-preview`) and
raw CAIP-2 ids (`cip34:1-764824073`, `cip34:0-1`, `cip34:0-2`). `cardano` is the
first Cardano entry in the registry, so it is the default for the family
(`default_chain_for_type(ChainType::Cardano)` → mainnet).

#### 1.2 CAIP-10 accounts

CAIP-10 account identifiers follow the existing OWS convention
`chain_id:address`, e.g.

```
cip34:1-764824073:addr1...
```

The account id is assembled in `derive_all_accounts` as
`format!("{}:{}", chain.chain_id, address)`, identical to every other family.

#### 1.3 Universal wallet membership

`ALL_CHAIN_TYPES` now contains 13 families (Cardano appended last). Because a
universal wallet derives one account per family plus the explicitly listed
testnet extras, Cardano contributes three rows:

- `UNIVERSAL_WALLET_EXTRA_CHAIN_NAMES = ["cardano-preprod", "cardano-preview"]`
- `universal_wallet_chains()` therefore yields mainnet (via the family default)
  plus the two testnets, in a stable order.

#### 1.4 RPC configuration (Koios, keyless)

OWS does not currently support authenticated RPC providers, so the default
provider is **Koios**, which offers a keyless free tier. Default endpoints are
registered in `Config::default_rpc()`:

| Chain id            | Default RPC                         |
| ------------------- | ----------------------------------- |
| `cip34:1-764824073` | `https://api.koios.rest/api/v1`     |
| `cip34:0-1`         | `https://preprod.koios.rest/api/v1` |
| `cip34:0-2`         | `https://preview.koios.rest/api/v1` |

RPC resolution reuses the generic precedence already in place: explicit override
→ user config exact `chain_id` → user config namespace match → built-in default.

#### 1.5 Signer resolution

`signer_for_chain` constructs `CardanoSigner::from_chain_id(chain.chain_id)`, which
selects network parameters from the CAIP-2 id (`cip34:0-1` → preprod, `cip34:0-2`
→ preview, anything else → mainnet). Network parameters come from
`cardano-serialization-lib`'s `NetworkInfo`.

### 2. Key derivation and cryptography

#### 2.1 New curve

A third `Curve` variant, `Ed25519Bip32`, is added (`ows-signer/src/curve.rs`):

- `private_key_len()` → `ed25519_bip32::XPRV_SIZE` (96 bytes: 64-byte extended
  secret key + 32-byte chain code)
- `public_key_len()` → 32 bytes

#### 2.2 Master key generation (Icarus)

For `Curve::Ed25519Bip32`, `HdDeriver::derive_from_mnemonic` does **not** use the
BIP-39 seed. Instead it follows the Cardano Icarus scheme
(`ed25519_bip32_master_xprv_from_entropy`):

1. Extract the raw BIP-39 **entropy** (checksum bits excluded) from the mnemonic.
   `Mnemonic::entropy()` was added for this purpose.
2. `PBKDF2-HMAC-SHA512` with an **empty password**, the entropy as the **salt**,
   `4096` iterations, producing a 96-byte output.
3. Normalize the result with `XPrv::normalize_bytes_force3rd` to obtain a valid
   master extended private key.

This is verified against published Icarus test vectors (including the all-zero
"abandon … about" mnemonic).

#### 2.3 Child derivation

`HdDeriver::derive` accepts a 96-byte master `XPrv` for `Ed25519Bip32`
(seed-length validation requires exactly `XPRV_SIZE`; the 16–64 byte rule that
applies to secp256k1/ed25519 is bypassed). Path components are walked with the
`ed25519-bip32` crate using **`DerivationScheme::V2`**, supporting both hardened
(`'`) and non-hardened indices. The result is the 96-byte child `XPrv`.

The deriver continues to expose the same surface for all curves:
`derive`, `derive_from_mnemonic`, and the cached `derive_from_mnemonic_cached`
(the cache key incorporates the `ed25519_bip32` curve tag so it cannot collide
with secp256k1/ed25519 keys for the same path).

#### 2.4 CIP-1852 paths

`CardanoSigner` exposes the CIP-1852 hierarchy
`m / 1852' / 1815' / account' / role / index`, where `role` is
`0` = external/payment, `1` = internal/change, `2` = stake:

| Helper                                    | Path                                 |
| ----------------------------------------- | ------------------------------------ |
| `payment_derivation_path(account, index)` | `m/1852'/1815'/{account}'/0/{index}` |
| `stake_derivation_path(account)`          | `m/1852'/1815'/{account}'/2/0`       |
| `account_derivation_path(account)`        | `m/1852'/1815'/{account}'`           |

Per the agreed scope, only **one base address per account at address index 0** is
supported initially. `default_derivation_path(index)` returns the payment leaf for
account 0 (`m/1852'/1815'/0'/0/{index}`), which is what the generic single-path
key-resolution code (`decrypt_signing_key`, `secret_to_signing_key`) uses today.

#### 2.5 `ChainSigner` integration

`CardanoSigner` implements `ChainSigner`:

- `chain_type()` → `ChainType::Cardano`
- `curve()` → `Curve::Ed25519Bip32`
- `coin_type()` → `1815`
- `default_derivation_path(index)` → payment leaf (see above)

> **Planned (stubbed today):** `derive_address`, `sign`, `sign_message`, and
> `sign_transaction` currently return errors. `derive_address` documents the
> intended input layout: a 192-byte private key = payment `XPrv` (96) ‖ stake
> `XPrv` (96) at matching CIP-1852 indices, from which a Shelley **base** address
> (`addr1…` on mainnet) will be assembled. The Shelley address encoding and the
> signing operations are separate, not-yet-completed deliverables.

#### 2.6 Multi-credential key storage

Because a Cardano account needs two credentials, the multi-curve key material was
extended (`ows-lib/src/ops.rs`):

- The `KeyPair` struct (used for raw-private-key imports) gains an
  `ed25519_bip32` field, serialized as
  `{"secp256k1":"…","ed25519":"…","ed25519_bip32":"…"}`. The `KeyType::PrivateKey`
  doc comment in `wallet_file.rs` is updated accordingly. The wallet-file schema
  version (`ows_version`) is unchanged at `2`; the new field is additive.
- For imported private-key wallets, `random_ed25519_bip32()` generates **two**
  normalized 96-byte `XPrv`s (payment ‖ stake = 192 bytes) so the layout matches
  the planned base-address encoding.
- `KeyPair::key_for_curve(Curve::Ed25519Bip32)` returns this material; empty
  material yields a clear "private key for chain is empty" error for wallets
  imported before Cardano support existed.

#### 2.7 Broadcast plumbing

`broadcast` dispatches `ChainType::Cardano` to `broadcast_cardano`, which POSTs the
raw CBOR transaction to Koios `{rpc}/submittx` (`Content-Type: application/cbor`),
expects HTTP `202`, and returns the 64-hex-character transaction hash. This path is
present but only exercisable once transaction signing/encoding lands.

## Rationale

- **`cip34` namespace.** CIP-34 is the Cardano-native CAIP-2 registration and
  encodes network id + network magic deterministically, which lets a single
  identifier disambiguate mainnet/preprod/preview without inventing OWS-specific
  aliases. CIP-34 is still in _Proposed_ status, which is a known risk we accept
  and monitor.
- **Generic `ed25519-bip32` instead of `cardano-serialization-lib` for
  derivation.** The simplest route would be to derive keys with
  `cardano-serialization-lib` (CSL). OWS deliberately keeps derivation
  chain-agnostic and generic (a single `HdDeriver` across all families), so we
  implement BIP32-Ed25519 with the lightweight `ed25519-bip32` crate and only use
  CSL for Cardano-specific concerns (network parameters now; address/tx encoding
  later). This avoids leaking a chain-specific library into the generic key path.
- **Base address with payment + stake.** Per agreement with IOHK, the initial
  implementation targets exactly one base address per account at address index 0,
  combining a payment credential (role 0) and a stake credential (role 2). This
  keeps the scope bounded while still producing a normal, stake-delegatable
  Shelley address rather than an enterprise (payment-only) address.
- **Two 96-byte keys in `KeyPair`.** Storing payment ‖ stake (192 bytes) up front
  makes the imported-key representation forward-compatible with base-address
  assembly without another schema change.

### Acceptance Criteria

These two deliverables are considered complete when:

1. `ChainType::Cardano` exists and round-trips through serde, `namespace()`,
   `from_namespace()`, `default_coin_type()`, and `Display`/`FromStr`.
2. `parse_chain` resolves `cardano`, `cardano-preprod`, `cardano-preview`, and the
   corresponding `cip34:*` ids; `default_chain_for_type(Cardano)` is mainnet.
3. Default Koios RPC endpoints are registered for all three networks and resolved
   by the generic RPC lookup.
4. `Curve::Ed25519Bip32` reports correct key lengths (96 / 32).
5. `HdDeriver` produces the correct Icarus master `XPrv` from entropy (matches
   published vectors) and performs V2 child derivation, including the CIP-1852
   payment/stake/account paths.
6. `CardanoSigner` reports curve `Ed25519Bip32`, coin type `1815`, and the
   CIP-1852 payment leaf as its default path.
7. Multi-curve key storage carries an `ed25519_bip32` entry (192 bytes for
   imported keys) without changing the wallet schema version.

> Shelley address encoding, message signing, and transaction signing are **not**
> part of these acceptance criteria.

### Implementation Plan

The two deliverables are landed and covered by unit/integration tests (see
[Testing](#testing)). Remaining Cardano work (separate deliverables) proceeds as:
Shelley base-address encoding (consuming the 192-byte payment ‖ stake layout),
transaction context resolution via Koios, transaction signing
(`sign`/`sign_transaction`), CIP-8/CIP-30-style message signing, and optional
alternative RPC providers (e.g. Blockfrost).

## Backwards Compatibility Assessment

- **Wallet file schema unchanged.** `ows_version` stays at `2`. The new
  `ed25519_bip32` key field is additive; existing mnemonic wallets need no
  migration (Cardano keys are derived on demand). Private-key wallets imported
  before Cardano support simply have no `ed25519_bip32` material and surface a
  clear error if used for Cardano, rather than silently degrading.
- **Existing families untouched.** secp256k1 and SLIP-10 ed25519 derivation paths
  are unchanged; the `Ed25519Bip32` branch is additive in `Curve`, `HdDeriver`,
  and `KeyPair`. Characterization tests on EVM/Solana derivation continue to pass.
- **Known abstraction gap.** `WalletAccount` still stores a single
  `derivation_path`, so the stored Cardano account currently records only the
  payment leaf. Carrying both payment and stake paths per account is a noted
  follow-up (`TODO` in `derive_all_accounts`) required before base-address
  derivation is finalized.

## Security Considerations

- **Key material handling.** All derived keys are wrapped in `SecretBytes`
  (zeroized on drop). Intermediate buffers in HD derivation are explicitly
  zeroized. The 96-byte extended private keys are treated as secrets identical to
  other curve keys.
- **Icarus master key.** Uses the standard PBKDF2-HMAC-SHA512 (4096 iterations,
  empty password, entropy as salt) and `normalize_bytes_force3rd`, matching
  ecosystem wallets; deviating would produce incompatible (and potentially
  unrecoverable-by-other-wallets) addresses.
- **Non-hardened derivation.** BIP32-Ed25519 V2 permits non-hardened child keys.
  This is required for Cardano interoperability, but callers should remain aware
  that a non-hardened branch's xpub + a single child xprv can expose sibling keys;
  the default account/payment/stake paths use hardened account-level segments.
- **Key cache isolation.** The derivation cache key includes the curve tag, so
  Ed25519-BIP32 keys cannot be confused with secp256k1/ed25519 keys derived at the
  same BIP path string.
- **Keyless RPC.** Koios needs no API key, avoiding credential storage. Broadcast
  is performed over HTTPS; transaction submission and input resolution will rely on
  this provider, so provider availability/trust is a deployment consideration.

## Implementation

Components modified or added:

- `ows-core/src/chain.rs` — `ChainType::Cardano`; `cip34` namespace mapping;
  coin type `1815`; mainnet/preprod/preview registry entries;
  `UNIVERSAL_WALLET_EXTRA_CHAIN_NAMES`; `parse_chain` support.
- `ows-core/src/config.rs` — default Koios RPC endpoints for the three networks.
- `ows-core/src/wallet_file.rs` — `KeyType::PrivateKey` doc updated to include
  `ed25519_bip32`.
- `ows-signer/src/curve.rs` — `Curve::Ed25519Bip32` and key lengths.
- `ows-signer/src/mnemonic.rs` — `Mnemonic::entropy()` (raw BIP-39 entropy).
- `ows-signer/src/hd.rs` — Icarus master-key generation and V2 child derivation.
- `ows-signer/src/chains/cardano.rs` — `CardanoSigner`, CIP-1852 path helpers,
  network selection, `ChainSigner` impl (address/sign methods stubbed).
- `ows-signer/src/chains/mod.rs` & `lib.rs` — register `CardanoSigner` in
  `signer_for_chain`.
- `ows-lib/src/ops.rs` — `KeyPair.ed25519_bip32`, random 192-byte generation,
  curve dispatch, and `broadcast_cardano`.
- `ows-cli` — `derive`/`info` commands surface the new family.

Dependencies added (`ows-signer/Cargo.toml`):

- `ed25519-bip32 = "0.4.1"` — generic BIP32-Ed25519 derivation.
- `pbkdf2 = "0.12"` — Icarus master-key derivation.
- `cardano-serialization-lib = "14.1.1"` — Cardano network parameters
  (`NetworkInfo`) now, address/transaction encoding later.

## Testing

Implemented and passing for these deliverables:

- **Curve** (`curve.rs`): key-length and equality tests for `Ed25519Bip32`.
- **Master key / derivation** (`hd.rs`): Icarus master `XPrv` vectors (named and
  all-zero "abandon" mnemonic); V2 hardened child derivation against
  `ed25519-bip32` crate vectors; rejection of a 64-byte BIP-39 seed for the
  Ed25519-BIP32 curve; equivalence of mnemonic-based vs master-`XPrv`-based
  derivation for `m/1852'/1815'/0'/0/0`.
- **Mnemonic** (`mnemonic.rs`): `entropy()` returns all-zero entropy for the
  "abandon" vector.
- **Chain registry** (`chain.rs`): serde round-trip including Cardano; namespace,
  coin type, and `from_namespace("cip34")` mappings; `parse_chain` for friendly
  names and `cip34:*` ids; universal-wallet order/count (mainnet + preprod +
  preview).
- **Config** (`config.rs`): default RPC lookups for all three Koios endpoints.
- **Signer** (`cardano.rs`): CIP-1852 path construction; chain type/curve/coin
  type; default path equals payment leaf.

Not yet covered (pending the signing/address deliverables): the
`signer_for_chain` integration test asserts a mainnet `addr1…` base address of
length 103; this depends on the not-yet-implemented Shelley address encoder and
will pass once that lands.

## References

- [CIP-34: Cardano Blockchain identification](https://cips.cardano.org/cip/CIP-34) (status: Proposed)
- [CIP-1852: HD Wallets for Cardano](https://cips.cardano.org/cip/CIP-1852)
- [CIP-3: Wallet key generation (Icarus master key)](https://cips.cardano.org/cip/CIP-3)
- [CIP-19: Cardano addresses](https://cips.cardano.org/cip/CIP-19)
- [BIP32-Ed25519 (Khovratovich & Law)](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf)
- [`ed25519-bip32` crate](https://docs.rs/ed25519-bip32/0.4.1/)
- [Koios API](https://api.koios.rest/)
- [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) and [CAIP-10](https://chainagnostic.org/CAIPs/caip-10)
- [SLIP-44: Registered coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) (ADA = 1815)
