# Cardano Support — Technical Specification

> Status: work in progress. This document specifies the Cardano integration parts
> that are **implemented** in this fork, and flags the parts that are still
> **planned**. It is scoped to five deliverables that are complete:
>
> 1. **Analysis, architecture, and setup** — codebase familiarization, build/test
>    pipeline, and a map of where Cardano fits into the existing abstractions (see
>    [Analysis, Architecture, and Setup](#analysis-architecture-and-setup)).
> 2. **CAIP-2 / CAIP-10 addressing abstraction**
> 3. **Key derivation and cryptography — Ed25519-BIP32**
> 4. **Implementing the chain plugin interface** — Shelley address encoding
>    (base/enterprise/reward), CIP-8 (COSE) message signing, and transaction
>    signing/witness encoding, all via `cardano-serialization-lib` and its
>    `cardano-message-signing` companion (see
>    [Transaction and Message Signing](#3-transaction-and-message-signing-chain-plugin-interface)).
> 5. **Policy engine support** — parsing an unsigned Cardano transaction (CBOR) into
>    the chain-agnostic `TransactionContext` that the OWS Policy Engine evaluates,
>    resolving input UTxO values via the configured Cardano RPC provider (Koios or
>    Blockfrost) so that ADA
>    and native-asset flows can be computed per address (see
>    [Policy Engine Support](#4-policy-engine-support)).
>
> Transaction *building* (input selection, fee/change calculation) and balance/UTxO
> fetching remain out of scope for these deliverables and are tracked separately;
> the signer operates on an already-assembled unsigned transaction (CBOR).

## Abstract

This specification adds Cardano mainnet support to the Open Wallet Standard (OWS)
reference implementation while preserving OWS's chain-agnostic, local-first design.
It introduces the `cip34` CAIP-2 namespace and registers Cardano mainnet, preprod,
and preview networks with canonical chain identifiers, a coin type, and default
(keyless) Koios RPC endpoints, with optional Blockfrost support for deployments
that prefer an authenticated provider. On the cryptographic side, it adds a new
`Ed25519Bip32` curve (Ed25519-V2 / BIP32-Ed25519) implemented generically via the
`ed25519-bip32` crate, together with the Cardano Icarus master-key scheme and
CIP-1852 hierarchical derivation. Cardano accounts are derived from two credentials
— a payment credential (`role = 0`) and a stake credential (`role = 2`) — which
diverges from OWS's prior assumption that one account maps to a single derivation
path; the key-storage and derivation layers were extended to carry the two
96-byte extended private keys required to assemble a Shelley base address. On top
of this foundation, the chain plugin interface (`ChainSigner`) is fully
implemented: Shelley **base**, **enterprise**, and **reward** address encoding;
raw Ed25519 signing; CIP-8 message signing (COSE `COSE_Sign1` structures); and
transaction signing that produces and CBOR-encodes the `Vkeywitness`es required to
make a transaction submittable. Address encoding, transaction (de)serialization,
and witness construction use `cardano-serialization-lib` (CSL), while the COSE
message structures use Emurgo's `cardano-message-signing` companion library.
Finally, it wires Cardano into the OWS Policy Engine: `make_transaction_context`
parses an unsigned transaction (CBOR) and, because UTxO inputs carry no value,
resolves them through the configured Cardano RPC provider to compute per-address ADA
and native-asset flows (`TransactionEffect`s) that built-in and executable policies
can evaluate before a key is used.

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
  for network parameters (`NetworkInfo`), address construction
  (`BaseAddress`/`EnterpriseAddress`/`RewardAddress`, `Credential`), extended-key
  helpers (`Bip32PrivateKey`), and CBOR transaction (de)serialization
  (`FixedTransaction`, `make_vkey_witness`, `Vkeywitness`). It is used for network
  parameters, Shelley address encoding, and transaction signing/witness encoding.
  Note CSL also pulls in `pbkdf2`, which we use directly for the Icarus master-key
  step.
- **`emurgo-cardano-message-signing` (1.1.0)** — Emurgo's COSE companion to CSL,
  used exclusively for CIP-8 message signing. It provides the `COSESign1Builder`,
  `HeaderMap`/`Headers`/`ProtectedHeaderMap`/`Label`, `AlgorithmId::EdDSA`, and
  `SignedMessage`/CBOR helpers needed to build and serialize the COSE `Sig_structure`
  and `COSE_Sign1` payload that Cardano wallets expect.

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
6. **CBOR transactions + pluggable RPC.** Transactions are CBOR (parsed and
   witness-encoded by CSL's `FixedTransaction`). Network access goes through a
   provider-agnostic `CardanoRpcProvider` trait; the default is keyless Koios,
   with Blockfrost available when the RPC URL points at Blockfrost and a
   `BLOCKFROST_PROJECT_ID` is set.
7. **COSE message signing (CIP-8).** Unlike most OWS chains, which sign a hashed
   or prefixed byte string, Cardano message signing follows CIP-8: the message is
   wrapped in a COSE `COSE_Sign1` structure whose protected headers carry the
   signing address, and the signature is over the COSE `Sig_structure`, not the
   raw message.

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

#### 1.4 RPC configuration (Koios and Blockfrost)

Cardano network access is implemented behind a provider-agnostic
`CardanoRpcProvider` trait in `ows-core/src/cardano_rpc/`. Two concrete providers
are supported:

| Provider    | Authentication | Default |
| ----------- | -------------- | ------- |
| **Koios**   | None (keyless) | Yes     |
| **Blockfrost** | `project_id` API key via the `BLOCKFROST_PROJECT_ID` environment variable | No (opt-in via RPC URL override) |

Both providers implement the same three operations: broadcast a signed
transaction (CBOR), fetch UTxOs for transaction inputs, and fetch address token
balances. `resolve_cardano_provider` selects the implementation from the
configured RPC URL (see [Provider selection](#provider-selection) below).

**Default endpoints (Koios).** Built-in defaults are registered in
`Config::default_rpc()`:

| Chain id            | Default RPC                         |
| ------------------- | ----------------------------------- |
| `cip34:1-764824073` | `https://api.koios.rest/api/v1`     |
| `cip34:0-1`         | `https://preprod.koios.rest/api/v1` |
| `cip34:0-2`         | `https://preview.koios.rest/api/v1` |

**Blockfrost endpoints.** To use Blockfrost instead, override the RPC URL in
user config to the Blockfrost API base for the target network, for example:

| Network | Blockfrost RPC URL                                      |
| ------- | ------------------------------------------------------- |
| Mainnet | `https://cardano-mainnet.blockfrost.io/api/v0`          |
| Preprod | `https://cardano-preprod.blockfrost.io/api/v0`          |
| Preview | `https://cardano-preview.blockfrost.io/api/v0`          |

Set `BLOCKFROST_PROJECT_ID` to your Blockfrost project id (API key) before any
Cardano RPC call; without it, `resolve_cardano_provider` fails when the URL
selects Blockfrost.

##### Provider selection

`resolve_cardano_provider` (`ows-core/src/cardano_rpc/mod.rs`) inspects the RPC
URL string and returns a `Box<dyn CardanoRpcProvider>`:

- **Blockfrost** — when the URL contains `blockfrost.io/api` **or** is prefixed
  with `blockfrost|`. The prefix form is for custom Blockfrost-compatible hosts
  that would not match the substring heuristic (e.g. `blockfrost|https://my-proxy.example/api/v0`).
  The `project_id` is read from **`BLOCKFROST_PROJECT_ID`**; if the variable is
  unset, resolution returns an error.
- **Koios** — when the URL contains `koios.rest/api` **or** is prefixed with
  `koios|` (same rationale for custom hosts).
- **Any other URL** — rejected as unsupported.

After selection, the `koios|` / `blockfrost|` prefix is stripped before the
provider issues HTTP requests. All Cardano call sites — `broadcast_cardano`
(`ows-lib`), `make_transaction_context` (`ows-signer`), and balance fetching
(`ows-pay`) — go through `resolve_cardano_provider`, so the same URL override
and provider-selection rules apply everywhere.

RPC URL lookup reuses the generic precedence already in place: explicit override
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
account 0 (`m/1852'/1815'/0'/0/{index}`). Generic single-path key resolution no
longer derives this leaf directly; instead generic call sites use
`default_derivation_paths` and `encode_keys` (see
[§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys)),
which for Cardano materialize both the payment leaf and the stake key
(`m/1852'/1815'/0'/2/0`) as a single 192-byte buffer.

#### 2.5 `ChainSigner` integration

`CardanoSigner` implements `ChainSigner`:

- `chain_type()` → `ChainType::Cardano`
- `curve()` → `Curve::Ed25519Bip32`
- `coin_type()` → `1815`
- `default_derivation_path(index)` → payment leaf (see above)

`derive_address`, `sign`, `sign_message`, `sign_transaction`, and
`encode_signed_transaction` are now fully implemented; mnemonic key resolution uses
`default_derivation_paths` and `encode_keys` (see [§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys));
they are specified in [§3](#3-transaction-and-message-signing-chain-plugin-interface).
The key material these methods consume is a 192-byte buffer = payment `XPrv` (96) ‖
stake `XPrv` (96) at matching CIP-1852 indices (or a bare 96-byte payment `XPrv`,
which yields an enterprise address with no staking component).

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
  the base-address encoding.
- `KeyPair::key_for_curve(Curve::Ed25519Bip32)` returns this material; empty
  material yields a clear "private key for chain is empty" error for wallets
  imported before Cardano support existed.
- Mnemonic wallets reach the same 192-byte layout through `default_derivation_paths`
  and `encode_keys` (see
  [§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys)) rather than through
  `KeyPair`, so both wallet kinds present an identical payment ‖ stake buffer to the
  signer.

#### 2.7 Broadcast plumbing

`broadcast` dispatches `ChainType::Cardano` to `broadcast_cardano`, which calls
`resolve_cardano_provider` on the configured RPC URL and submits the signed CBOR
via `CardanoRpcProvider::broadcast_tx` (Koios: `POST {rpc}/submittx` with
`Content-Type: application/cbor`, HTTP `202`; Blockfrost:
`POST {rpc}/tx/submit`). The fully signed CBOR produced by
`encode_signed_transaction` (see [§3.4](#34-transaction-signing)) is what feeds
this path.

### 3. Transaction and message signing (Chain Plugin Interface)

This deliverable implements the `ChainSigner` plugin surface for Cardano:
address encoding, raw signing, CIP-8 message signing, and transaction
signing/witness encoding. Address construction, transaction (de)serialization, and
witness encoding use `cardano-serialization-lib` (CSL); COSE message structures use
Emurgo's `cardano-message-signing` companion crate.

All signer methods accept the **key material** layout described in
[§2.5](#25-chainsigner-integration): either a 192-byte payment `XPrv` ‖ stake
`XPrv`, or a bare 96-byte payment `XPrv`. Two small private helpers slice this
buffer:

- `payment_bip32(key_material)` → payment `Bip32PrivateKey` (accepts 96 or 192
  bytes; anything else is a clear `InvalidPrivateKey` error).
- `stake_bip32(key_material)` → `Some(stake)` when 192 bytes are supplied, `None`
  for the 96-byte payment-only case.

#### 3.1 Shelley address encoding

`derive_address` chooses the address kind from whether a stake key is present:

| Key material            | Address kind | Helper                          | Example prefix |
| ----------------------- | ------------ | ------------------------------- | -------------- |
| payment ‖ stake (192 B) | base         | `base_address_bech32`           | `addr1q…`      |
| payment only (96 B)     | enterprise   | `enterprise_address_bech32`     | `addr1v…`      |
| stake only (signing)    | reward       | `reward_address_bech32`         | `stake1…`      |

Each helper hashes the relevant public key (`to_public().to_raw_key().hash()`),
wraps it in a `Credential::from_keyhash`, builds the matching CSL address type
(`BaseAddress` / `EnterpriseAddress` / `RewardAddress`) bound to the signer's
`network_id`, and bech32-encodes it. The reward address is not produced by
`derive_address` directly; it is used during message signing when a stake/reward
address is the requested signer.

#### 3.2 Raw signing (`sign`)

`sign` produces a bare 64-byte Ed25519 signature over the supplied bytes using the
**payment** key, returning the signature plus the payment public key. It performs
no hashing or prefixing (the caller decides what to sign) and is the low-level
primitive used by transaction witnessing.

#### 3.3 CIP-8 message signing (`sign_message`)

`sign_message` follows [CIP-8](https://cips.cardano.org/cip/CIP-8): the message is
embedded in a COSE `COSE_Sign1` structure and the signature is computed over the
COSE `Sig_structure`, not the raw message. The flow:

1. **Select the signing credential from the optional `address`.** The address (a
   bech32 string) determines which key signs and is embedded in the protected
   headers:
   - `Reward` (`stake1…`) → sign with the **stake** key; requires 192-byte
     material, else `InvalidPrivateKey`.
   - `Base` (`addr1q…`) → sign with the **payment** key; also requires the stake
     key so the base address can be reconstructed and verified.
   - `Enterprise` (`addr1v…`) → sign with the **payment** key.
   - Any other address kind → `AddressMismatch`.
   In each case the signer **re-derives** the address from the key material and
   compares it to the requested one, returning `AddressMismatch` on any
   discrepancy. This guarantees the embedded `address` header is one the key
   actually controls.
2. **No `address` supplied** → sign with the payment key and embed the address
   derived from the key material (base if a stake key is present, else
   enterprise).
3. **Build the COSE structure.** A `HeaderMap` of protected headers is populated
   with `AlgorithmId::EdDSA` and an `"address"` label whose value is the **raw
   address bytes** (CBOR byte string). A `COSESign1Builder` is constructed over
   these headers and the message payload; `make_data_to_sign()` yields the
   `Sig_structure`, which is signed with the selected raw Ed25519 key.
4. **Serialize.** The signature is folded back into the builder, wrapped as a
   `SignedMessage::new_cose_sign1`, and serialized to CBOR. `SignOutput.signature`
   is the serialized `COSE_Sign1`; `public_key` is the signing key's public key.

#### 3.4 Transaction signing

`sign_transaction` consumes the unsigned transaction CBOR (it does **not** build
transactions — input selection, fees, and change are the caller's responsibility):

1. Parse the bytes into a CSL `FixedTransaction` (`InvalidTransaction` on failure).
2. Always create a payment witness with `make_vkey_witness(tx_hash, payment_raw_key)`.
3. If stake key material is present **and** the transaction body's
   `required_signers` set contains the stake key hash, also create a stake witness.
   (Stake witnesses are only added when the transaction explicitly requires them —
   e.g. certificate or withdrawal transactions — to avoid attaching superfluous
   signatures.)
4. `SignOutput.signature` is the **concatenation** of the CBOR-encoded witness(es)
   (payment, optionally followed by stake); `public_key` is the payment witness's
   public key.

`encode_signed_transaction` assembles the submittable transaction: it re-parses the
unsigned CBOR into a `FixedTransaction`, splits the signature buffer into
fixed-size 101-byte chunks (`VKEY_WITNESS_CBOR_BYTES` = 32-byte pubkey + 64-byte
signature + 5 bytes of CBOR framing), decodes each chunk into a `Vkeywitness`, adds
it with `add_vkey_witness`, and returns the CBOR of the now-witnessed transaction.
This is the byte string handed to `broadcast_cardano` ([§2.7](#27-broadcast-plumbing)).

#### 3.5 Key-material abstraction (`default_derivation_paths` and `encode_keys`)

To let a chain decide how mnemonic-derived key material is shaped, `ChainSigner`
exposes two overridable hooks:

- `default_derivation_paths(index)` — all BIP paths bound to one account. The
  default returns a single-element vector containing `default_derivation_path(index)`,
  so every other chain is unaffected.
- `encode_keys(keys)` — packs the resolved key bundle into the single opaque blob
  that signing methods consume. The default returns the primary (first) key
  unchanged.

`CardanoSigner` overrides both: `default_derivation_paths` returns the payment leaf
`m/1852'/1815'/0'/0/{index}` and the stake key `m/1852'/1815'/0'/2/0`;
`encode_keys` concatenates the two 96-byte `XPrv`s into the 192-byte payment ‖
stake buffer the address and signing methods expect. Generic call sites were
migrated to this pattern — `derive_all_accounts`, `secret_to_signing_key`,
`derive_address` (the public lib function), the CLI `derive` command, and the
signer integration test now call `signer.default_derivation_paths(index)`, derive
keys via `HdDeriver`, then `signer.encode_keys(&keys)` instead of deriving a single
path inline. This is what lets Cardano transparently carry two credentials through
code that still assumes "one account → one key blob".

#### 3.6 Address-aware `sign_message` across all chains

CIP-8 needs to know *which* of a wallet's Cardano addresses a signature is for, so
the `sign_message` signature gained an `address: Option<&str>` parameter across the
whole `ChainSigner` trait, every chain implementation, the `ows-lib` entry points
(`sign_message`, `sign_typed_data`, and their API-key variants), the CLI (a new
`--address` flag on `sign message`), and the Node/Python bindings.

For non-Cardano chains the parameter is an optional safety check: a new default
trait method `verify_sign_message_address` re-derives the address from the private
key and compares it (case-insensitively, ignoring a `0x` prefix) to the requested
one, returning the new `SignerError::AddressMismatch` on a mismatch. Each chain
calls it at the top of `sign_message` (and EVM's typed-data path calls it too), so
passing an `address` that the key does not control is rejected everywhere, while
passing `None` keeps the prior behavior. Cardano does not use the default check —
it performs richer, address-kind-aware selection and verification inline (see
[§3.3](#33-cip-8-message-signing-sign_message)).

### 4. Policy engine support

OWS gates every signing request through a **Policy Engine**: before a key is
decrypted and used, the request is turned into a chain-agnostic
`PolicyContext` (`ows-core/src/policy.rs`) that built-in rules and custom
**executable** policies evaluate and can veto. The core of that context is a
`TransactionContext`, whose `effects` field is a list of per-address asset
deltas:

```rust
pub struct TransactionEffect {
    pub address: String,
    pub diff: Vec<(String, i64)>, // (asset_id, signed change)
}

pub struct TransactionContext {
    pub effects: Vec<TransactionEffect>,
    pub raw_hex: String,          // the raw unsigned transaction
    pub data: Option<String>,     // calldata (EVM only)
}
```

Each `ChainSigner` produces this context from raw transaction bytes via
`make_transaction_context(tx_bytes, rpc_url)`. The trait's default implementation
returns empty `effects` (just the `raw_hex`), which suffices for chains where the
transaction already carries enough information — or where flow analysis is not yet
implemented. This deliverable overrides it for Cardano so that a policy can reason
about the **actual ADA and native-asset movement** a transaction causes, per
address.

#### 4.1 Why Cardano needs the RPC provider

Cardano is UTxO-based. A transaction body lists its inputs only as
`(transaction_hash, index)` references — it does **not** carry the value or assets
locked at those UTxOs. To compute how much each address gains or loses, the signer
must resolve every referenced input to its underlying UTxO. This is the
architectural consequence flagged in the scope: unlike the account-based effects on
other chains, building a Cardano `TransactionContext` **depends on network access**
to the configured RPC provider (Koios or Blockfrost).

Accordingly, `make_transaction_context` takes an `Option<&str>` RPC URL, and the
`ows-lib` call sites that build the policy context — `sign_and_send`
(`ops.rs`) and `sign_with_api_key` (`key_ops.rs`) — resolve the Cardano RPC
endpoint and pass it through. Resolution reuses the generic precedence
(explicit override → config exact `chain_id` → config namespace → built-in
default; see [§1.4](#14-rpc-configuration-koios-and-blockfrost)); `resolve_rpc_url`
was made `pub(crate)`-visible for this. For every non-Cardano chain the URL
stays `None`, so no network call is introduced anywhere else.

#### 4.2 Parsing and input resolution (`CardanoRpcProvider::fetch_utxos`)

`CardanoSigner::make_transaction_context` (`ows-signer/src/chains/cardano.rs`):

1. Parse the bytes into a CSL `FixedTransaction` (`InvalidTransaction` on failure),
   and record the raw hex for `TransactionContext.raw_hex`.
2. Collect input references as `(tx_hash_hex, index)` pairs from `tx.body().inputs()`.
3. If there are inputs, an RPC URL is **required** (else `InvalidMessage`);
   `resolve_cardano_provider` selects Koios or Blockfrost from the URL (see
   [§1.4](#14-rpc-configuration-koios-and-blockfrost)) and calls
   `fetch_utxos` on the resulting provider:
   - **Koios** — `POST {rpc}/utxo_info` with
     `{"_utxo_refs": ["<hash>#<index>", …], "_extended": true}`. `_extended: true`
     is required so the response includes each UTxO's `asset_list`. Requests are
     **chunked** at 80 refs per call.
   - **Blockfrost** — per-transaction `GET {rpc}/txs/{hash}/utxos`, then the
     matching output index for each input (Blockfrost has no batch UTxO endpoint).
   - Both providers use a blocking `reqwest` client with a `45s` timeout.
   - Failures map to `SignerError::RpcError`. Koios additionally rejects a chunk
     that returns fewer matching UTxO rows than requested (`InvalidTransaction`);
     Blockfrost errors if a referenced output index is missing.

Each resolved `CardanoUtxo` carries the input's `address`, its lovelace amount,
and a list of native assets keyed by `policy_id ‖ asset_name` (hex).

#### 4.3 Computing per-address effects

The signer builds two `address → (asset_id → amount)` maps and diffs them:

- **Inputs** map is populated from the resolved provider UTxOs (lovelace →
  `lovelace`,
  each native asset → `policy_id ‖ asset_name`).
- **Outputs** map is read directly from `tx.body().outputs()`: the `coin` becomes
  `lovelace`, and each `multiasset` entry becomes `policy_id_hex ‖ asset_name_hex`.
- ADA is represented by the reserved asset id **`"lovelace"`**; every native asset
  is keyed by the concatenation of its (hex) policy id and (hex) asset name, so the
  same token nets out across inputs and outputs.

For every address touched by either side, and every asset id it involves, the
effect is `output_balance − input_balance` as a signed `i64`. Zero-diff assets and
zero-diff addresses are dropped; the remaining `diff` entries are sorted by asset
id and the `effects` list is sorted by address, so the context is deterministic
(important for reproducible policy decisions and stable test vectors). A pure
self-transfer, for example, yields a single effect on the sender with only the
negative fee.

The result is returned as `TransactionContext { effects, raw_hex, data: None }` and
handed to the policy engine, which passes it (as part of `PolicyContext`) to
built-in rules and to executable policies over stdin.

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
  CSL for Cardano-specific concerns (network parameters, address encoding, and
  transaction/witness encoding). This avoids leaking a chain-specific library into
  the generic key path while still using the canonical library for the parts that
  must match the ecosystem byte-for-byte.
- **CSL + `cardano-message-signing` for the chain plugin, per IOHK.** As recorded
  in the deliverable description (IOHK agreed on 8.4.2026 to use
  `cardano-serialization-lib`), address encoding and transaction signing go through
  CSL, and CIP-8 message signing uses Emurgo's `cardano-message-signing` COSE
  helpers rather than a hand-rolled COSE encoder. This keeps the produced
  addresses, witnesses, and signed messages compatible with mainstream Cardano
  wallets and tooling.
- **Base address with payment + stake.** Per agreement with IOHK, the initial
  implementation targets exactly one base address per account at address index 0,
  combining a payment credential (role 0) and a stake credential (role 2). This
  keeps the scope bounded while still producing a normal, stake-delegatable
  Shelley address rather than an enterprise (payment-only) address.
- **Two 96-byte keys in `KeyPair`.** Storing payment ‖ stake (192 bytes) up front
  makes the imported-key representation forward-compatible with base-address
  assembly without another schema change.
- **`default_derivation_paths` + `encode_keys` instead of widening the signer
  surface.** Rather than special-casing Cardano in every generic call site,
  overridable `ChainSigner::default_derivation_paths` and `encode_keys` let a chain
  declare how many keys per account it needs and how to pack them into one blob.
  The defaults keep single-path behavior for all other chains; only Cardano returns
  the 192-byte payment ‖ stake buffer. This localizes the "two credentials per
  account" peculiarity to the Cardano signer.
- **`address`-driven message signing.** CIP-8 embeds the signing address in the
  COSE protected headers, so `sign_message` must know which address the caller
  intends. Threading an optional `address` through the trait (rather than a
  Cardano-only API) also gave every other chain a cheap opt-in guard against
  signing with the wrong key (`verify_sign_message_address` →
  `AddressMismatch`).
- **Concatenated witnesses + fixed-size chunking.** `sign_transaction` returns the
  CBOR witnesses concatenated, and `encode_signed_transaction` splits them back on
  the fixed 101-byte `Vkeywitness` size. This keeps `SignOutput.signature` a flat
  byte string (consistent with other chains) while still supporting the
  multi-witness (payment + stake) case.
- **RPC-resolved transaction effects for policy.** Cardano inputs carry no value,
  so a meaningful `TransactionContext` cannot be built from the transaction bytes
  alone. Rather than inventing a Cardano-only policy path, the existing
  `make_transaction_context` hook is overridden to resolve inputs via the
  configured `CardanoRpcProvider` (Koios or Blockfrost) and emit
  the same chain-agnostic `TransactionEffect` shape every other chain uses — so
  executable policies see uniform per-address asset deltas regardless of chain. The
  RPC dependency is threaded only for Cardano; all other chains keep passing `None`.
- **Reject missing input UTxOs.** If the provider returns fewer UTxOs than
  requested (Koios) or a referenced output is absent (Blockfrost),
  `make_transaction_context` errors instead of proceeding. An unresolved input would
  silently understate the ADA/asset outflow and could let a spending policy pass a
  transaction it should have denied, so a partial resolution is treated as a hard
  failure.

  > **⚠️ Warning — chained/unconfirmed transactions.** This same strictness breaks
  > transaction *chaining*. If a transaction spends an input that was created by an
  > earlier transaction which has **not yet been confirmed in a block**, the RPC
  > provider does not know that UTxO yet and omits it from the response. Because the
  > returned data is then incomplete,
  > `make_transaction_context` fails (surfaced as `InvalidTransaction` or
  > `RpcError`) and the signing request is rejected, even though
  > the transaction itself is well-formed. In other words, a transaction cannot be
  > signed through the policy engine until every input it references has been
  > confirmed and indexed by the provider. Building and submitting a chain of dependent
  > transactions back-to-back (before the parents confirm) is therefore not currently
  > supported.
- **Deterministic effect ordering.** Effects are sorted by address and each `diff`
  by asset id, and ADA is normalized to the single `"lovelace"` key. This makes the
  context stable across runs, so policy decisions are reproducible and reference
  vectors are exact.

### Acceptance Criteria

These deliverables are considered complete when:

1. `ChainType::Cardano` exists and round-trips through serde, `namespace()`,
   `from_namespace()`, `default_coin_type()`, and `Display`/`FromStr`.
2. `parse_chain` resolves `cardano`, `cardano-preprod`, `cardano-preview`, and the
   corresponding `cip34:*` ids; `default_chain_for_type(Cardano)` is mainnet.
3. Default Koios RPC endpoints are registered for all three networks and resolved
   by the generic RPC lookup; Blockfrost is selectable by RPC URL override plus
   `BLOCKFROST_PROJECT_ID`.
4. `Curve::Ed25519Bip32` reports correct key lengths (96 / 32).
5. `HdDeriver` produces the correct Icarus master `XPrv` from entropy (matches
   published vectors) and performs V2 child derivation, including the CIP-1852
   payment/stake/account paths.
6. `CardanoSigner` reports curve `Ed25519Bip32`, coin type `1815`, and the
   CIP-1852 payment leaf as its default path.
7. Multi-curve key storage carries an `ed25519_bip32` entry (192 bytes for
   imported keys) without changing the wallet schema version.
8. `derive_address` produces the correct mainnet Shelley **base** address from
   192-byte key material and the correct **enterprise** address from 96-byte
   payment-only material (verified against fixed vectors for 12- and 24-word
   mnemonics).
9. `sign_message` produces a CIP-8 `COSE_Sign1` matching reference vectors for the
   no-address, base, enterprise, and reward-address cases, and rejects an address
   the key does not control with `AddressMismatch`.
10. `sign_transaction` produces correct `Vkeywitness`(es) — payment only, and
    payment + stake when the transaction's `required_signers` demand it — and
    `encode_signed_transaction` round-trips them into a submittable transaction
    matching reference CBOR vectors.
11. `default_derivation_paths` returns both CIP-1852 paths for Cardano, and
    `encode_keys` returns the 192-byte payment ‖ stake buffer; all other chains
    remain on their single-path defaults.
12. `make_transaction_context` parses an unsigned Cardano transaction, resolves its
    inputs via `CardanoRpcProvider::fetch_utxos` (Koios or Blockfrost), and produces
    per-address `TransactionEffect`s with correct signed ADA and native-asset diffs
    (verified against mocked provider responses for self-transfer, external+change,
    asset-carrying, and multi-input/multi-output cases); it errors when the RPC URL
    is missing for a transaction with inputs, or when the provider returns incomplete
    UTxO data.

### Implementation Plan

All five deliverables are landed and covered by unit/integration tests (see
[Testing](#testing)): the chain-registry/addressing layer, Ed25519-BIP32 key
derivation, the chain plugin interface (Shelley base/enterprise/reward address
encoding, raw signing, CIP-8 message signing, and transaction signing/witness
encoding), policy-engine support (`make_transaction_context` with provider-based
input resolution), and a pluggable Cardano RPC layer (Koios default, Blockfrost
opt-in). Remaining Cardano work (separate deliverables) proceeds as:
transaction *building* (input selection, fee/change), general balance/UTxO
fetching, persisting both payment and stake paths per `WalletAccount`.

## Backwards Compatibility Assessment

- **Wallet file schema unchanged.** `ows_version` stays at `2`. The new
  `ed25519_bip32` key field is additive; existing mnemonic wallets need no
  migration (Cardano keys are derived on demand). Private-key wallets imported
  before Cardano support simply have no `ed25519_bip32` material and surface a
  clear error if used for Cardano, rather than silently degrading.
- **Existing families untouched.** secp256k1 and SLIP-10 ed25519 derivation paths
  are unchanged; the `Ed25519Bip32` branch is additive in `Curve`, `HdDeriver`,
  and `KeyPair`. Characterization tests on EVM/Solana derivation continue to pass.
- **`sign_message` signature changed (binding-level).** Adding `address:
  Option<&str>` to `ChainSigner::sign_message` and to the `ows-lib`/binding entry
  points is a source-breaking change for direct callers, mitigated by making the
  parameter optional: passing `None` reproduces the prior behavior exactly, and
  every chain's non-Cardano message signing is unchanged when no address is given.
  `default_derivation_paths` and `encode_keys` are purely additive (defaults mirror
  the old inline single-path derivation).
- **Policy context is additive.** `make_transaction_context` already existed on
  `ChainSigner` with a default-empty implementation; Cardano overrides it and the new
  `SignerError::RpcError` variant is additive, so no other chain's behavior changes.
  The lib call sites resolve an RPC URL only for Cardano (all other chains keep
  passing `None`), so no new network call is introduced for existing chains.
- **New network dependency for Cardano signing requests.** Building a Cardano
  policy context now performs an RPC call when the transaction has inputs; a Cardano
  signing request that previously would have proceeded with empty effects now
  requires provider reachability (and errors if none is configured/available). This
  is intended — the policy engine needs the flow to make a decision — but it is a
  behavioral change for Cardano relative to the prior default-empty context.
- **Known abstraction gap.** `WalletAccount` still stores a single
  `derivation_path`, so the stored Cardano account currently records only the
  payment leaf even though the signer now derives both payment and stake keys at
  runtime via `default_derivation_paths` and `encode_keys`. Persisting both paths
  per account is a noted
  follow-up (`TODO` in `derive_all_accounts`).

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
- **RPC providers.** Koios needs no API key, avoiding credential storage for the
  default deployment. Blockfrost authenticates with a `project_id` read from
  `BLOCKFROST_PROJECT_ID` (not stored in the wallet config). Broadcast and input
  resolution rely on whichever provider the RPC URL selects, so provider
  availability and trust are deployment considerations.
- **Address-bound message signing.** `sign_message` always re-derives the address
  from the supplied key material and refuses to sign for an `address` the key does
  not control (`AddressMismatch`). The signing address is embedded in the CIP-8
  COSE protected headers, so a verifier can confirm which credential signed. Across
  other chains the same `verify_sign_message_address` guard prevents signing a
  message under an address the wallet did not derive.
- **Selective stake witnessing.** `sign_transaction` only attaches a stake
  witness when the transaction body's `required_signers` explicitly lists the
  stake key hash, so a routine payment transaction is never signed with the stake
  key. Transaction *content* is not otherwise inspected or policy-checked here —
  the signer trusts the caller-provided unsigned CBOR — so transaction building and
  vetting remain the responsibility of upstream layers.
- **Trust in the RPC-derived context.** Cardano input values come from the
  configured RPC provider, so the `TransactionContext` a policy evaluates is only
  as trustworthy as that endpoint: a malicious or compromised provider could
  misreport input values and skew the computed effects. The keyless Koios default
  trades authentication for operational simplicity; deployments with stronger
  requirements can point RPC config at Blockfrost (with `BLOCKFROST_PROJECT_ID`) or
  another trusted host via the `koios|` / `blockfrost|` URL prefixes. To limit
  silent under-reporting, a transaction with inputs and no RPC URL is rejected,
  and incomplete UTxO resolution aborts context construction rather than degrading
  to a partial view. Unparseable quantities are coerced to `0`, which can
  understate a flow — a known limitation of the current implementation.

## Implementation

Components modified or added:

- `ows-core/src/chain.rs` — `ChainType::Cardano`; `cip34` namespace mapping;
  coin type `1815`; mainnet/preprod/preview registry entries;
  `UNIVERSAL_WALLET_EXTRA_CHAIN_NAMES`; `parse_chain` support.
- `ows-core/src/config.rs` — default Koios RPC endpoints for the three networks.
- `ows-core/src/cardano_rpc/` — `CardanoRpcProvider` trait,
  `resolve_cardano_provider`, `KoiosProvider`, and `BlockfrostProvider`.
- `ows-core/src/wallet_file.rs` — `KeyType::PrivateKey` doc updated to include
  `ed25519_bip32`.
- `ows-signer/src/curve.rs` — `Curve::Ed25519Bip32` and key lengths.
- `ows-signer/src/mnemonic.rs` — `Mnemonic::entropy()` (raw BIP-39 entropy).
- `ows-signer/src/hd.rs` — Icarus master-key generation and V2 child derivation.
- `ows-signer/src/chains/cardano.rs` — `CardanoSigner`, CIP-1852 path helpers,
  network selection, and the full `ChainSigner` impl: base/enterprise/reward
  address encoding, `sign`, CIP-8 `sign_message`, `sign_transaction`,
  `encode_signed_transaction`, the `default_derivation_paths` / `encode_keys`
  overrides, and the `make_transaction_context` override (resolves inputs via
  `resolve_cardano_provider` and `CardanoRpcProvider::fetch_utxos`).
- `ows-signer/src/traits.rs` — `sign_message` gains `address: Option<&str>`; new
  default methods `verify_sign_message_address`, `default_derivation_paths`, and
  `encode_keys`; new `SignerError::AddressMismatch` and `SignerError::RpcError`.
  (`make_transaction_context` already existed as a default-empty hook; Cardano now
  overrides it.)
- `ows-lib/src/ops.rs` & `ows-lib/src/key_ops.rs` — `sign_and_send` and
  `sign_with_api_key` resolve the Cardano RPC URL and pass it into
  `make_transaction_context`; `broadcast_cardano` uses `resolve_cardano_provider`;
  `resolve_rpc_url` is exposed for reuse.
- `ows-pay/src/cardano.rs` — address balance fetching via
  `CardanoRpcProvider::get_balances`.
- `ows-signer/src/chains/*.rs` — every chain's `sign_message` updated to the new
  signature and calls `verify_sign_message_address`.
- `ows-signer/src/chains/mod.rs` & `lib.rs` — register `CardanoSigner` in
  `signer_for_chain`; integration test uses `default_derivation_paths` and
  `encode_keys`.
- `ows-lib/src/ops.rs` — `KeyPair.ed25519_bip32`, random 192-byte generation,
  curve dispatch, `broadcast_cardano`; `sign_message`/`sign_typed_data` thread the
  `address` argument; mnemonic derivation routes through `default_derivation_paths`
  and `encode_keys`.
- `ows-lib/src/key_ops.rs` — API-key `sign_message`/`sign_typed_data` thread
  `address` and call `verify_sign_message_address`.
- `ows-cli` — `sign message --address` flag; `derive` uses `default_derivation_paths`
  and `encode_keys`.
- `bindings/node` & `bindings/python` — `sign_message`/`sign_typed_data` expose
  the optional `address` argument.

Dependencies added (`ows-signer/Cargo.toml`):

- `ed25519-bip32 = "0.4.1"` — generic BIP32-Ed25519 derivation.
- `pbkdf2 = "0.12"` — Icarus master-key derivation.
- `cardano-serialization-lib = "14.1.1"` — Cardano network parameters
  (`NetworkInfo`), Shelley address encoding, and transaction/witness encoding.
- `emurgo-cardano-message-signing = "1.1.0"` — CIP-8 COSE message-signing helpers.
- `reqwest = "0.12"` (blocking, `json`, `rustls-tls`, no default features) —
  HTTP client for the Cardano RPC providers (`ows-core/src/cardano_rpc/`).
- `mockito = "1"` (dev-dependency) — mocks provider endpoints in the
  `make_transaction_context` and `cardano_rpc` tests.

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
- **Address encoding** (`cardano.rs`): mainnet **base** address from 12- and
  24-word mnemonics (via `default_derivation_paths` and `encode_keys`) against fixed
  `addr1q…` vectors;
  **enterprise** address from a payment-only key against fixed `addr1v…` vectors.
- **Message signing** (`cardano.rs`): CIP-8 `COSE_Sign1` output against reference
  vectors for the no-address, base, enterprise, and reward-address cases
  (including the expected public key per signing credential).
- **Transaction signing** (`cardano.rs`): a CBOR test-transaction builder
  exercises the payment-only witness path and the payment + required-stake-key
  path; both `sign_transaction` signatures and the `encode_signed_transaction`
  output are asserted against reference CBOR.
- **Cross-chain `sign_message`** (`evm.rs`, etc.): `AddressMismatch` is returned
  for a wrong `address`, and signing succeeds when the derived address is passed;
  `None` reproduces prior signatures (`solana.rs`, `bitcoin.rs`).
- **Integration** (`lib.rs`): `signer_for_chain` derives a mainnet `addr1…` base
  address via `default_derivation_paths`, `encode_keys`, and `derive_address`, now
  passing end-to-end.
- **Policy context** (`cardano.rs`, `cardano_rpc/`): `make_transaction_context` is
  exercised with a mocked Koios `utxo_info` endpoint (`mockito`, via the `koios|`
  URL prefix) across the flow shapes that matter for policy evaluation — a
  self-transfer (only the negative fee shows up), a single input with an external
  payment plus change, the same with a native asset split between external and
  change outputs, and multi-input/multi-output transactions that rebalance across
  the wallet's own addresses and to a third party. Each asserts the exact sorted
  `effects` (per-address signed lovelace and asset diffs) and that the mock
  endpoint was hit. `KoiosProvider` and `BlockfrostProvider` have dedicated unit
  tests for broadcast, UTxO fetch, and balance queries.

## References

- [CIP-34: Cardano Blockchain identification](https://cips.cardano.org/cip/CIP-34) (status: Proposed)
- [CIP-1852: HD Wallets for Cardano](https://cips.cardano.org/cip/CIP-1852)
- [CIP-3: Wallet key generation (Icarus master key)](https://cips.cardano.org/cip/CIP-3)
- [CIP-8: Message signing](https://cips.cardano.org/cip/CIP-8)
- [CIP-30: Cardano dApp-Wallet Web Bridge (`signData`)](https://cips.cardano.org/cip/CIP-30)
- [CIP-19: Cardano addresses](https://cips.cardano.org/cip/CIP-19)
- [BIP32-Ed25519 (Khovratovich & Law)](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf)
- [`ed25519-bip32` crate](https://docs.rs/ed25519-bip32/0.4.1/)
- [`cardano-serialization-lib`](https://github.com/Emurgo/cardano-serialization-lib)
- [`cardano-message-signing`](https://github.com/Emurgo/message-signing)
- [RFC 8152: CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc8152)
- [Koios API](https://api.koios.rest/)
- [Blockfrost API](https://blockfrost.io/)
- [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) and [CAIP-10](https://chainagnostic.org/CAIPs/caip-10)
- [SLIP-44: Registered coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) (ADA = 1815)
