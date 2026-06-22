# Topic 01 — Addresses

> **Status:** first-pass populated by 2b + 2c. **Second-pass augmented** by 2d (WalletEngine spec, license-pending — user override 2026-04-29), 2e (connector v4.0.0), 2f (Lace) — see "Second-pass refinements" section. **X-1 closed by-finding** (2g) — see [02-curves.md](02-curves.md).

## What Midnight has (per 2c — `midnight-wallet`)

**Three address kinds per logical account, derived from one mnemonic** via five HD roles:

| Role enum | Path role index | Purpose |
|---|---|---|
| `NightExternal` | 0 | Unshielded receiving address |
| `NightInternal` | 1 | Unshielded change/internal address |
| `Dust` | 2 | Dust fee address |
| `Zswap` | 3 | Shielded coin pubkey + encryption pubkey base |
| `Metadata` | 4 | Signing metadata |

Derivation path: `m/44'/2400'/<account>'/<role>/<index>` — see `packages/hd/src/HDWallet.ts`. **Coin type 2400 is Midnight-specific BIP-44**.

API shape (`packages/hd/src/HDWallet.ts`):
- `HDWallet.fromSeed(seed) -> HDWalletResult` — validates seed, returns wallet or `seedError`.
- `wallet.selectAccount(n) -> AccountKey`.
- `accountKey.selectRole(role) -> RoleKey`.
- `roleKey.deriveKeyAt(i) -> { key: Uint8Array } | { keyOutOfBounds }`.
- `roleKey.deriveAllKeysAt(i) -> { keys: Record<Role, Uint8Array> }` — convenience to derive all 5 roles at one index.

Underlying curve operation: BIP-32 secp256k1 derivation, then curve-specific transformation per role (per 2c — but see §Open question below for a curve conflict).

## Address encoding (per 2c — `midnight-wallet/packages/address-format`)

**Bech32m with `mn` prefix** plus a sub-type tag and optional network suffix:

| Address kind | HRP (full) | Bytes | Example |
|---|---|---|---|
| Shielded full | `mn_shield-addr` | 64 (coin pk + enc pk) | `mn_shield-addr1...` |
| Shielded coin pubkey only | `mn_shield-cpk` | 32 | `mn_shield-cpk1...` |
| Shielded encryption pubkey only | `mn_shield-epk` | 32 | `mn_shield-epk1...` |
| Shielded encryption seckey | `mn_shield-esk` | variable | `mn_shield-esk1...` |
| Unshielded | `mn_addr` | 32 | `mn_addr1...` |
| Dust | `mn_dust` | variable (BLS scalar) | `mn_dust1...` |

Network handling:
- **Mainnet:** suffix omitted (`mn_addr1...`).
- **Testnet/preview:** suffix included as `_<network>` before the `1` (`mn_addr_preview1...`).

Encoding pipeline (per 2c):
```
addressObject = new ShieldedAddress(coinPubKey, encPubKey)
encoded = MidnightBech32m.encode(networkId, addressObject)
addressString = encoded.asString()
parsed = MidnightBech32m.parse(addressString)
decoded = parsed.decode(ShieldedAddress, networkId)
```

The codec is symbol-based (`Bech32mSymbol`) for type-safe encode/decode without casting (`packages/address-format/src/index.ts:155-335`).

## What the ledger says about addresses (per 2b — `midnight-ledger`)

- `preliminaries.md`: shielded keys are random 256-bit secrets (`ZswapCoinSecretKey`), with SHA-256 of the secret as the public key (`ZswapCoinPublicKey`).
- `night.md`: unshielded address = `Hash<VerifyingKey>` — RIPEMD-160-like hash of the (per 2b) Schnorr-secp256k1 verifying key.
- `zswap.md`: coins are addressed by `CoinCommitment = Hash<(CoinInfo, ZswapCoinPublicKey)>` and nullified by `CoinNullifier = Hash<(CoinInfo, ZswapCoinSecretKey)>`. **No key reuse across coins** — each coin has its own randomized commitment/nullifier.
- `dust.md`: dust uses Poseidon hash in ZK-friendly field `Fr`: `DustPublicKey = field::Hash<DustSecretKey>` where `DustSecretKey ∈ Fr`.
- Bech32m HRPs are not in the ledger spec — wallet-layer concern.

## Single-address proposal (scope §8.4.2026)

Per [`../scope/midnight-scope.md`](../scope/midnight-scope.md):

> IOHK will share a proposal for a single address capturing unshielded, shielded and dust addresses, which should simplify OWS abstractions.

**Status: not shared as of 2026-04-29** (per HANDOVER §7 question 4). Phase 2 records the three-address-per-account model as the *current* contract; phase 3 will track the proposal.

## Address comparison vs OWS today

OWS today: one address per logical account per chain (`ows-baseline/chain-signer-trait.md`'s `derive_address(private_key) -> String`). Midnight: three addresses per account, all derivable from one mnemonic.

**Two natural shapes for OWS:**

1. **Sibling chains.** Treat Midnight as three sibling chain types (`midnight-shielded`, `midnight-unshielded`, `midnight-dust`). Each is its own `ChainSigner` with its own `coin_type` (e.g., 2400a/b/c). Existing `derive_address` works unchanged. Hides the wallet-account unity.
2. **One chain, multi-address API.** Add `derive_addresses(private_key) -> MidnightAddresses` (or per-domain methods) on a single `MidnightSigner`. Breaks `ChainSigner`'s contract.

The single-address proposal would collapse this to one address-per-account, restoring the existing `derive_address` shape. Phase 3 should make decision conditional on proposal landing.

## Second-pass refinements (2d / 2e / 2f / X-1)

**2d (WalletEngine `Specification.md`):** confirms three-address model and 5-role HD enum **exactly** (`Specification.md:189-214`). Address derivation details:

- **Unshielded address = SHA-256 hash of secp256k1 Schnorr public key** (32 bytes; `Specification.md:323-329`).
- **Shielded address = CPK ‖ EPK** concatenation (32+32 bytes; `Specification.md:351-366`). CPK = SHA-256 of coin secret key; EPK = `esk · G` on JubJub.
- **Dust address = SCALE-encoded compact Dust public key** (BLS12-381 scalar field element, variable length up to 33 bytes; `Specification.md:337-349`).
- **Shielded ESK and CPK separately encodable** with their own HRPs (`Specification.md:368-377`).
- **Address malleability noted** — shielded addresses are prone to malleability (attacker can replace coin or encryption key). Zcash solved this with diversified addresses (ZIP-0316); Midnight mentions this as possible future mitigation (`Specification.md:358`). OWS port should validate addresses defensively and warn UI.

**Test vectors directly portable to OWS Rust:** `WalletEngine/test-vectors/addresses.json` (2,281 lines, 10+ cases) and `keyDerivation.json` (400 lines, 20 seeds) cover address roundtrip and key derivation deterministically. Networks include `null` (mainnet), `"my-private-net"`, `"test"`, `"dev"`, `"undeployed"`. Format: hex payload + bech32m. Roundtrip assertion: `bech32.decode(bech32.encode(hex, ctx)) == hex`.

**2e (connector v4.0.0):** **structurally enforces three address types per account** at the dapp boundary — three separate methods (`getShieldedAddresses`, `getUnshieldedAddress`, `getDustAddress`), each mandatory on `WalletConnectedAPI`. Wallets cannot omit any without rejecting via `PermissionRejected`. **No bundled `getAddresses()` umbrella method.** Dapps must compose. Each address kind also appears as `kind: "shielded" | "unshielded"` on `DesiredOutput` / `DesiredInput` (`api.ts:272-286`) — tx-time per-method scoping, not per-domain.

This **closes X-4 with strong bias toward single-chain modeling** (see [open-questions.md](../open-questions.md) X-4). Three-address cohesion is stronger than sibling-chain modeling because all three derive from one mnemonic + one account.

**2f (Lace):** wraps SDK address types in branded value objects (`midnight-address.vo.ts`, `midnight-network-id.vo.ts`) for type safety. No new derivation logic — Lace consumes `@midnight-ntwrk/wallet-sdk-address-format` directly. This validates the upstream contract is mature enough to depend on.

## Open questions (after second pass)

- **Q-curves-1 → CLOSED (X-1, 2g 2026-04-29).** See [02-curves.md](02-curves.md). Outcome a: Schnorr-secp256k1 (BIP-340), no Ed25519.
- **Q-network-1:** address format encodes network as a Bech32m suffix; the canonical CAIP-2 reference for Midnight mainnet is undecided. Connector v4.0.0 uses bare strings. OWS adopts `midnight:mainnet` provisionally and translates at the boundary. See [`08-caip2.md`](08-caip2.md).
- **Q-roles-1:** the 5-role HD enum is hardcoded. New token types in future would either reuse Zswap or require a hard-fork. OWS must mirror this discipline; if we expose role customization, we deviate from upstream.
- **Q-addr-malleability (NEW from 2d):** shielded address malleability is a known issue noted in `Specification.md:358`. OWS should implement explicit validation + UX warning when receiving addresses that look suspicious, and should not silently accept addresses with extra/changed payload bytes.
