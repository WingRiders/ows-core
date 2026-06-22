# Topic 08 — CAIP-2 namespace and chain registry

> **Status:** first-pass populated by 2b (no CAIP-2 in spec) + 2c (no CAIP-2 in wallet) + scope. 2e (connector API) confirms `networkId="mainnet"` non-CAIP-2 convention.

## What's known (firm)

- **Midnight ledger spec** does not reference CAIP-2 (per 2b §B-08). Spec uses internal `version_tuple` for Cardano-system-transaction headers, not CAIP-2 strings.
- **Midnight wallet** uses an internal `NetworkId` branded type (per 2c §B-01); the wire form is mainnet (omitted suffix) or testnet/preview (`_<network>` suffix in Bech32m addresses).
- **Dapp connector API** uses `networkId="mainnet"` — bare string, not CAIP-2 (per HANDOVER §6 finding 7).
- **Scope (8.4.2026 update):** "IOHK stated that the CAIP-2 for Midnight is in progress and might not be finalized before the implementation concludes."

So **`midnight:mainnet` is OWS-internal until upstream CAIP-2 finalization.**

## OWS's CAIP-2 discipline

Per `docs/07-supported-chains.md:7-8`:

> OWS uses CAIP identifiers throughout. All wallet files, policy contexts, audit logs, and API parameters use these canonical formats — never shorthand aliases.

`docs/07-supported-chains.md:109`:

> Aliases MUST be resolved to full CAIP-2 identifiers before any processing. They MUST NOT appear in wallet files, policy files, or audit logs.

OWS is canonical on CAIP-2. Adopting `midnight:mainnet` provisionally creates a tension if upstream picks a different namespace (e.g., `midnight:0x...` with a chain-id-like reference, or merging into `polkadot:` since Midnight is Substrate-based).

## Plausible upstream CAIP-2 forms

Speculation, not commitment:
1. **`midnight:mainnet`** — what scope assumes. Simple. Likely eventual choice.
2. **`midnight:<genesis-hash-prefix>`** — analogous to Bitcoin's `bip122:000000000019d6689c085ae165831e93`. Pinned to a specific chain.
3. **`polkadot:<network-id>` or `substrate:<network-id>`** — given Midnight is a Substrate node + partner chain. Less likely because Midnight has its own ledger semantics.
4. **`midnight-ntwrk:mainnet`** — using the npm-org-style hyphenated name. Awkward but possible.

OWS should be designed to **swap the namespace string** without trait/core changes — the only places that hardcode it are `chain.rs::ChainType::namespace()`, `from_namespace`, and `KNOWN_CHAINS` entries. All change-of-string-only.

## Adding `ChainType::Midnight` to OWS

Per `../ows-baseline/chain-registry.md`, the additions:

1. `ChainType::Midnight` variant (`chain.rs:8-20`).
2. `ALL_CHAIN_TYPES` array entry — only if Midnight is part of universal cross-chain derivation (it probably is; one mnemonic produces Midnight account 0 alongside EVM/Solana/Bitcoin/etc.).
3. `KNOWN_CHAINS` entry: `Chain { name: "midnight", chain_type: ChainType::Midnight, chain_id: "midnight:mainnet" }`.
4. `ChainType::namespace() -> "midnight"` arm.
5. `ChainType::default_coin_type() -> 2400` arm (per 2c §B-01: midnight-wallet uses `m/44'/2400'/...`). **Note:** SLIP-44 [coin type registry](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) doesn't currently allocate 2400; need to verify with IOHK whether they've registered it or are using a private number.
6. `ChainType::from_namespace("midnight") -> Some(ChainType::Midnight)` arm.
7. `Display` and `FromStr` impls.
8. CLI alias if desired (`midnight` → `midnight:mainnet`) per `docs/07-supported-chains.md:79-109`.

Plus the `signer_for_chain` dispatch arm (`chains/mod.rs:29-43`).

## Multi-domain chain registry: three sibling chains?

Per [`01-addresses.md`](01-addresses.md): one option is to expose Midnight as three sibling chains (`midnight-shielded`, `midnight-unshielded`, `midnight-dust`). That would require:

- 3 `ChainType` variants (or one `ChainType::Midnight(MidnightDomain)`).
- 3 `KNOWN_CHAINS` entries.
- 3 namespace strings? (Doesn't fit OWS's `&'static str` mapping cleanly — these would be sub-namespaces of `midnight:` plus a domain marker.)

Phase 3 picks; phase 2 records that the registry can accommodate either shape with similar-shaped edits.

## Cross-CAIP issue: CAIP-10

`docs/07-supported-chains.md:13-22`:

```typescript
type AccountId = `${ChainId}:${string}`;
// e.g. "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
```

If `ChainId = "midnight:mainnet"` and address is the Bech32m string `mn_addr1...`, then CAIP-10 form is `midnight:mainnet:mn_addr1...`. Trips on the internal `:` separator if the address itself has colons (it doesn't, but Bech32m's separator `1` is structurally fine).

For three-address-per-account: there are three CAIP-10 IDs per logical account. Not problematic but verbose.

## What this means for OWS

- **Add `Midnight` variant + `KNOWN_CHAINS` entry now**, with `chain_id: "midnight:mainnet"`. Plan a one-line update if upstream CAIP-2 finalizes differently.
- **Coin type 2400** — confirm with IOHK SLIP-44 status before treating as canonical.
- **Single chain or sibling chains** is a phase-3 decision; both fit the registry.
- **Bare-string `networkId="mainnet"` from connector** — translate at the OWS↔connector boundary; never let bare strings into OWS's internal types or wallet files.

## Open questions

- **Q-caip2-1:** upstream CAIP-2 finalization timing/form. HANDOVER §7 question 7. Track via [https://github.com/ChainAgnostic/CAIPs](https://github.com/ChainAgnostic/CAIPs) PRs.
- **Q-caip2-2:** SLIP-44 coin type 2400 status — is this IOHK-registered, IOHK-private, or speculative?
- **Q-caip2-3:** one chain or three-sibling-chains registry shape (tied to [`01-addresses.md`](01-addresses.md) and `pluggability-seams.md` decisions).
