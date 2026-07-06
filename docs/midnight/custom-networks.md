# Custom Midnight networks

> Status: implemented. Use this guide for ad-hoc testnets, private deployments, and feature
> branches that are **not** mainnet, preview, or preprod.

## Overview

OWS treats Midnight network identity the same way the [DApp Connector
API](https://github.com/midnightntwrk/midnight-dapp-connector-api) does: a bare **network id string**
that must stay consistent across addresses, ledger `StandardTransaction.network_id`, and indexer
state. In OWS that string is the CAIP-2 **reference** portion of the chain id:

```
midnight:<network>
```

Examples:

| Deployment | OWS chain id | Ledger / connector `networkId` |
|---|---|---|
| Public preview | `midnight:preview` | `preview` |
| Public mainnet | `midnight:mainnet` | `mainnet` |
| Private feature net | `midnight:my-feature-testnet` | `my-feature-testnet` |
| Local dev (connector convention) | `midnight:undeployed` | `undeployed` |

You do **not** register custom networks in the OWS source tree. Point `--chain` at any
`midnight:<name>` that `parse_chain()` accepts (any non-empty reference after the `midnight:`
namespace). Built-in **friendly aliases** (`midnight-preview`, `midnight-preprod`, `midnight`) map
only to the three public networks; for everything else use the full CAIP-2 id.

## Configuration

Midnight uses **two** endpoints per network. Both are keyed by exact chain id in
`~/.ows/config.json` under the top-level `rpc` map (merged over built-in defaults):

| Purpose | Config key | Used for |
|---|---|---|
| Indexer (GraphQL HTTP + WebSocket) | `rpc["midnight:<network>"]` | Balance sync, UTXO selection, unsealed tx balancing/proving, post-submit refresh |
| Node JSON-RPC | `rpc["midnight:<network>:node"]` | `ows sign send-tx` → `author_submitExtrinsic` |

### Example: private testnet

```json
{
  "rpc": {
    "midnight:my-feature-testnet": "https://indexer.my-feature.example/api/v4/graphql",
    "midnight:my-feature-testnet:node": "https://rpc.my-feature.example"
  }
}
```

If a required URL is missing, OWS returns an explicit error (there is no silent fallback to
mainnet). Public networks ship defaults in `ows-core/src/config.rs`; custom networks must supply
both keys (or pass node RPC on send — see below).

### Per-send node override

`ows sign send-tx --rpc-url <url>` overrides **only** the node RPC for that invocation; the indexer
URL still comes from config. There is no CLI flag or environment variable to override the indexer
URL — add it to `config.json` (or extend OWS if you need ad-hoc indexer URLs without editing
config).

## Address and HRP rules

Bech32m human-readable parts (HRPs) follow the WalletEngine / address-format convention:

- **Mainnet** (`midnight:mainnet`): base HRP with no suffix — `mn_addr`, `mn_shield-addr`, `mn_dust`
- **Any other network**: base HRP + `_` + network reference — e.g. `midnight:preview` →
  `mn_addr_preview`; `midnight:my-feature-testnet` → `mn_addr_my-feature-testnet`

The same mnemonic-derived keys produce the same underlying payloads; only the HRP (and thus the
displayed Bech32m string) changes per network. Universal wallets still store the **mainnet** HRP
unshielded address in the vault; OWS re-encodes to the target network HRP at operation time when you
pass `--chain midnight:<network>`.

See [addressing.md](./addressing.md) for CAIP-10 shape and role derivation paths.

## What works without config

These operations need only a valid `midnight:<network>` chain id and a wallet — **no** indexer or
node URLs:

| Operation | Notes |
|---|---|
| `ows sign message` | DApp Connector `signData` prefix applied; local BIP-340 Schnorr |
| Address derivation (library / `derive_address`) | HRP derived from chain id |
| `ows sign tx` with **already sealed** wire bytes | Parses and signs owned inputs locally |

## What requires config

| Operation | Missing config error |
|---|---|
| `ows fund balance` | No indexer URL for chain id |
| `ows sign tx` with **unsealed** payloads | Indexer (balancing, UTXO/coin selection, DUST) |
| `ows sign tx` with DApp Connector JSON (`makeTransfer`, …) | Indexer (materialization / balancing) |
| `ows sign send-tx` | Node RPC (`:node` key or `--rpc-url`) |

All Midnight networks (mainnet, preview, preprod, and custom ids) use **DUST fee registration**
on unsealed intents when balancing. That path requires a mnemonic wallet with DUST role seed
(`m/44'/2400'/0'/2/{index}`), not a bare imported private key.

## CLI examples

Configure once:

```bash
# ~/.ows/config.json — see example above
```

Sign a message (no RPC):

```bash
ows sign message \
  --chain 'midnight:my-feature-testnet' \
  --wallet my-wallet \
  --message 'hello'
```

Check balances (indexer required):

```bash
ows fund balance \
  --chain 'midnight:my-feature-testnet' \
  --wallet my-wallet
```

Sign and broadcast (node RPC required):

```bash
ows sign send-tx \
  --chain 'midnight:my-feature-testnet' \
  --wallet my-wallet \
  --tx '<sealed-or-unsealed-payload>' \
  --rpc-url 'https://rpc.my-feature.example'   # optional if :node is in config
```

Use the **same** `--chain` value everywhere so `network_id` in built transactions, Bech32m HRPs,
and sync cache keys (`{vault}/sync/midnight/...`) all refer to one logical network.

## Library and bindings

Rust (`ows_lib::parse_chain`, `sign_message`, etc.), Node (`@open-wallet-standard/core`), and
Python bindings accept the same chain id strings as the CLI. Custom networks follow the same
config rules: indexer via `Config::load_or_default().rpc`, node RPC via config or the
`rpc_url` / `rpcUrl` argument on **sign-and-send** only.

## Related docs

- [addressing.md](./addressing.md) — CAIP-2 / CAIP-10 and HRP tables
- [architecture.md](./architecture.md) — indexer sync streams and transaction pipelines
- [chain-plugin-interface.md](./chain-plugin-interface.md) — signing and connector surface
- [07 — Supported Chains](../07-supported-chains.md) — registry entry and public network aliases
