# Midnight Support — CAIP-2 / CAIP-10 Addressing

> Status: implemented. This document specifies Midnight’s **CAIP-2 / CAIP-10 addressing** in OWS,
> including how the multi-credential wallet model (unshielded / shielded / DUST) maps onto the
> standard one-address-per-chain-family wallet record.

## Abstract

OWS identifies Midnight networks using **CAIP-2-shaped** identifiers of the form `namespace:reference`,
and represents wallet membership using **CAIP-10-shaped** identifiers of the form `chain_id:address`.
At the time of writing, **no Midnight namespace profile is registered** in the [Chain Agnostic Namespaces registry](https://github.com/ChainAgnostic/namespaces). OWS uses `midnight:*` identifiers in **CAIP-2 shape** until an official profile is published. Midnight has **three** address /
credential types (unshielded Night, shielded Zswap, and DUST). OWS stores **one address per chain family** in the wallet file, so the **unshielded (Night)** address is the canonical
CAIP-10 `address` portion for Midnight accounts. Shielded and DUST credentials are derived and used when an operation requires them.

## Specification

### 1. CAIP-2 chain identifiers

Midnight chains use the **`midnight`** namespace in a **provisional, CAIP-2-compatible** form.
These identifiers are stable in OWS releases, but callers should not treat `midnight` as a registered
CAIP-2 namespace until a Midnight profile is published in the Chain Agnostic Namespaces registry.

| Network | OWS name | CAIP-2 chain id |
|---|---|---|
| Mainnet | `midnight` | `midnight:mainnet` |
| Preview | `midnight-preview` | `midnight:preview` |
| Preprod | `midnight-preprod` | `midnight:preprod` |

`parse_chain()` accepts both friendly names and raw CAIP-2 ids; see `ows-core/src/chain.rs`.

### 2. CAIP-10 accounts (unshielded-only in OWS core)

OWS uses the CAIP-10 shape:

```
midnight:<network>:<address>
```

Where:

- `midnight:<network>` is one of the CAIP-2 chain ids above.
- `<address>` is the **unshielded (Night)** Bech32m address for that network.

Examples:

```
midnight:mainnet:mn_addr1...
midnight:preview:mn_addr_preview1...
midnight:preprod:mn_addr_preprod1...
```

The account id is assembled in the generic account derivation code as:
`format!("{}:{}", chain.chain_id, address)` (see `ows-lib/src/ops.rs`).

### 3. Address formats and network-specific HRPs

#### 3.1 Unshielded (Night) address (used as CAIP-10 `address`)

OWS derives the unshielded address from the wallet’s Midnight unshielded signing key (BIP-340 Schnorr
over secp256k1), following the WalletEngine rule:

- **Public key**: BIP-340 **x-only** verifying key (32 bytes)
- **Payload**: `SHA-256(x_only_pubkey)` (32 bytes)
- **Encoding**: Bech32m with network-specific HRP

Network HRPs:

| Network | HRP prefix |
|---|---|
| Mainnet | `mn_addr` |
| Preview | `mn_addr_preview` |
| Preprod | `mn_addr_preprod` |

For any other network reference `<network>` (e.g. `midnight:my-feature-testnet`), OWS uses
`mn_addr_<network>`, `mn_shield-addr_<network>`, and `mn_dust_<network>`. Mainnet is the only
network with unsuffixed HRPs. See [custom-networks.md](./custom-networks.md).

OWS stores the mainnet-HRP unshielded address in universal wallets, and re-encodes it to preview /
preprod HRPs at operation time when the same underlying key is used against another network. This is
intentional and mirrors the “same key, different network encoding” pattern used by XRPL.

#### 3.2 Shielded (Zswap) address (not used as CAIP-10 `address`)

Midnight shielded addresses are derived from a **32-byte shielded seed** (not the unshielded signing
key) and are Bech32m-encoded under network-specific HRPs:

| Network | HRP prefix |
|---|---|
| Mainnet | `mn_shield-addr` |
| Preview | `mn_shield-addr_preview` |
| Preprod | `mn_shield-addr_preprod` |

OWS uses shielded credentials for shielded balance sync and for connector flows that require a
shielded recipient (e.g. `makeIntent`), but does not expose shielded addresses as the chain family
account address in the wallet file.

#### 3.3 DUST address (not used as CAIP-10 `address`)

Midnight DUST addresses are derived from a **32-byte dust seed**, encoded as Bech32m under
network-specific HRPs:

| Network | HRP prefix |
|---|---|
| Mainnet | `mn_dust` |
| Preview | `mn_dust_preview` |
| Preprod | `mn_dust_preprod` |

DUST credentials are used for fee registration and related ledger flows on all Midnight networks.

### 4. HD derivation paths and “roles” (WalletEngine)

OWS follows the WalletEngine layout:

```
m / 44' / 2400' / account' / role / index
```

OWS uses `account = 0` and the following roles:

| Credential / purpose | Role | Path used by OWS |
|---|---:|---|
| Unshielded (Night) | 0 | `m/44'/2400'/0'/0/{index}` |
| DUST seed | 2 | `m/44'/2400'/0'/2/{index}` |
| Shielded seed (Zswap) | 3 | `m/44'/2400'/0'/3/{index}` |

Because OWS stores a single derivation path per `WalletAccount`, Midnight accounts
record the **unshielded** derivation path and address. Shielded / DUST roles are derived on demand
from the mnemonic when an operation requires them.

### 5. Wallet-type constraints (mnemonic vs imported private key)

OWS supports importing wallets from raw private keys, but that representation only carries
the **unshielded Night** secret for Midnight.

- **Mnemonic wallets**: can derive unshielded + shielded + DUST roles.
- **Imported private-key wallets**: can derive **only** the unshielded Night address; shielded balances
  and DUST-fee unsealed signing require a mnemonic wallet.

## References

- [CAIP-2: Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10: Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [Chain Agnostic Namespaces (registry)](https://github.com/ChainAgnostic/namespaces)
- [CAIP-104: Namespace Reference Purpose and Guidelines](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-104.md)
- [SLIP-44: Registered coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) (Midnight = 2400)
