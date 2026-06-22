# Chain registry — `ows-core::chain`

## ChainType enum

`ows/crates/ows-core/src/chain.rs:6-20`

```rust
pub enum ChainType {
    Evm, Solana, Cosmos, Bitcoin, Tron, Ton, Spark, Filecoin, Sui, Xrpl, Nano,
}
```

11 variants. Unit (zero-sized) — no per-variant data. Serializes to lowercase string via `#[serde(rename_all = "lowercase")]`.

`ALL_CHAIN_TYPES` (`chain.rs:23-34`) is a 10-entry array used for "universal wallet derivation." Filecoin is intentionally absent from this array (present in the enum, present in `KNOWN_CHAINS`, but excluded from cross-chain bulk derivation).

## Chain struct

`chain.rs:37-42`

```rust
pub struct Chain {
    pub name: &'static str,        // friendly name ("ethereum", "base")
    pub chain_type: ChainType,     // family
    pub chain_id: &'static str,    // CAIP-2 ID ("eip155:1", ...)
}
```

No runtime metadata (no RPC endpoint, no per-chain feature flags). Endpoint discovery is implementation-specific per `docs/07-supported-chains.md:43-46`.

## KNOWN_CHAINS

`chain.rs:77-193`

23 chains in the static registry:

- **EVM (11):** ethereum (eip155:1), polygon (eip155:137), arbitrum (eip155:42161), optimism (eip155:10), base (eip155:8453), plasma (eip155:9745), bsc (eip155:56), avalanche (eip155:43114), etherlink (eip155:42793), tempo (eip155:4217), hyperliquid (eip155:999).
- **Non-EVM (12):** solana, bitcoin (bip122:000000000019d6689c085ae165831e93), cosmos (cosmos:cosmoshub-4), tron, ton, spark, filecoin, sui, xrpl + xrpl-testnet + xrpl-devnet, nano. All non-EVM use `<namespace>:mainnet` except where the CAIP-2 spec defines a network-specific reference (Solana genesis hash, Bitcoin genesis-hash prefix, Cosmos chain-id).

## parse_chain

`chain.rs:200-260`

Accepts:
1. Friendly name ("ethereum", "base")
2. Full CAIP-2 ID ("eip155:1", "eip155:8453")
3. Bare numeric EVM ID ("8453" → eip155:8453)
4. Legacy "evm" (deprecated, warns to stderr, resolves to ethereum)

For unknown CAIP-2 IDs whose namespace is recognized (e.g., a previously-unseen `eip155:N`), creates a synthetic `Chain` by **leaking a `String` into a `'static str`** (`chain.rs:228`, `chain.rs:240-248`) — necessary because `Chain.name` and `Chain.chain_id` are `&'static str`. Acceptable per the inline comment because callers feed user-supplied chain identifiers, bounded.

For unknown chain identifiers, returns `Err(format!(...))` listing supported chains in a help string (`chain.rs:251-259`).

## ChainType methods

- `namespace() -> &'static str` (`chain.rs:269-283`) — hardcoded 1:1 mapping to CAIP-2 namespaces. 11 arms.
- `default_coin_type() -> u32` (`chain.rs:286-300`) — hardcoded SLIP-44 coin types. 11 arms. Values: EVM 60, Solana 501, Cosmos 118, Bitcoin 0, Tron 195, Ton 607, Spark 8797555, Filecoin 461, Sui 784, Xrpl 144, Nano 165.
- `from_namespace(ns: &str) -> Option<ChainType>` (`chain.rs:303-318`) — reverse mapping. 11 arms.
- `Display` (`chain.rs:321-338`) and `FromStr` (`chain.rs:340-359`) impls.

## Tests

`chain.rs:361-631` — 24 unit tests cover serde roundtrip, namespace mapping, coin-type mapping, `parse_chain` legacy/CAIP-2/numeric/aliases, `evm_chain_reference`, `from_str`, `from_namespace`, and `default_chain_for_type`.

## Aliases (CLI-only)

Per `docs/07-supported-chains.md:79-109`: aliases are CLI-only convenience. They MUST be resolved to full CAIP-2 IDs before any processing. They MUST NOT appear in wallet files, policy files, or audit logs.

## Salient facts for delta vs. Midnight

- **Closed enum.** Adding a chain edits this enum in five places (variant, `ALL_CHAIN_TYPES` if cross-chain-derivable, `namespace`, `default_coin_type`, `from_namespace`, `Display`, `FromStr`).
- **One coin type per ChainType.** No multi-coin-type per family (Midnight has three logical key-domains, each plausibly its own coin-type).
- **Single namespace per ChainType.** No namespace versioning — adding `midnight:mainnet` while CAIP-2 finalizes upstream ([scope 8.4.2026](../../scope/midnight-scope.md)) means the namespace is OWS-internal until the registry catches up.
- **`KNOWN_CHAINS` carries no curve hint.** The curve mapping lives in `signer_for_chain()`'s constructed signers via `ChainSigner::curve()`. No `Chain.curve` field.
