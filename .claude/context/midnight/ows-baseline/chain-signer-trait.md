# ChainSigner trait — `ows-signer::traits`

## Definition

`ows/crates/ows-signer/src/traits.rs:19-82`

```rust
pub trait ChainSigner: Send + Sync {
    fn chain_type(&self) -> ChainType;
    fn curve(&self) -> Curve;
    fn coin_type(&self) -> u32;
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError>;
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;
    fn sign_transaction(&self, private_key: &[u8], tx_bytes: &[u8]) -> Result<SignOutput, SignerError>;
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> { Ok(tx_bytes) }
    fn encode_signed_transaction(&self, tx_bytes: &[u8], signature: &SignOutput) -> Result<Vec<u8>, SignerError> { /* default: error */ }
    fn default_derivation_path(&self, index: u32) -> String;
}
```

**9 methods total.** `extract_signable_bytes` and `encode_signed_transaction` have default impls (the latter errors). The remaining 7 are required.

## SignOutput

`traits.rs:5-13`

```rust
pub struct SignOutput {
    pub signature: Vec<u8>,
    pub recovery_id: Option<u8>,         // None for ed25519
    pub public_key: Option<Vec<u8>>,     // some chains include pubkey in wire format (Sui)
}
```

Single signature per call. No multi-sig, threshold, or composite signature shape.

## SignerError

`traits.rs:85-101` — five variants: `InvalidPrivateKey`, `InvalidMessage`, `SigningFailed`, `AddressDerivationFailed`, `InvalidTransaction`. All carry `String` payloads. No structured fields.

## Trait-level invariants

The trait doc-comment (`traits.rs:17-18`) states: "All methods take raw `&[u8]` private keys — callers are responsible for HD derivation and zeroization of key material." This makes signers **stateless w.r.t. keys** — they neither own nor cache key material.

The trait requires `Send + Sync`, so signers are usable across threads.

## Per-chain implementations

`ows/crates/ows-signer/src/chains/mod.rs:1-43` registers 11 chain modules and the dispatcher:

```rust
pub fn signer_for_chain(chain: ChainType) -> Box<dyn ChainSigner> {
    match chain {
        ChainType::Evm => Box::new(EvmSigner),
        ChainType::Solana => Box::new(SolanaSigner),
        ChainType::Bitcoin => Box::new(BitcoinSigner::mainnet()),
        ChainType::Cosmos => Box::new(CosmosSigner::cosmos_hub()),
        ChainType::Tron => Box::new(TronSigner),
        ChainType::Ton => Box::new(TonSigner),
        ChainType::Spark => Box::new(SparkSigner),
        ChainType::Filecoin => Box::new(FilecoinSigner),
        ChainType::Sui => Box::new(SuiSigner),
        ChainType::Xrpl => Box::new(XrplSigner),
        ChainType::Nano => Box::new(NanoSigner),
    }
}
```

`Box<dyn ChainSigner>` — single dispatch per chain type. All variants are zero-sized except `BitcoinSigner` (parameterizes Bech32 HRP via `mainnet()`/`testnet()`) and `CosmosSigner` (parameterizes via `cosmos_hub()` etc.).

## Representative implementation: EvmSigner

`ows/crates/ows-signer/src/chains/evm.rs:200-314` — full impl of the trait.

Concrete behavior:
- `derive_address` (`evm.rs:213-229`) — uncompressed pubkey → keccak256 → last 20 bytes → EIP-55 checksum.
- `sign` (`evm.rs:231-257`) — requires 32-byte prehash; uses `k256::ecdsa::SigningKey::sign_prehash_recoverable`; returns 65-byte sig (r ‖ s ‖ v) + recovery id.
- `sign_message` (`evm.rs:292-309`) — EIP-191 prefix `\x19Ethereum Signed Message:\n{len}` then keccak256 then `sign`; sets `v = 27 + recovery_id`.
- `sign_transaction` (`evm.rs:259-267`) — keccak256 of tx_bytes then `sign`.
- `encode_signed_transaction` (`evm.rs:269-290`) — assembles RLP-encoded signed transaction via `crate::rlp::encode_signed_typed_tx`.
- `default_derivation_path` (`evm.rs:311-313`) — `m/44'/60'/0'/0/{index}`.
- Extra (not in trait): `authorization_payload`, `authorization_hash` (EIP-7702), `sign_typed_data` (EIP-712 with domain separator).

## Salient facts for delta vs. Midnight

- **Single-curve, single-key.** Each `ChainSigner` impl returns one `Curve` and signs with one private key. Midnight will need three keys per logical account (shielded/unshielded/dust) over potentially three curves (BLS12-381 + JubJub for shielded/dust, secp256k1 for unshielded per the wallet contracts).
- **No proving.** Trait's signing methods are signature operations only. ZK proof generation is out of scope. Midnight's shielded transactions require a proof, which doesn't fit any of the 9 method shapes.
- **Stateless.** No prover keys, no sync state, no per-call memoization beyond the global 5-second LRU `HdDeriver` cache. Midnight prover state (CRS, proving keys) is large and not cleanly stateless.
- **`SignOutput` is single-sig.** Midnight transactions can carry a *binding signature* + per-input *spend authorizations* — multi-signature shape inside one tx.
- **`extract_signable_bytes` is `&'a [u8] -> &'a [u8]` zero-copy.** Midnight may need a deeper restructure (e.g., parse balanced tx → re-serialize). Default's borrowing won't survive that; Solana's override (`solana.rs:80-99`) sets the precedent for non-trivial extraction but stays zero-copy.
