use bech32::{Bech32m, Hrp};
use k256::schnorr::{signature::Signer as _, SigningKey};
use midnight_ledger::dust::{DustPublicKey, DustSecretKey};
use midnight_serialize::{tagged_deserialize, ScaleBigInt, Serializable};
use midnight_zswap::keys::{SecretKeys as ZswapSecretKeys, Seed as ZswapSeed};
use num_bigint::BigUint;
use sha2::Digest;

use crate::curve::Curve as OwsCurve;
use crate::hd::HdDeriver;
use crate::mnemonic::Mnemonic;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;

/// Midnight (unshielded / Night) signing support.
///
/// Note: Midnight also has Dust and Shielded credentials that are not modeled by the
/// current OWS chain abstraction (single curve + single address per chain family).
/// This signer implements the unshielded/Night key + address as specified in the
/// Midnight WalletEngine specification.
pub struct MidnightSigner;

/// Bech32m HRP bases used for Midnight addresses; network references must produce valid
/// combined HRPs for each (`mn_addr_{network}`, …).
const MIDNIGHT_ADDRESS_BASE_HRPS: &[&str] =
    &["mn_addr", "mn_shield-addr", "mn_dust", "mn_shield-esk"];

/// Extract the ledger / DApp connector network id from a CAIP-2 Midnight chain id
/// (`midnight:<network>`).
pub fn network_reference_from_chain_id(chain_id: &str) -> Result<String, SignerError> {
    let trimmed = chain_id.trim();
    let (namespace, reference) = trimmed.split_once(':').ok_or_else(|| {
        SignerError::AddressDerivationFailed(format!(
            "expected midnight CAIP-2 chain id (midnight:<network>), got {chain_id:?}"
        ))
    })?;
    if !namespace.eq_ignore_ascii_case("midnight") {
        return Err(SignerError::AddressDerivationFailed(format!(
            "expected midnight namespace in chain id, got {chain_id:?}"
        )));
    }
    if reference.is_empty() {
        return Err(SignerError::AddressDerivationFailed(
            "midnight chain id must include a network reference after 'midnight:'".into(),
        ));
    }
    validate_network_reference(reference)?;
    Ok(reference.to_string())
}

/// Reject network references that are not safe Midnight network id strings or would produce
/// invalid Bech32m HRPs when suffixed.
fn validate_network_reference(network_ref: &str) -> Result<(), SignerError> {
    if !network_ref
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(SignerError::AddressDerivationFailed(format!(
            "invalid midnight network reference {network_ref:?}: must contain only lowercase letters, digits, and hyphens"
        )));
    }
    if network_ref.starts_with('-') || network_ref.ends_with('-') {
        return Err(SignerError::AddressDerivationFailed(format!(
            "invalid midnight network reference {network_ref:?}: must not start or end with a hyphen"
        )));
    }
    validate_network_reference_for_bech32_hrp(network_ref)
}

/// Reject network references that would produce invalid Bech32m HRPs when suffixed.
fn validate_network_reference_for_bech32_hrp(network_ref: &str) -> Result<(), SignerError> {
    for base in MIDNIGHT_ADDRESS_BASE_HRPS {
        let hrp = hrp_for_network(base, network_ref);
        Hrp::parse(&hrp).map_err(|e| {
            SignerError::AddressDerivationFailed(format!(
                "invalid midnight network reference {network_ref:?} (Bech32m HRP {hrp:?}): {e}"
            ))
        })?;
    }
    Ok(())
}

/// True when the network reference is mainnet (no Bech32m HRP suffix).
pub fn is_mainnet_network_reference(network_ref: &str) -> bool {
    network_ref.eq_ignore_ascii_case("mainnet")
}

/// Build a Bech32m HRP for a Midnight address type on the given network.
///
/// Mainnet uses the base HRP with no suffix (`mn_addr`). Every other network appends
/// `_{network}` (`mn_addr_preview`, `mn_addr_my-feature`, …).
pub fn hrp_for_network(base_hrp: &str, network_ref: &str) -> String {
    if is_mainnet_network_reference(network_ref) {
        base_hrp.to_string()
    } else {
        format!("{base_hrp}_{network_ref}")
    }
}

/// Midnight has three address types (unshielded, shielded, dust).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidnightAddresses {
    pub unshielded: String,
    pub shielded: String,
    pub dust: String,
}

impl MidnightSigner {
    /// Bech32m HRP for a Midnight unshielded (Night) address on the given chain id.
    ///
    /// Mainnet (`midnight:mainnet`) → `mn_addr`. Every other network uses
    /// `mn_addr_{network}` (e.g. `mn_addr_preview`, `mn_addr_my-feature-testnet`).
    pub fn unshielded_hrp_for_chain_id(chain_id: &str) -> Result<String, SignerError> {
        let network = network_reference_from_chain_id(chain_id)?;
        Ok(hrp_for_network("mn_addr", &network))
    }

    /// Bech32m HRP for a Midnight shielded (Zswap) address on the given chain id.
    pub fn shielded_hrp_for_chain_id(chain_id: &str) -> Result<String, SignerError> {
        let network = network_reference_from_chain_id(chain_id)?;
        Ok(hrp_for_network("mn_shield-addr", &network))
    }

    /// Bech32m HRP for a Midnight DUST address on the given chain id.
    pub fn dust_hrp_for_chain_id(chain_id: &str) -> Result<String, SignerError> {
        let network = network_reference_from_chain_id(chain_id)?;
        Ok(hrp_for_network("mn_dust", &network))
    }

    /// Re-encode a stored unshielded address for another Midnight network.
    ///
    /// Universal wallets store the mainnet-HRP address only; preview / preprod (and future
    /// networks) use the same key with a different Bech32m HRP — same pattern as XRPL testnet
    /// sharing a key but with network-specific address encoding.
    pub fn reencode_unshielded_address_for_chain_id(
        target_chain_id: &str,
        address: &str,
    ) -> Result<String, SignerError> {
        use bech32::primitives::decode::CheckedHrpstring;

        let checked = CheckedHrpstring::new::<Bech32m>(address).map_err(|e| {
            SignerError::AddressDerivationFailed(format!("invalid midnight address bech32m: {e}"))
        })?;
        let payload = checked.byte_iter().collect::<Vec<u8>>();
        let hrp_str = Self::unshielded_hrp_for_chain_id(target_chain_id)?;
        let hrp = Hrp::parse(&hrp_str).map_err(|e| {
            SignerError::AddressDerivationFailed(format!("invalid midnight hrp: {e}"))
        })?;
        bech32::encode::<Bech32m>(hrp, &payload)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("bech32m encode: {e}")))
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte secp256k1 key, got {} bytes",
                private_key.len()
            )));
        }
        SigningKey::from_bytes(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid secp256k1 key: {e}")))
    }

    fn bech32m_encode(hrp: &str, payload: &[u8]) -> Result<String, SignerError> {
        let hrp = Hrp::parse(hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("invalid hrp: {e}")))?;
        bech32::encode::<Bech32m>(hrp, payload)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("bech32m encode: {e}")))
    }

    /// Derive the unshielded (Night) Bech32m address from a 32-byte BIP-340 x-only public key.
    ///
    /// For the same keypair, this matches [`Self::derive_unshielded_address_with_hrp`] when
    /// `hrp` is the network unshielded HRP (see [`Self::unshielded_hrp_for_chain_id`]).
    pub fn derive_unshielded_address_from_xonly_pubkey(
        pk_xonly: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        if pk_xonly.len() != 32 {
            return Err(SignerError::AddressDerivationFailed(format!(
                "expected 32-byte x-only pubkey, got {} bytes",
                pk_xonly.len()
            )));
        }
        let hash = sha2::Sha256::digest(pk_xonly);
        Self::bech32m_encode(hrp, &hash)
    }

    fn derive_unshielded_address_with_hrp(
        &self,
        private_key: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let pk_xonly = sk.verifying_key().to_bytes(); // 32 bytes
        Self::derive_unshielded_address_from_xonly_pubkey(&pk_xonly, hrp)
    }

    // === Midnight Wallet SDK-compatible helpers ===

    /// Derive the unshielded address (type `mn_addr1...`) from a 32-byte secret key.
    ///
    /// For preview / preprod networks, use [`ChainSigner::derive_address_for_chain_id`].
    pub fn derive_unshielded_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        <Self as ChainSigner>::derive_address(self, private_key)
    }

    /// Derive a shielded address with the given Bech32m HRP from a 32-byte shielded seed.
    ///
    /// Follows the Wallet SDK convention:
    /// - `coinPublicKey` is a 32-byte hash-derived public key
    /// - `encryptionPublicKey` is a 32-byte Jubjub group encoding
    /// - address payload is `coinPublicKey || encryptionPublicKey` (64 bytes), Bech32m-encoded
    fn derive_shielded_address_with_hrp(
        &self,
        seed: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!(
                "expected 32-byte shielded seed, got {} bytes",
                seed.len()
            ))
        })?;
        let keys = ZswapSecretKeys::from(ZswapSeed::from(seed_arr));

        let coin_public = keys.coin_public_key().0 .0;

        let mut enc_public = Vec::new();
        keys.enc_public_key()
            .serialize(&mut enc_public)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
        if enc_public.len() != 32 {
            return Err(SignerError::AddressDerivationFailed(format!(
                "unexpected encryption public key length: {}",
                enc_public.len()
            )));
        }

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&coin_public);
        payload.extend_from_slice(&enc_public);

        Self::bech32m_encode(hrp, &payload)
    }

    /// Derive the shielded address (type `mn_shield-addr1...`) from a 32-byte shielded seed.
    ///
    /// For preview / preprod networks, use [`Self::derive_shielded_address_from_seed_for_chain_id`].
    pub fn derive_shielded_address_from_seed(&self, seed: &[u8]) -> Result<String, SignerError> {
        self.derive_shielded_address_with_hrp(seed, "mn_shield-addr")
    }

    /// Derive the shielded address for the given Midnight `chain_id` from a 32-byte shielded seed.
    ///
    /// HRP is selected via [`Self::shielded_hrp_for_chain_id`], mirroring
    /// [`ChainSigner::derive_address_for_chain_id`] on the unshielded side.
    pub fn derive_shielded_address_from_seed_for_chain_id(
        &self,
        chain_id: &str,
        seed: &[u8],
    ) -> Result<String, SignerError> {
        let hrp = Self::shielded_hrp_for_chain_id(chain_id)?;
        self.derive_shielded_address_with_hrp(seed, &hrp)
    }

    /// Derive the dust address (type `mn_dust1...`) from a 32-byte dust seed.
    ///
    /// Wallet SDK encodes the dust *public key* (a field element) as SCALE compact,
    /// then Bech32m-encodes it under the `mn_dust` HRP (mainnet).
    ///
    /// For preview / preprod networks, use [`Self::derive_dust_address_from_seed_for_chain_id`].
    pub fn derive_dust_address_from_seed(&self, seed: &[u8]) -> Result<String, SignerError> {
        self.derive_dust_address_from_seed_with_hrp(seed, "mn_dust")
    }

    /// Derive the dust address for the given Midnight `chain_id` from a 32-byte dust seed.
    ///
    /// HRP is selected via [`Self::dust_hrp_for_chain_id`], mirroring
    /// [`Self::derive_shielded_address_from_seed_for_chain_id`] on the shielded side.
    pub fn derive_dust_address_from_seed_for_chain_id(
        &self,
        chain_id: &str,
        seed: &[u8],
    ) -> Result<String, SignerError> {
        let hrp = Self::dust_hrp_for_chain_id(chain_id)?;
        self.derive_dust_address_from_seed_with_hrp(seed, &hrp)
    }

    fn derive_dust_address_from_seed_with_hrp(
        &self,
        seed: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        if seed.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte dust seed, got {} bytes",
                seed.len()
            )));
        }

        let seed_arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| SignerError::InvalidPrivateKey("seed must be 32 bytes".into()))?;
        let dsk = DustSecretKey::derive_secret_key(&seed_arr);
        let dpk = DustPublicKey::from(dsk);

        // JS `fr_to_bigint`: bytes are little-endian, reversed, then interpreted as a hex bigint.
        // So numeric value is the same; we can build it directly from big-endian bytes.
        let mut be = dpk.0.as_le_bytes();
        be.reverse();
        let dust_pk = BigUint::from_bytes_be(&be);

        let payload = scale_bigint_encode_biguint(&dust_pk)?;
        Self::bech32m_encode(hrp, &payload)
    }

    /// Convenience: derive all Midnight address types from a BIP-39 mnemonic.
    ///
    /// Wallet SDK path: `m/44'/2400'/account'/role/index`
    /// - role 0: unshielded (Night external)
    /// - role 3: shielded (Zswap)
    /// - role 2: dust
    pub fn derive_all_from_mnemonic(
        &self,
        mnemonic: &Mnemonic,
        passphrase: &str,
        account: u32,
        index: u32,
    ) -> Result<MidnightAddresses, SignerError> {
        let unshielded_path = format!("m/44'/2400'/{}'/0/{}", account, index);
        let shielded_path = format!("m/44'/2400'/{}'/3/{}", account, index);
        let dust_path = format!("m/44'/2400'/{}'/2/{}", account, index);

        let unshielded_key = HdDeriver::derive_from_mnemonic(
            mnemonic,
            passphrase,
            &unshielded_path,
            OwsCurve::Secp256k1,
        )
        .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let shielded_seed = HdDeriver::derive_from_mnemonic(
            mnemonic,
            passphrase,
            &shielded_path,
            OwsCurve::Secp256k1,
        )
        .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let dust_seed =
            HdDeriver::derive_from_mnemonic(mnemonic, passphrase, &dust_path, OwsCurve::Secp256k1)
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        Ok(MidnightAddresses {
            unshielded: self.derive_unshielded_address(unshielded_key.expose())?,
            shielded: self.derive_shielded_address_from_seed(shielded_seed.expose())?,
            dust: self.derive_dust_address_from_seed(dust_seed.expose())?,
        })
    }
}

/// Standard Midnight transaction wire shape (preimage vs proven proofs).
///
/// Mirrors [midnight-wallet-cli](https://github.com/nel349/midnight-wallet-cli) `ConnectedAPI`:
/// `balanceUnsealedTransaction` ↔ [`MidnightStandardTxKind::Unsealed`] (`ProofPreimageMarker`),
/// `balanceSealedTransaction` ↔ [`MidnightStandardTxKind::Sealed`] (`ProofMarker`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidnightStandardTxKind {
    Unsealed,
    Sealed,
}

impl MidnightStandardTxKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsealed => "unsealed",
            Self::Sealed => "sealed",
        }
    }
}

fn scale_bigint_encode_biguint(n: &BigUint) -> Result<Vec<u8>, SignerError> {
    // Midnight uses a custom SCALE-compatible BigInt encoding (`ScaleBigInt`).
    // This matches the wallet-sdk / ledger-v8 behavior.
    let bytes_le = n.to_bytes_le();
    if bytes_le.len() > 67 {
        return Err(SignerError::AddressDerivationFailed(
            "ScaleBigInt: integer too large".into(),
        ));
    }
    let mut sb = ScaleBigInt::default();
    sb.0[..bytes_le.len()].copy_from_slice(&bytes_le);
    let mut out = Vec::new();
    sb.serialize(&mut out)
        .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
    Ok(out)
}

impl ChainSigner for MidnightSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Midnight
    }

    fn curve(&self) -> OwsCurve {
        OwsCurve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        2400
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        // Spec: Unshielded payment address is SHA256(unshielded pubkey), encoded in Bech32m.
        // Pubkey is the Schnorr (BIP-340 style) public key (x-only).
        // Mainnet HRP: `mn_addr` (no network suffix).
        self.derive_unshielded_address_with_hrp(private_key, "mn_addr")
    }

    fn derive_address_for_chain_id(
        &self,
        chain_id: &str,
        private_key: &[u8],
    ) -> Result<String, SignerError> {
        let hrp = Self::unshielded_hrp_for_chain_id(chain_id)?;
        self.derive_unshielded_address_with_hrp(private_key, &hrp)
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Midnight unshielded uses Schnorr over secp256k1 (BIP-340).
        //
        // Although BIP-340 is commonly described as signing 32-byte message hashes, the underlying
        // library (`k256`) accepts arbitrary-length messages and performs the required hashing as
        // part of the signing algorithm. Midnight ledger code signs over domain-separated
        // serialized payloads (often longer than 32 bytes), so we must accept arbitrary lengths.
        let sk = Self::signing_key(private_key)?;
        let sig = sk.sign(message);
        Ok(SignOutput {
            signature: sig.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(sk.verifying_key().to_bytes().to_vec()),
        })
    }

    /// Sign arbitrary bytes with the wallet's **unshielded (Night)** signing key (BIP-340 Schnorr).
    ///
    /// The `private_key` is the same 32-byte secret used for the unshielded Bech32m payment address
    /// ([`Self::derive_unshielded_address`]). OWS does not offer message signing with shielded or dust
    /// credentials on Midnight; that matches the Midnight DApp Connector `signData` API, where the
    /// only [`SignDataOptions.keyType`](https://github.com/midnightntwrk/midnight-dapp-connector-api/blob/36c46edcb8101fed94c84d913598d07ab9120973/src/api.ts#L296-L309)
    /// for arbitrary payloads is `'unshielded'`.
    ///
    /// Wallets sign the decoded payload bytes directly (no Ethereum-style envelope); see unit tests
    /// for captured `signData` vectors.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Midnight transaction signing signs over the (segment_id, signature-erased, proof-erased)
        // intent payload, not necessarily over the raw serialized transaction bytes.
        //
        // If the caller provides a full `midnight:transaction[...]` blob (as seen on the wire),
        // we try to parse it and locate an unshielded input owned by this private key. If found,
        // we sign the exact intent `data_to_sign(segment_id)` bytes used by the ledger.
        //
        let sk = Self::signing_key(private_key)?;
        let vk_bytes: [u8; 32] = sk.verifying_key().to_bytes().into();

        // Only the canonical on-wire container is supported.
        if !tx_bytes.starts_with(b"midnight:transaction") {
            return Err(SignerError::InvalidTransaction(
                "expected tagged midnight transaction bytes (prefix `midnight:transaction`)".into(),
            ));
        }

        let sig = sign_midnight_txbytes_for_owner(tx_bytes, &vk_bytes, &sk)?;
        Ok(SignOutput {
            signature: sig,
            recovery_id: None,
            public_key: Some(vk_bytes.to_vec()),
        })
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // WalletEngine spec: m / 44' / 2400' / account' / role / index
        // We expose the unshielded external role (0) under the standard OWS single-address model.
        format!("m/44'/2400'/0'/0/{}", index)
    }
}

impl MidnightSigner {
    /// Detect whether a tagged Standard transaction uses the **unsealed** (proof preimage) or
    /// **sealed** (proven) ledger encoding — same ordering as [`MidnightSigner::sign_and_encode`].
    pub fn classify_standard_midnight_transaction(
        tx_bytes: &[u8],
    ) -> Result<MidnightStandardTxKind, SignerError> {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{
            ProofKind, ProofMarker, ProofPreimageMarker, Transaction,
        };
        use midnight_storage::db::InMemoryDB;

        if !tx_bytes.starts_with(b"midnight:transaction") {
            return Err(SignerError::InvalidTransaction(
                "expected tagged midnight transaction bytes (prefix `midnight:transaction`)".into(),
            ));
        }

        type TxPre = Transaction<
            MnSig,
            ProofPreimageMarker,
            <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;
        type TxProven = Transaction<
            MnSig,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;

        let mut reader: &[u8] = tx_bytes;
        if let Ok(tx) = tagged_deserialize::<TxPre>(&mut reader) {
            let Transaction::Standard(_) = tx else {
                return Err(SignerError::InvalidTransaction(
                    "expected Standard transaction".into(),
                ));
            };
            return Ok(MidnightStandardTxKind::Unsealed);
        }

        let mut reader: &[u8] = tx_bytes;
        let tx: TxProven = tagged_deserialize::<TxProven>(&mut reader).map_err(|e| {
            SignerError::InvalidTransaction(format!("failed to parse midnight tx bytes: {e}"))
        })?;
        let Transaction::Standard(_) = tx else {
            return Err(SignerError::InvalidTransaction(
                "expected Standard transaction".into(),
            ));
        };
        Ok(MidnightStandardTxKind::Sealed)
    }

    /// Parse a tagged `midnight:transaction` blob, sign **all** guaranteed unshielded inputs that
    /// match this key (same owner as `private_key`), and return re-serialized tagged bytes.
    ///
    /// Unsupported today: contract actions, **dust spends** (ZK proofs), and
    /// partially-owned guaranteed inputs (every guaranteed input must be spendable by this key).
    /// Fallible unshielded inputs owned by this key are supported.
    ///
    /// **Dust registrations** (fee allowance without spends) are supported: each registration must
    /// bind the same Night verifying key as this `private_key`.
    pub fn sign_and_encode(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        use midnight_base_crypto::signatures::SigningKey as LedgerSigningKey;
        use midnight_ledger::structure::{
            ProofKind, ProofMarker, ProofPreimageMarker, Transaction,
        };
        use midnight_serialize::{tagged_deserialize, tagged_serialize};
        use midnight_storage::db::InMemoryDB;
        use midnight_storage::storage::HashMap as MnHashMap;
        use rand::rngs::OsRng;
        use std::ops::Deref as _;

        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte secp256k1 key, got {} bytes",
                private_key.len()
            )));
        }
        if !tx_bytes.starts_with(b"midnight:transaction") {
            return Err(SignerError::InvalidTransaction(
                "expected tagged midnight transaction bytes (prefix `midnight:transaction`)".into(),
            ));
        }

        let ledger_sk = LedgerSigningKey::from_bytes(private_key).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("invalid midnight signing key: {e}"))
        })?;
        let vk = ledger_sk.verifying_key();

        type TxPre = Transaction<
            midnight_base_crypto::signatures::Signature,
            ProofPreimageMarker,
            <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;
        type TxProven = Transaction<
            midnight_base_crypto::signatures::Signature,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;

        fn sign_standard_tx<P, B>(
            mut stx: midnight_ledger::structure::StandardTransaction<
                midnight_base_crypto::signatures::Signature,
                P,
                B,
                InMemoryDB,
            >,
            vk: midnight_base_crypto::signatures::VerifyingKey,
            ledger_sk: LedgerSigningKey,
        ) -> Result<
            midnight_ledger::structure::StandardTransaction<
                midnight_base_crypto::signatures::Signature,
                P,
                B,
                InMemoryDB,
            >,
            SignerError,
        >
        where
            P: ProofKind<InMemoryDB>,
            B: midnight_storage::Storable<InMemoryDB>
                + midnight_serialize::Serializable
                + midnight_ledger::structure::PedersenDowngradeable<InMemoryDB>,
        {
            let mut intents_out = MnHashMap::new();
            for seg_id in stx.intents.keys() {
                let intent_sp = stx.intents.get(&seg_id).ok_or_else(|| {
                    SignerError::InvalidTransaction("missing intent segment".into())
                })?;
                let intent = (*intent_sp.deref()).clone();

                if !intent.actions.is_empty() {
                    return Err(SignerError::InvalidTransaction(
                        "transaction contains contract actions; not supported by sign_and_encode"
                            .into(),
                    ));
                }
                let dust_registration_keys: Vec<LedgerSigningKey> =
                    match intent.dust_actions.as_deref() {
                        None => Vec::new(),
                        Some(da) => {
                            let mut keys = Vec::new();
                            for reg in da.registrations.iter() {
                                if reg.night_key != vk {
                                    return Err(SignerError::InvalidTransaction(
                                        "dust registration night key must match the signing key"
                                            .into(),
                                    ));
                                }
                                keys.push(ledger_sk.clone());
                            }
                            keys
                        }
                    };

                if !intent.fallible_inputs().is_empty() {
                    for inp in intent.fallible_inputs() {
                        if inp.owner != vk {
                            return Err(SignerError::InvalidTransaction(
                                "all fallible unshielded inputs must be owned by the signing key"
                                    .into(),
                            ));
                        }
                    }
                }

                let guaranteed_inputs = intent.guaranteed_inputs();
                let fallible_inputs = intent.fallible_inputs();
                let n_g = guaranteed_inputs.len();
                let n_f = fallible_inputs.len();
                if n_g == 0 && n_f == 0 && dust_registration_keys.is_empty() {
                    intents_out = intents_out.insert(seg_id, intent);
                    continue;
                }
                if n_g > 0 {
                    for inp in &guaranteed_inputs {
                        if inp.owner != vk {
                            return Err(SignerError::InvalidTransaction(
                                "all guaranteed unshielded inputs must be owned by the signing key"
                                    .into(),
                            ));
                        }
                    }
                }
                let g_keys = vec![ledger_sk.clone(); n_g];
                let f_keys = vec![ledger_sk.clone(); n_f];
                let signed = intent
                    .sign(
                        &mut OsRng,
                        seg_id,
                        &g_keys,
                        &f_keys,
                        &dust_registration_keys,
                    )
                    .map_err(|e| {
                        SignerError::InvalidTransaction(format!("intent signing failed: {e:?}"))
                    })?;
                intents_out = intents_out.insert(seg_id, signed);
            }
            stx.intents = intents_out;
            Ok(stx)
        }

        // Try preimage tx first; fall back to proven tx.
        let mut reader: &[u8] = tx_bytes;
        if let Ok(tx) = tagged_deserialize::<TxPre>(&mut reader) {
            let Transaction::Standard(stx) = tx else {
                return Err(SignerError::InvalidTransaction(
                    "expected Standard transaction".into(),
                ));
            };
            let stx = sign_standard_tx(stx, vk, ledger_sk)?;
            let out_tx: TxPre = Transaction::Standard(stx);
            let mut out = Vec::new();
            tagged_serialize(&out_tx, &mut out).map_err(|e| {
                SignerError::InvalidTransaction(format!("failed to serialize signed tx: {e}"))
            })?;
            return Ok(out);
        }

        let mut reader: &[u8] = tx_bytes;
        let tx: TxProven = tagged_deserialize::<TxProven>(&mut reader).map_err(|e| {
            SignerError::InvalidTransaction(format!("failed to parse midnight tx bytes: {e}"))
        })?;
        let Transaction::Standard(stx) = tx else {
            return Err(SignerError::InvalidTransaction(
                "expected Standard transaction".into(),
            ));
        };
        let stx = sign_standard_tx(stx, vk, ledger_sk)?;
        let out_tx: TxProven = Transaction::Standard(stx);
        let mut out = Vec::new();
        tagged_serialize(&out_tx, &mut out).map_err(|e| {
            SignerError::InvalidTransaction(format!("failed to serialize signed tx: {e}"))
        })?;
        Ok(out)
    }
}

fn sign_midnight_txbytes_for_owner(
    tx_bytes: &[u8],
    owner_vk_xonly: &[u8; 32],
    sk: &SigningKey,
) -> Result<Vec<u8>, SignerError> {
    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofKind, ProofMarker, ProofPreimageMarker, Transaction};
    use midnight_storage::db::InMemoryDB;
    use std::ops::Deref as _;

    fn ser<T: midnight_serialize::Serializable>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.serialize(&mut out)
            .expect("in-memory serialize should succeed");
        out
    }

    fn scan_standard<P, B>(
        std: &midnight_ledger::structure::StandardTransaction<MnSig, P, B, InMemoryDB>,
        owner_vk_xonly: &[u8; 32],
        sk: &SigningKey,
    ) -> Result<Vec<u8>, SignerError>
    where
        P: midnight_ledger::structure::ProofKind<InMemoryDB>,
        B: midnight_storage::Storable<InMemoryDB>
            + midnight_serialize::Serializable
            + midnight_ledger::structure::PedersenDowngradeable<InMemoryDB>,
    {
        for seg_intent in std.intents.iter() {
            let segment_id = *seg_intent.0;
            let intent = seg_intent.1.deref();

            let erased = intent.erase_proofs().erase_signatures();
            let verify_input = erased.data_to_sign(segment_id);

            for offer in intent
                .guaranteed_unshielded_offer
                .iter()
                .chain(intent.fallible_unshielded_offer.iter())
            {
                let offer = offer.deref();
                for (inp, _sig) in offer.inputs.iter_deref().zip(offer.signatures.iter_deref()) {
                    let inp_owner = ser(&inp.owner);
                    if inp_owner.as_slice() == owner_vk_xonly {
                        let sig = sk.sign(&verify_input);
                        return Ok(sig.to_bytes().to_vec());
                    }
                }
            }
        }

        Err(SignerError::InvalidTransaction(
            "no matching unshielded input owner found for this key".into(),
        ))
    }

    type TxMarker = Transaction<
        MnSig,
        ProofMarker,
        <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;
    type TxPreimage = Transaction<
        MnSig,
        ProofPreimageMarker,
        <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;

    let mut reader: &[u8] = tx_bytes;
    if let Ok(Transaction::Standard(std)) = tagged_deserialize::<TxMarker>(&mut reader) {
        return scan_standard(&std, owner_vk_xonly, sk);
    }

    let mut reader: &[u8] = tx_bytes;
    let tx: TxPreimage = tagged_deserialize::<TxPreimage>(&mut reader).map_err(|e| {
        SignerError::InvalidTransaction(format!("failed to parse midnight tx bytes: {e}"))
    })?;

    let Transaction::Standard(std) = tx else {
        return Err(SignerError::InvalidTransaction(
            "expected Standard transaction".into(),
        ));
    };

    scan_standard(&std, owner_vk_xonly, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::signature::Verifier as _;
    use k256::schnorr::Signature as SchnorrSignature;

    #[test]
    fn test_midnight_classify_standard_tx_unsealed_vs_sealed() {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{
            Intent, ProofKind, ProofMarker, ProofPreimageMarker, Transaction,
        };
        use midnight_serialize::tagged_serialize;
        use midnight_storage::db::InMemoryDB;
        use midnight_storage::storage::HashMap as MnHashMap;
        use rand::rngs::OsRng;

        // Minimal Standard transaction: one empty intent segment.
        let mut rng = OsRng;
        let intent = Intent::new(
            &mut rng,
            None,   // guaranteed_unshielded_offer
            None,   // fallible_unshielded_offer
            vec![], // actions
            vec![], // parties
            vec![], // witnesses
            None,   // dust_actions
            midnight_base_crypto::time::Timestamp::from_secs(1_700_000_000),
        );
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1u16, intent);
        let tx_unsealed: Transaction<
            MnSig,
            ProofPreimageMarker,
            <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        > = Transaction::from_intents("preview", intents);

        let mut unsealed_bytes = Vec::new();
        tagged_serialize(&tx_unsealed, &mut unsealed_bytes).expect("serialize unsealed");
        assert_eq!(
            MidnightSigner::classify_standard_midnight_transaction(&unsealed_bytes).unwrap(),
            MidnightStandardTxKind::Unsealed
        );

        let tx_sealed: Transaction<
            MnSig,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        > = tx_unsealed.mock_prove().expect("mock_prove");
        let mut sealed_bytes = Vec::new();
        tagged_serialize(&tx_sealed, &mut sealed_bytes).expect("serialize sealed");
        assert_eq!(
            MidnightSigner::classify_standard_midnight_transaction(&sealed_bytes).unwrap(),
            MidnightStandardTxKind::Sealed
        );
    }

    #[test]
    fn test_midnight_three_addresses_vector() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let signer = MidnightSigner;
        let addrs = signer
            .derive_all_from_mnemonic(&mnemonic, "", 0, 0)
            .unwrap();

        assert_eq!(
            addrs.unshielded,
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );

        assert_eq!(
            addrs.shielded,
            "mn_shield-addr1ywxc2p9986usecc9xert79afzq4m9x35u62sx0a4e2tc5w6mta5ulwhc432vhrlpnvygfep3pxcdt8tgzfstesrm6tf7hjc5jgpl20gcwvwgz"
        );

        assert_eq!(
            addrs.dust,
            "mn_dust1wwcff2ckd4n5hfj43055td8glwtzkhhf6z88xwf0rpftvgstr7zpxpl07jx"
        );
    }

    #[test]
    fn test_midnight_preview_unshielded_address_matches_har() {
        // Regression: preview HRP + derivation should be stable.
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();

        let signer = MidnightSigner;
        let curve = signer.curve();
        let path = signer.default_derivation_path(0);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve).unwrap();

        let preview_addr = signer
            .derive_address_for_chain_id("midnight:preview", key.expose())
            .unwrap();

        assert!(preview_addr.starts_with("mn_addr_preview1"));
        assert!(preview_addr.len() > "mn_addr_preview1".len());

        let mainnet_addr = signer.derive_address(key.expose()).unwrap();
        let reencoded = MidnightSigner::reencode_unshielded_address_for_chain_id(
            "midnight:preview",
            &mainnet_addr,
        )
        .unwrap();
        assert_eq!(reencoded, preview_addr);
    }

    #[test]
    fn test_midnight_preview_dust_address_uses_network_hrp() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();

        let signer = MidnightSigner;
        let dust_path = "m/44'/2400'/0'/2/0";
        let dust_seed =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", dust_path, signer.curve()).unwrap();

        let mainnet_dust = signer
            .derive_dust_address_from_seed(dust_seed.expose())
            .unwrap();
        assert!(mainnet_dust.starts_with("mn_dust1"));

        let preview_dust = signer
            .derive_dust_address_from_seed_for_chain_id("midnight:preview", dust_seed.expose())
            .unwrap();
        assert!(preview_dust.starts_with("mn_dust_preview1"));

        // Same underlying key; only the Bech32m HRP differs.
        use bech32::primitives::decode::CheckedHrpstring;
        let mainnet_payload = CheckedHrpstring::new::<Bech32m>(&mainnet_dust)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        let preview_payload = CheckedHrpstring::new::<Bech32m>(&preview_dust)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        assert_eq!(mainnet_payload, preview_payload);
    }

    #[test]
    fn custom_network_reference_hrp_and_address() {
        let chain = "midnight:my-feature-testnet";
        assert_eq!(
            super::network_reference_from_chain_id(chain).unwrap(),
            "my-feature-testnet"
        );
        assert_eq!(
            MidnightSigner::unshielded_hrp_for_chain_id(chain).unwrap(),
            "mn_addr_my-feature-testnet"
        );
        assert_eq!(
            MidnightSigner::shielded_hrp_for_chain_id(chain).unwrap(),
            "mn_shield-addr_my-feature-testnet"
        );
        assert_eq!(
            MidnightSigner::dust_hrp_for_chain_id(chain).unwrap(),
            "mn_dust_my-feature-testnet"
        );

        let signer = MidnightSigner;
        let key = [11u8; 32];
        let addr = signer
            .derive_address_for_chain_id(chain, &key)
            .expect("custom network address");
        assert!(addr.starts_with("mn_addr_my-feature-testnet1"));
    }

    #[test]
    fn custom_network_unshielded_reencode_round_trip() {
        let chain = "midnight:custom-net";
        let signer = MidnightSigner;
        let key = [11u8; 32];

        let custom_addr = signer
            .derive_address_for_chain_id(chain, &key)
            .expect("custom network address");
        assert!(custom_addr.starts_with("mn_addr_custom-net1"));

        let mainnet_addr = signer.derive_address(&key).expect("mainnet address");
        let reencoded =
            MidnightSigner::reencode_unshielded_address_for_chain_id(chain, &mainnet_addr)
                .expect("reencode stored mainnet address");
        assert_eq!(reencoded, custom_addr);
    }

    #[test]
    fn custom_network_shielded_and_dust_share_mainnet_payload() {
        use bech32::primitives::decode::CheckedHrpstring;

        let chain = "midnight:custom-net";
        let signer = MidnightSigner;
        let shielded_seed = [22u8; 32];
        let dust_seed = [33u8; 32];

        let mainnet_shielded = signer
            .derive_shielded_address_from_seed(&shielded_seed)
            .expect("mainnet shielded");
        let custom_shielded = signer
            .derive_shielded_address_from_seed_for_chain_id(chain, &shielded_seed)
            .expect("custom shielded");
        assert!(custom_shielded.starts_with("mn_shield-addr_custom-net1"));
        let mainnet_shielded_payload = CheckedHrpstring::new::<Bech32m>(&mainnet_shielded)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        let custom_shielded_payload = CheckedHrpstring::new::<Bech32m>(&custom_shielded)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        assert_eq!(mainnet_shielded_payload, custom_shielded_payload);

        let mainnet_dust = signer
            .derive_dust_address_from_seed(&dust_seed)
            .expect("mainnet dust");
        let custom_dust = signer
            .derive_dust_address_from_seed_for_chain_id(chain, &dust_seed)
            .expect("custom dust");
        assert!(custom_dust.starts_with("mn_dust_custom-net1"));
        let mainnet_dust_payload = CheckedHrpstring::new::<Bech32m>(&mainnet_dust)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        let custom_dust_payload = CheckedHrpstring::new::<Bech32m>(&custom_dust)
            .unwrap()
            .byte_iter()
            .collect::<Vec<u8>>();
        assert_eq!(mainnet_dust_payload, custom_dust_payload);
    }

    #[test]
    fn network_reference_from_chain_id_rejects_invalid_ids() {
        let err = super::network_reference_from_chain_id("preview").unwrap_err();
        assert!(err.to_string().contains("midnight CAIP-2"), "{err}");

        let err = super::network_reference_from_chain_id("midnight:").unwrap_err();
        assert!(err.to_string().contains("network reference"), "{err}");

        let err = super::network_reference_from_chain_id("eip155:1").unwrap_err();
        assert!(err.to_string().contains("midnight namespace"), "{err}");

        let err = super::network_reference_from_chain_id("midnight:foo/bar").unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid midnight network reference"),
            "{err}"
        );

        let err = super::network_reference_from_chain_id("midnight:Preview").unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid midnight network reference"),
            "{err}"
        );

        let err = super::network_reference_from_chain_id("midnight:-bad").unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid midnight network reference"),
            "{err}"
        );
    }

    #[test]
    fn test_midnight_sign_message_hashes_then_signs() {
        let signer = MidnightSigner;
        let private_key = [7u8; 32];
        let message = b"hello midnight";

        let out = signer.sign_message(&private_key, message).unwrap();
        assert_eq!(out.signature.len(), 64);
        assert_eq!(out.recovery_id, None);
        assert_eq!(out.public_key.as_ref().unwrap().len(), 32);

        // sign_message() == sign(raw_message_bytes)
        let expected = signer.sign(&private_key, message).unwrap();

        assert_eq!(out.signature, expected.signature);
        assert_eq!(out.public_key, expected.public_key);

        // Signature verifies against the returned x-only pubkey and message bytes.
        let vk = k256::schnorr::VerifyingKey::from_bytes(out.public_key.as_ref().unwrap())
            .expect("valid verifying key");
        let sig = SchnorrSignature::try_from(out.signature.as_slice()).expect("valid signature");
        assert!(vk.verify(message, &sig).is_ok());

        let expected_unshielded = signer
            .derive_unshielded_address(&private_key)
            .expect("derive unshielded address");
        let from_signing_pubkey = MidnightSigner::derive_unshielded_address_from_xonly_pubkey(
            out.public_key.as_ref().unwrap(),
            "mn_addr",
        )
        .expect("address from signing pubkey");
        assert_eq!(
            from_signing_pubkey, expected_unshielded,
            "signature pubkey must correspond to the wallet unshielded address"
        );
    }

    #[test]
    fn test_midnight_sign_message_matches_wallet_sign_data_vector() {
        // Deterministic fixture for Midnight message signing:
        // - mnemonic: standard BIP-39 test vector ("abandon ... about")
        // - message: "hello world"
        //
        // We assert that:
        // - the derived x-only verifying key is stable
        // - the produced signature verifies against the message bytes
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let signer = MidnightSigner;

        let path = signer.default_derivation_path(0);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, signer.curve()).unwrap();

        let expected_unshielded = signer
            .derive_unshielded_address(key.expose())
            .expect("derive unshielded address");
        assert_eq!(
            expected_unshielded,
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );

        let msg = b"hello world";
        let out = signer.sign_message(key.expose(), msg).unwrap();

        // Public key is x-only (32 bytes) and stable for the derived key.
        let derived_vk = out.public_key.as_ref().unwrap();
        assert_eq!(derived_vk.len(), 32);

        // Signature verifies against the message bytes.
        let vk = k256::schnorr::VerifyingKey::from_bytes(derived_vk).unwrap();
        let sig = SchnorrSignature::try_from(out.signature.as_slice()).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());

        // Signing pubkey must match the unshielded payment address (SHA256(xonly) → Bech32m).
        let from_signing_pubkey =
            MidnightSigner::derive_unshielded_address_from_xonly_pubkey(derived_vk, "mn_addr")
                .expect("address from signing pubkey");
        assert_eq!(
            from_signing_pubkey, expected_unshielded,
            "message signing must be attributable to this wallet's unshielded address"
        );

        assert_eq!(
            hex::encode(&out.signature),
            "64b41c8c7aa7763f9b4291268c517900e1b044e10e8f53a5725359a67255bf97d6531252b8541965027ccfd2973181d33455ac9bdce9e6caea30e6c6a875f1a0"
        );
    }

    #[test]
    fn test_midnight_sign_transaction_hashes_then_signs() {
        let signer = MidnightSigner;
        let private_key = [9u8; 32];

        let tx_bytes = b"some serialized midnight intent / tx bytes";
        let err = signer
            .sign_transaction(&private_key, tx_bytes)
            .expect_err("expected non-tagged tx bytes to be rejected");
        match err {
            SignerError::InvalidTransaction(_) => {}
            other => panic!("expected InvalidTransaction, got: {other:?}"),
        }
    }

    #[test]
    fn sign_and_encode_accepts_fallible_unshielded_inputs() {
        use midnight_base_crypto::hash::HashOutput;
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_base_crypto::signatures::SigningKey as LedgerSigningKey;
        use midnight_base_crypto::time::Timestamp;
        use midnight_coin_structure::coin::NIGHT;
        use midnight_ledger::structure::{
            Intent, IntentHash, ProofKind, ProofPreimageMarker, Transaction, UnshieldedOffer,
            UtxoSpend, STARS_PER_NIGHT,
        };
        use midnight_serialize::tagged_serialize;
        use midnight_storage::db::InMemoryDB;
        use midnight_storage::storage::HashMap as MnHashMap;
        use rand::rngs::OsRng;

        let private_key = [9u8; 32];
        let ledger_sk = LedgerSigningKey::from_bytes(&private_key).unwrap();
        let vk = ledger_sk.verifying_key();

        let spend = UtxoSpend {
            value: STARS_PER_NIGHT,
            owner: vk,
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([7u8; 32])),
            output_no: 0,
        };
        let fallible = UnshieldedOffer::<MnSig, InMemoryDB> {
            inputs: vec![spend].into(),
            outputs: vec![].into(),
            signatures: vec![].into(),
        };
        let mut rng = OsRng;
        let intent = Intent::new(
            &mut rng,
            None,
            Some(fallible),
            vec![],
            vec![],
            vec![],
            None,
            Timestamp::from_secs(1_700_000_000),
        );
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1, intent);
        let tx: Transaction<
            MnSig,
            ProofPreimageMarker,
            <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        > = Transaction::from_intents("preview", intents);
        let mut tx_bytes = Vec::new();
        tagged_serialize(&tx, &mut tx_bytes).expect("serialize tx");

        MidnightSigner::sign_and_encode(&MidnightSigner, &private_key, &tx_bytes)
            .expect("fallible unshielded inputs should be signable");
    }

    #[test]
    fn test_midnight_sign_is_deterministic_for_same_input() {
        let signer = MidnightSigner;
        let private_key = [1u8; 32];
        let msg = b"not necessarily 32 bytes";

        let a = signer.sign(&private_key, msg).unwrap();
        let b = signer.sign(&private_key, msg).unwrap();
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.public_key, b.public_key);
    }

    #[test]
    fn test_midnight_sign_transaction_matches_signature_in_har_txbytes() {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{ProofKind, ProofMarker, Transaction};
        use midnight_storage::db::InMemoryDB;
        use std::ops::Deref as _;

        // `txBytes` of actual midnight tx
        const TX_BYTES_HEX: &str = "6d69646e696768743a7472616e73616374696f6e5b76395d287369676e61747572655b76315d2c70726f6f662c706564657273656e2d7363686e6f72725b76315d293a74000857d900ad2e0b80fa6235940d7360c67a1e5b4eab2a72069fb442458108446b4272e5d16430e1187f696e69da677378d3ac216f93242721da1857d4fd90eb31adf120943e5f9264ebaa55b026ea71812d90d5952dcbb66769591f1feb734eb940eb330cb9fa31864fc621db135caef91fc922b043abd75c29cf8d448bf2033c41ab3fef8085a417b5a738f2ca77a6bb0014fe105f572ac4890cddfe0af989b806096257eb56f7fc4f2ed5f223c891a8b9a9bc818e6b911339d3c9f1fab2dae9f5f24b3a4b4432bf5e71f97f7e2f0fa39522d20e8a863bf0a425f876221fc76f35b71817bd7c8bc9b28d13fece378107c5ed9a01d2122317c33c211d1f1ede88c127292a02dfb12976014f59a2d94b0a13a392408fa783d5afc09abcf7dfb59c84dc7ca755c741cd9db709688f9f9b2c5cd9971ac1601ca00eac4d37e1fd79b2768d16dab4000d41f52f9f83b43a5ed42967a95872fc2721ec3d60df6e790c160b93a4a4ca2a47d13cbfc9e056a6d7f83a819bcf042d7135d9b9b67a0f04f6007878ec46724b89ed122beef1e7a1dff7d21b0f0eb3ccf30ad4685f69c7a1f5e7a7b6bdfd6d52b9b5915002246e0a5b6819947f9b3bf1424db8c327a2b03203f31166ed0e795d452095ba0f03288aaa210185b23396783e6200db4624a6541dd4eb7aadcb983ab1bdb4aff02200169a9d838fc00e516b2a4b90c973dc2f69c5eea385f92a98bf7addfb334de04eed511b9abda3e0cd4c63b8c7848d9d9891c0537649068e46c26305e35b9aefc7ae1b652d95fc8a19a7623ce0f9d3f1a45ae8dc55619ff2658e41e60d6c6c71660e685728e692640925ccbf2205ba1d7b4ae82fb08409205f92b43ecc00b550c105d709598a2c1f3b08c1103e929c6c35b68dcea3b075c4505960c8cd03498244b5cb1c0a88bf88161f574d149da8e031ba2a2b719c355d8ef28f7ca3b1cb1dd8be6b4868149211fa10bbfbfc1a3579a58571153fac4d11f52f37ae24c33c0dc90880269570b9859e04117fabd5de5d1316947b0018dd66457709ad774cc747ab3a535e9cb771314f0273455e3787e16b93c3de5e0920c76130ab59e5815933cd376cb283ffe5652f25aad1e5b9707663a1f8bfecad35d7c7e6658dcf69bcaabb0b9bf337bc80a66cc8fac5d4e6b5e5f06514519b6ad2ceb09c9fad6a138fd91d3d784a1d97492bb529e94b9d0553ab309112eb1c19fcb48cfa9d5e6ea9372db0fe877c994581d62f3ff021eb4070ac6ce36af62d810c02c62d5ccfd2b086e21eeba61ec4c2d84d1aa6cfca731aec9d7920da6ee90ea041654517a3958d76a558077245d684429d0508d64099f2c239fad8fa53903700b84e5edce0fa0e4eb2560a500417aedb9111d6d0e469f96e9ab0aa3299baa6b20a8e8baa1500cb88f04d546a7585bd82980aa7bdd128b3c8e86fd32e43602c292318f23de94e71391133557895b60000000000000000000000000000000000000000000000000000000000000000a1915b7b6dba3729964974cda2b677257e38eeaa7c31b7257a3681097855544d99dc8ea020ce505a15dcc7247351c90714141c5a51f4d69c4550e926b45fc928fefe960ae4132c7f0c47051d2903bd2b7bc4779ebf4410ac0b8db17ec6e02905d2730c71021fd2860bdc49c12c30faa6d0c1743f0d86b4dec658cdc6d78bc90b6a63d3ebd24d736072dea9c3d188084aa375ae60cfd1056651fe1bfab6d3634de710e3529cf8c45767a8f7d3b30de4b9569ae1527cea8569ab117fa6b74406447b3e58a617f0aeb98df50b15cfe882edf3a14cb9fe3453faafb782292cf3a934c38ef8a095857289c3afa2692354c7d12785a7977424899117d9d7852b970312ed723d41648880ed0248b9f85d92667b43b78bb21728fb9821763dac396e0a47283956fb916df6ea509fa89b5a661703ff023a82b8116e85cefd155a30fe7657bbdd1170d236a0b4fe6a4df8b33554e6c625e7b850d10eaa42e0fe5df3fdaf51adf5e926eb552fccda36bb2572c87e1044ebaead19628056c65c4057dbfd8903e78e327b41dd950e715b25d2d776aa9a3a6a5ddd058b096b6d825873f44c32036d560cfeccea6f579d1ea5730b880f369397784793230bb09a08b3f7d8c5f75a537b6e8aa3b3cb22e9214fc693fb2fd8812cd3d9002bb4524c4b0a60b84d6b3c17920c0537449db599c324b1e1cbac59006b179e1a671c4e530caffee66992280103d6889fce31d5c0b03645190c67ed7d28c7d73321a28620d340ebe059ab2080fa5346af74a2661eeb430111adfdbd386da588a18768b32b84e9872f7a860f84ff2e35abb9ccd1ed5e4f8accc38ed406a5e86a5556f952efcaa6c7b5227214f7fa31d2dfd25334422133598ef0cf151b44da011e196922bb7af28fbd13685a1e3727aebc2e3da83d3d0343ae2f0cd1337cc56aa6d7fb549cb3172d8548620b592f721aea92982e4b1796f1d07c38ea05815d8b1207205d187c6f9a5ba0206fff19baed2e28b640b10809cf2814727bc71b06b04c786b1e62c17cb8094c6929d1b59e1f5a42f41c592233d6a03d45acc11ff12e512e38eea78128df6cfd350b1caff09b7e71c064f23d7461408c415039ff41771941101526b1e1c6ccca211600000000000000000000000000000000000000000000000000000000000000007b72c175cbdbfa287b56b2ba0317213e32371113d369229ef6b7177a73e83845452971201171e10c2218babc13e97c9ed783e91233d523fb1e981a783dbad40ffcf9a371e8718e1d534fccd6e4d16db8729047379ba4f720b77f85e020780158af28569114c0251d63493f74e8e60c71d73499f2e3087dd5b96a5d2eb70aa00dc2069e3ee3cf51eec5ff4aed4622f3d1daeb3e6e50bfa88a4ea27760f22ce03b21f4fdea17950a48ea2ab39fbac30273a3d863c7bdb16ae5900b9600a6cc6e1c37c741181a5c5377b376d523a3e74921567ec94f7c4d4e822ee0709d644780235f2edb0fe53b446d6e63336e4b034344e7e94e5073f1c3ebd26dac6bc60ad02763036e2ffd3ba53a0bbed1cc27e116fe471aa174d49308340387cc92a72ca94b35e77dee2b7630d3f1f039278ed65e371f5e94aacedd2565b20cf7f3b4a7b72af14496b292206189cebe22a904b1f469d110ee30e0420f264bc02364d709e8113b25bc0643b9e68fe5c81e157d953a8fe075071907df28d01603de32b557af4b3237fff1b6113ff6b8d5eef5a49f2235e571a7b5bcc7f8799e0346748549225294debbe2fa52974f2f291117ab65284f9f90b67aa345d5246b3b1f6afdbc106b1267deeb13d708c53baaabc71b445f1d331e043de6665f9c4232858b5dc02910105019d00e7e5e88abee591de73c2bda7dd8183a25af1fc5e1d7d3d6832b5d6154a541d8e6dfa33bae798ce57e6c4e029980396063a304f037165afe7086f652f100874af0dc8355483b8c09ab9df66ec100b118f52eadfe7ab84b4d2de2073214fa50350582fa0399925a51c879fe04b107b3ef3a4c5b7940905533069728423c265e5277cae7eddfaf25980a5271a4848fcc0649745f05ac61687c9250be12ef9473ee2454e061435b043ccee393578dab04589c637e268087942277dd2d035308f0613bfea13a52c296a37db894ce6f1590ee85967e9e6dbe5d57c720440795f34381ae2aa22c870cccee2e93799f359d4ebb1f3646e6754f7f7499a78866bb73c63248a9052e1c272268098c7c2de9d2479053370d3895028c8a6982967046a470c85ef9d798db7b0313bcd0a6b25e462ddc943411706bbc1b914f95df2dece324de543b24b0bbbaa780af29f3a6407fb819d45caf01ed5af7d46baace26391dbc9a477d66987fa27a7158e4397e33e788dbc0306214b168ff0b7e5d5b3da9dea2521e6c91fb9c2735431ec933f565ee7f88d59cdddc4afea8c9a62526f32ec46587dd65c4754bf3d8b46fdb76b91fae08a434e70196df6d60b715b69723e167f25c1709801f8893823b16a3da39b0de961053a9b8e9c3da5b46d345c0c591093a9aa0c769f4d156e2b82a808a20a1d83328b73e16308b0dd90daa12680036a652f2da73d4e5d95dfbf354841110454486bfd37cd4a0965cdc999c362f87264979fbf6b8155b77c7920ecc6f68518062b7c292afce1466f95f4ed21cab0514771dc1421ebc43e1aa1eb2b850a04a0344d0ebfb79a9ce530b6f8bb3fb38c100b12e0f81c50bfc440301731883121794ead4a6bedc4727874cb5aada930bde8bd5a552499d3cad2f6bab3373237d088594eadde3808b02f9f948edc2d3c53a8a2617283c42e393bdee827413812db2d6a50050ddd4d42a0cd205204bd358674d15a1d67b7365e3fc0e84a93d143111a5748410cd3338b728b49827989cb2a689884c551adc8a79e2d294eb9253ef2c1278c30a6f1061e4a08180fe06ffa4b24e1523afcc9b352aad93a02889d98289bb0aac57b12e811d4c02cd2bfc0f744a041bd0d8e9f701130390ec547b9dd9cb77190330b8025838b7a720ef1add158c037b88b4b113d155678ca7cd4d6a1a1b1b300839b89bd0a4602aada89a5bb49677d3c8182bde541327003caceceb2d99360eb43c78d16bce71f3861fbcb64e222cc1c3f23dd69b46db7b2f63322d80522978a4e95682f9f1380b599bc3e5d9a5b8be9dedb231209b6f02873f5a15e0e302ed835e264452bce263d31f22b795da5bcd66077a704f2c308b7010bcaec68b0631a4e15201ada7b14fc644fa189f2c660479fcde4247747dbfcef86eceec7deccfc0785bc2053760ce898474ea6bacc7709781ce954f1d533bbd387b0753ac134e09dd518bd1404453331d73adf6bf65e74380688866e74fcec5f96c8dc4b63be4a40378aed3760a5a202f340f9b539db694bda895d177d49b084ec3aa46f157b07adb231ffc1f2a8b271e3f0b22b12c2fb4931e915e771a195c6bed03e7f4831558dc51c39aecc0573f97db0d657b99982b604f5cc7d4c150648f7d0deab8c80521655dbbe482921f3d523b79f4ff94f7e55dac930e99067d834500d47c1059d6e5b7c899a92fa61644a90675b2af248e576c86e7759b5c32a39317c90eb46d2159e234e76fd05f29ea7fd55b55f7c22c41b36f622687c5fd3d9b4fe20693b6ebf3dcb42fb0cdb32de85b76633bce98cacfca4423e4e8ae9981d415ebee3b2e86a33a3f857c02dea9c3316a50c089d7f5f5bc747f71673bd566ee72e7202972c2afa3a44cc861a7d1ee30711212e08680d0b41e9cbb70c5732d6659ec25a0e92c5c3f3c949cc9cb7dcfaa765ca5090866f037d5a9c04de9bd425ebf377b980ed3b30627698d4d0895a251d9849dab4a4ab2ffc6ccb4a2d92f4ebec1227e7de1a2b513db6df1ae8cc0dd3537651c473f488047ac5af72c5a6f336b3e7294a1c3f734b1be9da993aa761336b8da1dff31c4273f66298a015e9c74877a49c50cff52066d9cfbe2a65bfa5f75e39c38a946f6342173dae69a5d48670d3af066896e947548397a74d02b976587adba22d75952d25914241e5c22ab78ef6b7e5fb7d20093c43c69475d1fef459346274238c56f95c33f1f2b9119e6a214258b77d2f92d5b510aa06e68cd6c9c248437b2ad6c66e82ebfc97be69a026592e904111290d7865143c5590265f008b1996071db8f3f994285d0ab1ca361b1149b07430000000000000000000000000000000000000000000000000000000000000000481f0f1d9537f007b10bf409b53d8f518be25f2935a101ea2d12c6dffd92744cba204db6c8ed209f34b2941fe26f2c309d3bf2d9644a48083e58ebdd0085e66e26c23fdc1ee5e10f171f2a876f8539a69cefd8f9b2f23248f5f35c63796fee5deb2c581884c0ead198be5a0bd05465eb3c65c75a13f96f08c87a01d13277700207c7aac45f47efafa3b63fe998329afd7c94d10cae0945f3a46e52ffdfadb56cb86e916a1163a2e8cee4076426e683a978001bcde46ce11c023ca812abf7884d7f0a163a2424bfdac119f5585a395411c389d8681eeb1f0dfb91c6da576a6b3c11683fa893d0416c94a563f60082285ac5f2423ecab6775fc3816a852336c81ff4832b0c7472aa9f8c80d41333559198273fb38b69bef3f72d529629008c5d4466767a906e665d4b5535d7435a15712bff771c72cacaed72feb399e0f7c664494e9365ef91da16551a55a582a9684ba8972434465491ceb578470527bda9ef71c44db2dbe505a437b27bf94426c5ab81a75cf8ccec50c6f47e720052714028616094ef815788911e0c56a7d9f8a7c19630f6a36941acdfbb6231c0b8ce040e301fde05415a1a9b369882289919902036ccf9aa224e84a43a0756230e47d5ed6f2353e10329a141952465b4502f7d2af3e629a01bfd7dba9d2fac7952444c6603c7daee37589b67d0c9c61ca33874600bcd84c0595c0f4e9765e80539919c832e2d34406e41f18904b9d8454eb6288a5cf5a56353e120396b14fa4fcacf7a071710bafa486c826e3951cfa6a6a16c474016fe551733865babd067b1eef7690904594b606cfb464cb83769ffe25d04717501047bf5d47dd9215ba5dc0a64a29d6e1edf1adabbd649323441b2015c114f7e3bead6559ea784849d8267a43a8f301f73fb34ebd81113dc007f66bf0b1af7d5fb596e38c4eb93ef8196dd88e0c0140d49cc9a2a71a59ebc08680b8ce35abfbb99466dd605d2eecea787ee7d4c02a70144a8e9ca38607382dd758788b867bae66c2c504d23244acb92ce710410cc277238e294cdb5d963b1ff594ca7abf12e9e1d5ab5d742a4ddc5108e7159b75b9625726bc90da5d2d2a4f340ebc2ad5a3d4e19f9b982d9f9308bf4978489640562270000000000000000000000000000000000000000000000000000000000000000d70e8caf8f3200cd8b58ec2eb679ca25617def3b3cba8c27bd6f1d13cea7e20502ed267d1894ff435fd1930a49c952bad8a5639f1b650e9728eb250fba62b80270760b050d4c7bfebd2d4dd77ae889ef7de9903deba78dcfb716f88d2b140008ecd772e89c40cf93d6f142296d68512354ed2b03ae3d08d7084cc0fd36671b05914331659f963ebf45aee2b709357238867f1a924ef7cfa0faebba97a680b85d14671c94b3f1ba7ebaf8ec27e8930d7e954290cf814814ea5e647579ef98bc6d740a675f5c5c1b8b5f575159d6c7eb33b3c61029445eaebcf04c12cfa4f87e26ff976a112e9899fcfdf1ae73408888299b2be4a2ffc07c2236a6f2513276b32c217ac63b7c4723d72167e59ed9079bdc8230948a6871b9748a549cb150f959592086658e339221ff0cd04f3bc7a53f949c3691410e1f55022bc1143dca0053626e284892311a1d7d6c8ba4a73a76b1c781855177a723cb92938184a87ba77023d07ec258a3a6a72386dcd2a984b855ce8cfe436477f13e5172111599562f12175225bcc425fd8aabf69359dca3cdb8295997edc53fa15510df836e3244d9fc4b3bcfa911ec7ddd2edd016187bc6308190f2664bde6ea94235ec9b1a48353213d1cc411825560d8ee6956adf560335bd3ca1b6b8f67913e78e17c5ee4a151fd2b00837171e8e52c3f1323b1715cca5d8bf8f12c056853d01363a27f80864d2b70ff920618471ef2433abe2d0c38185e3dff88e29a228f0143099549bcc49eea006722cbe3c831af6ef0e9bd0c18234d5358192825d482cae9ef256e71b579140b7765771baa2619bfb32b7e53ec48915a4c3bee2df5fa1c5d211ef1d9f00afd349f1194d848cbe1c4ba8da797faad81a05d5d9b47cd7992378767e915ac5bcc2e19ca001b7a1074f77a97b26c332c849f15adf97b786476533c08102533306d039ad6ae223eca6cc7884023f96e52d798d2947b3af08f8119e79fd3c8a7efae60c2292d85c1ebbd43bf512efe05401ac592a784a0c4ab580b817b7aaabf6d7b16ec09f6a1ef9316e74962e79b4e473cd179ac0baacc02a2d2ca0cf613969bc434e91696a62bf78c1a459e910323066e4492503f7e068627a3952f7a0aa428b96d50ccbf69c641d99d6e13af819447ab4f12441b1ea7c08400dfd47c9081a63413c4405557710d20b77e310143d0c7c4b6ee9b34a64dfe1a81026c82c68828175fa647e6c4f144045f3c7601524c18f009c65ca04db0f47186a197b71d3e686bf5ca512ca8aba76eb2ce2b78aad028bd8156f262aeadb59a96bc143c29e3ce32ae649958d4e5b73d470b6fe963b267f02f3b6ddb651b832e9abdc424db9ec09a3313c1fed2dfdb4abbef31ba493a9e3825e552d0067c1bce57282bf71c7df9d303e51bb83e231411decd379e6c99d45f294acf3efad18f2c6152201926d0777ab17bfd228803b090d936b2282496b1871f82b9e5efb5696e7e1e5379d6e293fe2680bc4c684606df59e53d9f5ab0b2924d98564d23b684a6a1ac24f9c031ecae740408080104040c14030401041008041008040800040008141814030415f26908181ca501010100033215f2696e9e12baa5208c7dc425e4a9a6ca680e8876b7a70cc51cd668fc118557c4555fa4b4c4d56d20f0c9bad85991d76079ee311c72cb76fce8383e502a34a6b8a418739e17bd5fafb5284cf981479437c802ac12ada93bdddf35797b5b0295b8b0180808002000042408010404289003043f8061c108c7ac69937e9beeb5d473f7a3a23b1f1b4b3bf0aa3f333b8faac42aa1f0000801000095010225fe63cb53cac4183b7e11df61c1b231abc9bce6ad767a989e8b4484b10e4acec0bc380000000000000000000000000000000000000000000000000000000000000000ffc3140690696a3ad444dfe86f018d2b2ff4b02e251dc6a975aa782ad74403c504043408010400110102093d00b04af12a676d8dd9f46c5a8b7e4ee3790f922e7b16460f58da72f975b084f89e0000000000000000000000000000000000000000000000000000000000000000001101021cc163b04af12a676d8dd9f46c5a8b7e4ee3790f922e7b16460f58da72f975b084f89e000000000000000000000000000000000000000000000000000000000000000004400801040444140304010410083c48080408000101e5b6ed069c0860f87e5b27c5261f11dd21c37ca191c51d1bf5bcf91d5a1e6f7dd490e0348ea4abae200113e71935f7a8a2494a7e9b0a4bc421b0927c57c18fa504500801040c384c5400085818a501010001031b1cf269808dfb5d5edabc3f86caabf841444149176751eb54b5531660b5ed3b41c1b70f75579e2eebf2224e0cef9ede3a9e7b846ecc43bb3598e3a20ee1a0b45878d95f734a09160d0e01780ee296546257d4edc05a681102302da4e2213a59a30a030a0408305c00046008010404649003043f807dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f25404018182c18681818181818181818181818080208086c18ac001c707265766965770173886af42f942da18c376fdd07e0248c92ca07bcf106be300d0070de0b436be606";

        let tx_bytes = hex::decode(TX_BYTES_HEX).unwrap();
        assert_eq!(
            MidnightSigner::classify_standard_midnight_transaction(&tx_bytes).unwrap(),
            MidnightStandardTxKind::Sealed
        );

        // Use the canonical OWS test mnemonic. This mnemonic does *not* correspond to the owner
        // who produced the signatures embedded in `txBytes`, so OWS should fall back to signing a
        // deterministic hash of the provided bytes.
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let signer = MidnightSigner;
        let key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &signer.default_derivation_path(0),
            signer.curve(),
        )
        .unwrap();

        // Parse the tx and find the expected signature for our input owner.
        let mut reader: &[u8] = &tx_bytes;
        type TxMarker = Transaction<
            MnSig,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;
        let tx: TxMarker = tagged_deserialize(&mut reader).unwrap();
        let Transaction::Standard(std) = tx else {
            panic!("expected Standard transaction");
        };

        fn ser<T: midnight_serialize::Serializable>(v: &T) -> Vec<u8> {
            let mut out = Vec::new();
            v.serialize(&mut out)
                .expect("in-memory serialize should succeed");
            out
        }

        // Pick the first embedded unshielded signature and assert it verifies against the
        // intent `data_to_sign(segment_id)` payload, using the input owner verifying key.
        let mut embedded: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = None; // (owner_vk_bytes, sig_bytes, verify_input)
        'outer: for seg_intent in std.intents.iter() {
            let segment_id = *seg_intent.0;
            let intent = seg_intent.1.deref();
            let erased = intent.erase_proofs().erase_signatures();
            let verify_input = erased.data_to_sign(segment_id);

            for offer in intent
                .guaranteed_unshielded_offer
                .iter()
                .chain(intent.fallible_unshielded_offer.iter())
            {
                let offer = offer.deref();
                for (inp, sig) in offer.inputs.iter_deref().zip(offer.signatures.iter_deref()) {
                    embedded = Some((ser(&inp.owner), ser(sig), verify_input.clone()));
                    break 'outer;
                }
            }
        }

        let (embedded_owner_vk_bytes, embedded_sig_bytes, verify_input) =
            embedded.expect("expected at least one embedded unshielded signature");
        let embedded_owner_vk =
            k256::schnorr::VerifyingKey::from_bytes(&embedded_owner_vk_bytes).unwrap();
        let embedded_sig = SchnorrSignature::try_from(embedded_sig_bytes.as_slice()).unwrap();
        assert!(embedded_owner_vk
            .verify(&verify_input, &embedded_sig)
            .is_ok());

        // Since the test mnemonic does not match any embedded input owner, signing should fail.
        let err = signer
            .sign_transaction(key.expose(), &tx_bytes)
            .expect_err("expected signing to fail for non-owner key");
        match err {
            SignerError::InvalidTransaction(_) => {}
            other => panic!("expected InvalidTransaction, got: {other:?}"),
        }
    }
}
