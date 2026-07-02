//! Vault-backed Midnight wallet orchestration: seed derivation, tx decoding,
//! signing, and node submission. Generic [`crate::ops`] dispatches here for
//! `ChainType::Midnight`.

use std::path::Path;

use ows_core::{Chain, ChainType, Config, KeyType};
use ows_signer::{
    chains::MidnightSigner, decrypt, signer_for_chain, ChainSigner as _, CryptoEnvelope, HdDeriver,
    Mnemonic, SecretBytes,
};

use super::{
    block_on, build_make_transfer_unsealed_tx, chain_needs_dust_fee_registration,
    is_balance_sealed_maker_payload, is_balance_unsealed_payload, materialize_connector_request,
    parse_connector_tx_json, parse_maker_swap_input, post_submit_sync::refresh_after_submit,
    prepare_balanced_sealed_from_maker_offer, prepare_sealed_from_unsealed,
    seal_imbalanced_unsealed, submit_unshielded_tx, ConnectorTxRequest, PayError, SyncCacheScope,
};
use crate::error::OwsLibError;
use crate::types::{SendResult, SignResult};
use crate::vault;

/// Decoded `--tx` / `tx_hex` input: raw bytes plus Midnight signing hints from connector JSON.
#[derive(Debug, Clone)]
pub struct DecodedTxInput {
    pub bytes: Vec<u8>,
    /// From connector `options.payFees` when applicable (default true).
    pub pay_fees: bool,
    /// When false (`makeIntent`), skip balancing and only sign → prove → seal.
    pub balance_before_sign: bool,
}

/// Resolved Midnight tx bytes and signing options for owner-mode sign / send.
pub struct MidnightOwnerTxContext {
    pub chain: Chain,
    pub shielded_seed: Option<SecretBytes>,
    pub dust_seed: Option<SecretBytes>,
    pub sync_scope: SyncCacheScope,
    pub tx_bytes: Vec<u8>,
    pub pay_fees: bool,
    pub balance_before_sign: bool,
}

/// Backward-compatible alias for [`MidnightOwnerTxContext`].
pub type OwnerTxContext = MidnightOwnerTxContext;

/// Material needed to sign or send a transaction once the signing key is known.
pub(crate) struct ResolvedTxMaterial {
    pub sync_scope: SyncCacheScope,
    pub decoded: DecodedTxInput,
    pub shielded_seed: Option<SecretBytes>,
    pub dust_seed: Option<SecretBytes>,
}

/// WalletEngine role under `m/44'/2400'/0'/{role}/{index}`.
#[derive(Clone, Copy)]
enum WalletRole {
    Dust,
    Shielded,
}

impl WalletRole {
    fn path_component(self) -> u32 {
        match self {
            Self::Dust => 2,
            Self::Shielded => 3,
        }
    }

    fn private_key_error(self) -> &'static str {
        match self {
            Self::Dust => {
                "Midnight DUST fee registration requires a mnemonic wallet (derive dust at \
                 m/44'/2400'/0'/2/<index>). Imported private-key wallets only expose the unshielded \
                 Night key — use a mnemonic wallet for Preview / Preprod unsealed transactions."
            }
            Self::Shielded => {
                "Midnight shielded balances require a mnemonic wallet (derive shielded at \
                 m/44'/2400'/0'/3/<index>). Imported private-key wallets only expose the unshielded \
                 Night key."
            }
        }
    }
}

fn invalid_input(msg: impl Into<String>) -> OwsLibError {
    OwsLibError::InvalidInput(msg.into())
}

fn pay_to_invalid(e: PayError) -> OwsLibError {
    invalid_input(e.to_string())
}

/// Resolve the GraphQL indexer URL for a Midnight CAIP-2 chain id.
pub fn resolve_indexer_url(chain_id: &str) -> Result<String, OwsLibError> {
    Config::load_or_default()
        .rpc_url(chain_id)
        .map(str::to_string)
        .ok_or_else(|| {
            invalid_input(format!(
                "no Midnight indexer URL configured for {chain_id} (set `rpc.{chain_id}` in config)"
            ))
        })
}

/// Resolve a Midnight **node** RPC URL (`midnight:*:node` config key), not the indexer.
pub fn resolve_node_rpc_url(chain_id: &str, explicit: Option<&str>) -> Result<String, OwsLibError> {
    if let Some(url) = explicit {
        return Ok(url.to_string());
    }
    let node_rpc_key = format!("{chain_id}:node");
    Config::load_or_default()
        .rpc
        .get(&node_rpc_key)
        .cloned()
        .or_else(|| Config::default_rpc().get(&node_rpc_key).cloned())
        .ok_or_else(|| {
            invalid_input(format!(
                "no node RPC URL configured for '{node_rpc_key}' (set `rpc.{node_rpc_key}` in config or pass --rpc-url)"
            ))
        })
}

/// Build a Midnight sync cache scope from a wallet name/id and optional vault path.
pub fn sync_scope_for_wallet(
    wallet_name_or_id: &str,
    chain_id: Option<&str>,
    vault_path: Option<&Path>,
) -> SyncCacheScope {
    let mut scope = match vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path) {
        Ok(w) => SyncCacheScope::for_wallet(w.id, vault_path),
        Err(_) => SyncCacheScope {
            vault_path: vault_path.map(Path::to_path_buf),
            ..Default::default()
        },
    };
    if let Some(cid) = chain_id {
        scope = scope.with_chain_id(cid);
    }
    scope
}

fn role_seed_from_wallet_secret(
    secret: &SecretBytes,
    key_type: &KeyType,
    role: WalletRole,
    index: Option<u32>,
) -> Result<SecretBytes, OwsLibError> {
    match key_type {
        KeyType::Mnemonic => {
            let phrase = std::str::from_utf8(secret.expose())
                .map_err(|_| invalid_input("wallet contains invalid UTF-8 mnemonic"))?;
            let mnemonic = Mnemonic::from_phrase(phrase)?;
            let i = index.unwrap_or(0);
            let r = role.path_component();
            let path = format!("m/44'/2400'/0'/{r}/{i}");
            let curve = signer_for_chain(ChainType::Midnight).curve();
            HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve).map_err(Into::into)
        }
        KeyType::PrivateKey => Err(invalid_input(role.private_key_error())),
    }
}

fn dust_seed_from_wallet_secret(
    secret: &SecretBytes,
    key_type: &KeyType,
    index: Option<u32>,
) -> Result<SecretBytes, OwsLibError> {
    role_seed_from_wallet_secret(secret, key_type, WalletRole::Dust, index)
}

/// Derive the Midnight **dust** seed (32 bytes) used for DUST fee registration on Preview / Preprod.
pub fn decrypt_dust_seed(
    wallet_name_or_id: &str,
    passphrase: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, OwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;
    dust_seed_from_wallet_secret(&secret, &wallet.key_type, index)
}

/// Derive the Midnight **shielded (Zswap)** seed (32 bytes).
pub fn decrypt_shielded_seed(
    wallet_name_or_id: &str,
    passphrase: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, OwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;
    role_seed_from_wallet_secret(&secret, &wallet.key_type, WalletRole::Shielded, index)
}

pub fn decrypt_shielded_seed_with_fallback(
    wallet_name_or_id: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
    prompt_passphrase: impl FnOnce() -> String,
) -> Result<SecretBytes, OwsLibError> {
    match decrypt_shielded_seed(wallet_name_or_id, "", index, vault_path) {
        Ok(seed) => Ok(seed),
        Err(OwsLibError::Crypto(_)) => {
            let passphrase = prompt_passphrase();
            decrypt_shielded_seed(wallet_name_or_id, &passphrase, index, vault_path)
        }
        Err(e) => Err(e),
    }
}

pub fn decrypt_dust_seed_with_fallback(
    wallet_name_or_id: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
    prompt_passphrase: impl FnOnce() -> String,
) -> Result<SecretBytes, OwsLibError> {
    match decrypt_dust_seed(wallet_name_or_id, "", index, vault_path) {
        Ok(seed) => Ok(seed),
        Err(OwsLibError::Crypto(_)) => {
            let passphrase = prompt_passphrase();
            decrypt_dust_seed(wallet_name_or_id, &passphrase, index, vault_path)
        }
        Err(e) => Err(e),
    }
}

/// Decrypt shielded and dust seeds for balance display, prompting at most once.
pub fn decrypt_auxiliary_seeds_with_fallback(
    wallet_name_or_id: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
    mut prompt_passphrase: impl FnMut() -> String,
) -> Result<(Option<SecretBytes>, Option<SecretBytes>), OwsLibError> {
    let mut cached_passphrase: Option<String> = None;

    let shielded = decrypt_role_optional(
        wallet_name_or_id,
        WalletRole::Shielded,
        index,
        vault_path,
        &mut cached_passphrase,
        &mut prompt_passphrase,
    )?;
    let dust = decrypt_role_optional(
        wallet_name_or_id,
        WalletRole::Dust,
        index,
        vault_path,
        &mut cached_passphrase,
        &mut prompt_passphrase,
    )?;
    Ok((shielded, dust))
}

fn decrypt_role_optional(
    wallet_name_or_id: &str,
    role: WalletRole,
    index: Option<u32>,
    vault_path: Option<&Path>,
    cached_passphrase: &mut Option<String>,
    prompt_passphrase: &mut impl FnMut() -> String,
) -> Result<Option<SecretBytes>, OwsLibError> {
    let decrypt_role = |passphrase: &str| -> Result<SecretBytes, OwsLibError> {
        let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
        let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
        let secret = decrypt(&envelope, passphrase)?;
        role_seed_from_wallet_secret(&secret, &wallet.key_type, role, index)
    };

    match decrypt_role("") {
        Ok(seed) => Ok(Some(seed)),
        Err(OwsLibError::Crypto(_)) => {
            let passphrase = cached_passphrase
                .get_or_insert_with(prompt_passphrase)
                .clone();
            match decrypt_role(&passphrase) {
                Ok(seed) => Ok(Some(seed)),
                Err(OwsLibError::InvalidInput(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(OwsLibError::InvalidInput(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn maybe_load_dust_seed_with_credential(
    wallet_name_or_id: &str,
    chain: &Chain,
    credential: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<Option<SecretBytes>, OwsLibError> {
    if chain.chain_type != ChainType::Midnight || !chain_needs_dust_fee_registration(chain.chain_id)
    {
        return Ok(None);
    }

    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        let token_hash = crate::key_store::hash_token(credential);
        let key_file = crate::key_store::load_api_key_by_token_hash(&token_hash, vault_path)?;
        let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
        if !key_file.wallet_ids.contains(&wallet.id) {
            return Err(invalid_input(format!(
                "API key '{}' is not authorized for wallet '{}'",
                key_file.name, wallet.id
            )));
        }
        let envelope_value = key_file.wallet_secrets.get(&wallet.id).ok_or_else(|| {
            invalid_input(format!(
                "API key has no encrypted secret for wallet {}",
                wallet.id
            ))
        })?;
        let envelope: CryptoEnvelope = serde_json::from_value(envelope_value.clone())?;
        let secret = decrypt(&envelope, credential)?;
        return dust_seed_from_wallet_secret(&secret, &wallet.key_type, index).map(Some);
    }

    decrypt_dust_seed(wallet_name_or_id, credential, index, vault_path).map(Some)
}

pub(crate) fn maybe_load_shielded_seed_with_credential(
    wallet_name_or_id: &str,
    chain: &Chain,
    credential: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<Option<SecretBytes>, OwsLibError> {
    if chain.chain_type != ChainType::Midnight {
        return Ok(None);
    }

    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return Ok(decrypt_shielded_seed(wallet_name_or_id, "", index, vault_path).ok());
    }

    match decrypt_shielded_seed(wallet_name_or_id, credential, index, vault_path) {
        Ok(seed) => Ok(Some(seed)),
        Err(OwsLibError::Crypto(_)) if credential.is_empty() => {
            Ok(decrypt_shielded_seed(wallet_name_or_id, "", index, vault_path).ok())
        }
        Err(OwsLibError::InvalidInput(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Bytes for policy evaluation before full connector materialization (e.g. API-key path).
///
/// - **Hex / sealed wire:** decoded transaction bytes.
/// - **`makeTransfer` JSON:** unsealed preimage built without wallet keys (outputs only).
/// - **`makeIntent` JSON:** empty — intent materialization needs the decrypted signing key
///   and optional shielded seed, so policy runs on an empty context and the real tx is
///   built in [`resolve_transaction_material`] after decrypt.
pub fn policy_context_tx_bytes(chain: &Chain, tx_arg: &str) -> Result<Vec<u8>, OwsLibError> {
    let trimmed = tx_arg.trim();
    if chain.chain_type == ChainType::Midnight && trimmed.starts_with('{') {
        match parse_connector_tx_json(trimmed).map_err(pay_to_invalid)? {
            ConnectorTxRequest::MakeIntent(_) => return Ok(Vec::new()),
            ConnectorTxRequest::BalanceSealedTransaction(b) => {
                return parse_maker_swap_input(chain.chain_id, &b.maker_tx).map_err(pay_to_invalid);
            }
            ConnectorTxRequest::MakeTransfer(t) => {
                return build_make_transfer_unsealed_tx(chain.chain_id, None, None, None, &t)
                    .map_err(pay_to_invalid);
            }
        }
    }
    if trimmed.starts_with("zswapoffer") {
        return parse_maker_swap_input(chain.chain_id, trimmed).map_err(pay_to_invalid);
    }
    let hex_s = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(hex_s).map_err(|e| invalid_input(format!("invalid hex transaction: {e}")))
}

/// Decode `--tx` for Midnight: hex wire bytes, `zswapoffer…` bech32, or DApp Connector JSON.
pub(crate) fn decode_midnight_transaction_input(
    chain: &Chain,
    tx_arg: &str,
    sender_private_key: Option<&[u8]>,
    shielded_seed: Option<&[u8]>,
    dust_seed: Option<&[u8]>,
    sync_scope: Option<&SyncCacheScope>,
    for_self_submit: bool,
) -> Result<DecodedTxInput, OwsLibError> {
    let trimmed = tx_arg.trim();
    if trimmed.starts_with('{') {
        let req = parse_connector_tx_json(trimmed).map_err(pay_to_invalid)?;
        let key32 = match &req {
            ConnectorTxRequest::MakeIntent(_) | ConnectorTxRequest::BalanceSealedTransaction(_) => {
                let key = sender_private_key.ok_or_else(|| {
                    invalid_input("this connector method requires a resolved wallet signing key")
                })?;
                key.try_into()
                    .map_err(|_| invalid_input("Midnight signing key must be 32 bytes"))?
            }
            ConnectorTxRequest::MakeTransfer(_) => sender_private_key
                .and_then(|k| <[u8; 32]>::try_from(k).ok())
                .unwrap_or([0u8; 32]),
        };
        let indexer_url = resolve_indexer_url(chain.chain_id)?;
        let default_scope = SyncCacheScope::default();
        let scope = sync_scope.unwrap_or(&default_scope);
        let shielded32 = shielded_seed.and_then(|s| <[u8; 32]>::try_from(s).ok());
        let dust32 = dust_seed.and_then(|s| <[u8; 32]>::try_from(s).ok());
        let (bytes, pay_fees, balance) = materialize_connector_request(
            chain.chain_id,
            &indexer_url,
            &key32,
            shielded32,
            dust32,
            req,
            scope,
            for_self_submit,
        )
        .map_err(pay_to_invalid)?;
        return Ok(DecodedTxInput {
            bytes,
            pay_fees,
            balance_before_sign: balance,
        });
    }
    if trimmed.starts_with("zswapoffer") {
        let bytes = parse_maker_swap_input(chain.chain_id, trimmed).map_err(pay_to_invalid)?;
        return Ok(DecodedTxInput {
            bytes,
            pay_fees: true,
            balance_before_sign: true,
        });
    }
    let hex_s = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes =
        hex::decode(hex_s).map_err(|e| invalid_input(format!("invalid hex transaction: {e}")))?;
    Ok(DecodedTxInput {
        bytes,
        pay_fees: true,
        balance_before_sign: true,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_transaction_material(
    wallet_name_or_id: &str,
    chain: &Chain,
    tx_arg: &str,
    credential: &str,
    sender_private_key: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
    for_self_submit: bool,
) -> Result<ResolvedTxMaterial, OwsLibError> {
    let sync_scope = sync_scope_for_wallet(wallet_name_or_id, Some(chain.chain_id), vault_path);
    let shielded_seed = maybe_load_shielded_seed_with_credential(
        wallet_name_or_id,
        chain,
        credential,
        index,
        vault_path,
    )?;
    let dust_seed = maybe_load_dust_seed_with_credential(
        wallet_name_or_id,
        chain,
        credential,
        index,
        vault_path,
    )?;
    let decoded = decode_midnight_transaction_input(
        chain,
        tx_arg,
        Some(sender_private_key),
        shielded_seed.as_ref().map(|s| s.expose()),
        dust_seed.as_ref().map(|s| s.expose()),
        Some(&sync_scope),
        for_self_submit,
    )?;
    Ok(ResolvedTxMaterial {
        sync_scope,
        decoded,
        shielded_seed,
        dust_seed,
    })
}

/// Sign using [`ResolvedTxMaterial`] (internal; use [`sign_transaction_for_wallet`]).
pub(crate) fn sign_transaction_from_material(
    chain: &Chain,
    private_key: &[u8],
    material: &ResolvedTxMaterial,
) -> Result<SignResult, OwsLibError> {
    sign_transaction(
        chain,
        private_key,
        material.shielded_seed.as_ref().map(|s| s.expose()),
        material.dust_seed.as_ref().map(|s| s.expose()),
        &material.decoded.bytes,
        Some(&material.sync_scope),
        material.decoded.pay_fees,
        material.decoded.balance_before_sign,
    )
}

/// Sign-and-send using [`ResolvedTxMaterial`] (internal; use [`sign_and_send_for_wallet`]).
pub(crate) fn sign_and_send_from_material(
    chain: &Chain,
    private_key: &[u8],
    material: &ResolvedTxMaterial,
    rpc_url: Option<&str>,
) -> Result<SendResult, OwsLibError> {
    sign_and_send(
        chain,
        private_key,
        material.shielded_seed.as_ref().map(|s| s.expose()),
        material.dust_seed.as_ref().map(|s| s.expose()),
        &material.decoded.bytes,
        rpc_url,
        Some(&material.sync_scope),
        material.decoded.pay_fees,
        material.decoded.balance_before_sign,
    )
}

/// Sign a Midnight transaction once the wallet signing key is known (owner or API-key path).
#[allow(clippy::too_many_arguments)]
pub fn sign_transaction_for_wallet(
    wallet_name_or_id: &str,
    chain: &Chain,
    tx_arg: &str,
    credential: &str,
    sender_private_key: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
    for_self_submit: bool,
) -> Result<SignResult, OwsLibError> {
    if chain.chain_type != ChainType::Midnight {
        return Err(invalid_input(
            "sign_transaction_for_wallet is only valid for Midnight chains",
        ));
    }
    let material = resolve_transaction_material(
        wallet_name_or_id,
        chain,
        tx_arg,
        credential,
        sender_private_key,
        index,
        vault_path,
        for_self_submit,
    )?;
    sign_transaction_from_material(chain, sender_private_key, &material)
}

/// Sign and broadcast a Midnight transaction once the wallet signing key is known.
#[allow(clippy::too_many_arguments)]
pub fn sign_and_send_for_wallet(
    wallet_name_or_id: &str,
    chain: &Chain,
    tx_arg: &str,
    credential: &str,
    sender_private_key: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
    rpc_url: Option<&str>,
) -> Result<SendResult, OwsLibError> {
    if chain.chain_type != ChainType::Midnight {
        return Err(invalid_input(
            "sign_and_send_for_wallet is only valid for Midnight chains",
        ));
    }
    let material = resolve_transaction_material(
        wallet_name_or_id,
        chain,
        tx_arg,
        credential,
        sender_private_key,
        index,
        vault_path,
        true,
    )?;
    sign_and_send_from_material(chain, sender_private_key, &material, rpc_url)
}

/// Sign using a prepared [`MidnightOwnerTxContext`] (CLI owner path).
pub fn sign_prepared_owner_transaction(
    private_key: &[u8],
    ctx: &MidnightOwnerTxContext,
) -> Result<SignResult, OwsLibError> {
    sign_transaction(
        &ctx.chain,
        private_key,
        ctx.shielded_seed.as_ref().map(|s| s.expose()),
        ctx.dust_seed.as_ref().map(|s| s.expose()),
        &ctx.tx_bytes,
        Some(&ctx.sync_scope),
        ctx.pay_fees,
        ctx.balance_before_sign,
    )
}

/// Sign and broadcast using a prepared [`MidnightOwnerTxContext`] (CLI owner path).
pub fn sign_and_send_prepared_owner_transaction(
    private_key: &[u8],
    ctx: &MidnightOwnerTxContext,
    rpc_url: Option<&str>,
) -> Result<SendResult, OwsLibError> {
    sign_and_send(
        &ctx.chain,
        private_key,
        ctx.shielded_seed.as_ref().map(|s| s.expose()),
        ctx.dust_seed.as_ref().map(|s| s.expose()),
        &ctx.tx_bytes,
        rpc_url,
        Some(&ctx.sync_scope),
        ctx.pay_fees,
        ctx.balance_before_sign,
    )
}

/// Decrypt auxiliary seeds, sync scope, and decode tx for Midnight owner-mode sign / send.
#[allow(clippy::too_many_arguments)]
pub fn prepare_midnight_owner_tx_context(
    wallet_name: &str,
    chain: &Chain,
    tx_hex: &str,
    signing_key: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
    for_self_submit: bool,
    mut prompt_passphrase: impl FnMut() -> String,
) -> Result<MidnightOwnerTxContext, OwsLibError> {
    if chain.chain_type != ChainType::Midnight {
        return Err(invalid_input(
            "prepare_midnight_owner_tx_context requires a Midnight chain",
        ));
    }
    let sync_scope = sync_scope_for_wallet(wallet_name, Some(chain.chain_id), vault_path);
    let (shielded_seed, dust_seed) = decrypt_auxiliary_seeds_with_fallback(
        wallet_name,
        index,
        vault_path,
        &mut prompt_passphrase,
    )?;
    let dust_seed = if chain_needs_dust_fee_registration(chain.chain_id) {
        dust_seed
    } else {
        None
    };
    let decoded = decode_midnight_transaction_input(
        chain,
        tx_hex,
        Some(signing_key),
        shielded_seed.as_ref().map(|s| s.expose()),
        dust_seed.as_ref().map(|s| s.expose()),
        Some(&sync_scope),
        for_self_submit,
    )?;
    Ok(MidnightOwnerTxContext {
        chain: *chain,
        shielded_seed,
        dust_seed,
        sync_scope,
        tx_bytes: decoded.bytes,
        pay_fees: decoded.pay_fees,
        balance_before_sign: decoded.balance_before_sign,
    })
}

/// Backward-compatible alias for [`prepare_midnight_owner_tx_context`].
#[allow(clippy::too_many_arguments)]
pub fn prepare_owner_tx_context(
    wallet_name: &str,
    chain: &Chain,
    tx_hex: &str,
    signing_key: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
    for_self_submit: bool,
    prompt_passphrase: impl FnMut() -> String,
) -> Result<MidnightOwnerTxContext, OwsLibError> {
    prepare_midnight_owner_tx_context(
        wallet_name,
        chain,
        tx_hex,
        signing_key,
        index,
        vault_path,
        for_self_submit,
        prompt_passphrase,
    )
}

fn run_prepare_sealed_from_unsealed(
    chain_id: &str,
    private_key: &[u8],
    shielded_seed: Option<&[u8]>,
    dust_seed: Option<&[u8]>,
    tx_bytes: &[u8],
    sync_scope: Option<&SyncCacheScope>,
    pay_fees: bool,
) -> Result<Vec<u8>, OwsLibError> {
    let indexer_url = resolve_indexer_url(chain_id)?;
    let mut scope = sync_scope.cloned().unwrap_or_default();
    if scope.chain_id.is_none() {
        scope = scope.with_chain_id(chain_id);
    }
    prepare_sealed_from_unsealed(
        chain_id,
        &indexer_url,
        private_key,
        shielded_seed,
        dust_seed,
        tx_bytes,
        &mut scope,
        pay_fees,
    )
    .map_err(pay_to_invalid)
}

fn seal_imbalanced_unsealed_local(
    chain_id: &str,
    private_key: &[u8],
    tx_bytes: &[u8],
) -> Result<Vec<u8>, OwsLibError> {
    let indexer_url = resolve_indexer_url(chain_id)?;
    seal_imbalanced_unsealed(chain_id, &indexer_url, private_key, tx_bytes).map_err(pay_to_invalid)
}

fn run_balance_sealed_transaction(
    chain_id: &str,
    private_key: &[u8],
    shielded_seed: Option<&[u8]>,
    dust_seed: Option<&[u8]>,
    tx_bytes: &[u8],
    sync_scope: Option<&SyncCacheScope>,
    pay_fees: bool,
) -> Result<Vec<u8>, OwsLibError> {
    let indexer_url = resolve_indexer_url(chain_id)?;
    let mut scope = sync_scope.cloned().unwrap_or_default();
    if scope.chain_id.is_none() {
        scope = scope.with_chain_id(chain_id);
    }
    prepare_balanced_sealed_from_maker_offer(
        chain_id,
        &indexer_url,
        private_key,
        shielded_seed,
        dust_seed,
        tx_bytes,
        &mut scope,
        pay_fees,
    )
    .map_err(pay_to_invalid)
}

/// Sign a Midnight transaction with an already-resolved private key.
#[allow(clippy::too_many_arguments)]
pub fn sign_transaction(
    chain: &Chain,
    private_key: &[u8],
    shielded_seed: Option<&[u8]>,
    dust_seed: Option<&[u8]>,
    tx_bytes: &[u8],
    sync_scope: Option<&SyncCacheScope>,
    pay_fees: bool,
    balance_before_sign: bool,
) -> Result<SignResult, OwsLibError> {
    if is_balance_unsealed_payload(tx_bytes) {
        let signed_wire = if balance_before_sign {
            run_prepare_sealed_from_unsealed(
                chain.chain_id,
                private_key,
                shielded_seed,
                dust_seed,
                tx_bytes,
                sync_scope,
                pay_fees,
            )?
        } else {
            seal_imbalanced_unsealed_local(chain.chain_id, private_key, tx_bytes)?
        };
        return Ok(SignResult::midnight_transaction(hex::encode(&signed_wire)));
    }

    if is_balance_sealed_maker_payload(tx_bytes) && balance_before_sign {
        let signed_wire = run_balance_sealed_transaction(
            chain.chain_id,
            private_key,
            shielded_seed,
            dust_seed,
            tx_bytes,
            sync_scope,
            pay_fees,
        )?;
        return Ok(SignResult::midnight_transaction(hex::encode(&signed_wire)));
    }

    let signer = MidnightSigner;
    let signed_wire = signer.sign_and_encode(private_key, tx_bytes)?;
    Ok(SignResult::midnight_transaction(hex::encode(&signed_wire)))
}

/// Sign and broadcast a Midnight transaction with an already-resolved private key.
#[allow(clippy::too_many_arguments)]
pub fn sign_and_send(
    chain: &Chain,
    private_key: &[u8],
    shielded_seed: Option<&[u8]>,
    dust_seed: Option<&[u8]>,
    tx_bytes: &[u8],
    rpc_url: Option<&str>,
    sync_scope: Option<&SyncCacheScope>,
    pay_fees: bool,
    balance_before_sign: bool,
) -> Result<SendResult, OwsLibError> {
    const SEALED_TAG: &[u8] =
        b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";

    let sealed_bytes: std::borrow::Cow<'_, [u8]> = if is_balance_unsealed_payload(tx_bytes) {
        std::borrow::Cow::Owned(if balance_before_sign {
            run_prepare_sealed_from_unsealed(
                chain.chain_id,
                private_key,
                shielded_seed,
                dust_seed,
                tx_bytes,
                sync_scope,
                pay_fees,
            )?
        } else {
            seal_imbalanced_unsealed_local(chain.chain_id, private_key, tx_bytes)?
        })
    } else if is_balance_sealed_maker_payload(tx_bytes) && balance_before_sign {
        std::borrow::Cow::Owned(run_balance_sealed_transaction(
            chain.chain_id,
            private_key,
            shielded_seed,
            dust_seed,
            tx_bytes,
            sync_scope,
            pay_fees,
        )?)
    } else if tx_bytes.starts_with(SEALED_TAG) {
        std::borrow::Cow::Borrowed(tx_bytes)
    } else {
        return Err(invalid_input(
            "Midnight send-tx expects a sealed tx (tag `midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):...`) or an unsealed payload (`...proof[-preimage],embedded-fr[v1]:...`).",
        ));
    };

    let rpc = resolve_node_rpc_url(chain.chain_id, rpc_url)?;
    let tx_hash = block_on(submit_unshielded_tx(&rpc, &sealed_bytes))
        .map_err(|e: PayError| OwsLibError::BroadcastFailed(e.to_string()))?;

    if let Some(scope) = sync_scope {
        if let Ok(indexer_url) = resolve_indexer_url(chain.chain_id) {
            let unshielded_address = <[u8; 32]>::try_from(private_key).ok().and_then(|key32| {
                MidnightSigner
                    .derive_address_for_chain_id(chain.chain_id, &key32)
                    .ok()
            });
            let shielded_seed32 = shielded_seed.and_then(|s| <[u8; 32]>::try_from(s).ok());
            let dust_seed32 = dust_seed.and_then(|s| <[u8; 32]>::try_from(s).ok());
            block_on(refresh_after_submit(
                &indexer_url,
                scope,
                &tx_hash,
                &sealed_bytes,
                unshielded_address.as_deref(),
                shielded_seed32.as_ref(),
                dust_seed32.as_ref(),
            ))
            .map_err(|e| invalid_input(format!("{e} (ledger tx hash {tx_hash})")))?;
        }
    }

    Ok(SendResult { tx_hash })
}

/// Submit a sealed Midnight transaction via the node RPC.
pub fn broadcast_sealed(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    block_on(submit_unshielded_tx(rpc_url, signed_bytes))
        .map_err(|e: PayError| OwsLibError::BroadcastFailed(e.to_string()))
}

// --- Backward-compatible re-exports under legacy ops names ---

pub use decrypt_auxiliary_seeds_with_fallback as decrypt_midnight_auxiliary_seeds_with_fallback;
pub use decrypt_dust_seed as decrypt_midnight_dust_seed;
pub use decrypt_dust_seed_with_fallback as decrypt_midnight_dust_seed_with_fallback;
pub use decrypt_shielded_seed as decrypt_midnight_shielded_seed;
pub use decrypt_shielded_seed_with_fallback as decrypt_midnight_shielded_seed_with_fallback;
pub use sync_scope_for_wallet as midnight_sync_scope_for_wallet;

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::KeyType;
    use ows_signer::SecretBytes;

    #[test]
    fn dust_seed_derivation_is_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let secret = SecretBytes::new(phrase.as_bytes().to_vec());
        let dust = dust_seed_from_wallet_secret(&secret, &KeyType::Mnemonic, Some(0)).unwrap();
        assert_eq!(dust.len(), 32);
        let dust2 = dust_seed_from_wallet_secret(&secret, &KeyType::Mnemonic, Some(0)).unwrap();
        assert_eq!(dust.expose(), dust2.expose());
    }

    #[test]
    fn private_key_wallet_rejects_dust_seed() {
        let secret = SecretBytes::new(vec![0u8; 32]);
        let err = dust_seed_from_wallet_secret(&secret, &KeyType::PrivateKey, None).unwrap_err();
        assert!(
            err.to_string().contains("mnemonic"),
            "expected mnemonic-only error, got: {err}"
        );
    }
}
