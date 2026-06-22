pub mod config;
pub mod derive;
pub mod fund;
pub mod generate;
pub mod info;
pub mod key;
pub mod pay;
pub mod policy;
pub mod send_transaction;
pub mod sign_message;
pub mod sign_transaction;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::CliError;
use ows_signer::process_hardening::clear_env_var;
use ows_signer::SecretBytes;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Vault directory from `~/.ows/config.json` (or defaults).
pub(crate) fn vault_dir() -> PathBuf {
    ows_core::Config::load_or_default().vault_path
}

/// Read mnemonic from OWS_MNEMONIC env var (or LWS_MNEMONIC fallback) or stdin.
pub fn read_mnemonic() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = clear_env_var("OWS_MNEMONIC").or_else(|| clear_env_var("LWS_MNEMONIC")) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set OWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a hex-encoded private key from OWS_PRIVATE_KEY env var (or LWS_PRIVATE_KEY fallback) or stdin.
pub fn read_private_key() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) =
        clear_env_var("OWS_PRIVATE_KEY").or_else(|| clear_env_var("LWS_PRIVATE_KEY"))
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no private key provided (set OWS_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a passphrase from OWS_PASSPHRASE env var (or LWS_PASSPHRASE fallback) or prompt interactively.
pub fn read_passphrase() -> Zeroizing<String> {
    if let Some(value) = clear_env_var("OWS_PASSPHRASE").or_else(|| clear_env_var("LWS_PASSPHRASE"))
    {
        return Zeroizing::new(value);
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Passphrase (empty for none): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        Zeroizing::new(line.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    }
}

/// Peek at the passphrase value without consuming the env var.
/// Returns `Some(value)` if OWS_PASSPHRASE is set (even if empty), `None` otherwise.
/// Used by sign commands to detect API tokens before deciding the code path.
pub fn peek_passphrase() -> Option<String> {
    std::env::var("OWS_PASSPHRASE")
        .ok()
        .or_else(|| std::env::var("LWS_PASSPHRASE").ok())
}

/// Resolve a wallet into the private key bytes for a specific chain.
///
/// Tries an empty passphrase first; if that fails, prompts the user.
/// Delegates to `ows_lib::decrypt_signing_key` for the actual decryption
/// and key derivation so the signing path is never duplicated.
pub fn resolve_signing_key(
    wallet_name: &str,
    chain_type: ows_core::ChainType,
    index: u32,
) -> Result<SecretBytes, CliError> {
    // Try empty passphrase first.
    match ows_lib::decrypt_signing_key(wallet_name, chain_type, "", Some(index), None) {
        Ok(key) => return Ok(key),
        Err(ows_lib::OwsLibError::Crypto(_)) => {
            // Empty passphrase didn't work — prompt the user.
        }
        Err(e) => return Err(e.into()),
    }

    let passphrase = read_passphrase();
    Ok(ows_lib::decrypt_signing_key(
        wallet_name,
        chain_type,
        &passphrase,
        Some(index),
        None,
    )?)
}

/// Owner-mode sign / send context (chain-specific).
pub enum OwnerSignContext {
    Midnight {
        key: ows_signer::SecretBytes,
        prepared: ows_lib::chains::midnight::MidnightOwnerTxContext,
    },
    Generic {
        chain: ows_core::Chain,
        key: ows_signer::SecretBytes,
        tx_bytes: Vec<u8>,
    },
}

/// Decrypt signing key and decode `--tx` for owner-mode sign / send (non–API-token).
pub fn resolve_owner_sign_context(
    wallet_name: &str,
    chain_str: &str,
    tx_hex: &str,
    index: u32,
    for_self_submit: bool,
) -> Result<OwnerSignContext, CliError> {
    let chain = crate::parse_chain(chain_str)?;
    let key = resolve_signing_key(wallet_name, chain.chain_type, index)?;
    if chain.chain_type == ows_core::ChainType::Midnight {
        let prepared = ows_lib::chains::midnight::prepare_midnight_owner_tx_context(
            wallet_name,
            &chain,
            tx_hex,
            key.expose(),
            Some(index),
            Some(vault_dir().as_path()),
            for_self_submit,
            || read_passphrase().to_string(),
        )
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;
        return Ok(OwnerSignContext::Midnight { key, prepared });
    }
    let tx_bytes = ows_lib::decode_owner_tx_hex(&chain, tx_hex)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    Ok(OwnerSignContext::Generic {
        chain,
        key,
        tx_bytes,
    })
}

/// Sign an owner-resolved transaction.
pub fn sign_owner_transaction(
    ctx: &OwnerSignContext,
) -> Result<ows_lib::SignResult, ows_lib::OwsLibError> {
    match ctx {
        OwnerSignContext::Midnight { key, prepared } => {
            ows_lib::chains::midnight::sign_prepared_owner_transaction(key.expose(), prepared)
        }
        OwnerSignContext::Generic {
            chain,
            key,
            tx_bytes,
        } => ows_lib::sign_transaction_with_key(chain, key.expose(), tx_bytes),
    }
}

/// Sign and broadcast an owner-resolved transaction.
pub fn send_owner_transaction(
    ctx: &OwnerSignContext,
    chain_str: &str,
    rpc_url: Option<&str>,
) -> Result<ows_lib::SendResult, ows_lib::OwsLibError> {
    match ctx {
        OwnerSignContext::Midnight { key, prepared } => {
            ows_lib::chains::midnight::sign_and_send_prepared_owner_transaction(
                key.expose(),
                prepared,
                rpc_url,
            )
        }
        OwnerSignContext::Generic {
            chain: _,
            key,
            tx_bytes,
        } => ows_lib::sign_encode_and_broadcast(key.expose(), chain_str, tx_bytes, rpc_url),
    }
}
