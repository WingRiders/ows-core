//! Midnight integration: indexer (GraphQL-over-WebSocket) helpers, prover, and
//! node submission.
//!
//! Concerns are split across siblings to keep each file focused:
//!
//! - [`unshielded_sync`] — replay `unshieldedTransactions` to materialize a
//!   wallet's spendable UTXO set; counterpart to [`shielded_sync`].
//! - [`shielded_sync`] — Zswap balance sync via `shieldedTransactions`.
//! - [`dust_sync`] — DUST local-state replay + decay-aware balance helper.
//! - [`ledger_params`] — indexer `block { ledgerParameters }` fetch + decode.
//! - [`prover`] — proof generation client (`OwsProver`).
//! - [`balance`] / [`sign`] — wallet-style balance → sign → prove → seal
//!   pipeline used to turn a dapp's unsealed payload into a submittable tx.
//! - [`submit`] — node `author_submitExtrinsic` submission for sealed txs.
//! - [`cache_io`] / [`dust_sync_cache`] / [`shielded_sync_cache`] — disk snapshots for
//!   the unshielded / shielded / dust sync streams.
//! - [`indexer_ws`] / [`midnight_env`] — shared WebSocket plumbing and env/network helpers.
//! - [`urls`] — URL-scheme helpers shared between sync modules and `submit`.
//!
//! The handful of pure chain-identity helpers (`TokenType`, `parse_token_type`,
//! `chain_needs_dust_fee_registration`, `ledger_network_id`) live in this file.

/// Shielded balances keyed by the hex-encoded `ShieldedTokenType`.
pub type ShieldedBalances = std::collections::BTreeMap<String, u128>;

mod async_runtime;
mod balance;
mod cache_io;
mod dapp_connector;
mod dust_sync;
mod dust_sync_cache;
mod error;
mod fund_balance;
mod indexer_ws;
mod ledger_params;
mod midnight_env;
mod prover;
mod session_cache;
mod shielded_session;
mod shielded_sync;
mod shielded_sync_cache;
mod sign;
mod submit;
mod unshielded_sync;
mod urls;
pub mod wallet;

mod sign_result;

pub use async_runtime::block_on;
pub use sign_result::{
    decode_midnight_message_signature, encode_midnight_message_signature,
    is_midnight_transaction_signature_hex, sign_result_from_message_output,
    MIDNIGHT_MESSAGE_PUBKEY_HEX_LEN, MIDNIGHT_MESSAGE_SIG_HEX_LEN,
};

pub use cache_io::{midnight_sync_log_enabled, SyncCacheScope};
pub use dapp_connector::{
    build_make_intent_unsealed_tx, build_make_transfer_unsealed_tx, materialize_connector_request,
    parse_connector_tx_json, ConnectorTxRequest, MakeIntentRequest, MakeTransferRequest,
};
pub use dust_sync::{
    format_dust_specks, fund_balance_skip_dust_sync, get_dust_balance_for_display_scoped,
};
pub use error::{PayError, PayErrorCode};
pub use fund_balance::print_fund_balance;
pub use ledger_params::fetch_indexer_ledger_parameters;
pub use midnight_env::shielded_vk_free_sync_enabled;
pub use prover::OwsProver;
pub use shielded_sync::{
    get_shielded_balances_for_display_scoped, get_shielded_balances_scoped,
    sync_shielded_wallet_state_scoped, ShieldedWalletState,
};
pub use submit::submit_unshielded_tx;
pub use unshielded_sync::{
    get_unshielded_utxos_for_display_scoped, refresh_unshielded_after_submit, UnshieldedUtxo,
};
pub use wallet::{
    broadcast_sealed, decrypt_midnight_auxiliary_seeds_with_fallback, decrypt_midnight_dust_seed,
    decrypt_midnight_dust_seed_with_fallback, decrypt_midnight_shielded_seed,
    decrypt_midnight_shielded_seed_with_fallback, midnight_sync_scope_for_wallet,
    policy_context_tx_bytes, prepare_midnight_owner_tx_context, prepare_owner_tx_context,
    sign_and_send_for_wallet, sign_and_send_prepared_owner_transaction,
    sign_prepared_owner_transaction, sign_transaction_for_wallet, DecodedTxInput,
    MidnightOwnerTxContext, OwnerTxContext,
};

mod zswap_ledger_sync;

use midnight_env::MidnightNetwork;

/// Native Night token or a custom unshielded token (32-byte domain-separated id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Native,
    Custom([u8; 32]),
}

impl TokenType {
    /// Hex-encoded 32-byte token type as used by the indexer (`NIGHT` is all-zeroes).
    pub fn to_wire_token_type(&self) -> String {
        match self {
            TokenType::Native => hex::encode([0u8; 32]),
            TokenType::Custom(b) => hex::encode(b),
        }
    }
}

/// Parse `--token` / x402 `asset`: `native` / empty / `night` → NIGHT; else 32-byte hex.
pub fn parse_token_type(token: Option<&str>) -> Result<TokenType, PayError> {
    let t = token.map(str::trim).unwrap_or("");
    if t.is_empty() || t.eq_ignore_ascii_case("native") || t.eq_ignore_ascii_case("night") {
        return Ok(TokenType::Native);
    }
    let hex_s = t.strip_prefix("0x").unwrap_or(t);
    let bytes = hex::decode(hex_s).map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidInput,
            format!("invalid token hex: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            format!("token id must be 32 bytes, got {} bytes", bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    if arr == [0u8; 32] {
        Ok(TokenType::Native)
    } else {
        Ok(TokenType::Custom(arr))
    }
}

/// Preview / Preprod unshielded transactions require a DUST fee registration on the intent.
pub fn chain_needs_dust_fee_registration(chain_id: &str) -> bool {
    MidnightNetwork::from_chain_id(chain_id).needs_dust_fee_registration()
}

/// CAIP-2 chain id → `StandardTransaction.network_id` string used by the ledger.
pub fn ledger_network_id(chain_id: &str) -> &'static str {
    MidnightNetwork::from_chain_id(chain_id).ledger_network_id()
}

const TAG_PROOF_EMBEDDED_FR: &[u8] =
    b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";
const TAG_PROOF_PREIMAGE_EMBEDDED_FR: &[u8] =
    b"midnight:transaction[v9](signature[v1],proof-preimage,embedded-fr[v1]):";

/// Pre-seal Midnight transaction shapes that the wallet pipeline understands.
///
/// Both shapes carry an `embedded-fr` (additive `PedersenRandomness`) binding,
/// meaning sealing is still pending; they differ only in whether the contract /
/// zswap proofs are still preimages (dapp pre-prove output) or full ZK proofs
/// (dapp post-prove output, e.g. when balancing is requested after proving).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnsealedKind {
    /// `proof-preimage,embedded-fr` — wallet performs balance → sign → prove → seal.
    ProofPreimage,
    /// `proof,embedded-fr` — wallet only needs to balance → sign → seal.
    Proven,
}

/// Classify a tagged v9 Midnight transaction blob, or `None` if it is already
/// sealed (or some other shape the wallet pipeline does not handle).
pub fn classify_unsealed_payload(tx_bytes: &[u8]) -> Option<UnsealedKind> {
    if tx_bytes.starts_with(TAG_PROOF_PREIMAGE_EMBEDDED_FR) {
        Some(UnsealedKind::ProofPreimage)
    } else if tx_bytes.starts_with(TAG_PROOF_EMBEDDED_FR) {
        Some(UnsealedKind::Proven)
    } else {
        None
    }
}

/// Detect any Midnight transaction payload that needs wallet-side balancing
/// before it can be signed and submitted.
pub fn is_balance_unsealed_payload(tx_bytes: &[u8]) -> bool {
    classify_unsealed_payload(tx_bytes).is_some()
}

/// Run the full wallet-style pipeline that turns a dapp-provided unsealed payload
/// into a sealed v9 transaction ready for submission.
///
/// Dispatches on the inbound header tag:
///
/// - `proof-preimage,embedded-fr` → balance → sign → prove → seal.
/// - `proof,embedded-fr` (dapp pre-proved) → balance → sign → seal.
///
/// `dust_seed` is required for chains that need DUST fee registration (Preview /
/// Preprod) and must be `Some(32 bytes)`. For Mainnet it is ignored.
///
/// Returns fully-tagged sealed v9 transaction bytes ready to submit via
/// [`submit_unshielded_tx`].
pub fn prepare_sealed_from_unsealed(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8],
    dust_seed: Option<&[u8]>,
    tx_bytes: &[u8],
    sync_scope: &SyncCacheScope,
    pay_fees: bool,
) -> Result<Vec<u8>, PayError> {
    let key32: [u8; 32] = sender_private_key.try_into().map_err(|_| {
        PayError::new(
            PayErrorCode::InvalidInput,
            "Midnight signing key must be 32 bytes",
        )
    })?;
    let dust_seed32 = dust_seed
        .map(|s| {
            <[u8; 32]>::try_from(s).map_err(|_| {
                PayError::new(
                    PayErrorCode::InvalidInput,
                    "Midnight dust seed must be 32 bytes",
                )
            })
        })
        .transpose()?;

    let kind = classify_unsealed_payload(tx_bytes).ok_or_else(|| {
        PayError::new(
            PayErrorCode::InvalidInput,
            "unrecognized Midnight transaction header tag (expected proof-preimage,embedded-fr \
             or proof,embedded-fr)",
        )
    })?;

    match kind {
        UnsealedKind::ProofPreimage => {
            let balanced = balance::balance_unsealed_preimage_standard_tx(
                chain_id,
                indexer_url,
                &key32,
                dust_seed32,
                tx_bytes,
                sync_scope,
                pay_fees,
            )?;
            sign::sign_prove_and_seal(chain_id, indexer_url, &balanced, &key32)
        }
        UnsealedKind::Proven => {
            let balanced = balance::balance_unsealed_proven_standard_tx(
                chain_id,
                indexer_url,
                &key32,
                dust_seed32,
                tx_bytes,
                sync_scope,
                pay_fees,
            )?;
            sign::sign_and_seal(&balanced, &key32)
        }
    }
}

/// Sign, prove, and seal an imbalanced unsealed payload (e.g. [`makeIntent`]) without balancing.
pub fn seal_imbalanced_unsealed(
    chain_id: &str,
    indexer_url: &str,
    sender_private_key: &[u8],
    tx_bytes: &[u8],
) -> Result<Vec<u8>, PayError> {
    let key32: [u8; 32] = sender_private_key.try_into().map_err(|_| {
        PayError::new(
            PayErrorCode::InvalidInput,
            "Midnight signing key must be 32 bytes",
        )
    })?;
    if classify_unsealed_payload(tx_bytes) != Some(UnsealedKind::ProofPreimage) {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            "makeIntent output must be a proof-preimage,embedded-fr transaction",
        ));
    }
    sign::sign_prove_and_seal(chain_id, indexer_url, tx_bytes, &key32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_balance_unsealed_detects_preimage_header() {
        let payload = b"midnight:transaction[v9](signature[v1],proof-preimage,embedded-fr[v1]):";
        assert!(is_balance_unsealed_payload(payload));
    }

    #[test]
    fn is_balance_unsealed_rejects_sealed_header() {
        let payload = b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";
        assert!(!is_balance_unsealed_payload(payload));
    }

    #[test]
    fn classify_unsealed_recognizes_both_unsealed_shapes() {
        let mut pre = TAG_PROOF_PREIMAGE_EMBEDDED_FR.to_vec();
        pre.push(0xab);
        assert_eq!(
            classify_unsealed_payload(&pre),
            Some(UnsealedKind::ProofPreimage)
        );

        let mut proven = TAG_PROOF_EMBEDDED_FR.to_vec();
        proven.push(0xab);
        assert_eq!(
            classify_unsealed_payload(&proven),
            Some(UnsealedKind::Proven)
        );

        assert!(is_balance_unsealed_payload(&pre));
        assert!(is_balance_unsealed_payload(&proven));
        assert!(!is_balance_unsealed_payload(b"midnight:not-a-tx"));
        assert_eq!(classify_unsealed_payload(b"sealed-bytes"), None);
    }
}
