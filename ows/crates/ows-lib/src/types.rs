use serde::{Deserialize, Serialize};

use crate::error::OwsLibError;

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Binding-friendly wallet information (no crypto envelope exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

/// Result from a signing operation.
///
/// Chain-specific encoding rules live with each chain adapter — for Midnight see
/// [`crate::chains::midnight`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u8>,
}

impl SignResult {
    /// Detached signature for chains that return `(signature, recovery_id)` only.
    pub fn detached_signature(signature: String, recovery_id: Option<u8>) -> Self {
        Self {
            signature,
            recovery_id,
        }
    }
}

/// Build a [`SignResult`] from a chain message signing output.
pub fn sign_result_from_message_output(
    chain_type: ows_core::ChainType,
    output: &ows_signer::SignOutput,
) -> Result<SignResult, OwsLibError> {
    if chain_type == ows_core::ChainType::Midnight {
        return crate::chains::midnight::sign_result_from_message_output(output);
    }
    Ok(SignResult::detached_signature(
        hex::encode(&output.signature),
        output.recovery_id,
    ))
}

pub use crate::chains::midnight::{
    decode_midnight_message_signature, encode_midnight_message_signature,
    is_midnight_transaction_signature_hex, MIDNIGHT_MESSAGE_PUBKEY_HEX_LEN,
    MIDNIGHT_MESSAGE_SIG_HEX_LEN,
};

/// Result from a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}
