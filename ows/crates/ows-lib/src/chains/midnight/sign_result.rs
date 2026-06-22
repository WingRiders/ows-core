//! Midnight-specific [`SignResult`] encoding helpers.

use crate::error::OwsLibError;
use crate::types::SignResult;

/// Hex length of a BIP-340 x-only verifying key in [`encode_midnight_message_signature`].
pub const MIDNIGHT_MESSAGE_PUBKEY_HEX_LEN: usize = 64;
/// Hex length of the BIP-340 signature suffix in [`encode_midnight_message_signature`].
pub const MIDNIGHT_MESSAGE_SIG_HEX_LEN: usize = 128;

impl SignResult {
    /// Midnight Standard transaction: full wire bytes in [`Self::signature`].
    pub fn midnight_transaction(signed_wire_hex: String) -> Self {
        Self {
            signature: signed_wire_hex,
            recovery_id: None,
        }
    }

    /// Midnight BIP-340 message signature with prefixed verifying key.
    pub fn midnight_message(public_key: &[u8], signature: &[u8]) -> Result<Self, String> {
        Ok(Self {
            signature: encode_midnight_message_signature(public_key, signature)?,
            recovery_id: None,
        })
    }
}

/// Build Midnight message `SignResult.signature`: hex(`pubkey[32] || sig[64]`).
pub fn encode_midnight_message_signature(
    public_key: &[u8],
    signature: &[u8],
) -> Result<String, String> {
    if public_key.len() != 32 {
        return Err(format!(
            "Midnight message pubkey must be 32 bytes (got {})",
            public_key.len()
        ));
    }
    if signature.len() != 64 {
        return Err(format!(
            "Midnight message signature must be 64 bytes (got {})",
            signature.len()
        ));
    }
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(public_key);
    out.extend_from_slice(signature);
    Ok(hex::encode(out))
}

/// Split a Midnight message `SignResult.signature` into `(pubkey, sig)` bytes.
pub fn decode_midnight_message_signature(
    signature_hex: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let hex_s = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let bytes =
        hex::decode(hex_s).map_err(|e| format!("invalid Midnight message signature hex: {e}"))?;
    if bytes.len() != 96 {
        return Err(format!(
            "Midnight message signature must be 96 bytes (got {})",
            bytes.len()
        ));
    }
    Ok((bytes[..32].to_vec(), bytes[32..].to_vec()))
}

/// True when `signature` hex decodes to a tagged Midnight transaction blob.
pub fn is_midnight_transaction_signature_hex(signature_hex: &str) -> bool {
    let hex_s = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let Ok(bytes) = hex::decode(hex_s) else {
        return false;
    };
    bytes.starts_with(b"midnight:transaction")
}

/// Build a [`SignResult`] from a chain message signing output (Midnight branch).
pub fn sign_result_from_message_output(
    output: &ows_signer::SignOutput,
) -> Result<SignResult, OwsLibError> {
    let pk = output.public_key.as_ref().ok_or_else(|| {
        OwsLibError::InvalidInput("Midnight message signing did not produce a verifying key".into())
    })?;
    SignResult::midnight_message(pk, &output.signature).map_err(OwsLibError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight_message_signature_roundtrip() {
        let pk = [0x11u8; 32];
        let sig = [0x22u8; 64];
        let hex = encode_midnight_message_signature(&pk, &sig).unwrap();
        assert_eq!(
            hex.len(),
            MIDNIGHT_MESSAGE_PUBKEY_HEX_LEN + MIDNIGHT_MESSAGE_SIG_HEX_LEN
        );
        let (pk2, sig2) = decode_midnight_message_signature(&hex).unwrap();
        assert_eq!(pk2, pk.to_vec());
        assert_eq!(sig2, sig.to_vec());
    }

    #[test]
    fn detects_midnight_transaction_signature() {
        assert!(is_midnight_transaction_signature_hex(&hex::encode(
            b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):"
        )));
        assert!(!is_midnight_transaction_signature_hex("deadbeef"));
    }
}
