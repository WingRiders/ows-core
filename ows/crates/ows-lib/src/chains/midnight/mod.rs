//! Midnight integration — stage 4: unshielded indexer sync only.

/// Shielded balances keyed by the hex-encoded `ShieldedTokenType`.
pub type ShieldedBalances = std::collections::BTreeMap<String, u128>;

mod async_runtime;
mod cache_io;
mod error;
mod indexer_ws;
mod ledger_params;
mod midnight_env;
mod session_cache;
mod unshielded_sync;
mod urls;

pub use async_runtime::block_on;
pub use cache_io::{midnight_sync_log_enabled, SyncCacheScope};
pub use error::{PayError, PayErrorCode};
pub use ledger_params::fetch_indexer_ledger_parameters;
pub use midnight_env::MidnightNetwork;
pub use unshielded_sync::{
    get_unshielded_utxos_for_display_scoped, refresh_unshielded_after_submit, UnshieldedUtxo,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Native,
    Custom([u8; 32]),
}

impl TokenType {
    pub fn to_wire_token_type(&self) -> String {
        match self {
            TokenType::Native => hex::encode([0u8; 32]),
            TokenType::Custom(b) => hex::encode(b),
        }
    }
}

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

pub fn chain_needs_dust_fee_registration(chain_id: &str) -> bool {
    MidnightNetwork::from_chain_id(chain_id).needs_dust_fee_registration()
}

pub fn ledger_network_id(chain_id: &str) -> &'static str {
    MidnightNetwork::from_chain_id(chain_id).ledger_network_id()
}
