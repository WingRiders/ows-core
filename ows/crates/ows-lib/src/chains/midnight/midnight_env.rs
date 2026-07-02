//! Midnight network identity and environment-variable helpers for sync modules.

use ows_signer::chains::{
    hrp_for_network, is_mainnet_network_reference, network_reference_from_chain_id,
};
use std::time::Duration;

/// Midnight network identity (`preview`, `mainnet`, or any ad-hoc testnet name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidnightNetwork {
    /// Ledger / DApp connector network id (the `<network>` in `midnight:<network>`).
    pub reference: String,
}

impl MidnightNetwork {
    pub fn from_chain_id(chain_id: &str) -> Result<Self, String> {
        let reference = network_reference_from_chain_id(chain_id).map_err(|e| e.to_string())?;
        Ok(Self { reference })
    }

    /// Require an explicit CAIP-2 chain id (`midnight:<network>`).
    ///
    /// Network identity is never inferred from the indexer URL — callers must supply
    /// `chain_id` so addresses, ledger state, and sync behavior stay aligned.
    pub fn resolve(chain_id: Option<&str>, _indexer_url: &str) -> Result<Self, String> {
        let cid = chain_id.ok_or_else(|| {
            "Midnight operations require a chain id (midnight:<network>)".to_string()
        })?;
        Self::from_chain_id(cid)
    }

    pub fn is_mainnet(&self) -> bool {
        is_mainnet_network_reference(&self.reference)
    }

    pub fn ledger_network_id(&self) -> &str {
        &self.reference
    }

    pub fn needs_dust_fee_registration(&self) -> bool {
        !self.is_mainnet()
    }

    /// Default for the zswap-ledger fallback on non-mainnet indexers.
    pub fn shielded_zswap_fallback_default(&self) -> bool {
        !self.is_mainnet()
    }

    pub fn viewing_key_hrp(&self) -> String {
        hrp_for_network("mn_shield-esk", &self.reference)
    }
}

/// Indexer sync stream (unshielded / shielded / dust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStream {
    Unshielded,
    Shielded,
    Dust,
}

/// Why the wallet is syncing (balance display vs tx building).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPurpose {
    Signing,
    Display,
}

impl SyncPurpose {
    pub fn is_display(self) -> bool {
        matches!(self, Self::Display)
    }

    /// Tx building uses WebSocket tip-verify; balance display uses HTTP `block.height` when set.
    pub fn must_catch_up_to_indexer_tip(self) -> bool {
        !self.is_display()
    }
}

/// Max time to wait after node submit for the indexer to reflect the tx and refresh local
/// sync snapshots (unshielded, shielded zswap wallet, dust). On timeout, `sign send-tx` fails
/// (the tx may already be on-chain). Set `OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS=0` to skip
/// the wait (still invalidates session cache).
pub fn post_submit_indexer_wait_timeout() -> Duration {
    Duration::from_secs(env_parse_u64(
        &["OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS"],
        120,
    ))
}

pub fn env_flag_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Parse the first valid u64 from a list of env var names (supports legacy aliases).
pub fn env_parse_u64(keys: &[&str], default: u64) -> u64 {
    for key in keys {
        if let Ok(v) = std::env::var(key) {
            if let Ok(n) = v.parse() {
                return n;
            }
        }
    }
    default
}

pub fn ws_idle_timeout(stream: SyncStream) -> Duration {
    let secs = match stream {
        SyncStream::Unshielded => {
            env_parse_u64(&["OWS_MIDNIGHT_UNSHIELDED_WS_IDLE_TIMEOUT_SECS"], 90)
        }
        SyncStream::Shielded => env_parse_u64(
            &[
                "OWS_MIDNIGHT_SHIELDED_WS_IDLE_TIMEOUT_SECS",
                "OWS_MIDNIGHT_DUST_WS_IDLE_TIMEOUT_SECS",
            ],
            90,
        ),
        SyncStream::Dust => env_parse_u64(&["OWS_MIDNIGHT_DUST_WS_IDLE_TIMEOUT_SECS"], 90),
    };
    Duration::from_secs(secs)
}

pub fn stall_timeout(stream: SyncStream) -> Duration {
    let secs = match stream {
        SyncStream::Unshielded => env_parse_u64(
            &[
                "OWS_MIDNIGHT_UNSHIELDED_STALL_TIMEOUT_SECS",
                "OWS_MIDNIGHT_UNSHIELDED_SYNC_TIMEOUT_SECS",
            ],
            120,
        ),
        SyncStream::Shielded => env_parse_u64(
            &[
                "OWS_MIDNIGHT_SHIELDED_STALL_TIMEOUT_SECS",
                "OWS_MIDNIGHT_SHIELDED_SYNC_TIMEOUT_SECS",
            ],
            120,
        ),
        SyncStream::Dust => env_parse_u64(
            &[
                "OWS_MIDNIGHT_DUST_STALL_TIMEOUT_SECS",
                "OWS_MIDNIGHT_DUST_BALANCE_SYNC_TIMEOUT_SECS",
                "OWS_MIDNIGHT_DUST_SYNC_TIMEOUT_SECS",
            ],
            120,
        ),
    };
    Duration::from_secs(secs)
}

/// Whether Midnight indexer sync should print progress lines to stderr.
pub fn midnight_sync_log_enabled() -> bool {
    [
        "OWS_MIDNIGHT_SYNC_LOG",
        "OWS_MIDNIGHT_DUST_SYNC_LOG",
        "OWS_PAY_MIDNIGHT_DUST_SYNC_LOG",
        "OWS_MIDNIGHT_UNSHIELDED_SYNC_LOG",
        "OWS_MIDNIGHT_SHIELDED_SYNC_LOG",
    ]
    .into_iter()
    .any(env_flag_truthy)
}

/// When true, shielded sync uses only `zswapLedgerEvents` replay (the midnight-wallet-sdk path).
/// This is the default for balance and spend; no `connect(viewingKey)` session is started.
pub fn shielded_vk_free_sync_enabled() -> bool {
    env_flag_truthy("OWS_MIDNIGHT_SHIELDED_VK_FREE")
}

/// Primary shielded sync uses `zswapLedgerEvents` + `ZswapLocalState::replay_events`, matching
/// `@midnight-ntwrk/wallet-sdk-shielded` (Lace). Enabled by default on preview/preprod.
pub fn shielded_zswap_ledger_sync_enabled(network: &MidnightNetwork) -> bool {
    shielded_vk_free_sync_enabled() || shielded_zswap_fallback_enabled(network)
}

pub fn shielded_zswap_fallback_enabled(network: &MidnightNetwork) -> bool {
    if shielded_vk_free_sync_enabled() {
        return true;
    }
    match std::env::var("OWS_MIDNIGHT_SHIELDED_ZSWAP_FALLBACK") {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
        _ => network.shielded_zswap_fallback_default(),
    }
}

/// Optional `connect(viewingKey)` + `shieldedTransactions` replay (wallet-indexer session).
/// Off by default — midnight-wallet-sdk does not use this for shielded balance/spend; it uses
/// `zswapLedgerEvents` locally. Opt in with `OWS_MIDNIGHT_SHIELDED_SESSION_SYNC=1` to compare.
pub fn shielded_indexer_session_sync_enabled() -> bool {
    if shielded_vk_free_sync_enabled() {
        return false;
    }
    env_flag_truthy("OWS_MIDNIGHT_SHIELDED_SESSION_SYNC")
}

/// After viewing-key session sync, merge qualified coins from the on-disk zswap-ledger snapshot
/// into spend state. **Off by default** — zswap `mt_index` values are not valid in the session
/// Merkle tree and cause `InvalidIndex` on spend. Opt in with `OWS_MIDNIGHT_SHIELDED_ZSWAP_HYDRATE=1`.
pub fn shielded_zswap_spend_hydrate_enabled(_network: &MidnightNetwork) -> bool {
    if shielded_vk_free_sync_enabled() {
        return false;
    }
    env_flag_truthy("OWS_MIDNIGHT_SHIELDED_ZSWAP_HYDRATE")
}

/// Build spend wallet state from `zswapLedgerEvents` + `ZswapLocalState::replay_events` (Lace model).
pub fn shielded_zswap_spend_wallet_enabled(network: &MidnightNetwork) -> bool {
    shielded_zswap_ledger_sync_enabled(network)
}

pub fn fund_balance_skip_dust_sync() -> bool {
    env_flag_truthy("OWS_MIDNIGHT_SKIP_DUST_BALANCE")
}

pub fn dust_sync_start_id() -> i64 {
    std::env::var("OWS_MIDNIGHT_DUST_SYNC_START_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Idle limit while confirming a saved dust snapshot is still at chain tip (signing).
/// On expiry with no new ledger events, the sync reconnects (up to several attempts).
pub fn dust_verify_idle_timeout() -> Duration {
    Duration::from_secs(env_parse_u64(
        &["OWS_MIDNIGHT_DUST_VERIFY_IDLE_TIMEOUT_SECS"],
        15,
    ))
}

/// Shorter tip-verify idle for `ows fund balance` display (default 3s vs 15s for signing).
pub fn dust_verify_idle_timeout_for(purpose: SyncPurpose) -> Duration {
    if purpose.is_display() {
        Duration::from_secs(env_parse_u64(
            &["OWS_MIDNIGHT_DUST_VERIFY_IDLE_TIMEOUT_DISPLAY_SECS"],
            3,
        ))
    } else {
        dust_verify_idle_timeout()
    }
}

/// Max reconnect attempts when verifying a saved tip snapshot against the indexer.
pub fn dust_verify_max_attempts() -> u32 {
    env_parse_u64(&["OWS_MIDNIGHT_DUST_VERIFY_MAX_ATTEMPTS"], 8) as u32
}

pub fn dust_verify_max_attempts_for(purpose: SyncPurpose) -> u32 {
    if purpose.is_display() {
        env_parse_u64(&["OWS_MIDNIGHT_DUST_VERIFY_MAX_ATTEMPTS_DISPLAY"], 2) as u32
    } else {
        dust_verify_max_attempts()
    }
}

/// Per-request timeout for Midnight indexer GraphQL HTTP calls.
pub fn indexer_http_timeout() -> Duration {
    Duration::from_secs(env_parse_u64(
        &["OWS_MIDNIGHT_INDEXER_HTTP_TIMEOUT_SECS"],
        30,
    ))
}

/// Timeout for establishing a Midnight indexer WebSocket connection.
pub fn ws_connect_timeout() -> Duration {
    Duration::from_secs(env_parse_u64(&["OWS_MIDNIGHT_WS_CONNECT_TIMEOUT_SECS"], 30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_from_chain_id() {
        let preview = MidnightNetwork::from_chain_id("midnight:preview").unwrap();
        assert_eq!(preview.reference, "preview");
        assert_eq!(preview.ledger_network_id(), "preview");

        let mainnet = MidnightNetwork::from_chain_id("midnight:mainnet").unwrap();
        assert_eq!(mainnet.reference, "mainnet");
        assert!(mainnet.is_mainnet());

        let custom = MidnightNetwork::from_chain_id("midnight:my-feature-testnet").unwrap();
        assert_eq!(custom.reference, "my-feature-testnet");
        assert_eq!(custom.ledger_network_id(), "my-feature-testnet");
        assert!(!custom.is_mainnet());
        assert!(custom.needs_dust_fee_registration());
    }

    #[test]
    fn resolve_requires_chain_id() {
        let err = MidnightNetwork::resolve(None, "https://indexer.example/graphql").unwrap_err();
        assert!(err.contains("chain id"), "{err}");

        let err = MidnightNetwork::resolve(Some("not-midnight"), "https://indexer.example/graphql")
            .unwrap_err();
        assert!(err.contains("midnight"), "{err}");
    }

    #[test]
    fn resolve_uses_explicit_chain_id() {
        let net = MidnightNetwork::resolve(
            Some("midnight:undeployed"),
            "https://indexer.preview.midnight.network/api/v4/graphql",
        )
        .unwrap();
        assert_eq!(net.reference, "undeployed");
    }

    #[test]
    fn ledger_network_ids() {
        assert_eq!(
            MidnightNetwork::from_chain_id("midnight:preview")
                .unwrap()
                .ledger_network_id(),
            "preview"
        );
        assert_eq!(
            MidnightNetwork::from_chain_id("midnight:preprod")
                .unwrap()
                .ledger_network_id(),
            "preprod"
        );
        assert_eq!(
            MidnightNetwork::from_chain_id("midnight:mainnet")
                .unwrap()
                .ledger_network_id(),
            "mainnet"
        );
    }

    #[test]
    fn custom_network_hrp_and_non_mainnet_defaults() {
        let custom = MidnightNetwork::from_chain_id("midnight:custom-net").expect("custom network");
        assert_eq!(custom.viewing_key_hrp(), "mn_shield-esk_custom-net");
        assert!(custom.needs_dust_fee_registration());
        assert!(custom.shielded_zswap_fallback_default());
    }
}
