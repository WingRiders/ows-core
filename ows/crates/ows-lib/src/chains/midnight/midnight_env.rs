//! Midnight network identity and environment-variable helpers for sync modules.

use std::time::Duration;

/// Midnight network (preview / preprod / mainnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidnightNetwork {
    Preview,
    Preprod,
    Mainnet,
}

impl MidnightNetwork {
    pub fn from_chain_id(chain_id: &str) -> Self {
        if chain_id.eq_ignore_ascii_case("midnight:preview") {
            Self::Preview
        } else if chain_id.eq_ignore_ascii_case("midnight:preprod") {
            Self::Preprod
        } else {
            Self::Mainnet
        }
    }

    /// Infer network from an indexer URL when no chain id is available.
    pub fn from_indexer_url(indexer_url: &str) -> Self {
        let u = indexer_url.to_ascii_lowercase();
        if u.contains("preview") {
            Self::Preview
        } else if u.contains("preprod") {
            Self::Preprod
        } else {
            Self::Mainnet
        }
    }

    pub fn ledger_network_id(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Preprod => "preprod",
            Self::Mainnet => "mainnet",
        }
    }

    pub fn needs_dust_fee_registration(self) -> bool {
        matches!(self, Self::Preview | Self::Preprod)
    }

    /// Default for the zswap-ledger fallback on preview/preprod indexers.
    pub fn shielded_zswap_fallback_default(self) -> bool {
        matches!(self, Self::Preview | Self::Preprod)
    }

    pub fn viewing_key_hrp(self) -> &'static str {
        match self {
            Self::Preview => "mn_shield-esk_preview",
            Self::Preprod => "mn_shield-esk_preprod",
            Self::Mainnet => "mn_shield-esk",
        }
    }
}

/// Indexer sync stream (unshielded / shielded / dust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStream {
    Unshielded,
    Shielded,
    Dust,
}

/// Why the wallet is syncing (balance display vs tx building). Both paths must reach
/// the indexer chain tip before returning — no stale snapshot or session-cache shortcuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPurpose {
    Signing,
    Display,
}

impl SyncPurpose {
    pub fn is_display(self) -> bool {
        matches!(self, Self::Display)
    }

    /// Balance display and tx balancing/signing always reconnect to the indexer.
    pub fn must_catch_up_to_indexer_tip(self) -> bool {
        let _ = self;
        true
    }
}

/// Max time to wait after node submit for the indexer to reflect the tx in unshielded state.
/// Set `OWS_MIDNIGHT_POST_SUBMIT_INDEXER_WAIT_SECS=0` to skip (still invalidates session cache).
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
pub fn shielded_zswap_ledger_sync_enabled(network: MidnightNetwork) -> bool {
    shielded_vk_free_sync_enabled() || shielded_zswap_fallback_enabled(network)
}

pub fn shielded_zswap_fallback_enabled(network: MidnightNetwork) -> bool {
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
pub fn shielded_zswap_spend_hydrate_enabled(_network: MidnightNetwork) -> bool {
    if shielded_vk_free_sync_enabled() {
        return false;
    }
    env_flag_truthy("OWS_MIDNIGHT_SHIELDED_ZSWAP_HYDRATE")
}

/// Build spend wallet state from `zswapLedgerEvents` + `ZswapLocalState::replay_events` (Lace model).
pub fn shielded_zswap_spend_wallet_enabled(network: MidnightNetwork) -> bool {
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

/// Idle limit while confirming a saved dust snapshot is still at chain tip.
/// On expiry with no new ledger events, the sync reconnects (up to several attempts).
pub fn dust_verify_idle_timeout() -> Duration {
    Duration::from_secs(env_parse_u64(
        &["OWS_MIDNIGHT_DUST_VERIFY_IDLE_TIMEOUT_SECS"],
        15,
    ))
}

/// Max reconnect attempts when verifying a saved tip snapshot against the indexer.
pub fn dust_verify_max_attempts() -> u32 {
    env_parse_u64(&["OWS_MIDNIGHT_DUST_VERIFY_MAX_ATTEMPTS"], 8) as u32
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
        assert_eq!(
            MidnightNetwork::from_chain_id("midnight:preview"),
            MidnightNetwork::Preview
        );
        assert_eq!(
            MidnightNetwork::from_chain_id("midnight:mainnet"),
            MidnightNetwork::Mainnet
        );
    }

    #[test]
    fn ledger_network_ids() {
        assert_eq!(MidnightNetwork::Preview.ledger_network_id(), "preview");
        assert_eq!(MidnightNetwork::Preprod.ledger_network_id(), "preprod");
        assert_eq!(MidnightNetwork::Mainnet.ledger_network_id(), "mainnet");
    }
}
