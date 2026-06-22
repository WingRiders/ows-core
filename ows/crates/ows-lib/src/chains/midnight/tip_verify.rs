//! Fast chain-tip checks via indexer HTTP (`block { height }`), avoiding slow WebSocket verify.

use super::async_runtime::block_on;
use super::cache_io::SyncCacheScope;
use super::ledger_params;

/// Populate [`SyncCacheScope::indexer_block_height`] once per signing/balance flow when unset.
pub(crate) fn ensure_indexer_block_height(scope: &mut SyncCacheScope, indexer_url: &str) {
    if scope.indexer_block_height.is_some() {
        return;
    }
    refresh_indexer_block_height(scope, indexer_url);
}

/// Always fetch the latest indexer `block.height` (signing / post-submit paths).
pub(crate) fn refresh_indexer_block_height(scope: &mut SyncCacheScope, indexer_url: &str) {
    if let Ok(height) = block_on(ledger_params::fetch_indexer_block_height(indexer_url)) {
        scope.indexer_block_height = Some(height);
        if super::midnight_env::midnight_sync_log_enabled() {
            eprintln!("[ows-midnight] indexer tip block height={height} (HTTP)");
        }
    } else if super::midnight_env::midnight_sync_log_enabled() {
        eprintln!(
            "[ows-midnight] indexer block height query failed; falling back to WebSocket tip-verify"
        );
    }
}

/// True when a complete on-disk snapshot can be trusted without WebSocket tip-verify.
pub(crate) fn snapshot_fresh_by_http_tip(
    scope: &SyncCacheScope,
    saved_block_height: i64,
    snapshot_complete: bool,
) -> bool {
    if !snapshot_complete {
        return false;
    }
    let Some(current) = scope.indexer_block_height else {
        return false;
    };
    saved_block_height > 0 && saved_block_height == current
}

pub(crate) fn block_height_for_snapshot(scope: &SyncCacheScope) -> i64 {
    scope.indexer_block_height.unwrap_or(0)
}

/// Fresh HTTP `block.height` matches a height stored with an on-disk snapshot.
pub(crate) async fn indexer_block_height_matches_saved(
    indexer_url: &str,
    saved_block_height: i64,
) -> bool {
    if saved_block_height <= 0 {
        return false;
    }
    ledger_params::fetch_indexer_block_height(indexer_url)
        .await
        .ok()
        .is_some_and(|h| h == saved_block_height)
}

#[cfg(test)]
mod tests {
    use super::snapshot_fresh_by_http_tip;
    use crate::chains::midnight::cache_io::SyncCacheScope;

    #[test]
    fn http_tip_fresh_when_height_matches_and_snapshot_complete() {
        let scope = SyncCacheScope {
            wallet_id: None,
            vault_path: None,
            chain_id: None,
            indexer_block_height: Some(100),
        };
        assert!(snapshot_fresh_by_http_tip(&scope, 100, true));
        assert!(!snapshot_fresh_by_http_tip(&scope, 99, true));
        assert!(!snapshot_fresh_by_http_tip(&scope, 100, false));
        assert!(!snapshot_fresh_by_http_tip(&scope, 0, true));
    }
}
