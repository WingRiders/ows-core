//! Fetch on-chain `LedgerParameters` via the indexer's `block` GraphQL query.
//!
//! Returned by the indexer as a hex-encoded SCALE blob; we decode it via the
//! ledger crate's tagged-deserialization so callers get a fully typed
//! [`midnight_ledger::structure::LedgerParameters`].

use super::error::{PayError, PayErrorCode};
use midnight_serialize::tagged_deserialize;
use serde::Deserialize;
use std::sync::OnceLock;

use super::midnight_env;

#[derive(Debug, Deserialize)]
struct IndexerBlockData {
    #[allow(dead_code)]
    height: i64,
    #[allow(dead_code)]
    hash: String,
    #[serde(rename = "ledgerParameters")]
    ledger_parameters: String,
    timestamp: serde_json::Value,
}

fn parse_indexer_timestamp_secs(v: &serde_json::Value) -> Option<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    // Indexer docs say seconds, but some deployments return milliseconds.
    if n >= 1_000_000_000_000 {
        Some(n / 1000)
    } else {
        Some(n)
    }
}

#[derive(Debug, Deserialize)]
struct IndexerBlockResp {
    block: Option<IndexerBlockData>,
}

#[derive(Debug, Deserialize)]
struct IndexerGraphqlResp<T> {
    data: Option<T>,
    errors: Option<Vec<serde_json::Value>>,
}

static INDEXER_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

/// Shared HTTP client for Midnight indexer GraphQL (bounded request timeout).
pub fn indexer_http_client() -> &'static reqwest::Client {
    INDEXER_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(midnight_env::indexer_http_timeout())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Minimal transaction metadata from the indexer HTTP API (post-submit sync).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexerTxSummary {
    pub zswap_ledger_event_count: usize,
    pub dust_ledger_event_count: usize,
    pub max_zswap_ledger_event_id: Option<i64>,
    pub max_dust_ledger_event_id: Option<i64>,
}

/// Look up a ledger transaction by hash via indexer HTTP GraphQL.
pub async fn fetch_indexer_transaction_by_hash(
    indexer_url: &str,
    ledger_tx_hash: &str,
) -> Result<Option<IndexerTxSummary>, PayError> {
    fetch_indexer_transaction_by_hash_with_client(
        indexer_http_client(),
        indexer_url,
        ledger_tx_hash,
    )
    .await
}

pub async fn fetch_indexer_transaction_by_hash_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
    ledger_tx_hash: &str,
) -> Result<Option<IndexerTxSummary>, PayError> {
    let bare = ledger_tx_hash.strip_prefix("0x").unwrap_or(ledger_tx_hash);
    let q = r#"query TxByHash($offset: TransactionOffset!) {
  transactions(offset: $offset) {
    hash
    zswapLedgerEvents { id }
    dustLedgerEvents { id }
  }
}"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": { "hash": format!("0x{bare}") } }
        }))
        .send()
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("indexer transaction query failed: {e}"),
            )
        })?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer read body failed: {e}"),
        )
    })?;
    if !status.is_success() {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer returned {status}: {body}"),
        ));
    }
    #[derive(Deserialize)]
    struct TxLedgerEventRef {
        id: i64,
    }

    #[derive(Deserialize)]
    struct TxEvents {
        #[serde(rename = "zswapLedgerEvents", default)]
        zswap_ledger_events: Vec<TxLedgerEventRef>,
        #[serde(rename = "dustLedgerEvents", default)]
        dust_ledger_events: Vec<TxLedgerEventRef>,
    }
    #[derive(Deserialize)]
    struct TxData {
        transactions: Vec<TxEvents>,
    }
    let parsed: IndexerGraphqlResp<TxData> = serde_json::from_str(&body).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid indexer json: {e}"),
        )
    })?;
    if let Some(errs) = parsed.errors {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer GraphQL error: {errs:?}"),
        ));
    }
    let Some(tx) = parsed.data.and_then(|d| d.transactions.into_iter().next()) else {
        return Ok(None);
    };
    Ok(Some(IndexerTxSummary {
        zswap_ledger_event_count: tx.zswap_ledger_events.len(),
        dust_ledger_event_count: tx.dust_ledger_events.len(),
        max_zswap_ledger_event_id: tx.zswap_ledger_events.iter().map(|e| e.id).max(),
        max_dust_ledger_event_id: tx.dust_ledger_events.iter().map(|e| e.id).max(),
    }))
}

/// Latest indexer block height (HTTP `block { height }`, ~sub-second).
pub async fn fetch_indexer_block_height(indexer_url: &str) -> Result<i64, PayError> {
    fetch_indexer_block_height_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_block_height_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<i64, PayError> {
    let q = r#"query BlockHeight { block(offset: null) { height } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({ "query": q }))
        .send()
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("indexer block height query failed: {e}"),
            )
        })?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer read body failed: {e}"),
        )
    })?;
    if !status.is_success() {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer returned {status}: {body}"),
        ));
    }
    #[derive(Deserialize)]
    struct HeightBlock {
        height: i64,
    }
    #[derive(Deserialize)]
    struct HeightData {
        block: Option<HeightBlock>,
    }
    let parsed: IndexerGraphqlResp<HeightData> = serde_json::from_str(&body).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid indexer json: {e}"),
        )
    })?;
    if let Some(errs) = parsed.errors {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer GraphQL error: {errs:?}"),
        ));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.height)
        .ok_or_else(|| PayError::new(PayErrorCode::HttpTransport, "indexer did not return block"))
}

/// Latest indexer block: on-chain ledger parameters and chain timestamp (unix seconds).
pub async fn fetch_indexer_tip(
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), PayError> {
    fetch_indexer_tip_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_tip_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), PayError> {
    let q = r#"query BlockHash($offset: BlockOffset) { block(offset: $offset) { height hash ledgerParameters timestamp } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| {
            PayError::new(
                PayErrorCode::HttpTransport,
                format!("indexer query failed: {e}"),
            )
        })?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer read body failed: {e}"),
        )
    })?;
    if !status.is_success() {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer returned {status}: {body}"),
        ));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockResp> =
        serde_json::from_str(&body).map_err(|e| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("invalid indexer json: {e}"),
            )
        })?;
    if let Some(errs) = parsed.errors {
        return Err(PayError::new(
            PayErrorCode::HttpTransport,
            format!("indexer GraphQL error: {errs:?}"),
        ));
    }
    let block = parsed.data.and_then(|d| d.block).ok_or_else(|| {
        PayError::new(PayErrorCode::HttpTransport, "indexer did not return block")
    })?;
    let timestamp_secs = parse_indexer_timestamp_secs(&block.timestamp).ok_or_else(|| {
        PayError::new(
            PayErrorCode::HttpTransport,
            "indexer did not return block.timestamp",
        )
    })?;
    let lp_hex = block.ledger_parameters;

    let raw = hex::decode(lp_hex.strip_prefix("0x").unwrap_or(lp_hex.as_str())).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid ledgerParameters hex: {e}"),
        )
    })?;
    let mut r: &[u8] = &raw;
    let ledger_parameters = tagged_deserialize::<midnight_ledger::structure::LedgerParameters>(
        &mut r,
    )
    .map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to decode ledger parameters: {e}"),
        )
    })?;
    Ok((ledger_parameters, timestamp_secs))
}

pub async fn fetch_indexer_ledger_parameters(
    indexer_url: &str,
) -> Result<midnight_ledger::structure::LedgerParameters, PayError> {
    Ok(fetch_indexer_tip(indexer_url).await?.0)
}
