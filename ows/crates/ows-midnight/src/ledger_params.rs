//! Fetch on-chain `LedgerParameters` via the indexer's `block` GraphQL query.
//!
//! Returned by the indexer as a hex-encoded SCALE blob; we decode it via the
//! ledger crate's tagged-deserialization so callers get a fully typed
//! [`midnight_ledger::structure::LedgerParameters`].

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
    #[serde(rename = "dustCommitmentMerkleTreeRoot", default)]
    dust_commitment_root: Option<String>,
    #[serde(rename = "dustGenerationMerkleTreeRoot", default)]
    dust_generation_root: Option<String>,
}

/// The latest block as the indexer reports it: the ledger parameters fees are priced with, its time,
/// and the roots of the two dust Merkle trees after it — what a DUST spend proof is checked against.
pub(crate) struct IndexerTip {
    pub ledger_parameters: midnight_ledger::structure::LedgerParameters,
    pub timestamp_secs: u64,
    /// `None` from an indexer that does not report them.
    pub dust_roots: Option<DustRoots>,
}

/// The roots of the dust commitment and generation trees, each the hex of the root's ledger
/// serialization (the indexer's `dust*MerkleTreeRoot` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DustRoots {
    pub commitment: String,
    pub generation: String,
}

pub(crate) fn parse_indexer_timestamp_secs(v: &serde_json::Value) -> Option<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    // Indexer docs say seconds, but some deployments return milliseconds.
    // Heuristic: anything >= year 33658 in seconds is definitely ms.
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

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightData {
    height: i64,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightResp {
    block: Option<IndexerBlockHeightData>,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHashData {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHashResp {
    block: Option<IndexerBlockHashData>,
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

/// Latest indexer block: on-chain ledger parameters and chain timestamp (unix seconds).
pub async fn fetch_indexer_tip(
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    fetch_indexer_tip_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_tip_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    let tip = fetch_tip(client, indexer_url, TIP_QUERY).await?;
    Ok((tip.ledger_parameters, tip.timestamp_secs))
}

/// The latest block with its dust roots — see [`IndexerTip`].
pub(crate) async fn fetch_indexer_tip_with_dust_roots(
    indexer_url: &str,
) -> Result<IndexerTip, std::io::Error> {
    fetch_tip(
        indexer_http_client(),
        indexer_url,
        TIP_WITH_DUST_ROOTS_QUERY,
    )
    .await
}

// GraphQL refuses a whole query that names a field its schema lacks, so only the callers that use
// the dust roots ask for them: fee pricing keeps working against an indexer that doesn't serve them.
const TIP_QUERY: &str = r#"query BlockHash($offset: BlockOffset) { block(offset: $offset) { height hash ledgerParameters timestamp } }"#;
const TIP_WITH_DUST_ROOTS_QUERY: &str = r#"query BlockHash($offset: BlockOffset) { block(offset: $offset) { height hash ledgerParameters timestamp dustCommitmentMerkleTreeRoot dustGenerationMerkleTreeRoot } }"#;

async fn fetch_tip(
    client: &reqwest::Client,
    indexer_url: &str,
    q: &str,
) -> Result<IndexerTip, std::io::Error> {
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    let block = parsed
        .data
        .and_then(|d| d.block)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))?;
    let timestamp_secs = parse_indexer_timestamp_secs(&block.timestamp)
        .ok_or_else(|| std::io::Error::other("indexer did not return block.timestamp"))?;
    let dust_roots = block
        .dust_commitment_root
        .zip(block.dust_generation_root)
        .map(|(commitment, generation)| DustRoots {
            commitment: commitment.trim_start_matches("0x").to_ascii_lowercase(),
            generation: generation.trim_start_matches("0x").to_ascii_lowercase(),
        });
    let lp_hex = block.ledger_parameters;

    let raw = hex::decode(lp_hex.strip_prefix("0x").unwrap_or(lp_hex.as_str()))
        .map_err(|e| std::io::Error::other(format!("invalid ledgerParameters hex: {e}")))?;
    let mut r: &[u8] = &raw;
    let ledger_parameters = tagged_deserialize::<midnight_ledger::structure::LedgerParameters>(
        &mut r,
    )
    .map_err(|e| std::io::Error::other(format!("failed to decode ledger parameters: {e}")))?;
    Ok(IndexerTip {
        ledger_parameters,
        timestamp_secs,
        dust_roots,
    })
}

/// Current indexer chain-tip block height (HTTP `block { height }`).
pub async fn fetch_indexer_block_height(indexer_url: &str) -> Result<i64, std::io::Error> {
    fetch_indexer_block_height_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_block_height_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<i64, std::io::Error> {
    let q = r#"query BlockHeight($offset: BlockOffset) { block(offset: $offset) { height } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockHeightResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.height)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))
}

/// Hash of the indexer's genesis block (HTTP `block(offset: { height: 0 }) { hash }`). It names the
/// chain instance behind a network id, which a testnet reset replaces while keeping the id.
pub async fn fetch_indexer_genesis_hash(indexer_url: &str) -> Result<String, std::io::Error> {
    let q = r#"query GenesisHash($offset: BlockOffset) { block(offset: $offset) { hash } }"#;
    let resp = indexer_http_client()
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": { "height": 0 } }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockHashResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.hash)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| std::io::Error::other("indexer did not return the genesis block"))
}

pub async fn fetch_indexer_ledger_parameters(
    indexer_url: &str,
) -> Result<midnight_ledger::structure::LedgerParameters, std::io::Error> {
    Ok(fetch_indexer_tip(indexer_url).await?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_failed_request_does_not_echo_the_url() {
        // A port that was just released refuses the connection.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("bind")
            .port();
        let url = format!("http://127.0.0.1:{port}/api/v4/graphql?project_id=SECRET");
        let err = fetch_indexer_block_height(&url)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("indexer query failed"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }

    /// Answers one request the way an indexer without the dust-root fields does: a query naming
    /// them gets a GraphQL error, any other gets the tip block.
    fn serve_rootless_indexer() -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}/api/v4/graphql", listener.local_addr().unwrap());
        let mut lp = Vec::new();
        midnight_serialize::tagged_serialize(
            &midnight_ledger::structure::INITIAL_PARAMETERS,
            &mut lp,
        )
        .expect("serialize ledger parameters");
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf).expect("read");
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let len = text[..head_end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if req.len() >= head_end + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let body = if String::from_utf8_lossy(&req).contains("dustCommitmentMerkleTreeRoot") {
                r#"{"errors":[{"message":"Unknown field \"dustCommitmentMerkleTreeRoot\" on type \"Block\""}]}"#.to_string()
            } else {
                format!(
                    r#"{{"data":{{"block":{{"height":7,"hash":"00","ledgerParameters":"{}","timestamp":1793000000}}}}}}"#,
                    hex::encode(&lp)
                )
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            conn.write_all(resp.as_bytes()).expect("write");
        });
        url
    }

    #[tokio::test]
    async fn fee_pricing_works_against_an_indexer_without_dust_roots() {
        let url = serve_rootless_indexer();
        let (_, timestamp) = fetch_indexer_tip(&url)
            .await
            .expect("tip without dust roots");
        assert_eq!(timestamp, 1793000000);
    }

    #[tokio::test]
    async fn only_the_dust_spend_path_asks_for_dust_roots() {
        let url = serve_rootless_indexer();
        let err = fetch_indexer_tip_with_dust_roots(&url)
            .await
            .err()
            .expect("a rootless indexer refuses the roots query")
            .to_string();
        assert!(err.contains("indexer GraphQL error"), "{err}");
    }
}
