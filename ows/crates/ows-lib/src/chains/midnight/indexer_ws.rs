//! Shared GraphQL-over-WebSocket helpers for Midnight indexer sync.

use super::error::{PayError, PayErrorCode};
use futures_util::{SinkExt as _, StreamExt as _};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::urls::indexer_ws_url;

pub type IndexerWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Inbound GraphQL-transport-ws subscription frame (`D` is the subscription `data` shape).
#[derive(Debug, Deserialize)]
pub struct WsFrame<D> {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(default)]
    pub payload: Option<WsPayload<D>>,
}

#[derive(Debug, Deserialize)]
pub struct WsPayload<D> {
    #[serde(default)]
    pub data: Option<D>,
    #[serde(default)]
    pub errors: Option<Vec<serde_json::Value>>,
}

fn transport_err(e: impl ToString) -> PayError {
    PayError::new(PayErrorCode::HttpTransport, e.to_string())
}

/// True when the stream can be resumed on a fresh WebSocket (RST, closed, I/O, etc.).
pub fn ws_error_recoverable(e: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error;
    match e {
        Error::ConnectionClosed | Error::AlreadyClosed | Error::Io(_) | Error::Protocol(_) => true,
        Error::Tls(_) | Error::Url(_) | Error::Capacity(_) | Error::AttackAttempt => false,
        _ => true,
    }
}

use super::midnight_env;

/// Outcome of waiting for the next GraphQL subscription `Text` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionTextRead {
    /// A subscription frame (`next` / `error` / `complete` payload).
    Text(String),
    /// No application data before `read_timeout` (excludes answered pings).
    IdleTimeout,
    /// WebSocket closed by peer.
    Closed,
}

/// If `text` is a graphql-transport-ws `ping` / `pong` control message, returns `Some("ping"|"pong")`.
pub fn graphql_transport_control_type(text: &str) -> Option<&'static str> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    match v.get("type").and_then(|t| t.as_str()) {
        Some("ping") => Some("ping"),
        Some("pong") => Some("pong"),
        _ => None,
    }
}

/// Reply to a graphql-transport-ws `ping` with `pong` (required by the subprotocol).
pub async fn reply_graphql_transport_pong(ws: &mut IndexerWs) -> Result<(), PayError> {
    use tokio_tungstenite::tungstenite::Message;
    ws.send(Message::Text(r#"{"type":"pong"}"#.to_string()))
        .await
        .map_err(transport_err)
}

/// Returns `true` when `text` was a transport-level ping/pong (caller should continue reading).
pub async fn handle_graphql_transport_text(
    ws: &mut IndexerWs,
    text: &str,
) -> Result<bool, PayError> {
    match graphql_transport_control_type(text) {
        Some("ping") => {
            reply_graphql_transport_pong(ws).await?;
            Ok(true)
        }
        Some("pong") => Ok(true),
        _ => Ok(false),
    }
}

/// Read the next subscription JSON text frame, answering WebSocket- and protocol-level pings.
pub async fn read_subscription_text(
    ws: &mut IndexerWs,
    read_timeout: Duration,
) -> Result<SubscriptionTextRead, PayError> {
    use tokio_tungstenite::tungstenite::Message;

    let deadline = Instant::now() + read_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(SubscriptionTextRead::IdleTimeout);
        }

        let msg = match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                if ws_error_recoverable(&e) {
                    return Ok(SubscriptionTextRead::Closed);
                }
                return Err(transport_err(e));
            }
            Ok(None) => return Ok(SubscriptionTextRead::Closed),
            Err(_) => return Ok(SubscriptionTextRead::IdleTimeout),
        };

        match msg {
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload))
                    .await
                    .map_err(transport_err)?;
            }
            Message::Pong(_) => {}
            Message::Text(t) => {
                if handle_graphql_transport_text(ws, &t).await? {
                    continue;
                }
                return Ok(SubscriptionTextRead::Text(t));
            }
            Message::Close(_) => return Ok(SubscriptionTextRead::Closed),
            Message::Binary(_) | Message::Frame(_) => {}
        }
    }
}

/// Open a GraphQL-transport-ws connection to the indexer.
pub async fn connect_indexer(indexer_url: &str) -> Result<IndexerWs, PayError> {
    let ws_url = indexer_ws_url(indexer_url)?;
    let mut req = ws_url
        .into_client_request()
        .map_err(|e| PayError::new(PayErrorCode::InvalidInput, e.to_string()))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "graphql-transport-ws".parse().expect("valid header"),
    );
    let connect_timeout = midnight_env::ws_connect_timeout();
    let (ws, _resp) = match tokio::time::timeout(connect_timeout, connect_async(req)).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!("failed to connect to Midnight indexer websocket: {e}"),
            ));
        }
        Err(_) => {
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!(
                    "timed out connecting to Midnight indexer websocket after {}s",
                    connect_timeout.as_secs()
                ),
            ));
        }
    };
    Ok(ws)
}

/// Send `connection_init` on an open WebSocket.
pub async fn send_connection_init(ws: &mut IndexerWs) -> Result<(), PayError> {
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({ "type": "connection_init" }).to_string(),
    ))
    .await
    .map_err(transport_err)
}

/// Wait for `connection_ack` (or fail on `connection_error` / idle timeout).
///
/// When `log_label` is set, prints a ready line after ack.
pub async fn wait_for_connection_ack(
    ws: &mut IndexerWs,
    ws_idle: Duration,
    log_label: Option<&str>,
) -> Result<(), PayError> {
    let started = Instant::now();
    loop {
        if started.elapsed() > ws_idle.saturating_mul(3) {
            return Err(PayError::new(
                PayErrorCode::HttpTransport,
                format!(
                    "timed out waiting for indexer connection_ack after {}s",
                    (ws_idle.saturating_mul(3)).as_secs()
                ),
            ));
        }
        match read_subscription_text(ws, ws_idle).await? {
            SubscriptionTextRead::Text(t) => {
                let v: serde_json::Value = serde_json::from_str(&t)
                    .map_err(|e| PayError::new(PayErrorCode::ProtocolMalformed, e.to_string()))?;
                match v.get("type").and_then(|x| x.as_str()) {
                    Some("connection_ack") => {
                        if let Some(label) = log_label {
                            eprintln!("[ows-midnight] {label}: indexer websocket ready");
                        }
                        return Ok(());
                    }
                    Some("connection_error") => {
                        return Err(PayError::new(
                            PayErrorCode::ProtocolMalformed,
                            format!("indexer connection_error: {t}"),
                        ));
                    }
                    _ => continue,
                }
            }
            SubscriptionTextRead::Closed => {
                return Err(PayError::new(
                    PayErrorCode::HttpTransport,
                    "indexer websocket closed before connection_ack".to_string(),
                ));
            }
            SubscriptionTextRead::IdleTimeout => {
                return Err(PayError::new(
                    PayErrorCode::HttpTransport,
                    format!(
                        "no indexer websocket data for {}s while waiting for connection_ack",
                        ws_idle.as_secs()
                    ),
                ));
            }
        }
    }
}

/// Connect, init, and wait for ack in one step.
pub async fn connect_and_init(
    indexer_url: &str,
    ws_idle: Duration,
    log_label: Option<&str>,
) -> Result<IndexerWs, PayError> {
    let mut ws = connect_indexer(indexer_url).await?;
    send_connection_init(&mut ws).await?;
    wait_for_connection_ack(&mut ws, ws_idle, log_label).await?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_reset_is_recoverable() {
        use tokio_tungstenite::tungstenite::Error;
        let e = Error::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        );
        assert!(ws_error_recoverable(&e));
    }

    #[test]
    fn detects_graphql_transport_ping_pong() {
        assert_eq!(
            graphql_transport_control_type(r#"{"type":"ping"}"#),
            Some("ping")
        );
        assert_eq!(
            graphql_transport_control_type(r#"{"type":"pong"}"#),
            Some("pong")
        );
        assert_eq!(
            graphql_transport_control_type(r#"{"type":"next","id":"1"}"#),
            None
        );
    }
}

/// Send a GraphQL subscription frame.
pub async fn subscribe(
    ws: &mut IndexerWs,
    sub_id: &str,
    query: &str,
    variables: serde_json::Value,
) -> Result<(), PayError> {
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({
            "id": sub_id,
            "type": "subscribe",
            "payload": { "query": query, "variables": variables }
        })
        .to_string(),
    ))
    .await
    .map_err(transport_err)
}
