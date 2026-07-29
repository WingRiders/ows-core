//! Cardano RPC provider abstraction.
//!
//! Cardano needs an RPC provider for three operations: broadcasting a signed
//! transaction, fetching UTxOs for a set of transaction inputs, and fetching an
//! address' token balances. This module defines a provider-agnostic
//! [`CardanoRpcProvider`] trait over those operations and
//! [`resolve_cardano_provider`], which selects the concrete provider from an RPC
//! URL. Provider-specific code lives in the [`koios`] submodule.
//!
//! The trait is synchronous (all call sites are effectively sync — the balance
//! path bridges via `spawn_blocking`) and object-safe, so the resolver can hand
//! back a `Box<dyn CardanoRpcProvider>`.

mod koios;

pub use koios::KoiosProvider;

use crate::TokenBalance;
use std::{collections::BTreeMap, time::Duration};

/// Lovelace-per-ADA exponent (1 ADA = 10^6 lovelace).
const ADA_DECIMALS: u32 = 6;
const REQUESTS_TIMEOUT: Duration = Duration::from_secs(45);

/// Errors returned by a [`CardanoRpcProvider`]. Consumers map these into their
/// own crate-local error types.
#[derive(Debug, thiserror::Error)]
pub enum CardanoRpcError {
    /// Transport-level failure (DNS, TLS, timeout, connection).
    #[error("HTTP error: {0}")]
    Http(String),
    /// The response could not be decoded into the expected shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The provider returned an error status or a semantically invalid response.
    #[error("RPC error: {0}")]
    Rpc(String),
}

/// Cardano RPC operations, independent of the concrete provider (Koios, Blockfrost, …).
pub trait CardanoRpcProvider: Send + Sync {
    /// Submit a signed transaction (CBOR bytes). Returns the transaction hash.
    fn broadcast_tx(&self, tx_cbor: &[u8]) -> Result<String, CardanoRpcError>;

    /// Fetch the CBOR-encoded transactions for a set of transaction hashes.
    /// NOTE: The result can be partial if some transactions are not found.
    fn fetch_txs_cbor(
        &self,
        tx_hashes: &[String],
    ) -> Result<BTreeMap<String, String>, CardanoRpcError>;

    /// Fetch the token balances (ADA + native assets) for an address.
    fn get_balances(&self, address: &str) -> Result<Vec<TokenBalance>, CardanoRpcError>;
}

/// Select a Cardano RPC provider from its URL.
pub fn resolve_cardano_provider(url: &str) -> Result<Box<dyn CardanoRpcProvider>, CardanoRpcError> {
    Ok(Box::new(KoiosProvider::new(url)))
}

/// Shared blocking HTTP client used by the providers.
fn blocking_client() -> Result<reqwest::blocking::Client, CardanoRpcError> {
    reqwest::blocking::Client::builder()
        .timeout(REQUESTS_TIMEOUT)
        .build()
        .map_err(|e| CardanoRpcError::Http(e.to_string()))
}

/// Largest response body a provider will buffer. These endpoints are untrusted — a
/// hostile or broken one could otherwise stream an unbounded body and exhaust memory
/// before a single byte is validated. Legitimate balance / UTxO / broadcast payloads
/// are orders of magnitude smaller.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Read a blocking response body into memory, refusing to buffer more than
/// [`MAX_RESPONSE_BYTES`]. `.text()` and `.json()` read the whole body first, so
/// reading through a capped reader is what enforces the bound.
fn read_capped_body(resp: reqwest::blocking::Response) -> Result<Vec<u8>, CardanoRpcError> {
    use std::io::Read;
    let mut buf = Vec::new();
    // One byte past the cap, so a body sitting exactly at the limit still reads.
    resp.take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CardanoRpcError::Http(format!("reading response: {e}")))?;

    if buf.len() > MAX_RESPONSE_BYTES {
        return Err(CardanoRpcError::Rpc(format!(
            "response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
        )));
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_koios() {
        // Non-blockfrost URL resolves without needing any env var.
        let provider = resolve_cardano_provider("https://api.koios.rest/api/v1").unwrap();
        // Smoke: the boxed provider is usable for the no-op empty utxo case.
        assert_eq!(provider.fetch_txs_cbor(&[]).unwrap(), BTreeMap::new());
    }
}
