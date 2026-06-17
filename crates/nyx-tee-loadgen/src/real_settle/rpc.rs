//! Minimal Solana JSON-RPC client (Increment B2) — just the calls the
//! real-settle flow needs: blockhash, sendTransaction, confirm, the tx logs
//! (NoteCreated), and raw account data (per-shard `leaf_count`).
//!
//! Hand-rolled on reqwest (mirrors `crates/nyx-tee/src/solana_rpc/client.rs`)
//! so the crate avoids the heavy `solana-client`, which conflicts with ark 0.5
//! on zeroize. The request envelope shaping is unit-tested; the live calls are
//! validated on a CVM run.

use base64::Engine;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::RealSettleError;

type R<T> = Result<T, RealSettleError>;

fn rpc_err(e: impl std::fmt::Display) -> RealSettleError {
    RealSettleError::Rpc(e.to_string())
}

/// A thin JSON-RPC 2.0 client over reqwest.
#[derive(Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    endpoint: String,
}

impl RpcClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.into(),
        }
    }

    /// Build the JSON-RPC request body for `method`/`params`. Pure (no I/O) so
    /// the envelope can be asserted in a unit test.
    pub fn request_body(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    /// POST a JSON-RPC call and deserialize `result`.
    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> R<T> {
        let body = Self::request_body(method, params);
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(rpc_err)?;
        let v: Value = resp.json().await.map_err(rpc_err)?;
        if let Some(e) = v.get("error") {
            return Err(RealSettleError::Rpc(format!("{method}: {e}")));
        }
        serde_json::from_value(v.get("result").cloned().unwrap_or(Value::Null))
            .map_err(|e| RealSettleError::Rpc(format!("{method} result decode: {e}")))
    }

    /// `getLatestBlockhash` → the base58 blockhash (confirmed).
    pub async fn latest_blockhash(&self) -> R<String> {
        let v: Value = self
            .call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))
            .await?;
        v.get("value")
            .and_then(|x| x.get("blockhash"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| RealSettleError::Rpc("getLatestBlockhash: no blockhash".into()))
    }

    /// `getSlot` (confirmed).
    pub async fn slot(&self) -> R<u64> {
        self.call("getSlot", json!([{ "commitment": "confirmed" }]))
            .await
    }

    /// `sendTransaction` for an already-base64-encoded signed tx.
    pub async fn send_transaction(&self, tx_b64: &str) -> R<String> {
        self.call(
            "sendTransaction",
            json!([tx_b64, { "encoding": "base64", "skipPreflight": false }]),
        )
        .await
    }

    /// Poll `getSignatureStatuses` until the tx is confirmed (or `tries` exhaust).
    /// Returns `true` if confirmed without error.
    pub async fn confirm(&self, signature: &str, tries: u32) -> R<bool> {
        for _ in 0..tries {
            let v: Value = self
                .call(
                    "getSignatureStatuses",
                    json!([[signature], { "searchTransactionHistory": false }]),
                )
                .await?;
            if let Some(status) = v
                .get("value")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .filter(|s| !s.is_null())
            {
                if status.get("err").map(|e| !e.is_null()).unwrap_or(false) {
                    return Ok(false);
                }
                let conf = status
                    .get("confirmationStatus")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                if conf == "confirmed" || conf == "finalized" {
                    return Ok(true);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
        Ok(false)
    }

    /// `getTransaction` → the tx's `meta.logMessages` (for NoteCreated parsing).
    pub async fn transaction_logs(&self, signature: &str) -> R<Vec<String>> {
        let v: Value = self
            .call(
                "getTransaction",
                json!([
                    signature,
                    { "encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 0 }
                ]),
            )
            .await?;
        Ok(v.get("meta")
            .and_then(|m| m.get("logMessages"))
            .and_then(|l| l.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `getAccountInfo` (base64) → the raw account data, or `None` if absent.
    pub async fn account_data(&self, pubkey_b58: &str) -> R<Option<Vec<u8>>> {
        let v: Value = self
            .call(
                "getAccountInfo",
                json!([pubkey_b58, { "encoding": "base64", "commitment": "confirmed" }]),
            )
            .await?;
        let Some(data) = v
            .get("value")
            .filter(|x| !x.is_null())
            .and_then(|val| val.get("data"))
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.as_str())
        else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| RealSettleError::Rpc(format!("account data b64: {e}")))?;
        Ok(Some(bytes))
    }
}

/// A per-shard `MerkleTree.leaf_count` (u64 @ offset 8, after the Anchor disc).
pub fn parse_leaf_count(account_data: &[u8]) -> R<u64> {
    if account_data.len() < 16 {
        return Err(RealSettleError::Rpc("MerkleTree account too short".into()));
    }
    let mut le = [0u8; 8];
    le.copy_from_slice(&account_data[8..16]);
    Ok(u64::from_le_bytes(le))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_is_jsonrpc_2_0() {
        let b = RpcClient::request_body("getSlot", json!([{ "commitment": "confirmed" }]));
        assert_eq!(b["jsonrpc"], "2.0");
        assert_eq!(b["method"], "getSlot");
        assert_eq!(b["params"][0]["commitment"], "confirmed");
    }

    #[test]
    fn leaf_count_reads_offset_8() {
        let mut data = vec![0u8; 24];
        data[8..16].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(parse_leaf_count(&data).unwrap(), 42);
        assert!(parse_leaf_count(&[0u8; 4]).is_err());
    }
}
