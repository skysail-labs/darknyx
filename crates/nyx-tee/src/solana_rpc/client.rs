//! JSON-RPC 2.0 client over reqwest.
//!
//! All methods follow the same pattern: build a `RpcEnvelope`
//! around the method name + params, POST it as JSON, parse the
//! response envelope, return the `result` field (or surface the
//! `error` field as [`super::error::RpcError::Rpc`]).
//!
//! The client is `Clone`-able cheaply because reqwest::Client is
//! internally `Arc`. Call-sites in 4g.3+ clone it into per-stage
//! worker tasks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use solana_address::Address;

use super::error::RpcError;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Solana commitment levels — passed in `params[].commitment` and
/// in `params[].config.commitment`. Default `Confirmed` is the
/// "fast enough + safe enough" pick for our settle pipeline
/// (Finalized adds ~10–13 s of confirmation time).
#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Commitment {
    Processed,
    #[default]
    Confirmed,
    Finalized,
}

/// Result of `getLatestBlockhash`.
#[derive(Debug, Clone)]
pub struct BlockhashWithSlot {
    /// The blockhash bytes — caller wraps in `solana_hash::Hash`
    /// when constructing a Message.
    pub blockhash: [u8; 32],
    /// Slot the blockhash was reported at. ALT creation uses this
    /// (NOT `getSlot("confirmed")`) — see CRYPTOGRAPHY.md §9.
    pub context_slot: u64,
    /// Last block height the blockhash will be valid for. After
    /// this height the tx must be rebuilt with a fresh blockhash.
    pub last_valid_block_height: u64,
}

/// Subset of `getSignatureStatuses` response fields the settle
/// scheduler cares about. The full Solana response carries more
/// (slot, err detail, confirmation count, confirmation status);
/// we surface only what the scheduler reads.
#[derive(Debug, Clone)]
pub struct RpcSignatureStatus {
    /// `Some(true)` = confirmed at or above the configured
    /// commitment; `Some(false)` = tx landed but at a lower
    /// commitment than we're polling for; `None` = unknown
    /// (still processing or already evicted from the cache).
    pub confirmed_at_commitment: Option<bool>,
    /// `Some` if the tx reverted on-chain (preflight passed,
    /// runtime failed). Carries the raw `InstructionError` JSON
    /// so call-sites can introspect.
    pub err: Option<Value>,
}

/// Result of `getAccountInfo` (truncated to fields we read).
#[derive(Debug, Clone)]
pub struct RpcAccountInfo {
    /// Account lamports.
    pub lamports: u64,
    /// Owner program id.
    pub owner: Address,
    /// Account data, decoded from base64. Empty for non-existent
    /// accounts (`null` `value` in the RPC response is collapsed
    /// to `None` by [`SolanaRpcClient::get_account_info`]).
    pub data: Vec<u8>,
    /// `true` if the account is rent-exempt.
    pub executable: bool,
    pub rent_epoch: u64,
}

/// Result of `simulateTransaction`. We extract a minimal subset —
/// enough to decide "was this tx going to succeed if sent?".
#[derive(Debug, Clone)]
pub struct RpcSimulationResult {
    /// `Some` if simulation failed. Same shape as
    /// `RpcSignatureStatus::err`.
    pub err: Option<Value>,
    /// Program logs emitted during simulation.
    pub logs: Vec<String>,
    /// Compute-unit count consumed. Useful for priority-fee sizing.
    pub units_consumed: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PrioritizationFee {
    pub slot: u64,
    pub prioritization_fee: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire envelopes (internal)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcEnvelope<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

/// Non-generic envelope to sidestep serde derive's generic-bounds
/// dance. The `result` field is captured as a raw `Value`; the
/// generic `call<R>` fn deserialises it into the caller's target
/// type via `serde_json::from_value` after the success/error
/// dispatch. One extra allocation per RPC call, but worth the
/// clarity.
#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcErrorEnvelope>,
}

#[derive(Deserialize)]
struct RpcErrorEnvelope {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Deserialize)]
struct RpcContextValue<V> {
    #[serde(default)]
    context: Option<RpcContext>,
    value: V,
}

#[derive(Deserialize)]
struct RpcContext {
    slot: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Client
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SolanaRpcClient {
    http: reqwest::Client,
    endpoint: String,
    commitment: Commitment,
    next_id: Arc<AtomicU64>,
}

impl SolanaRpcClient {
    /// Construct with the default reqwest client + default
    /// commitment ([`Commitment::Confirmed`]).
    pub fn new(endpoint: impl Into<String>) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            // Reuse the same rustls path nyx-tee already uses for
            // Hermes — no system OpenSSL inside the CVM.
            .use_rustls_tls()
            .build()?;
        Ok(Self {
            http,
            endpoint: endpoint.into(),
            commitment: Commitment::default(),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub fn with_commitment(mut self, c: Commitment) -> Self {
        self.commitment = c;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn commitment(&self) -> Commitment {
        self.commitment
    }

    // ─── The 6 methods ──────────────────────────────────────────

    /// `getLatestBlockhash` — returns the current blockhash + the
    /// slot it was reported at (used by per-batch ALT creation in
    /// 4g.5 — see CRYPTOGRAPHY.md §9 for why we read context.slot,
    /// not `getSlot("confirmed")`).
    pub async fn get_latest_blockhash(&self) -> Result<BlockhashWithSlot, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            blockhash: String,
            #[serde(rename = "lastValidBlockHeight")]
            last_valid_block_height: u64,
        }
        let resp: RpcContextValue<Inner> = self
            .call(
                "getLatestBlockhash",
                serde_json::json!([{ "commitment": self.commitment }]),
            )
            .await?;
        let blockhash = decode_b58_32(&resp.value.blockhash, "blockhash")?;
        let context_slot = resp.context.map(|c| c.slot).ok_or_else(|| {
            RpcError::Schema("getLatestBlockhash response missing context.slot".to_string())
        })?;
        Ok(BlockhashWithSlot {
            blockhash,
            context_slot,
            last_valid_block_height: resp.value.last_valid_block_height,
        })
    }

    /// `sendTransaction` — accepts the already-base64-encoded
    /// signed tx bytes. Returns the signature (base58).
    pub async fn send_transaction(&self, tx_b64: &str) -> Result<String, RpcError> {
        // `skipPreflight=false` keeps the safety net during dev;
        // `preflightCommitment` matches our default. 4g.5 may
        // expose these as options once we know the failure shape
        // we want.
        let params = serde_json::json!([
            tx_b64,
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": self.commitment,
                "maxRetries": 0u32,
            }
        ]);
        let sig: String = self.call("sendTransaction", params).await?;
        Ok(sig)
    }

    /// `getSignatureStatuses` — poll for confirmation. `searchTransactionHistory`
    /// is left at the RPC default (`false`) — Solana keeps the most
    /// recent ~150 slots in its in-memory cache, which is plenty for
    /// the settle pipeline's confirmation window.
    pub async fn get_signature_statuses(
        &self,
        sigs: &[String],
    ) -> Result<Vec<Option<RpcSignatureStatus>>, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            #[serde(rename = "confirmationStatus", default)]
            confirmation_status: Option<String>,
            #[serde(default)]
            err: Option<Value>,
        }
        let params = serde_json::json!([sigs, { "searchTransactionHistory": false }]);
        let raw: RpcContextValue<Vec<Option<Inner>>> =
            self.call("getSignatureStatuses", params).await?;

        let target = self.commitment;
        let out = raw
            .value
            .into_iter()
            .map(|opt| {
                opt.map(|i| {
                    let confirmed_at_commitment = i.confirmation_status.as_deref().map(|s| {
                        // The RPC returns "processed" / "confirmed" /
                        // "finalized". Map to "are we at or above our
                        // configured commitment".
                        let rank = |c: &str| match c {
                            "processed" => 0,
                            "confirmed" => 1,
                            "finalized" => 2,
                            _ => 0,
                        };
                        let want = match target {
                            Commitment::Processed => 0,
                            Commitment::Confirmed => 1,
                            Commitment::Finalized => 2,
                        };
                        rank(s) >= want
                    });
                    RpcSignatureStatus {
                        confirmed_at_commitment,
                        err: i.err,
                    }
                })
            })
            .collect();
        Ok(out)
    }

    /// `getAccountInfo` — base64 encoding, returns `None` if the
    /// account doesn't exist.
    pub async fn get_account_info(
        &self,
        address: &Address,
    ) -> Result<Option<RpcAccountInfo>, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            lamports: u64,
            owner: String,
            data: Vec<String>, // [base64_data, "base64"]
            executable: bool,
            #[serde(rename = "rentEpoch")]
            rent_epoch: u64,
        }
        let params = serde_json::json!([
            address.to_string(),
            { "encoding": "base64", "commitment": self.commitment }
        ]);
        let resp: RpcContextValue<Option<Inner>> = self.call("getAccountInfo", params).await?;
        match resp.value {
            None => Ok(None),
            Some(i) => {
                use base64::Engine as _;
                let data_b64 = i.data.first().cloned().unwrap_or_default();
                let data = base64::engine::general_purpose::STANDARD
                    .decode(&data_b64)
                    .map_err(|e| RpcError::Schema(format!("account data base64: {e}")))?;
                let owner: Address = i.owner.parse().map_err(|e| {
                    RpcError::Schema(format!("account owner is not a valid address: {e}"))
                })?;
                Ok(Some(RpcAccountInfo {
                    lamports: i.lamports,
                    owner,
                    data,
                    executable: i.executable,
                    rent_epoch: i.rent_epoch,
                }))
            }
        }
    }

    /// `simulateTransaction` — pre-flight a signed tx. Used by the
    /// scheduler to surface preflight failures (compute budget,
    /// invalid signer, etc.) before paying for an on-chain send.
    pub async fn simulate_transaction(
        &self,
        tx_b64: &str,
    ) -> Result<RpcSimulationResult, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            #[serde(default)]
            err: Option<Value>,
            #[serde(default)]
            logs: Option<Vec<String>>,
            #[serde(rename = "unitsConsumed", default)]
            units_consumed: Option<u64>,
        }
        let params = serde_json::json!([
            tx_b64,
            {
                "encoding": "base64",
                "commitment": self.commitment,
                // sigVerify=false so we can simulate a partially-
                // signed tx during construction; the scheduler
                // re-simulates with sigVerify=true right before
                // send.
                "sigVerify": false,
                "replaceRecentBlockhash": false,
            }
        ]);
        let resp: RpcContextValue<Inner> = self.call("simulateTransaction", params).await?;
        Ok(RpcSimulationResult {
            err: resp.value.err,
            logs: resp.value.logs.unwrap_or_default(),
            units_consumed: resp.value.units_consumed,
        })
    }

    /// `getRecentPrioritizationFees` — Solana returns the median
    /// priority fee per slot over a recent window. Caller passes
    /// the writable accounts the upcoming tx will touch; the RPC
    /// returns fees for slots where ANY of those accounts were
    /// also written.
    pub async fn get_recent_prioritization_fees(
        &self,
        writable: &[Address],
    ) -> Result<Vec<PrioritizationFee>, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            slot: u64,
            #[serde(rename = "prioritizationFee")]
            prioritization_fee: u64,
        }
        let addresses: Vec<String> = writable.iter().map(|a| a.to_string()).collect();
        let params = serde_json::json!([addresses]);
        let raw: Vec<Inner> = self.call("getRecentPrioritizationFees", params).await?;
        Ok(raw
            .into_iter()
            .map(|i| PrioritizationFee {
                slot: i.slot,
                prioritization_fee: i.prioritization_fee,
            })
            .collect())
    }

    // ─── Generic transport ──────────────────────────────────────

    async fn call<P, R>(&self, method: &str, params: P) -> Result<R, RpcError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = RpcEnvelope {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let resp = self.http.post(&self.endpoint).json(&body).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(RpcError::Schema(format!(
                "HTTP {status} from {endpoint}: {body}",
                endpoint = self.endpoint,
                body = preview(&bytes)
            )));
        }
        let envelope: RpcResponse =
            serde_json::from_slice(&bytes).map_err(|e| RpcError::InvalidJson {
                body_preview: preview(&bytes),
                error: e,
            })?;
        if let Some(err) = envelope.error {
            return Err(RpcError::Rpc {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }
        let result_value = envelope.result.ok_or_else(|| {
            RpcError::Schema(format!(
                "rpc {method} returned neither result nor error: {body}",
                body = preview(&bytes)
            ))
        })?;
        serde_json::from_value(result_value)
            .map_err(|e| RpcError::Schema(format!("rpc {method} result shape: {e}")))
    }
}

fn preview(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= 512 {
        s.into_owned()
    } else {
        format!("{}…", &s[..512])
    }
}

fn decode_b58_32(s: &str, label: &str) -> Result<[u8; 32], RpcError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| RpcError::Schema(format!("{label} not valid base58: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RpcError::Schema(format!("{label} must be 32 bytes; got {}", bytes.len())))?;
    Ok(arr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_serialises_with_required_fields() {
        let env = RpcEnvelope {
            jsonrpc: "2.0",
            id: 42,
            method: "getLatestBlockhash",
            params: serde_json::json!([{"commitment":"confirmed"}]),
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"id\":42"));
        assert!(s.contains("\"method\":\"getLatestBlockhash\""));
    }

    #[test]
    fn rpc_error_response_parses() {
        let raw = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":1}"#;
        let r: RpcResponse = serde_json::from_str(raw).unwrap();
        assert!(r.result.is_none());
        let err = r.error.unwrap();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "Invalid params");
    }

    #[test]
    fn rpc_success_response_parses() {
        let raw = r#"{"jsonrpc":"2.0","result":"yes","id":1}"#;
        let r: RpcResponse = serde_json::from_str(raw).unwrap();
        // result is captured as Value first; call() does the
        // subsequent from_value into the caller's target type.
        assert_eq!(r.result.as_ref().and_then(|v| v.as_str()), Some("yes"));
        assert!(r.error.is_none());
    }

    #[test]
    fn context_value_envelope_parses() {
        let raw =
            r#"{"context":{"slot":1234},"value":{"blockhash":"abc","lastValidBlockHeight":7}}"#;
        #[derive(Deserialize)]
        struct V {
            #[allow(dead_code)]
            blockhash: String,
            #[serde(rename = "lastValidBlockHeight")]
            #[allow(dead_code)]
            last_valid_block_height: u64,
        }
        let r: RpcContextValue<V> = serde_json::from_str(raw).unwrap();
        assert_eq!(r.context.unwrap().slot, 1234);
    }

    #[test]
    fn b58_32_round_trips() {
        let pubkey = [0xABu8; 32];
        let b58 = bs58::encode(pubkey).into_string();
        let back = decode_b58_32(&b58, "test").unwrap();
        assert_eq!(back, pubkey);
    }

    #[test]
    fn b58_32_rejects_wrong_length() {
        let too_short = bs58::encode([0u8; 16]).into_string();
        assert!(decode_b58_32(&too_short, "test").is_err());
    }

    #[test]
    fn commitment_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&Commitment::Processed).unwrap(),
            "\"processed\""
        );
        assert_eq!(
            serde_json::to_string(&Commitment::Confirmed).unwrap(),
            "\"confirmed\""
        );
        assert_eq!(
            serde_json::to_string(&Commitment::Finalized).unwrap(),
            "\"finalized\""
        );
    }

    /// Env-gated devnet smoke test: hit api.devnet.solana.com for
    /// real and assert `getLatestBlockhash` returns sane data.
    /// Skipped without `RUN_DEVNET_RPC_SMOKE=1` so it doesn't
    /// flake CI when devnet is twitchy or the runner is offline.
    #[tokio::test]
    async fn devnet_get_latest_blockhash_smoke() {
        if std::env::var("RUN_DEVNET_RPC_SMOKE").ok().as_deref() != Some("1") {
            return;
        }
        let client = SolanaRpcClient::new("https://api.devnet.solana.com").unwrap();
        let bh = client.get_latest_blockhash().await.unwrap();
        assert_ne!(bh.blockhash, [0u8; 32]);
        assert!(bh.context_slot > 0);
        assert!(bh.last_valid_block_height > bh.context_slot);
    }
}
