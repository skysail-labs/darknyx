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
use std::time::Duration;

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
    /// The slot the tx was processed in. Lets the settle worker
    /// measure block CO-INCLUSION: many settle txs sharing one slot
    /// means the leader batched them → they confirm together (the
    /// throughput lever — see settle::worker concurrent sends).
    pub slot: Option<u64>,
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

/// Solana's `getMultipleAccounts` caps a single request at 100 keys.
pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;

/// The wire shape of one account, shared by `getAccountInfo` and
/// `getMultipleAccounts` so the two cannot decode differently. They previously
/// could not drift because only one existed; now that there are two, one
/// definition is what keeps a batched read byte-identical to the single read it
/// replaces.
#[derive(Deserialize)]
struct RawAccount {
    lamports: u64,
    owner: String,
    data: Vec<String>, // [base64_data, "base64"]
    executable: bool,
    #[serde(rename = "rentEpoch")]
    rent_epoch: u64,
}

fn decode_account(i: RawAccount) -> Result<RpcAccountInfo, RpcError> {
    use base64::Engine as _;
    let data_b64 = i.data.first().cloned().unwrap_or_default();
    let data = base64::engine::general_purpose::STANDARD
        .decode(&data_b64)
        .map_err(|e| RpcError::Schema(format!("account data base64: {e}")))?;
    let owner: Address = i
        .owner
        .parse()
        .map_err(|e| RpcError::Schema(format!("account owner is not a valid address: {e}")))?;
    Ok(RpcAccountInfo {
        lamports: i.lamports,
        owner,
        data,
        executable: i.executable,
        rent_epoch: i.rent_epoch,
    })
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

/// One entry from `getSignaturesForAddress` (returned newest-first).
#[derive(Debug, Clone)]
pub struct RpcSignatureInfo {
    pub signature: String,
    pub slot: u64,
    /// `Some` if the transaction reverted on-chain — its leaves never
    /// landed, so the Merkle sync skips it.
    pub err: Option<Value>,
}

/// One compiled instruction from a fetched transaction (the subset the
/// Merkle sync needs).
#[derive(Debug, Clone)]
pub struct RpcInstruction {
    /// Program that owns the instruction, base58, resolved from the message's
    /// static account keys via `programIdIndex`.
    ///
    /// **Load-bearing, not best-effort.** `merkle::sync::settle_ix_data`
    /// requires it to match the vault; without that, an attacker's instruction
    /// whose data merely starts with the settle discriminator supplies the leaf
    /// VALUES for a forged `TradeSettled` event.
    ///
    /// Reliably populated: Solana sanitizes `program_id_index` against the
    /// **static** account keys, so a program id is never resolved through an
    /// address lookup table — including in the v0 settle transactions, whose
    /// other accounts do come from ALTs. (An earlier comment here claimed the
    /// opposite and was the stated reason the field went unused.) Empty only if
    /// the RPC returns an out-of-range index, which no honest node does and
    /// which fails the vault comparison anyway.
    pub program_id: String,
    /// Instruction data, base58-decoded.
    pub data: Vec<u8>,
}

/// A fetched transaction (the subset the Merkle sync reads): its slot,
/// revert status, the Anchor `Program data:` log lines, and the
/// top-level instructions.
#[derive(Debug, Clone)]
pub struct RpcTransaction {
    pub slot: u64,
    /// `meta.err` — `Some` if the tx reverted (skip its leaves).
    pub err: Option<Value>,
    /// `meta.logMessages` — carries the Anchor event `Program data:`
    /// lines the leaf decoder parses.
    pub log_messages: Vec<String>,
    /// Top-level compiled instructions.
    pub instructions: Vec<RpcInstruction>,
}

/// Sort order for [`SolanaRpcClient::get_transactions_for_address`].
#[derive(Debug, Clone, Copy)]
pub enum TxSortOrder {
    /// Oldest-first (chronological) — leaf indices arrive in append order.
    Asc,
    /// Newest-first.
    Desc,
}

impl TxSortOrder {
    fn as_str(self) -> &'static str {
        match self {
            TxSortOrder::Asc => "asc",
            TxSortOrder::Desc => "desc",
        }
    }
}

/// One FULL transaction from `getTransactionsForAddress` — like
/// [`RpcTransaction`] but carries its own `signature` inline (the address
/// scan returns the whole tx, so no follow-up `getTransaction` is needed).
#[derive(Debug, Clone)]
pub struct RpcAddressTx {
    pub signature: String,
    pub slot: u64,
    /// `meta.err` — `Some` if the tx reverted. (Empty when the call filters
    /// `status: succeeded`, but parsed defensively.)
    pub err: Option<Value>,
    pub log_messages: Vec<String>,
    pub instructions: Vec<RpcInstruction>,
}

/// One page of [`SolanaRpcClient::get_transactions_for_address`].
#[derive(Debug, Clone)]
pub struct AddressTxPage {
    pub txs: Vec<RpcAddressTx>,
    /// Opaque `"slot:position"` cursor for the NEXT page; `None` at the end.
    pub pagination_token: Option<String>,
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
    /// The real endpoint, credential and all. **Never format this** — see
    /// [`Self::endpoint_host`].
    endpoint: String,
    /// Scheme + host (+ port) of `endpoint`, with userinfo, path, query, and
    /// fragment removed. This is the only form that may appear in an error or
    /// a log line.
    endpoint_host: String,
    commitment: Commitment,
    next_id: Arc<AtomicU64>,
}

/// Reduce an RPC URL to `scheme://host[:port]`.
///
/// `DARKNYX_TEE_SOLANA_RPC_URL` carries its credential as a query parameter
/// (`https://devnet.helius-rpc.com/?api-key=<secret>`) because that is Helius'
/// standard auth — we cannot forbid it the way `validate_hermes_endpoint`
/// forbids credentials in the Hermes URL. So the credential-bearing parts are
/// dropped here instead, and only this form is ever formatted.
///
/// Deliberately allowlist-shaped: it rebuilds the string from parsed
/// components rather than trying to strip the secret out of the original. A
/// blocklist ("remove everything after `?`") would keep working right up until
/// a provider moves the key into the path or the userinfo.
///
/// An unparseable URL yields `"<redacted-endpoint>"` rather than the input —
/// failing closed, because a URL we cannot parse is one whose secret we cannot
/// locate.
pub fn redact_endpoint(endpoint: &str) -> String {
    // `reqwest::Url` is the re-exported `url` crate — the same parser
    // `config::validate_hermes_endpoint` uses, and no new dependency.
    match reqwest::Url::parse(endpoint) {
        Ok(u) => match u.host_str() {
            Some(host) => match u.port() {
                Some(port) => format!("{}://{host}:{port}", u.scheme()),
                None => format!("{}://{host}", u.scheme()),
            },
            None => "<redacted-endpoint>".to_string(),
        },
        Err(_) => "<redacted-endpoint>".to_string(),
    }
}

impl SolanaRpcClient {
    /// Construct with the default reqwest client + default
    /// commitment ([`Commitment::Confirmed`]).
    pub fn new(endpoint: impl Into<String>) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            // Reuse the same rustls path darknyx-tee already uses for
            // Hermes — no system OpenSSL inside the CVM.
            .use_rustls_tls()
            // Bound every RPC call so a stuck endpoint can't hang the
            // settle worker indefinitely.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        let endpoint = endpoint.into();
        Ok(Self {
            endpoint_host: redact_endpoint(&endpoint),
            http,
            endpoint,
            commitment: Commitment::default(),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub fn with_commitment(mut self, c: Commitment) -> Self {
        self.commitment = c;
        self
    }

    /// The real endpoint, credential included. For issuing requests only —
    /// **never** put this in an error, a log line, or an API response.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// `scheme://host[:port]` — the only form safe to format. Use this
    /// everywhere the endpoint would otherwise appear in text.
    pub fn endpoint_host(&self) -> &str {
        &self.endpoint_host
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
    /// signed tx bytes. Returns the signature (base58). Runs
    /// preflight (the dev safety net).
    pub async fn send_transaction(&self, tx_b64: &str) -> Result<String, RpcError> {
        self.send_transaction_opts(tx_b64, false).await
    }

    /// `sendTransaction` with an explicit `skip_preflight`. The settle
    /// Tx D rebroadcast loop ([`crate::settle::submit::send_and_confirm_with_rebroadcast`])
    /// validates the tx with preflight on the FIRST send, then re-pushes the
    /// identical (idempotent — the network dedups by signature) signed tx with
    /// `skip_preflight=true` so each resend is a cheap re-broadcast to more
    /// leaders, not a full re-simulation (which also avoids a spurious
    /// preflight failure if the resend hits a leader whose bank fork hasn't yet
    /// processed the per-batch ALT extend).
    pub async fn send_transaction_opts(
        &self,
        tx_b64: &str,
        skip_preflight: bool,
    ) -> Result<String, RpcError> {
        // `preflightCommitment` matches our default.
        //
        // `maxRetries` is intentionally NOT pinned to 0: the big v0
        // settle tx (~1.2 KB, near the cap) is easily dropped on a
        // single broadcast under devnet load — it passes preflight,
        // gets a signature, then never lands (confirmation polls
        // forever as `[None]`). Omitting the field lets the RPC node
        // rebroadcast the tx to successive leaders until its blockhash
        // expires (~150 slots), which is what web3.js's
        // sendAndConfirmTransaction (the SDK settle path) relies on.
        // Resending the same signed tx is idempotent — the network
        // dedups by signature — so this is safe for the smaller init
        // txs too.
        let params = serde_json::json!([
            tx_b64,
            {
                "encoding": "base64",
                "skipPreflight": skip_preflight,
                "preflightCommitment": self.commitment,
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
            #[serde(default)]
            slot: Option<u64>,
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
                        slot: i.slot,
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
        let params = serde_json::json!([
            address.to_string(),
            { "encoding": "base64", "commitment": self.commitment }
        ]);
        let resp: RpcContextValue<Option<RawAccount>> = self.call("getAccountInfo", params).await?;
        resp.value.map(decode_account).transpose()
    }

    /// `getMultipleAccounts` — one round trip for up to
    /// [`MAX_MULTIPLE_ACCOUNTS`] addresses (PF-27).
    ///
    /// The result is positional: element `i` corresponds to `addresses[i]`, and
    /// a missing account is `None` in place, exactly as `get_account_info`
    /// returns `None`. Callers depend on that alignment to map results back to
    /// their inputs, so this returns an error rather than a short vector if the
    /// RPC ever returns a different length — a silently truncated response
    /// would shift every subsequent account onto the wrong address, and for the
    /// recovery loop that means classifying one entry's consumed-state from
    /// another entry's PDA.
    ///
    /// Chunking is the CALLER's job: an over-long request is an error here
    /// rather than a silent split, because a caller that needs more than one
    /// chunk also needs to decide what a partial failure means.
    pub async fn get_multiple_accounts(
        &self,
        addresses: &[Address],
    ) -> Result<Vec<Option<RpcAccountInfo>>, RpcError> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        if addresses.len() > MAX_MULTIPLE_ACCOUNTS {
            return Err(RpcError::Schema(format!(
                "getMultipleAccounts accepts at most {MAX_MULTIPLE_ACCOUNTS} addresses, got {}",
                addresses.len()
            )));
        }
        let keys: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
        let params = serde_json::json!([
            keys,
            { "encoding": "base64", "commitment": self.commitment }
        ]);
        let resp: RpcContextValue<Vec<Option<RawAccount>>> =
            self.call("getMultipleAccounts", params).await?;
        if resp.value.len() != addresses.len() {
            return Err(RpcError::Schema(format!(
                "getMultipleAccounts returned {} entries for {} addresses; \
                 results are positional and cannot be realigned",
                resp.value.len(),
                addresses.len()
            )));
        }
        resp.value
            .into_iter()
            .map(|opt| opt.map(decode_account).transpose())
            .collect()
    }

    /// `getSignaturesForAddress` — transaction signatures touching
    /// `address`, newest-first, up to `limit` (RPC caps at 1000).
    /// `before` pages backward: pass the oldest signature from the
    /// previous page. Used by the Merkle cold-boot sync to walk the
    /// vault program's history; an empty result means the page is
    /// exhausted.
    pub async fn get_signatures_for_address(
        &self,
        address: &Address,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RpcSignatureInfo>, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            signature: String,
            slot: u64,
            #[serde(default)]
            err: Option<Value>,
        }
        let mut cfg = serde_json::Map::new();
        cfg.insert("limit".to_string(), serde_json::json!(limit));
        cfg.insert("commitment".to_string(), serde_json::json!(self.commitment));
        if let Some(b) = before {
            cfg.insert("before".to_string(), serde_json::json!(b));
        }
        let params = serde_json::json!([address.to_string(), Value::Object(cfg)]);
        let rows: Vec<Inner> = self.call("getSignaturesForAddress", params).await?;
        Ok(rows
            .into_iter()
            .map(|r| RpcSignatureInfo {
                signature: r.signature,
                slot: r.slot,
                err: r.err,
            })
            .collect())
    }

    /// `getTransaction` (`encoding=json`, `maxSupportedTransactionVersion=0`
    /// so v0 settle txs decode). Returns `None` when the signature is
    /// unknown / not yet confirmed at the configured commitment. Only
    /// the slot, revert status, log messages, and top-level
    /// instructions are extracted — enough for the Merkle leaf decoder.
    pub async fn get_transaction(
        &self,
        signature: &str,
    ) -> Result<Option<RpcTransaction>, RpcError> {
        #[derive(Deserialize)]
        struct Inner {
            slot: u64,
            #[serde(default)]
            meta: Option<Meta>,
            transaction: Tx,
        }
        #[derive(Deserialize)]
        struct Meta {
            #[serde(rename = "logMessages", default)]
            log_messages: Option<Vec<String>>,
            #[serde(default)]
            err: Option<Value>,
        }
        #[derive(Deserialize)]
        struct Tx {
            message: Msg,
        }
        #[derive(Deserialize)]
        struct Msg {
            #[serde(rename = "accountKeys", default)]
            account_keys: Vec<String>,
            #[serde(default)]
            instructions: Vec<CompiledIx>,
        }
        #[derive(Deserialize)]
        struct CompiledIx {
            #[serde(rename = "programIdIndex")]
            program_id_index: usize,
            data: String, // base58
        }

        let params = serde_json::json!([
            signature,
            {
                "encoding": "json",
                "commitment": self.commitment,
                "maxSupportedTransactionVersion": 0,
            }
        ]);
        let inner: Option<Inner> = self.call("getTransaction", params).await?;
        let Some(inner) = inner else {
            return Ok(None);
        };

        let (log_messages, err) = match inner.meta {
            Some(m) => (m.log_messages.unwrap_or_default(), m.err),
            None => (Vec::new(), None),
        };

        let keys = &inner.transaction.message.account_keys;
        let instructions = inner
            .transaction
            .message
            .instructions
            .into_iter()
            .map(|ci| RpcInstruction {
                // Static keys only; ALT-loaded program ids resolve to "".
                program_id: keys.get(ci.program_id_index).cloned().unwrap_or_default(),
                data: bs58::decode(&ci.data).into_vec().unwrap_or_default(),
            })
            .collect();

        Ok(Some(RpcTransaction {
            slot: inner.slot,
            err,
            log_messages,
            instructions,
        }))
    }

    /// `getTransactionsForAddress` (Helius-exclusive) — returns up to `limit`
    /// **full** transactions touching `address` in ONE call, collapsing the
    /// `getSignaturesForAddress` + per-signature `getTransaction` fan-out the
    /// Merkle sync used to do (1 + N calls). NOTE: Helius caps a
    /// `transactionDetails: full` request at **100** — a larger `limit` is
    /// rejected with `-32603 Invalid limit`, so callers page via
    /// `pagination_token` (see `merkle::sync::GTFA_PAGE_LIMIT`).
    ///
    /// Pinned options: `transactionDetails: full`, `encoding: json`,
    /// `maxSupportedTransactionVersion: 0` (v0 settle txs decode), and
    /// `status: succeeded` (a reverted tx appends no leaves, so we never need
    /// it — and this drops the per-tx err check). `slot_gte` floors the scan at
    /// the cold-boot / last-applied slot; `pagination_token` (the prior page's
    /// `"slot:position"`) continues a multi-page scan.
    ///
    /// `sort_order = Asc` yields oldest-first so leaves arrive in append order.
    ///
    /// NOTE: on **devnet** Helius retains only ~2 weeks of history; this is fine
    /// because the mirror always cold-boots from a recent `from_slot` floor
    /// (the deploy / `reset_merkle_tree` slot), never genesis.
    pub async fn get_transactions_for_address(
        &self,
        address: &Address,
        sort_order: TxSortOrder,
        slot_gte: Option<u64>,
        pagination_token: Option<&str>,
        limit: usize,
    ) -> Result<AddressTxPage, RpcError> {
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            data: Vec<Inner>,
            #[serde(rename = "paginationToken", default)]
            pagination_token: Option<String>,
        }
        #[derive(Deserialize)]
        struct Inner {
            slot: u64,
            #[serde(default)]
            meta: Option<Meta>,
            transaction: Tx,
        }
        #[derive(Deserialize)]
        struct Meta {
            #[serde(rename = "logMessages", default)]
            log_messages: Option<Vec<String>>,
            #[serde(default)]
            err: Option<Value>,
        }
        #[derive(Deserialize)]
        struct Tx {
            #[serde(default)]
            signatures: Vec<String>,
            message: Msg,
        }
        #[derive(Deserialize)]
        struct Msg {
            #[serde(rename = "accountKeys", default)]
            account_keys: Vec<String>,
            #[serde(default)]
            instructions: Vec<CompiledIx>,
        }
        #[derive(Deserialize)]
        struct CompiledIx {
            #[serde(rename = "programIdIndex")]
            program_id_index: usize,
            data: String, // base58
        }

        let mut filters = serde_json::Map::new();
        if let Some(s) = slot_gte {
            filters.insert("slot".to_string(), serde_json::json!({ "gte": s }));
        }
        filters.insert("status".to_string(), serde_json::json!("succeeded"));

        let mut cfg = serde_json::Map::new();
        cfg.insert("transactionDetails".to_string(), serde_json::json!("full"));
        cfg.insert("encoding".to_string(), serde_json::json!("json"));
        cfg.insert(
            "sortOrder".to_string(),
            serde_json::json!(sort_order.as_str()),
        );
        cfg.insert("limit".to_string(), serde_json::json!(limit));
        cfg.insert("commitment".to_string(), serde_json::json!(self.commitment));
        cfg.insert(
            "maxSupportedTransactionVersion".to_string(),
            serde_json::json!(0),
        );
        cfg.insert("filters".to_string(), Value::Object(filters));
        if let Some(tok) = pagination_token {
            cfg.insert("paginationToken".to_string(), serde_json::json!(tok));
        }

        let params = serde_json::json!([address.to_string(), Value::Object(cfg)]);
        let page: Page = self.call("getTransactionsForAddress", params).await?;

        let txs = page
            .data
            .into_iter()
            .map(|inner| {
                let (log_messages, err) = match inner.meta {
                    Some(m) => (m.log_messages.unwrap_or_default(), m.err),
                    None => (Vec::new(), None),
                };
                let keys = &inner.transaction.message.account_keys;
                let instructions = inner
                    .transaction
                    .message
                    .instructions
                    .into_iter()
                    .map(|ci| RpcInstruction {
                        program_id: keys.get(ci.program_id_index).cloned().unwrap_or_default(),
                        data: bs58::decode(&ci.data).into_vec().unwrap_or_default(),
                    })
                    .collect();
                RpcAddressTx {
                    signature: inner
                        .transaction
                        .signatures
                        .into_iter()
                        .next()
                        .unwrap_or_default(),
                    slot: inner.slot,
                    err,
                    log_messages,
                    instructions,
                }
            })
            .collect();

        Ok(AddressTxPage {
            txs,
            pagination_token: page.pagination_token,
        })
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
        // Retry HTTP 429 (rate limited) with exponential backoff. Under the
        // concurrent settle pipeline a burst of RPCs can transiently exceed the
        // provider's rate limit; a settle must not die on a *transient* 429.
        // Non-429 HTTP errors + JSON-RPC errors are NOT retried (they're real).
        // `id`/`body` are reused across attempts — reads are idempotent and tx
        // sends dedup by signature, so re-sending is safe.
        const MAX_429_RETRIES: u32 = 6;
        let mut attempt = 0u32;
        let mut backoff = std::time::Duration::from_millis(200);
        let bytes = loop {
            let resp = self.http.post(&self.endpoint).json(&body).send().await?;
            let status = resp.status();
            let bytes = resp.bytes().await?;
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < MAX_429_RETRIES {
                attempt += 1;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(4));
                continue;
            }
            if !status.is_success() {
                // Host only — `self.endpoint` carries `?api-key=<secret>` and
                // this string reaches a settle job's failure reason (SW-01).
                return Err(RpcError::Schema(format!(
                    "HTTP {status} from {endpoint}: {body}",
                    endpoint = self.endpoint_host,
                    body = preview(&bytes)
                )));
            }
            break bytes;
        };
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
        // A JSON-RPC `"result": null` (e.g. getTransaction for a
        // not-yet-found signature) deserializes `envelope.result` to
        // None. Treat that as `Value::Null` and let the caller's `R`
        // absorb it: for an `Option<T>` return that yields `Ok(None)`
        // (the not-found path get_transaction relies on); for a
        // non-optional `R` it still fails deserialization → Schema, so
        // shape validation for genuinely-malformed responses is kept.
        let result_value = envelope.result.unwrap_or(Value::Null);
        serde_json::from_value(result_value)
            .map_err(|e| RpcError::Schema(format!("rpc {method} result shape: {e}")))
    }
}

fn preview(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= 512 {
        s.into_owned()
    } else {
        // Truncate at a char boundary — slicing `&s[..512]` by raw
        // byte index panics if 512 lands mid-codepoint.
        let end = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 512)
            .last()
            .unwrap_or(0);
        format!("{}…", &s[..end])
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

    // ── SW-01: the RPC URL carries the credential, so it must never be
    //    formatted. These pin the redaction itself; the HTTP-status path that
    //    consumes it is covered by `http_error_reports_host_only`, and the
    //    transport path by `solana_rpc::error`'s test.

    #[test]
    fn redaction_keeps_only_scheme_and_host() {
        // The shape CLAUDE.md §3.2 actually provisions.
        assert_eq!(
            redact_endpoint("https://devnet.helius-rpc.com/?api-key=SUPERSECRET"),
            "https://devnet.helius-rpc.com"
        );
        // No path separator before the query — the shape that defeated the
        // previous hand-rolled `split('/')` redaction in main.rs.
        assert_eq!(
            redact_endpoint("https://devnet.helius-rpc.com?api-key=SUPERSECRET"),
            "https://devnet.helius-rpc.com"
        );
        // Credential in the userinfo instead.
        assert_eq!(
            redact_endpoint("https://user:SUPERSECRET@rpc.example.com/v1"),
            "https://rpc.example.com"
        );
        // Credential in the path.
        assert_eq!(
            redact_endpoint("https://rpc.example.com/SUPERSECRET/rpc"),
            "https://rpc.example.com"
        );
        // A non-default port is diagnostic and carries nothing secret.
        assert_eq!(
            redact_endpoint("http://127.0.0.1:8899/?api-key=SUPERSECRET"),
            "http://127.0.0.1:8899"
        );
    }

    #[test]
    fn redaction_fails_closed_on_an_unparseable_url() {
        // A URL we cannot parse is one whose secret we cannot locate, so we
        // must not echo the input back on the assumption it is harmless.
        for weird in ["not a url at all", "", "://?api-key=SUPERSECRET"] {
            let out = redact_endpoint(weird);
            assert_eq!(out, "<redacted-endpoint>", "input {weird:?}");
            assert!(!out.contains("SUPERSECRET"));
        }
    }

    #[test]
    fn a_constructed_client_exposes_only_the_redacted_host() {
        let c = SolanaRpcClient::new("https://devnet.helius-rpc.com/?api-key=SUPERSECRET").unwrap();
        // The real endpoint is still available for issuing requests…
        assert!(c.endpoint().contains("SUPERSECRET"));
        // …but the form intended for text carries nothing.
        assert_eq!(c.endpoint_host(), "https://devnet.helius-rpc.com");
        assert!(!c.endpoint_host().contains("SUPERSECRET"));
    }

    #[tokio::test]
    async fn http_error_reports_host_only() {
        // A server that answers 503 drives the `!status.is_success()` branch —
        // the exact site SW-01 anchors on.
        use axum::{routing::post, Router};
        let app = Router::new().route(
            "/",
            post(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "upstream down") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = SolanaRpcClient::new(format!("http://{addr}/?api-key=SUPERSECRET")).unwrap();
        let err = client
            .get_latest_blockhash()
            .await
            .expect_err("503 must surface as an error");

        let rendered = format!("{err}");
        assert!(
            !rendered.contains("SUPERSECRET"),
            "the API key must not reach the error string: {rendered}"
        );
        // Still useful to an operator: status + host + body preview.
        assert!(rendered.contains("503"), "status retained: {rendered}");
        assert!(
            rendered.contains(&addr.ip().to_string()),
            "host retained: {rendered}"
        );
    }

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

    /// Env-gated Helius smoke for `getTransactionsForAddress` (Helius-exclusive,
    /// so it needs a Helius URL in `HELIUS_RPC_URL`). Validates the wire format
    /// end-to-end: a full-tx page over the devnet vault program returns txs that
    /// carry their signature, slot, log messages, and instructions inline — no
    /// follow-up `getTransaction`. Skipped without `RUN_DEVNET_RPC_SMOKE=1` +
    /// `HELIUS_RPC_URL`.
    #[tokio::test]
    async fn devnet_get_transactions_for_address_smoke() {
        if std::env::var("RUN_DEVNET_RPC_SMOKE").ok().as_deref() != Some("1") {
            return;
        }
        let Ok(url) = std::env::var("HELIUS_RPC_URL") else {
            return; // gTFA is Helius-only; skip without a Helius endpoint
        };
        let client = SolanaRpcClient::new(&url).unwrap();
        let vault: Address = "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx"
            .parse()
            .unwrap();
        let page = client
            .get_transactions_for_address(&vault, TxSortOrder::Desc, None, None, 10)
            .await
            .expect("gTFA call should succeed against Helius");
        assert!(!page.txs.is_empty(), "vault program has history");
        for tx in &page.txs {
            assert!(!tx.signature.is_empty(), "full tx carries its signature");
            assert!(tx.slot > 0);
            // status:succeeded is filtered server-side.
            assert!(tx.err.is_none());
        }
    }
}

#[cfg(test)]
mod multiple_accounts_tests {
    use super::*;

    /// Serve one canned JSON-RPC response so the REAL `get_multiple_accounts`
    /// path is exercised, guard included.
    async fn serve_once(value: serde_json::Value) -> String {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/",
            post(move || {
                let v = value.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": { "context": { "slot": 1 }, "value": v },
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}/")
    }

    fn addrs(n: usize) -> Vec<Address> {
        // Distinct, valid addresses; the values do not matter, only the count.
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = (i + 1) as u8;
                Address::new_from_array(b)
            })
            .collect()
    }

    /// PF-27 — `getMultipleAccounts` results are POSITIONAL, and every caller
    /// maps them back to inputs by index.
    ///
    /// A short response is therefore not a partial success: it shifts every
    /// subsequent account onto the wrong address. In `recover.rs` that means
    /// classifying one journal entry's consumed-state from another entry's PDA,
    /// which can turn `NeitherConsumed` into `BothConsumed` and authorise — or
    /// suppress — a redrive on evidence about a different match. The client
    /// refuses rather than return a realignable-looking vector.
    #[tokio::test]
    async fn a_short_response_is_an_error_not_a_short_vector() {
        // Two addresses requested, one returned.
        let url = serve_once(serde_json::json!([null])).await;
        let rpc = SolanaRpcClient::new(url).unwrap();
        let err = rpc
            .get_multiple_accounts(&addrs(2))
            .await
            .expect_err("a truncated response must not be accepted");
        assert!(
            format!("{err}").contains("positional"),
            "the error must say why realignment is impossible, got: {err}"
        );
    }

    /// The same guard in the other direction — a response with MORE entries
    /// than requested is equally unmappable.
    #[tokio::test]
    async fn an_overlong_response_is_also_rejected() {
        let url = serve_once(serde_json::json!([null, null, null])).await;
        let rpc = SolanaRpcClient::new(url).unwrap();
        assert!(rpc.get_multiple_accounts(&addrs(2)).await.is_err());
    }

    /// A matching-length response IS accepted, positions intact — without this
    /// the two assertions above could be passing because everything fails.
    #[tokio::test]
    async fn a_matching_response_is_accepted_with_positions_intact() {
        let url = serve_once(serde_json::json!([
            null,
            {
                "lamports": 5u64,
                "owner": "11111111111111111111111111111111",
                "data": ["AQID", "base64"],
                "executable": false,
                "rentEpoch": 0u64,
            }
        ]))
        .await;
        let rpc = SolanaRpcClient::new(url).unwrap();
        let got = rpc.get_multiple_accounts(&addrs(2)).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got[0].is_none(), "absent account stays at index 0");
        assert_eq!(got[1].as_ref().unwrap().data, vec![1, 2, 3]);
    }

    /// Over the RPC's own cap, the client refuses rather than silently
    /// splitting: a caller needing more than one chunk also needs to decide
    /// what a partial failure means, and both call sites do so explicitly.
    #[tokio::test]
    async fn an_oversized_request_is_refused_rather_than_split() {
        let url = serve_once(serde_json::json!([])).await;
        let rpc = SolanaRpcClient::new(url).unwrap();
        let err = rpc
            .get_multiple_accounts(&addrs(MAX_MULTIPLE_ACCOUNTS + 1))
            .await
            .expect_err("over the cap must be an error");
        assert!(format!("{err}").contains("at most"), "got: {err}");
    }

    /// Both read paths must decode identically — a batched read replacing a
    /// single read is only safe if the bytes come out the same.
    #[test]
    fn batch_and_single_decode_the_same_account() {
        let account = serde_json::json!({
            "lamports": 42u64,
            "owner": "11111111111111111111111111111111",
            "data": ["AQID", "base64"],
            "executable": false,
            "rentEpoch": 7u64,
        });
        let one: RawAccount = serde_json::from_value(account.clone()).unwrap();
        let many: Vec<Option<RawAccount>> =
            serde_json::from_value(serde_json::json!([account])).unwrap();

        let a = decode_account(one).unwrap();
        let b = decode_account(many.into_iter().next().unwrap().unwrap()).unwrap();
        assert_eq!(a.lamports, b.lamports);
        assert_eq!(a.owner, b.owner);
        assert_eq!(a.data, b.data, "base64 payload must decode identically");
        assert_eq!(a.data, vec![1, 2, 3]);
        assert_eq!(a.rent_epoch, b.rent_epoch);
    }

    /// An absent account is `None` IN PLACE, not a gap — otherwise positional
    /// mapping breaks precisely when some accounts do not exist, which is the
    /// normal case for consumed-note PDAs before a settle lands.
    #[test]
    fn absent_accounts_hold_their_position() {
        let value: Vec<Option<RawAccount>> = serde_json::from_value(serde_json::json!([
            null,
            {
                "lamports": 1u64,
                "owner": "11111111111111111111111111111111",
                "data": ["", "base64"],
                "executable": false,
                "rentEpoch": 0u64,
            },
            null
        ]))
        .unwrap();
        assert_eq!(value.len(), 3);
        assert!(value[0].is_none(), "absent stays at index 0");
        assert!(value[1].is_some(), "present stays at index 1");
        assert!(value[2].is_none(), "absent stays at index 2");
    }
}
