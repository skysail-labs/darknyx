//! Real-settle orchestration (Increment B2): drive a REAL crossing pair through
//! the live CVM — mint collateral, deposit a bid + ask note on-chain, prove
//! VALID_INPUT, POST both orders, and watch the on-chain settle land. The
//! loadgen analogue of `packages/sdk/tests/cvm-settle-e2e.test.ts`.
//!
//! Inputs are co-shard (shard 0): a batch's input notes must share a shard
//! (the order carries no tree_id), so a split would fail lock with
//! StaleMerkleRoot — see cvm-multimatch-settle. The settle OUTPUTS still
//! round-robin across the K shards.

use anyhow::{anyhow, Result};
use darkpool_crypto::note::owner_commitment;
use darkpool_crypto::{ephemeral_public, fr_to_be_bytes, nullifier_v2, Fr};
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::OrderCanonical;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use solana_address::Address;
use solana_signer::Signer as _;

use super::flow::{load_keypair, DepositedNote, RealSettleHarness};
use super::rpc::RpcClient;
use super::vault::associated_token_address;
use super::{spl, ValidInputProof};
use crate::auth::{acquire_bearer, fetch_boot_session_id};
use crate::config::RunConfig;
use crate::settlement_benchmark::{fetch_metrics, BenchmarkArtifact, ClientProveSummary};

/// Knobs for one real-settle round (a single crossing pair).
pub struct RealSettleParams {
    pub rpc_url: String,
    pub gateway: String,
    pub circuits_dir: String,
    pub admin_keypair: String,
    pub num_trees: u8,
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub symbol: String,
    pub fee_rate_bps: u16,
    pub price_scale: u64,
    pub oracle_twap: u64,
    pub qty: u64,
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: String,
    // ── load-rig knobs ──
    /// Number of scenario INSTANCES (each a self-crossing order group).
    pub traders: usize,
    /// Weighted scenario mix, e.g. "exact-match:50,merge:20,partial-fill:30".
    pub mix: String,
    /// `partial-fill`: small asks crossing the one big bid.
    pub partial_fill_asks: u8,
    pub client_prove_concurrency: usize,
    pub real_submit_rate: f64,
    pub min_measured_batches: usize,
    pub settle_drain_timeout_secs: u64,
    pub settlement_metrics_poll_ms: u64,
    pub warmup_batches: usize,
    pub benchmark_label: String,
    pub metrics_json: Option<std::path::PathBuf>,
    pub report: Option<std::path::PathBuf>,
}

impl RealSettleParams {
    pub fn from_config(cfg: &RunConfig) -> Result<Self> {
        Ok(Self {
            rpc_url: cfg
                .rpc_url
                .clone()
                .ok_or_else(|| anyhow!("--rpc-url is required for --real-settle"))?,
            gateway: cfg.endpoint.clone(),
            circuits_dir: cfg.circuits_dir.clone(),
            admin_keypair: cfg
                .admin_keypair
                .clone()
                .ok_or_else(|| anyhow!("--admin-keypair is required for --real-settle"))?,
            num_trees: cfg.real_num_trees,
            base_mint: cfg.base_mint_bytes()?,
            quote_mint: cfg.quote_mint_bytes()?,
            symbol: cfg.symbol.clone(),
            fee_rate_bps: cfg.fee_rate_bps,
            price_scale: cfg.price_scale,
            oracle_twap: cfg.oracle_twap,
            qty: cfg.real_qty,
            api_key: cfg.api_key.clone(),
            api_secret: cfg.api_secret.clone(),
            passphrase: cfg.passphrase.clone(),
            traders: cfg.traders,
            mix: cfg.real_mix.clone(),
            partial_fill_asks: cfg.real_partial_fill_asks,
            client_prove_concurrency: cfg.client_prove_concurrency,
            real_submit_rate: cfg.real_submit_rate,
            min_measured_batches: cfg.min_measured_batches,
            settle_drain_timeout_secs: cfg.settle_drain_timeout_secs,
            settlement_metrics_poll_ms: cfg.settlement_metrics_poll_ms,
            warmup_batches: cfg.warmup_batches,
            benchmark_label: cfg.benchmark_label.clone(),
            metrics_json: cfg.metrics_json.clone(),
            report: cfg.report.clone(),
        })
    }
}

fn with_fee(nominal: u64, fee_bps: u16) -> u64 {
    nominal + ((nominal as u128) * fee_bps as u128 / 10_000) as u64
}

fn scaled_quote(base: u64, price: u64, price_scale: u64) -> Result<u64> {
    if price_scale == 0 {
        return Err(anyhow!("price scale is zero"));
    }
    let quote = (base as u128)
        .checked_mul(price as u128)
        .ok_or_else(|| anyhow!("scaled quote product overflow"))?
        / price_scale as u128;
    u64::try_from(quote).map_err(|_| anyhow!("scaled quote exceeds u64"))
}

#[derive(Deserialize)]
struct InstrumentWire {
    tick_size: String,
}

async fn fetch_tick_size(http: &reqwest::Client, gateway: &str, symbol: &str) -> Result<u64> {
    let response = http
        .get(format!(
            "{}/instruments/{symbol}",
            gateway.trim_end_matches('/')
        ))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "instrument preflight for {symbol} returned {status}: {}",
            response
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    let instrument: InstrumentWire = response.json().await?;
    let tick_size = instrument
        .tick_size
        .parse::<u64>()
        .map_err(|e| anyhow!("instrument {symbol} has invalid tick_size: {e}"))?;
    if tick_size == 0 {
        return Err(anyhow!("instrument {symbol} has zero tick_size"));
    }
    Ok(tick_size)
}

fn crossing_prices(oracle_twap: u64, tick_size: u64) -> Result<(u64, u64)> {
    if tick_size == 0 {
        return Err(anyhow!("tick size is zero"));
    }
    let align_down = |price: u64| price - price % tick_size;
    let bid_price = align_down(oracle_twap.saturating_mul(12) / 10);
    let ask_price = align_down(oracle_twap.saturating_mul(8) / 10);
    if ask_price == 0 || bid_price <= ask_price {
        return Err(anyhow!(
            "cannot construct positive crossing prices from oracle_twap={oracle_twap}, tick_size={tick_size}"
        ));
    }
    Ok((bid_price, ask_price))
}

/// A per-run sub-second nonce (ms since epoch) — the salt that makes every
/// run's `order_id`s unique. Sub-second so back-to-back runs don't collide.
fn run_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a unique `order_id`: `[run_nonce (8 LE) | order index (8 LE)]`.
///
/// The settlement ID derivation also binds the two order IDs. Output safety no
/// longer depends on their uniqueness, but unique IDs keep run observability and
/// exact-idempotency semantics unambiguous.
fn salted_order_id(nonce: u64, index: u64) -> [u8; 16] {
    let mut oid = [0u8; 16];
    oid[..8].copy_from_slice(&nonce.to_le_bytes());
    oid[8..16].copy_from_slice(&index.to_le_bytes());
    oid
}

/// A trader's keys for one order.
struct Persona {
    spending_key: Fr,
    owner_blinding: Fr,
    owner_commit: [u8; 32],
    trading: SigningKey,
}

impl Persona {
    fn new(seed: u64) -> Result<Self> {
        let spending_key = Fr::from(seed | 1); // non-zero
        let owner_blinding = Fr::from(seed.wrapping_add(0xfeed));
        let owner_commit = owner_commitment(&spending_key, &owner_blinding)
            .map_err(|e| anyhow!("owner_commitment: {e}"))?;
        let mut tseed = [0u8; 32];
        tseed[..8].copy_from_slice(&seed.to_le_bytes());
        let trading = SigningKey::from_bytes(&tseed);
        Ok(Self {
            spending_key,
            owner_blinding,
            owner_commit,
            trading,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_order_body(
    p: &Persona,
    side: OrderSide,
    order_type: OrderType,
    price_limit: u64,
    note: &DepositedNote,
    proof: &ValidInputProof,
    order_id: [u8; 16],
    qty: u64,
    expiry_slot: u64,
    symbol: &str,
    boot_session_id: [u8; 32],
) -> Result<serde_json::Value> {
    let viewing_pubkey = ephemeral_public(&p.trading.to_bytes());

    let canonical = OrderCanonical {
        symbol: symbol.as_bytes(),
        side,
        order_type,
        amount: qty,
        price_limit,
        min_fill_size: 0,
        expiry_slot,
        order_id,
        note_commitment: note.commitment,
        arrival_nonce: 1,
        viewing_pubkey,
        session_id: boot_session_id,
    };
    let digest = canonical.digest().map_err(|e| anyhow!("digest: {e}"))?;
    let sig = p.trading.sign(&digest);
    let nullifier =
        nullifier_v2(&p.spending_key, &note.inner_hash).map_err(|e| anyhow!("nullifier: {e}"))?;
    Ok(serde_json::json!({
        "symbol": symbol,
        "side": match side { OrderSide::Bid => "bid", OrderSide::Ask => "ask" },
        "order_type": match order_type {
            OrderType::Limit => "limit",
            OrderType::Ioc => "ioc",
            OrderType::Fok => "fok",
        },
        "amount": qty,
        "price_limit": price_limit,
        "min_fill_size": 0u64,
        "expiry_slot": expiry_slot,
        "order_id": hex::encode(order_id),
        "note_commitment": hex::encode(note.commitment),
        "arrival_nonce": 1u64,
        "trading_key": hex::encode(p.trading.verifying_key().to_bytes()),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "viewing_pubkey": hex::encode(viewing_pubkey),
        "session_id": hex::encode(boot_session_id),
        "owner_commitment": hex::encode(p.owner_commit),
        "note_inner_hash": hex::encode(note.inner_hash),
        "nullifier": hex::encode(nullifier),
        "merkle_root": hex::encode(proof.merkle_root),
        "valid_input_proof": hex::encode(proof.proof_bytes),
        "collateral_amount": note.amount,
        // Which shard the input note lives in — lets the CVM route lock_note to
        // the right merkle_tree so a batch's inputs can span shards (cross-shard fix).
        "tree_id": note.tree_id,
    }))
}

/// Run a single real crossing pair end-to-end: mint → deposit → prove → POST →
/// watch settle. Returns the on-chain leaf-count growth.
pub async fn run_real_settle(p: RealSettleParams) -> Result<()> {
    let http = reqwest::Client::new();
    let boot_session_id = fetch_boot_session_id(&http, &p.gateway).await?;
    let tick_size = fetch_tick_size(&http, &p.gateway, &p.symbol).await?;
    let rpc = RpcClient::new(p.rpc_url.clone());
    let mut harness = RealSettleHarness::new(rpc.clone(), &p.circuits_dir, p.num_trees)?;
    let admin = load_keypair(&p.admin_keypair)?;

    let start = harness.leaf_count().await?;
    if start != 0 {
        return Err(anyhow!(
            "tree not empty (leaf_count={start}) — reset + redeploy the CVM first"
        ));
    }

    // Salt persona keys so commitments are fresh each run. Tree reset does not
    // clear deposited/consumed-note replay guards, so an exact commitment
    // replay would collide on a later run. Nanosecond resolution keeps closely
    // spaced runs distinct.
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let buyer = Persona::new(0x40_0000 ^ salt)?;
    let seller = Persona::new(0x80_0000 ^ salt)?;

    let (bid_price, ask_price) = crossing_prices(p.oracle_twap, tick_size)?;
    let buyer_note_amt = with_fee(
        scaled_quote(p.qty, bid_price, p.price_scale)?,
        p.fee_rate_bps,
    );
    let seller_note_amt = with_fee(p.qty, p.fee_rate_bps);
    let base = Address::new_from_array(p.base_mint);
    let quote = Address::new_from_array(p.quote_mint);
    let buyer_quote_ata = associated_token_address(&admin.pubkey(), &quote);
    let seller_base_ata = associated_token_address(&admin.pubkey(), &base);

    tracing::info!(
        qty = p.qty,
        bid_price,
        ask_price,
        buyer_note_amt,
        seller_note_amt,
        "real-settle: minting collateral + depositing a crossing pair"
    );

    // 1. Mint collateral to the admin's ATAs (admin = mint authority + payer).
    harness
        .sign_send_confirm(
            &admin,
            spl::build_create_ata_idempotent_ix(
                &admin.pubkey(),
                &buyer_quote_ata,
                &admin.pubkey(),
                &quote,
            ),
        )
        .await?;
    harness
        .sign_send_confirm(
            &admin,
            spl::build_create_ata_idempotent_ix(
                &admin.pubkey(),
                &seller_base_ata,
                &admin.pubkey(),
                &base,
            ),
        )
        .await?;
    harness
        .sign_send_confirm(
            &admin,
            spl::build_mint_to_ix(&quote, &buyer_quote_ata, &admin.pubkey(), buyer_note_amt),
        )
        .await?;
    harness
        .sign_send_confirm(
            &admin,
            spl::build_mint_to_ix(&base, &seller_base_ata, &admin.pubkey(), seller_note_amt),
        )
        .await?;

    // 2. Deposit both notes into shard 0 (co-shard inputs).
    let buyer_recovery_nonce = fr_to_be_bytes(&Fr::from(salt ^ 0xB));
    let seller_recovery_nonce = fr_to_be_bytes(&Fr::from(salt ^ 0x5));
    let buyer_note = harness
        .deposit(
            &admin,
            p.quote_mint,
            &buyer_quote_ata,
            buyer_note_amt,
            &buyer.spending_key,
            &buyer.owner_blinding,
            &buyer_recovery_nonce,
            0,
        )
        .await?;
    let seller_note = harness
        .deposit(
            &admin,
            p.base_mint,
            &seller_base_ata,
            seller_note_amt,
            &seller.spending_key,
            &seller.owner_blinding,
            &seller_recovery_nonce,
            0,
        )
        .await?;
    tracing::info!(
        deposit_leaf_count = harness.leaf_count().await?,
        "deposited buyer + seller notes"
    );

    // 3. Prove VALID_INPUT for both.
    let buyer_proof = harness.prove(&buyer.spending_key, &buyer.owner_blinding, &buyer_note)?;
    let seller_proof = harness.prove(&seller.spending_key, &seller.owner_blinding, &seller_note)?;

    // 4. Build + sign both orders. Salt the order_ids per run (see
    // `salted_order_id`) for clear idempotency and settlement observability.
    // Within MAX_LOCK_TTL_SLOTS (4_500 ≈ 30 min; F-05) so intake accepts it.
    let expiry_slot = rpc.slot().await? + 3_000;
    let pair_nonce = run_nonce();
    let buyer_order = build_order_body(
        &buyer,
        OrderSide::Bid,
        OrderType::Limit,
        bid_price,
        &buyer_note,
        &buyer_proof,
        salted_order_id(pair_nonce, 0),
        p.qty,
        expiry_slot,
        &p.symbol,
        boot_session_id,
    )?;
    let seller_order = build_order_body(
        &seller,
        OrderSide::Ask,
        OrderType::Limit,
        ask_price,
        &seller_note,
        &seller_proof,
        salted_order_id(pair_nonce, 1),
        p.qty,
        expiry_slot,
        &p.symbol,
        boot_session_id,
    )?;

    // 5. Auth + submit both.
    let token = acquire_bearer(&http, &p.gateway, &p.api_key, &p.api_secret, &p.passphrase)
        .await
        .map_err(|e| anyhow!("auth: {e}"))?;
    for (name, body) in [("buyer", &buyer_order), ("seller", &seller_order)] {
        let r = http
            .post(format!("{}/orders", p.gateway))
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;
        let status = r.status();
        if !status.is_success() {
            return Err(anyhow!(
                "{name} order rejected ({status}): {}",
                r.text().await.unwrap_or_default()
            ));
        }
        tracing::info!(%name, "order accepted");
    }

    // 6. Watch the settle land (leaf_count grows by ≥ 2).
    let before = harness.leaf_count().await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut final_count = before;
    while std::time::Instant::now() < deadline {
        final_count = harness.leaf_count().await?;
        if final_count >= before + 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    if final_count < before + 2 {
        return Err(anyhow!(
            "settle did not land — leaf_count {before} → {final_count} (check `phala cvms logs`)"
        ));
    }
    tracing::info!(
        before,
        final_count,
        "real-settle SUCCESS — on-chain settle landed"
    );
    Ok(())
}

// ─── Multi-trader, multi-scenario load rig (B1+B2+B4) ────────────────────────

use std::sync::Arc;
use std::time::Instant;

use super::{MergeInput, MergeProver};

/// Order-shape scenarios the load rig drives through the live CVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealScenario {
    /// 1 bid + 1 ask, equal qty — baseline full-fill settle.
    ExactMatch,
    /// Bid note larger than required (surplus → change note).
    OverCollateral,
    /// 1 big bid + M small asks → M fills over M batches.
    PartialFill,
    /// Deposit 2 sub-threshold notes → VALID_MERGE → ask off the merged note.
    Merge,
    /// Crossing pair with IOC (bid) / FOK (ask) execution policy.
    IocFok,
}

impl RealScenario {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "exact-match" => Self::ExactMatch,
            "over-collateral" => Self::OverCollateral,
            "partial-fill" => Self::PartialFill,
            "merge" => Self::Merge,
            "ioc-fok" => Self::IocFok,
            _ => return None,
        })
    }
}

/// Parse `"exact-match:50,merge:20"` → weighted scenarios.
fn parse_mix(s: &str) -> Result<Vec<(RealScenario, u32)>> {
    let mut out = Vec::new();
    for part in s.split(',').filter(|p| !p.trim().is_empty()) {
        let (name, w) = part
            .split_once(':')
            .ok_or_else(|| anyhow!("--real-mix entry '{part}' must be name:weight"))?;
        let scenario = RealScenario::parse(name.trim())
            .ok_or_else(|| anyhow!("--real-mix: unknown scenario '{name}'"))?;
        let weight: u32 = w
            .trim()
            .parse()
            .map_err(|_| anyhow!("--real-mix bad weight '{w}'"))?;
        out.push((scenario, weight));
    }
    if out.is_empty() {
        anyhow::bail!("--real-mix is empty");
    }
    Ok(out)
}

/// Deterministic weighted pick for instance `i` of `n`. Spreads the `n`
/// instances PROPORTIONALLY across the weighted buckets (`pos = i*total/n`), so
/// every scenario is represented even at small `n` (a plain `i % total` would
/// cluster the first instances on the first bucket when weights are large).
fn pick_scenario(mix: &[(RealScenario, u32)], i: usize, n: usize) -> RealScenario {
    let total: u64 = mix.iter().map(|(_, w)| *w as u64).sum::<u64>().max(1);
    let pos = (i as u64 * total) / (n.max(1) as u64);
    let mut acc = 0u64;
    for (s, w) in mix {
        acc += *w as u64;
        if pos < acc {
            return *s;
        }
    }
    mix[0].0
}

const ON_CHAIN_ROOT_HISTORY_SIZE: u64 = 64;

fn planned_matches(mix: &[(RealScenario, u32)], traders: usize, partial_fill_asks: u8) -> u64 {
    (0..traders)
        .map(|instance| match pick_scenario(mix, instance, traders) {
            RealScenario::PartialFill => partial_fill_asks.max(1) as u64,
            _ => 1,
        })
        .sum()
}

fn validate_root_history_budget(expected_matches: u64, num_trees: u8) -> Result<()> {
    let shards = num_trees.max(1) as u64;
    let max_root_updates_per_shard = expected_matches.div_ceil(shards);
    if max_root_updates_per_shard > ON_CHAIN_ROOT_HISTORY_SIZE {
        return Err(anyhow!(
            "benchmark would stale placement-time VALID_INPUT roots: {expected_matches} matches across {shards} shard(s) can append {max_root_updates_per_shard} roots per shard, exceeding ROOT_HISTORY_SIZE={ON_CHAIN_ROOT_HISTORY_SIZE}; increase --real-num-trees or reduce the workload"
        ));
    }
    Ok(())
}

/// One order, post-setup: ready to prove + submit.
struct LiveOrder {
    persona: Persona,
    side: OrderSide,
    order_type: OrderType,
    price: u64,
    qty: u64,
    note: DepositedNote,
}

#[derive(Debug, Default)]
struct SubmitResult {
    status: u16,
    attempts: u64,
    rate_limited_retries: u64,
    transient_retries: u64,
    rejection: Option<String>,
}

/// Submit an idempotent signed order, respecting the production per-account
/// limiter. Retrying the exact body is safe because the canonical order id and
/// signature are unchanged and intake resolves exact idempotency before nonce
/// monotonicity.
async fn submit_order_reliably(
    http: reqwest::Client,
    url: String,
    token: String,
    body: serde_json::Value,
) -> SubmitResult {
    const MAX_ATTEMPTS: u32 = 20;
    let mut result = SubmitResult::default();
    for attempt in 0..MAX_ATTEMPTS {
        result.attempts += 1;
        match http.post(&url).bearer_auth(&token).json(&body).send().await {
            Ok(response) if response.status().is_success() => {
                result.status = response.status().as_u16();
                return result;
            }
            Ok(response) if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                result.rate_limited_retries += 1;
                if attempt + 1 == MAX_ATTEMPTS {
                    result.status = response.status().as_u16();
                    result.rejection = Some(
                        response
                            .text()
                            .await
                            .unwrap_or_default()
                            .chars()
                            .take(300)
                            .collect(),
                    );
                    return result;
                }
                let retry_secs = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(1)
                    .clamp(1, 5);
                tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
            }
            Ok(response) if response.status().is_server_error() => {
                result.transient_retries += 1;
                if attempt + 1 == MAX_ATTEMPTS {
                    result.status = response.status().as_u16();
                    result.rejection = Some(
                        response
                            .text()
                            .await
                            .unwrap_or_default()
                            .chars()
                            .take(300)
                            .collect(),
                    );
                    return result;
                }
                let backoff_ms = 100u64.saturating_mul(1u64 << attempt.min(4)).min(2_000);
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }
            Ok(response) => {
                result.status = response.status().as_u16();
                result.rejection = Some(
                    response
                        .text()
                        .await
                        .unwrap_or_default()
                        .chars()
                        .take(300)
                        .collect(),
                );
                return result;
            }
            Err(_) => {
                result.transient_retries += 1;
                if attempt + 1 == MAX_ATTEMPTS {
                    return result;
                }
                let backoff_ms = 100u64.saturating_mul(1u64 << attempt.min(4)).min(2_000);
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }
        }
    }
    result
}

/// Run the multi-trader, multi-scenario load rig: N scenario instances → mint +
/// deposit (+merge) all notes → prove all VALID_INPUT (concurrent) → submit all
/// (concurrent) → drain the settle. Reports client prove-rate + end-to-end
/// settled-matches/sec — the prover-bottleneck evidence.
pub async fn run_real_settle_load(p: RealSettleParams) -> Result<()> {
    let http = reqwest::Client::new();
    let boot_session_id = fetch_boot_session_id(&http, &p.gateway).await?;
    let tick_size = fetch_tick_size(&http, &p.gateway, &p.symbol).await?;
    let mix = parse_mix(&p.mix)?;
    let expected_matches = planned_matches(&mix, p.traders, p.partial_fill_asks);
    validate_root_history_budget(expected_matches, p.num_trees)?;
    let needs_merge = mix.iter().any(|(s, _)| *s == RealScenario::Merge);
    let rpc = RpcClient::new(p.rpc_url.clone());
    let mut harness = RealSettleHarness::new(rpc.clone(), &p.circuits_dir, p.num_trees)?;
    let merge_prover = if needs_merge {
        Some(MergeProver::load(&p.circuits_dir, 2)?)
    } else {
        None
    };
    let admin = load_keypair(&p.admin_keypair)?;

    if harness.leaf_count().await? != 0 {
        return Err(anyhow!("tree not empty — reset + redeploy the CVM first"));
    }

    // Nanosecond resolution so two runs started within the same second get
    // distinct salts (as_secs() collided → nullifier-PDA replay on re-run).
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let (bid_price, ask_price) = crossing_prices(p.oracle_twap, tick_size)?;
    let base = Address::new_from_array(p.base_mint);
    let quote = Address::new_from_array(p.quote_mint);
    let base_ata = associated_token_address(&admin.pubkey(), &base);
    let quote_ata = associated_token_address(&admin.pubkey(), &quote);
    let k = p.num_trees.max(1);

    // Create the admin's collateral ATAs once.
    harness
        .sign_send_confirm(
            &admin,
            spl::build_create_ata_idempotent_ix(
                &admin.pubkey(),
                &quote_ata,
                &admin.pubkey(),
                &quote,
            ),
        )
        .await?;
    harness
        .sign_send_confirm(
            &admin,
            spl::build_create_ata_idempotent_ix(&admin.pubkey(), &base_ata, &admin.pubkey(), &base),
        )
        .await?;

    // ── Phase 1: plan + deposit (sequential; shards round-robined) ──
    let mut orders: Vec<LiveOrder> = Vec::new();
    let mut g: usize = 0; // global note index → shard

    tracing::info!(traders = p.traders, mix = %p.mix, "real-settle LOAD: planning + depositing");
    for inst in 0..p.traders {
        let scenario = pick_scenario(&mix, inst, p.traders);
        // Per-instance, per-side fresh personas (salted → fresh nullifiers).
        //
        // DISJOINT BIT FIELDS are load-bearing. Each note's seed is
        // `seed_base ^ tag`, where `tag` is a small per-order constant
        // (`0x1` bid, `0x2`/merge, `0x10+j` partial-fill asks, and the merge
        // inner-hash tags up to `0x3900`). The old `(salt<<20) ^ (inst<<4)`
        // let `inst<<4` (bits 4-11) overlap the tag bits, so e.g. inst=0 ask
        // j=1 (`S^0x11`) collided with inst=1 bid (`(S^0x10)^0x1 = S^0x11`).
        // Keep salt / instance / tag in non-overlapping fields so recovery
        // derivations and exact note commitments remain unique: tag in bits
        // 0-15 (≤ 0x3900), instance in bits 16-31, salt above.
        let seed_base = ((salt & 0xFFFF_FFFF) << 32) ^ ((inst as u64) << 16);

        // Helper to mint + deposit one note, returning (persona, note).
        macro_rules! mint_deposit {
            ($side:expr, $mint:expr, $ata:expr, $amount:expr, $seed:expr) => {{
                let persona = Persona::new($seed)?;
                let shard = (g % k as usize) as u8;
                g += 1;
                let recovery_nonce = fr_to_be_bytes(&Fr::from($seed ^ 0xA5A5));
                harness
                    .sign_send_confirm(
                        &admin,
                        spl::build_mint_to_ix(
                            &Address::new_from_array($mint),
                            &$ata,
                            &admin.pubkey(),
                            $amount,
                        ),
                    )
                    .await?;
                let note = harness
                    .deposit(
                        &admin,
                        $mint,
                        &$ata,
                        $amount,
                        &persona.spending_key,
                        &persona.owner_blinding,
                        &recovery_nonce,
                        shard,
                    )
                    .await?;
                if g % 16 == 0 {
                    tracing::info!(
                        deposited_notes = g,
                        num_trees = k,
                        "real-settle deposit progress"
                    );
                }
                (persona, note)
            }};
        }

        match scenario {
            RealScenario::ExactMatch | RealScenario::IocFok | RealScenario::OverCollateral => {
                let (bid_ot, ask_ot) = if scenario == RealScenario::IocFok {
                    (OrderType::Ioc, OrderType::Fok)
                } else {
                    (OrderType::Limit, OrderType::Limit)
                };
                let bid_nominal = scaled_quote(p.qty, bid_price, p.price_scale)?;
                let surplus = if scenario == RealScenario::OverCollateral {
                    with_fee(bid_nominal, p.fee_rate_bps) / 5
                // +20%
                } else {
                    0
                };
                let bid_amt = with_fee(bid_nominal, p.fee_rate_bps) + surplus;
                let ask_amt = with_fee(p.qty, p.fee_rate_bps);
                let (bp, bn) = mint_deposit!(
                    OrderSide::Bid,
                    p.quote_mint,
                    quote_ata,
                    bid_amt,
                    seed_base ^ 0x1
                );
                let (sp, sn) = mint_deposit!(
                    OrderSide::Ask,
                    p.base_mint,
                    base_ata,
                    ask_amt,
                    seed_base ^ 0x2
                );
                orders.push(LiveOrder {
                    persona: bp,
                    side: OrderSide::Bid,
                    order_type: bid_ot,
                    price: bid_price,
                    qty: p.qty,
                    note: bn,
                });
                orders.push(LiveOrder {
                    persona: sp,
                    side: OrderSide::Ask,
                    order_type: ask_ot,
                    price: ask_price,
                    qty: p.qty,
                    note: sn,
                });
            }
            RealScenario::PartialFill => {
                // One big bid (M×qty) + M small asks (qty each) → M batches.
                let m = p.partial_fill_asks.max(1) as u64;
                let big_qty = p.qty.saturating_mul(m);
                let bid_amt = with_fee(
                    scaled_quote(big_qty, bid_price, p.price_scale)?,
                    p.fee_rate_bps,
                );
                let (bp, bn) = mint_deposit!(
                    OrderSide::Bid,
                    p.quote_mint,
                    quote_ata,
                    bid_amt,
                    seed_base ^ 0x1
                );
                orders.push(LiveOrder {
                    persona: bp,
                    side: OrderSide::Bid,
                    order_type: OrderType::Limit,
                    price: bid_price,
                    qty: big_qty,
                    note: bn,
                });
                for j in 0..m {
                    let ask_amt = with_fee(p.qty, p.fee_rate_bps);
                    let (sp, sn) = mint_deposit!(
                        OrderSide::Ask,
                        p.base_mint,
                        base_ata,
                        ask_amt,
                        seed_base ^ (0x10 + j)
                    );
                    orders.push(LiveOrder {
                        persona: sp,
                        side: OrderSide::Ask,
                        order_type: OrderType::Limit,
                        price: ask_price,
                        qty: p.qty,
                        note: sn,
                    });
                }
            }
            RealScenario::Merge => {
                // Bid (normal) + ask whose note is the MERGE of two sub-threshold notes.
                let bid_amt = with_fee(
                    scaled_quote(p.qty, bid_price, p.price_scale)?,
                    p.fee_rate_bps,
                );
                let (bp, bn) = mint_deposit!(
                    OrderSide::Bid,
                    p.quote_mint,
                    quote_ata,
                    bid_amt,
                    seed_base ^ 0x1
                );
                orders.push(LiveOrder {
                    persona: bp,
                    side: OrderSide::Bid,
                    order_type: OrderType::Limit,
                    price: bid_price,
                    qty: p.qty,
                    note: bn,
                });

                // Seller deposits 2 base notes → merge → 1 note of withFee(qty).
                let sp = Persona::new(seed_base ^ 0x2)?;
                let shard = (g % k as usize) as u8;
                g += 1;
                let merged_amt = with_fee(p.qty, p.fee_rate_bps);
                let a1 = merged_amt / 2;
                let a0 = merged_amt - a1;
                // Distinct high-bit XORs (NOT 0x30/0x31 — they differ only in
                // bit0, which a `|1` would clobber, making both inner_hashes —
                // and thus both nullifiers — equal → merge NoteAlreadyConsumed).
                let nonce0 = fr_to_be_bytes(&Fr::from(seed_base ^ 0x1300));
                let nonce1 = fr_to_be_bytes(&Fr::from(seed_base ^ 0x2500));
                harness
                    .sign_send_confirm(
                        &admin,
                        spl::build_mint_to_ix(&base, &base_ata, &admin.pubkey(), a0 + a1),
                    )
                    .await?;
                let n0 = harness
                    .deposit(
                        &admin,
                        p.base_mint,
                        &base_ata,
                        a0,
                        &sp.spending_key,
                        &sp.owner_blinding,
                        &nonce0,
                        shard,
                    )
                    .await?;
                let n1 = harness
                    .deposit(
                        &admin,
                        p.base_mint,
                        &base_ata,
                        a1,
                        &sp.spending_key,
                        &sp.owner_blinding,
                        &nonce1,
                        shard,
                    )
                    .await?;
                let ih0 = n0.inner_hash;
                let ih1 = n1.inner_hash;
                // Merge-prove + submit the merge ix.
                let mp = merge_prover
                    .as_ref()
                    .ok_or_else(|| anyhow!("merge prover not loaded"))?;
                let w0 = harness.shadow_witness(shard, n0.leaf_index)?;
                let w1 = harness.shadow_witness(shard, n1.leaf_index)?;
                let mproof = mp
                    .prove(
                        &sp.spending_key,
                        &sp.owner_blinding,
                        &p.base_mint,
                        &[
                            MergeInput {
                                amount: a0,
                                inner_hash: ih0,
                                witness: w0.clone(),
                            },
                            MergeInput {
                                amount: a1,
                                inner_hash: ih1,
                                witness: w1,
                            },
                        ],
                    )
                    .map_err(|e| anyhow!("merge prove: {e}"))?;
                let merge_ix = super::vault::build_merge_ix(
                    shard,
                    &admin.pubkey(),
                    &mproof.input_use_tags,
                    &mproof.output_commitment,
                    &base,
                    &w0.root,
                    2,
                    &mproof.proof_bytes,
                );
                let msig = harness.sign_send_confirm(&admin, merge_ix).await?;
                let (mtree, mleaf) = harness.note_merged(&msig).await?;
                harness.append_shadow(mtree, mproof.output_commitment);
                let merged_note = DepositedNote {
                    mint: p.base_mint,
                    amount: mproof.output_amount,
                    inner_hash: mproof.output_inner_hash,
                    commitment: mproof.output_commitment,
                    tree_id: mtree,
                    leaf_index: mleaf,
                };
                orders.push(LiveOrder {
                    persona: sp,
                    side: OrderSide::Ask,
                    order_type: OrderType::Limit,
                    price: ask_price,
                    qty: p.qty,
                    note: merged_note,
                });
            }
        }
    }
    let deposit_leaves = harness.leaf_count().await?;
    tracing::info!(
        orders = orders.len(),
        deposit_leaves,
        "deposited all notes; proving"
    );

    // Preload the bid side before offering asks. For the throughput fixture this
    // avoids arrival-order underpacking: every later ask sees the full set of
    // persistent partial-fill bids, so steady-state pages can fill N=16.
    orders.sort_by_key(|order| match order.side {
        OrderSide::Bid => 0u8,
        OrderSide::Ask => 1u8,
    });

    // ── Phase 2: prove all VALID_INPUT concurrently (client prover load) ──
    let harness = Arc::new(harness);
    let prove_start = Instant::now();
    let mut proofs = Vec::with_capacity(orders.len());
    let mut prove_us: Vec<u64> = Vec::with_capacity(orders.len());
    // Bound the actual number of spawn_blocking jobs. Native witnesses and
    // ark-groth16 proofs are CPU/memory-heavy.
    for order_chunk in orders.chunks(p.client_prove_concurrency) {
        let mut prove_handles = Vec::with_capacity(order_chunk.len());
        for order in order_chunk {
            let h = harness.clone();
            let (sk, ob, note) = (
                order.persona.spending_key,
                order.persona.owner_blinding,
                order.note.clone(),
            );
            prove_handles.push(tokio::task::spawn_blocking(move || {
                let t = Instant::now();
                let proof = h.prove(&sk, &ob, &note);
                (proof, t.elapsed().as_micros() as u64)
            }));
        }
        for handle in prove_handles {
            let (proof, us) = handle.await.map_err(|e| anyhow!("prove task: {e}"))?;
            proofs.push(proof.map_err(|e| anyhow!("VALID_INPUT prove: {e}"))?);
            prove_us.push(us);
        }
    }
    let prove_wall = prove_start.elapsed();
    prove_us.sort_unstable();
    let pct = |v: &[u64], q: f64| {
        v.get(((v.len() as f64 * q) as usize).min(v.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    tracing::info!(
        proofs = proofs.len(),
        wall_s = prove_wall.as_secs_f64(),
        per_sec = proofs.len() as f64 / prove_wall.as_secs_f64().max(1e-9),
        p50_ms = pct(&prove_us, 0.50) as f64 / 1000.0,
        p95_ms = pct(&prove_us, 0.95) as f64 / 1000.0,
        "CLIENT VALID_INPUT prove rate"
    );

    // ── Phase 3: submit all orders concurrently ──
    let token = acquire_bearer(&http, &p.gateway, &p.api_key, &p.api_secret, &p.passphrase)
        .await
        .map_err(|e| anyhow!("auth: {e}"))?;
    let baseline_metrics = fetch_metrics(&http, &p.gateway, &token, None)
        .await
        .map_err(|e| anyhow!("settlement metrics preflight: {e}"))?;
    // Within MAX_LOCK_TTL_SLOTS (4_500 ≈ 30 min; F-05) so intake accepts it.
    let expiry_slot = rpc.slot().await? + 3_000;
    let submit_nonce = run_nonce();
    let mut bodies = Vec::with_capacity(orders.len());
    for (i, o) in orders.iter().enumerate() {
        let oid = salted_order_id(submit_nonce, i as u64);
        bodies.push(build_order_body(
            &o.persona,
            o.side,
            o.order_type,
            o.price,
            &o.note,
            &proofs[i],
            oid,
            o.qty,
            expiry_slot,
            &p.symbol,
            boot_session_id,
        )?);
    }
    let submit_start = Instant::now();
    let submitted_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let n_orders = bodies.len();
    let mut submit_handles = Vec::with_capacity(n_orders);
    let submit_interval =
        std::time::Duration::from_secs_f64(1.0 / p.real_submit_rate.max(f64::MIN_POSITIVE));
    for (index, body) in bodies.into_iter().enumerate() {
        let http = http.clone();
        let token = token.clone();
        let url = format!("{}/orders", p.gateway);
        submit_handles.push(tokio::spawn(async move {
            submit_order_reliably(http, url, token, body).await
        }));
        if index + 1 < n_orders {
            tokio::time::sleep(submit_interval).await;
        }
    }
    let mut accepted = 0usize;
    let mut submission_attempts = 0u64;
    let mut rate_limited_retries = 0u64;
    let mut transient_retries = 0u64;
    let mut first_rejection = None;
    for handle in submit_handles {
        let result = handle.await.unwrap_or_default();
        submission_attempts += result.attempts;
        rate_limited_retries += result.rate_limited_retries;
        transient_retries += result.transient_retries;
        if (200..300).contains(&result.status) {
            accepted += 1;
        } else if first_rejection.is_none() {
            first_rejection = Some(format!(
                "HTTP {}: {}",
                result.status,
                result.rejection.unwrap_or_default()
            ));
        }
    }
    tracing::info!(
        submitted = n_orders,
        accepted,
        submission_attempts,
        rate_limited_retries,
        transient_retries,
        target_rate = p.real_submit_rate,
        ms = submit_start.elapsed().as_millis() as u64,
        "orders submitted"
    );
    if accepted != n_orders {
        return Err(anyhow!(
            "benchmark invalid: only {accepted}/{n_orders} orders accepted; first rejection: {}",
            first_rejection.unwrap_or_else(|| "transport failure without response".to_string())
        ));
    }
    let submission_completed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(submitted_at_ms);

    // ── Phase 4: drain using terminal settlement records ────────
    // One ask contributes one match in every supported real-load scenario.
    // Unlike leaf-count deltas this remains correct when a match emits change
    // and/or fee notes.
    let assembled_expected_matches = orders
        .iter()
        .filter(|order| order.side == OrderSide::Ask)
        .count() as u64;
    debug_assert_eq!(assembled_expected_matches, expected_matches);
    let drain_start = Instant::now();
    let deadline = Instant::now() + std::time::Duration::from_secs(p.settle_drain_timeout_secs);
    let mut cursor = baseline_metrics.latest_seq;
    let mut batches = Vec::new();
    let mut last_progress = 0u64;
    while Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(
            p.settlement_metrics_poll_ms,
        ))
        .await;
        let snapshot = fetch_metrics(&http, &p.gateway, &token, Some(cursor)).await?;
        cursor = snapshot.latest_seq.max(cursor);
        batches.extend(snapshot.recent_batches);
        let observed: u64 = batches
            .iter()
            .map(|batch| {
                batch.outcomes.confirmed + batch.outcomes.rejected + batch.outcomes.ambiguous
            })
            .sum();
        if observed > last_progress {
            tracing::info!(
                observed_matches = observed,
                expected_matches,
                queue_depth = snapshot.queue.depth,
                "settlement metrics progress"
            );
            last_progress = observed;
        }
        if observed >= expected_matches && snapshot.queue.depth == 0 {
            break;
        }
    }
    let final_count = harness.leaf_count().await?;
    batches.sort_by_key(|batch| batch.seq);
    batches.dedup_by_key(|batch| batch.seq);
    let settled_matches: u64 = batches.iter().map(|batch| batch.outcomes.confirmed).sum();
    let observed_matches: u64 = batches
        .iter()
        .map(|batch| batch.outcomes.confirmed + batch.outcomes.rejected + batch.outcomes.ambiguous)
        .sum();
    if observed_matches < expected_matches {
        return Err(anyhow!(
            "settlement drain timed out after {}s: measured {observed_matches}/{expected_matches} settlement outcomes",
            p.settle_drain_timeout_secs
        ));
    }
    let drain_s = drain_start.elapsed().as_secs_f64();
    tracing::info!(
        deposit_leaves,
        final_count,
        settled_matches,
        settled_per_sec = settled_matches as f64 / drain_s.max(1e-9),
        "real-settle LOAD complete — settle throughput (prover-bound)"
    );
    let collected_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let artifact = BenchmarkArtifact {
        schema_version: 2,
        label: p.benchmark_label.clone(),
        endpoint: p.gateway.clone(),
        app_id: baseline_metrics.app_id,
        compose_hash: baseline_metrics.compose_hash,
        boot_session_id: baseline_metrics.boot_session_id,
        expected_matches,
        submitted_orders: n_orders as u64,
        accepted_orders: accepted as u64,
        target_submit_rate_orders_per_second: p.real_submit_rate,
        submission_attempts,
        rate_limited_retries,
        transient_retries,
        client_prove: ClientProveSummary {
            proof_count: proofs.len() as u64,
            concurrency: p.client_prove_concurrency,
            wall_us: prove_wall.as_micros().min(u64::MAX as u128) as u64,
            p50_us: pct(&prove_us, 0.50),
            p95_us: pct(&prove_us, 0.95),
            p99_us: pct(&prove_us, 0.99),
            max_us: prove_us.last().copied().unwrap_or(0),
        },
        warmup_batches_excluded: p.warmup_batches,
        submitted_at_ms,
        submission_completed_at_ms,
        collected_at_ms,
        batches,
    };
    let markdown = artifact.render_markdown();
    println!("\n{markdown}");
    if let Some(path) = &p.report {
        std::fs::write(path, &markdown)?;
        tracing::info!(?path, "wrote settlement benchmark markdown");
    }
    if let Some(path) = &p.metrics_json {
        std::fs::write(path, serde_json::to_vec_pretty(&artifact)?)?;
        tracing::info!(?path, "wrote settlement benchmark JSON");
    }
    if artifact.measured_batches().len() < p.min_measured_batches {
        return Err(anyhow!(
            "benchmark invalid: only {} measured batches after warm-up; require at least {}",
            artifact.measured_batches().len(),
            p.min_measured_batches
        ));
    }
    let rejected: u64 = artifact
        .batches
        .iter()
        .map(|batch| batch.outcomes.rejected)
        .sum();
    let ambiguous: u64 = artifact
        .batches
        .iter()
        .map(|batch| batch.outcomes.ambiguous)
        .sum();
    if rejected != 0 || ambiguous != 0 {
        return Err(anyhow!(
            "benchmark completed with unhealthy outcomes: rejected={rejected}, ambiguous={ambiguous}"
        ));
    }
    println!(
        "\n=== real-settle load summary ===\n\
         orders submitted: {} (accepted {})\n\
         client VALID_INPUT prove: {} proofs in {:.1}s ({:.2}/s)\n\
         measured confirmed matches: {} in {:.1}s ({:.2} matches/s)\n\
         on-chain leaf count: {} → {}\n",
        n_orders,
        accepted,
        proofs.len(),
        prove_wall.as_secs_f64(),
        proofs.len() as f64 / prove_wall.as_secs_f64().max(1e-9),
        settled_matches,
        drain_s,
        settled_matches as f64 / drain_s.max(1e-9),
        deposit_leaves,
        final_count,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::crossing_prices;

    #[test]
    fn live_oracle_crossing_prices_are_tick_aligned() {
        let (bid, ask) = crossing_prices(7_713_464_441, 5).unwrap();
        assert_eq!(bid, 9_256_157_325);
        assert_eq!(ask, 6_170_771_550);
        assert_eq!(bid % 5, 0);
        assert_eq!(ask % 5, 0);
        assert!(bid > ask);
    }

    #[test]
    fn zero_tick_is_rejected() {
        assert!(crossing_prices(150_000_000, 0).is_err());
    }

    #[test]
    fn fixed_fixture_requires_enough_root_history_shards() {
        assert!(super::validate_root_history_budget(144, 1).is_err());
        assert!(super::validate_root_history_budget(144, 2).is_err());
        super::validate_root_history_budget(144, 3).unwrap();
        super::validate_root_history_budget(144, 4).unwrap();
    }

    /// The current (fixed) seed_base layout: salt in bits 32+, inst in bits
    /// 16-31, leaving bits 0-15 for the per-order tag. MUST match the inline
    /// formula in `run_real_settle_load`.
    fn seed_base(salt: u64, inst: u64) -> u64 {
        ((salt & 0xFFFF_FFFF) << 32) ^ (inst << 16)
    }

    /// Every per-order PRIMARY-note seed is `seed_base ^ tag`. Two primary
    /// notes share a nullifier iff they share a seed (nullifier_v2 ignores
    /// mint+amount). So the safety invariant is: across all instances, all
    /// `seed_base(inst) ^ tag` are globally unique for the primary tag set
    /// (`0x1` bid, `0x2` seller, `0x10+j` partial-fill asks).
    #[test]
    fn per_note_seeds_are_globally_unique() {
        let salt = 0x1234_5678u64;
        let mut tags = vec![0x1u64, 0x2];
        tags.extend((0..64u64).map(|j| 0x10 + j)); // generous partial-fill ask span
        let mut seen = HashSet::new();
        for inst in 0..256u64 {
            let sb = seed_base(salt, inst);
            for &t in &tags {
                assert!(
                    seen.insert(sb ^ t),
                    "seed collision: inst={inst} tag={t:#x} — would alias a nullifier"
                );
            }
        }
    }

    /// Regression guard: the OLD `(salt<<20) ^ (inst<<4)` layout aliased
    /// inst=0's ask j=1 with inst=1's bid (the multi-scenario settle bug).
    /// Pin that the fix breaks that specific collision so we can't revert.
    #[test]
    fn old_overlapping_layout_collided() {
        let salt = 0x1234_5678u64;
        let old = |inst: u64| (salt << 20) ^ (inst << 4);
        assert_eq!(
            old(0) ^ 0x11,
            old(1) ^ 0x1,
            "old layout collision (documented)"
        );
        // The new layout must NOT collide for the same pair.
        assert_ne!(seed_base(salt, 0) ^ 0x11, seed_base(salt, 1) ^ 0x1);
    }
}
