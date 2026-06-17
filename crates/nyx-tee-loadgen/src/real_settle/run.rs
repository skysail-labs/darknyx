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
use darkpool_crypto::{fr_to_be_bytes, nullifier_v2, Fr};
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::{
    anchor_pool_hash, Anchor, OrderCanonical, ANCHOR_POOL_SIZE,
};
use ed25519_dalek::{Signer, SigningKey};
use solana_address::Address;
use solana_signer::Signer as _;

use super::flow::{load_keypair, DepositedNote, RealSettleHarness};
use super::rpc::RpcClient;
use super::vault::associated_token_address;
use super::{spl, ValidInputProof};
use crate::auth::acquire_bearer;
use crate::config::RunConfig;

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
    /// `partial-fill`: small asks crossing the one big bid (= anchors consumed).
    pub multi_anchor_asks: u8,
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
            oracle_twap: cfg.oracle_twap,
            qty: cfg.real_qty,
            api_key: cfg.api_key.clone(),
            api_secret: cfg.api_secret.clone(),
            passphrase: cfg.passphrase.clone(),
            traders: cfg.traders,
            mix: cfg.real_mix.clone(),
            multi_anchor_asks: cfg.real_multi_anchor_asks,
        })
    }
}

fn with_fee(nominal: u64, fee_bps: u16) -> u64 {
    nominal + ((nominal as u128) * fee_bps as u128 / 10_000) as u64
}

/// Deterministic, BN254-Fr-safe (top byte 0) 32-byte field for a synthetic
/// anchor entry — anchors aren't consumed by an exact fill, so synthetic is
/// fine; the pool_hash just has to be consistent with what we sign.
fn fr_safe(order_id: &[u8; 16], tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = order_id[i % 16] ^ tag ^ (i as u8);
    }
    out[0] = 0;
    out
}

/// A trader's keys for one order.
struct Persona {
    spending_key: Fr,
    owner_blinding: Fr,
    owner_commit: [u8; 32],
    trading: SigningKey,
    user_commitment: [u8; 32],
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
        let mut user_commitment = trading.verifying_key().to_bytes();
        user_commitment[0] = 0; // Fr-safe + intake's top-byte-zero requirement
        Ok(Self {
            spending_key,
            owner_blinding,
            owner_commit,
            trading,
            user_commitment,
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
) -> Result<serde_json::Value> {
    let anchors: Vec<Anchor> = (0..ANCHOR_POOL_SIZE)
        .map(|i| Anchor {
            inner_hash: fr_safe(&order_id, 0x10 + i as u8),
            nullifier: fr_safe(&order_id, 0x80 + i as u8),
        })
        .collect();
    let pool_hash = anchor_pool_hash(&anchors);

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
        user_commitment: p.user_commitment,
        arrival_nonce: 1,
        anchor_pool_hash: pool_hash,
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
        "user_commitment": hex::encode(p.user_commitment),
        "arrival_nonce": 1u64,
        "trading_key": hex::encode(p.trading.verifying_key().to_bytes()),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "owner_commitment": hex::encode(p.owner_commit),
        "note_inner_hash": hex::encode(note.inner_hash),
        "nullifier": hex::encode(nullifier),
        "merkle_root": hex::encode(proof.merkle_root),
        "valid_input_proof": hex::encode(proof.proof_bytes),
        "collateral_amount": note.amount,
        // Which shard the input note lives in — lets the CVM route lock_note to
        // the right merkle_tree so a batch's inputs can span shards (cross-shard fix).
        "tree_id": note.tree_id,
        "anchors": anchors.iter().map(|a| serde_json::json!({
            "inner_hash": hex::encode(a.inner_hash),
            "nullifier": hex::encode(a.nullifier),
        })).collect::<Vec<_>>(),
    }))
}

/// Run a single real crossing pair end-to-end: mint → deposit → prove → POST →
/// watch settle. Returns the on-chain leaf-count growth.
pub async fn run_real_settle(p: RealSettleParams) -> Result<()> {
    let rpc = RpcClient::new(p.rpc_url.clone());
    let mut harness = RealSettleHarness::new(rpc.clone(), &p.circuits_dir, p.num_trees)?;
    let admin = load_keypair(&p.admin_keypair)?;

    let start = harness.leaf_count().await?;
    if start != 0 {
        return Err(anyhow!(
            "tree not empty (leaf_count={start}) — reset + redeploy the CVM first"
        ));
    }

    // Salt the personas' keys so the v2 nullifiers are fresh each run (a fixed
    // key collides the settle's NullifierEntry PDA on re-run).
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let buyer = Persona::new(0x40_0000 ^ salt)?;
    let seller = Persona::new(0x80_0000 ^ salt)?;

    let bid_price = p.oracle_twap.saturating_mul(12) / 10;
    let ask_price = p.oracle_twap.saturating_mul(8) / 10;
    let buyer_note_amt = with_fee(p.qty.saturating_mul(bid_price), p.fee_rate_bps);
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
    let buyer_inner = fr_to_be_bytes(&Fr::from(salt ^ 0xB));
    let seller_inner = fr_to_be_bytes(&Fr::from(salt ^ 0x5));
    let buyer_commit = darkpool_crypto::commitment_from_fields_v2(
        &p.quote_mint,
        buyer_note_amt,
        &buyer.owner_commit,
        &buyer_inner,
    )
    .map_err(|e| anyhow!("commit: {e}"))?;
    let seller_commit = darkpool_crypto::commitment_from_fields_v2(
        &p.base_mint,
        seller_note_amt,
        &seller.owner_commit,
        &seller_inner,
    )
    .map_err(|e| anyhow!("commit: {e}"))?;
    let buyer_note = harness
        .deposit(
            &admin,
            p.quote_mint,
            &buyer_quote_ata,
            buyer_note_amt,
            &buyer.owner_commit,
            &buyer_inner,
            buyer_commit,
            0,
        )
        .await?;
    let seller_note = harness
        .deposit(
            &admin,
            p.base_mint,
            &seller_base_ata,
            seller_note_amt,
            &seller.owner_commit,
            &seller_inner,
            seller_commit,
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

    // 4. Build + sign both orders.
    let expiry_slot = rpc.slot().await? + 50_000;
    let buyer_order = build_order_body(
        &buyer,
        OrderSide::Bid,
        OrderType::Limit,
        bid_price,
        &buyer_note,
        &buyer_proof,
        [0x0b; 16],
        p.qty,
        expiry_slot,
        &p.symbol,
    )?;
    let seller_order = build_order_body(
        &seller,
        OrderSide::Ask,
        OrderType::Limit,
        ask_price,
        &seller_note,
        &seller_proof,
        [0x05; 16],
        p.qty,
        expiry_slot,
        &p.symbol,
    )?;

    // 5. Auth + submit both.
    let http = reqwest::Client::new();
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
    /// 1 big bid + M small asks → M fills over M batches → consumes M anchors.
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

/// Deterministic weighted pick by instance index.
fn pick_scenario(mix: &[(RealScenario, u32)], i: usize) -> RealScenario {
    let total: u32 = mix.iter().map(|(_, w)| *w).sum::<u32>().max(1);
    let pos = (i as u32) % total;
    let mut acc = 0;
    for (s, w) in mix {
        acc += *w;
        if pos < acc {
            return *s;
        }
    }
    mix[0].0
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

/// Run the multi-trader, multi-scenario load rig: N scenario instances → mint +
/// deposit (+merge) all notes → prove all VALID_INPUT (concurrent) → submit all
/// (concurrent) → drain the settle. Reports client prove-rate + end-to-end
/// settled-matches/sec — the prover-bottleneck evidence.
pub async fn run_real_settle_load(p: RealSettleParams) -> Result<()> {
    let mix = parse_mix(&p.mix)?;
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

    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bid_price = p.oracle_twap.saturating_mul(12) / 10;
    let ask_price = p.oracle_twap.saturating_mul(8) / 10;
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
        let scenario = pick_scenario(&mix, inst);
        // Per-instance, per-side fresh personas (salted → fresh nullifiers).
        let seed_base = (salt << 20) ^ ((inst as u64) << 4);

        // Helper to mint + deposit one note, returning (persona, note).
        macro_rules! mint_deposit {
            ($side:expr, $mint:expr, $ata:expr, $amount:expr, $seed:expr) => {{
                let persona = Persona::new($seed)?;
                let shard = (g % k as usize) as u8;
                g += 1;
                let inner = fr_to_be_bytes(&Fr::from($seed ^ 0xA5A5));
                let commit = darkpool_crypto::commitment_from_fields_v2(
                    &$mint,
                    $amount,
                    &persona.owner_commit,
                    &inner,
                )
                .map_err(|e| anyhow!("commit: {e}"))?;
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
                        &persona.owner_commit,
                        &inner,
                        commit,
                        shard,
                    )
                    .await?;
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
                let surplus = if scenario == RealScenario::OverCollateral {
                    with_fee(p.qty.saturating_mul(bid_price), p.fee_rate_bps) / 5
                // +20%
                } else {
                    0
                };
                let bid_amt = with_fee(p.qty.saturating_mul(bid_price), p.fee_rate_bps) + surplus;
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
                // One big bid (M×qty) + M small asks (qty each) → M anchors over M batches.
                let m = p.multi_anchor_asks.max(1) as u64;
                let big_qty = p.qty.saturating_mul(m);
                let bid_amt = with_fee(big_qty.saturating_mul(bid_price), p.fee_rate_bps);
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
                let bid_amt = with_fee(p.qty.saturating_mul(bid_price), p.fee_rate_bps);
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
                let ih0 = fr_to_be_bytes(&Fr::from((seed_base ^ 0x30) | 1));
                let ih1 = fr_to_be_bytes(&Fr::from((seed_base ^ 0x31) | 1));
                let c0 = darkpool_crypto::commitment_from_fields_v2(
                    &p.base_mint,
                    a0,
                    &sp.owner_commit,
                    &ih0,
                )
                .map_err(|e| anyhow!("c0: {e}"))?;
                let c1 = darkpool_crypto::commitment_from_fields_v2(
                    &p.base_mint,
                    a1,
                    &sp.owner_commit,
                    &ih1,
                )
                .map_err(|e| anyhow!("c1: {e}"))?;
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
                        &sp.owner_commit,
                        &ih0,
                        c0,
                        shard,
                    )
                    .await?;
                let n1 = harness
                    .deposit(
                        &admin,
                        p.base_mint,
                        &base_ata,
                        a1,
                        &sp.owner_commit,
                        &ih1,
                        c1,
                        shard,
                    )
                    .await?;
                // Merge-prove + submit the merge ix.
                let mp = merge_prover
                    .as_ref()
                    .ok_or_else(|| anyhow!("merge prover not loaded"))?;
                let w0 = harness.shadow_witness(shard, n0.leaf_index)?;
                let w1 = harness.shadow_witness(shard, n1.leaf_index)?;
                let out_ih = fr_to_be_bytes(&Fr::from((seed_base ^ 0x39) | 1));
                let mproof = mp
                    .prove(
                        &sp.spending_key,
                        &sp.owner_blinding,
                        &out_ih,
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
                let nf0 = nullifier_v2(&sp.spending_key, &ih0).map_err(|e| anyhow!("nf0: {e}"))?;
                let nf1 = nullifier_v2(&sp.spending_key, &ih1).map_err(|e| anyhow!("nf1: {e}"))?;
                let merge_ix = super::vault::build_merge_ix(
                    shard,
                    &admin.pubkey(),
                    &[nf0, nf1],
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
                    inner_hash: out_ih,
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

    // ── Phase 2: prove all VALID_INPUT concurrently (client prover load) ──
    let harness = Arc::new(harness);
    let prove_start = Instant::now();
    let mut prove_handles = Vec::with_capacity(orders.len());
    for o in &orders {
        let h = harness.clone();
        let (sk, ob, note) = (
            o.persona.spending_key,
            o.persona.owner_blinding,
            o.note.clone(),
        );
        prove_handles.push(tokio::task::spawn_blocking(move || {
            let t = Instant::now();
            let proof = h.prove(&sk, &ob, &note);
            (proof, t.elapsed().as_micros() as u64)
        }));
    }
    let mut proofs = Vec::with_capacity(orders.len());
    let mut prove_us: Vec<u64> = Vec::with_capacity(orders.len());
    for handle in prove_handles {
        let (proof, us) = handle.await.map_err(|e| anyhow!("prove task: {e}"))?;
        proofs.push(proof.map_err(|e| anyhow!("VALID_INPUT prove: {e}"))?);
        prove_us.push(us);
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
    let http = reqwest::Client::new();
    let token = acquire_bearer(&http, &p.gateway, &p.api_key, &p.api_secret, &p.passphrase)
        .await
        .map_err(|e| anyhow!("auth: {e}"))?;
    let expiry_slot = rpc.slot().await? + 50_000;
    let mut bodies = Vec::with_capacity(orders.len());
    for (i, o) in orders.iter().enumerate() {
        let mut oid = [0u8; 16];
        oid[..8].copy_from_slice(&(i as u64).to_le_bytes());
        oid[15] = 1;
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
        )?);
    }
    let submit_start = Instant::now();
    let n_orders = bodies.len();
    let mut submit_handles = Vec::with_capacity(n_orders);
    for b in bodies {
        let http = http.clone();
        let token = token.clone();
        let url = format!("{}/orders", p.gateway);
        submit_handles.push(tokio::spawn(async move {
            http.post(url)
                .bearer_auth(&token)
                .json(&b)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        }));
    }
    let mut accepted = 0usize;
    for h in submit_handles {
        if (200..300).contains(&h.await.unwrap_or(0)) {
            accepted += 1;
        }
    }
    tracing::info!(
        submitted = n_orders,
        accepted,
        ms = submit_start.elapsed().as_millis() as u64,
        "orders submitted"
    );

    // ── Phase 4: drain the settle, measure settled-matches/sec ──
    let drain_start = Instant::now();
    let mut last = deposit_leaves;
    let deadline = Instant::now() + std::time::Duration::from_secs(180);
    while Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let now = harness.leaf_count().await?;
        if now > last {
            tracing::info!(
                leaf_count = now,
                settled_matches_approx = (now - deposit_leaves) / 2,
                "settle progress"
            );
            last = now;
        }
    }
    let final_count = harness.leaf_count().await?;
    let settled_matches = (final_count.saturating_sub(deposit_leaves)) / 2;
    let drain_s = drain_start.elapsed().as_secs_f64();
    tracing::info!(
        deposit_leaves,
        final_count,
        settled_matches,
        settled_per_sec = settled_matches as f64 / drain_s.max(1e-9),
        "real-settle LOAD complete — settle throughput (prover-bound)"
    );
    println!(
        "\n=== real-settle load summary ===\n\
         orders submitted: {} (accepted {})\n\
         client VALID_INPUT prove: {} proofs in {:.1}s ({:.2}/s)\n\
         on-chain settled matches: {} in {:.1}s ({:.2} matches/s)\n\
         → cross-reference the TEE prover: phala cvms logs <cvm> | grep -E \"prove breakdown|settle pipeline timing\"\n",
        n_orders, accepted,
        proofs.len(), prove_wall.as_secs_f64(), proofs.len() as f64 / prove_wall.as_secs_f64().max(1e-9),
        settled_matches, drain_s, settled_matches as f64 / drain_s.max(1e-9),
    );
    Ok(())
}
