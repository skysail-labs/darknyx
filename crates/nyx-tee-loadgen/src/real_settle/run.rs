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
        order_type: OrderType::Limit,
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
        "order_type": "limit",
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
