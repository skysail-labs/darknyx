//! Bearer-token acquisition + per-order signing helpers.
//!
//! `acquire_bearer` is a one-shot `POST /auth/token` against the
//! configured endpoint, returning the access_token string. The
//! traders cache the token for the run's duration — the test JWT
//! TTL is 3600s and no realistic bench window exceeds that.

use anyhow::{anyhow, Result};
use darkpool_crypto::note::commitment_from_fields_v2;
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::{CancelCanonical, OrderCanonical};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct TokenRequest<'a> {
    api_key: &'a str,
    api_secret: &'a str,
    passphrase: &'a str,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct InfoResponse {
    boot_session_id: String,
}

/// Fetch the process-boot session that every canonical order must sign.
/// A restart deliberately invalidates every order body prepared for the old
/// process, so callers fetch this once immediately before a run.
pub async fn fetch_boot_session_id(http: &reqwest::Client, endpoint: &str) -> Result<[u8; 32]> {
    let url = format!("{endpoint}/info");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("GET {url}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("GET {url} returned {status}: {body}"));
    }
    let parsed: InfoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("response body is not an InfoResponse: {e}; body={body}"))?;
    let decoded = hex::decode(&parsed.boot_session_id)
        .map_err(|e| anyhow!("/info boot_session_id is not hex: {e}"))?;
    decoded
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("/info boot_session_id is {} bytes, expected 32", v.len()))
}

pub async fn acquire_bearer(
    http: &reqwest::Client,
    endpoint: &str,
    api_key: &str,
    api_secret: &str,
    passphrase: &str,
) -> Result<String> {
    let req = TokenRequest {
        api_key,
        api_secret,
        passphrase,
    };
    let url = format!("{endpoint}/auth/token");
    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| anyhow!("POST {url}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("POST {url} returned {status}: {body}"));
    }
    let parsed: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("response body is not a TokenResponse: {e}; body={body}"))?;
    Ok(parsed.access_token)
}

/// JSON body for `POST /orders`, signed by `trading_key`. The
/// canonical bytes are reconstructed and signed with `key` so the
/// TEE's `verify_strict` accepts.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_place_body(
    key: &SigningKey,
    side: OrderSide,
    order_type: OrderType,
    amount: u64,
    price_limit: u64,
    expiry_slot: u64,
    order_id: [u8; 16],
    arrival_nonce: u64,
    symbol: &str,
    fee_rate_bps: u16,
    price_scale: u64,
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    collateral_surplus_bps: u16,
    boot_session_id: [u8; 32],
) -> serde_json::Value {
    let user_commitment = synthesised_user_commitment(key);

    // Build a synthetic input-note opening + the matching commitment so
    // the order passes the TEE intake's opening verification (4g.7a/c):
    // intake recomputes `commitment_from_fields_v2(mint, note_amount,
    // owner, inner_hash)` and asserts it equals `note_commitment`.
    //
    // `note_amount` MUST mirror intake's derivation EXACTLY (orders.rs):
    // a fee-inclusive collateral `nominal + floor(nominal * fee_rate_bps
    // / 10_000)`, where nominal = floor(amount × price / price_scale) for a
    // bid or amount for an ask.
    // The fee term is what lets a filled order pay its OWN protocol fee
    // out of its own collateral; intake re-derives the commitment with
    // this same amount, so an OLD nominal-only value would fail
    // `verify_commitment` (400) whenever the CVM runs fee_rate_bps > 0.
    // `fee_rate_bps` MUST equal the CVM's DARKNYX_TEE_FEE_RATE_BPS. fee=0 →
    // nominal-only, unchanged. `token_mint` must equal the TEE's per-side
    // collateral mint (bid → quote, ask → base); against a real
    // `from_boot` CVM those are `dev_match_config()`'s placeholder mints
    // (base = 0x01..0xb1, quote = 0x01..0x9e). The nullifier /
    // merkle_root / VALID_INPUT proof are not verified at intake (only
    // stored), so synthetic values are fine.
    // TODO(loadgen): take mints via --base-mint/--quote-mint once the TEE
    // reads its market from the on-chain MarketConfig PDA.
    let nominal = match side {
        OrderSide::Bid => u64::try_from(
            (amount as u128).saturating_mul(price_limit as u128) / price_scale.max(1) as u128,
        )
        .unwrap_or(u64::MAX),
        OrderSide::Ask => amount,
    };
    let fee = ((nominal as u128) * (fee_rate_bps as u128) / 10_000u128) as u64;
    let required = nominal.saturating_add(fee).max(1);
    // Over-collateralization: a `collateral_amount` above the fee-inclusive
    // minimum. `0` ⇒ exact (no explicit collateral_amount field; intake uses
    // the derived required). The synthetic note opening is re-derived against
    // `note_amount`, which MUST equal the declared collateral_amount.
    let surplus = ((required as u128) * (collateral_surplus_bps as u128) / 10_000u128) as u64;
    let note_amount = required.saturating_add(surplus);
    // The ASK side locks BASE collateral; the BID side locks QUOTE.
    let token_mint: [u8; 32] = match side {
        OrderSide::Bid => *quote_mint,
        OrderSide::Ask => *base_mint,
    };
    let owner_commitment = fr_safe_opening_field(&order_id, 0x01);
    let note_inner_hash = fr_safe_opening_field(&order_id, 0x02);
    let note_commitment = commitment_from_fields_v2(
        &token_mint,
        note_amount,
        &owner_commitment,
        &note_inner_hash,
    )
    .expect("synthetic opening fields are Fr-safe (top byte zero)");
    // Opaque-to-intake fields: a deterministic nullifier + an all-zero
    // root + a 256-byte zero VALID_INPUT proof.
    let nullifier = {
        let mut n = [0u8; 32];
        n[..16].copy_from_slice(&order_id);
        n[16..].copy_from_slice(&order_id);
        n
    };
    let merkle_root = [0u8; 32];
    let valid_input_proof = [0u8; 256];

    // A valid per-trader X25519 viewing key. Both this key and the process
    // boot session are signed, so neither can be substituted in transit.
    let viewing_pubkey = darkpool_crypto::ephemeral_public(&key.to_bytes());

    let canonical = OrderCanonical {
        symbol: symbol.as_bytes(),
        side,
        order_type,
        amount,
        price_limit,
        min_fill_size: 0,
        expiry_slot,
        order_id,
        note_commitment,
        user_commitment,
        arrival_nonce,
        viewing_pubkey,
        session_id: boot_session_id,
    };
    let digest = canonical.digest().expect("symbol bounded by caller");
    let sig = key.sign(&digest);
    let trading_key = key.verifying_key().to_bytes();
    let mut body = serde_json::json!({
        "symbol": symbol,
        "side": match side { OrderSide::Bid => "bid", OrderSide::Ask => "ask" },
        "order_type": match order_type {
            OrderType::Limit => "limit",
            OrderType::Ioc => "ioc",
            OrderType::Fok => "fok",
        },
        "amount": amount,
        "price_limit": price_limit,
        "min_fill_size": 0u64,
        "expiry_slot": expiry_slot,
        "order_id": hex::encode(order_id),
        "note_commitment": hex::encode(note_commitment),
        "user_commitment": hex::encode(user_commitment),
        "arrival_nonce": arrival_nonce,
        "trading_key": hex::encode(trading_key),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "viewing_pubkey": hex::encode(viewing_pubkey),
        "session_id": hex::encode(boot_session_id),
        // Input-note opening + VALID_INPUT relay (required since 4g.7a/c).
        "owner_commitment": hex::encode(owner_commitment),
        "note_inner_hash": hex::encode(note_inner_hash),
        "nullifier": hex::encode(nullifier),
        "merkle_root": hex::encode(merkle_root),
        "valid_input_proof": hex::encode(valid_input_proof),
    });

    // Over-collateral: declare the surplus collateral so intake takes the
    // over-collateral path (note ≥ required). Omitted at surplus 0 so the
    // exact-fill path stays byte-identical to before.
    if surplus > 0 {
        body["collateral_amount"] = serde_json::json!(note_amount);
    }

    body
}

/// JSON body for `DELETE /orders/{order_id}`. Same canonical
/// signing as `build_signed_place_body` but against the cancel
/// domain tag.
pub fn build_signed_cancel_body(
    key: &SigningKey,
    order_id: [u8; 16],
    cancel_nonce: u64,
    session_id: [u8; 32],
) -> serde_json::Value {
    let trading_key = key.verifying_key().to_bytes();
    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce,
        session_id,
    };
    let sig = key.sign(&cancel.digest());
    serde_json::json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": cancel_nonce,
        "session_id": hex::encode(session_id),
        "trading_key_signature": hex::encode(sig.to_bytes()),
    })
}

// ─── Synthesised commitments ────────────────────────────────────────────────
//
// The loadgen doesn't have real on-chain notes backing its orders.
// We need 32-byte note_commitment / user_commitment values that:
//   1. Pass intake validation (BN254 Fr-safe — top byte = 0 for
//      user_commitment, which the matcher Poseidon-hashes).
//   2. Are deterministic per (trader, order_id) so reruns produce
//      the same byte stream + the matcher's change-note Poseidon
//      hashes are reproducible.
//
// note_commitment doesn't need to be Fr-safe (the matcher doesn't
// hash it directly — only `user_commitment` goes into Poseidon in
// the change-note construction).

/// Deterministic, BN254-Fr-safe (top byte 0) 32-byte field for the
/// synthetic note opening, distinct per (order_id, tag). Fr-safe so
/// `commitment_from_fields` accepts it; deterministic so reruns
/// reproduce the same byte stream.
fn fr_safe_opening_field(order_id: &[u8; 16], tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = order_id[i % 16] ^ tag ^ (i as u8);
    }
    out[0] = 0; // < 2^248 < Fr modulus
    out
}

fn synthesised_user_commitment(key: &SigningKey) -> [u8; 32] {
    // Use the trading pubkey as the seed — distinct per trader.
    // Zero the top byte for Fr-safety.
    let mut out = key.verifying_key().to_bytes();
    out[0] = 0;
    out
}
