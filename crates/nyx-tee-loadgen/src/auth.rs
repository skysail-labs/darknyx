//! Bearer-token acquisition + per-order signing helpers.
//!
//! `acquire_bearer` is a one-shot `POST /auth/token` against the
//! configured endpoint, returning the access_token string. The
//! traders cache the token for the run's duration — the test JWT
//! TTL is 3600s and no realistic bench window exceeds that.

use anyhow::{anyhow, Result};
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
) -> serde_json::Value {
    let note_commitment = synthesised_note_commitment(&order_id);
    let user_commitment = synthesised_user_commitment(key);

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
    };
    let digest = canonical.digest().expect("symbol bounded by caller");
    let sig = key.sign(&digest);
    let trading_key = key.verifying_key().to_bytes();

    serde_json::json!({
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
    })
}

/// JSON body for `DELETE /orders/{order_id}`. Same canonical
/// signing as `build_signed_place_body` but against the cancel
/// domain tag.
pub fn build_signed_cancel_body(
    key: &SigningKey,
    order_id: [u8; 16],
    cancel_nonce: u64,
) -> serde_json::Value {
    let trading_key = key.verifying_key().to_bytes();
    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce,
    };
    let sig = key.sign(&cancel.digest());
    serde_json::json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": cancel_nonce,
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

fn synthesised_note_commitment(order_id: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // Repeat the order_id twice for determinism + uniqueness across
    // orders. No top-byte constraint here.
    out[..16].copy_from_slice(order_id);
    out[16..].copy_from_slice(order_id);
    out
}

fn synthesised_user_commitment(key: &SigningKey) -> [u8; 32] {
    // Use the trading pubkey as the seed — distinct per trader.
    // Zero the top byte for Fr-safety.
    let mut out = key.verifying_key().to_bytes();
    out[0] = 0;
    out
}
