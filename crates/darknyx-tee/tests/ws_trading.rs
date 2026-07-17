//! `/v1/stream` order core — the transport-agnostic intake the socket dispatches to,
//! plus the cancel-on-disconnect teardown. We exercise
//! `orders::{place_core, cancel_core, cancel_resting_unchecked}` directly
//! against a real `ApiState` + `MatcherState` (the exact functions the
//! stream handler calls per frame), so we cover the order-management
//! semantics without binding a socket. The frame (de)serialization is unit-
//! tested in `api::stream`.

use std::sync::Arc;

use darknyx_tee::api::orders::{
    cancel_core, cancel_resting_unchecked, place_core, CancelOrderRequest, PlaceOrderRequest,
};
use darknyx_tee::api::ApiState;
use darknyx_tee::matcher::openings::NoteOpening;
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::{CancelCanonical, OrderCanonical};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;

const ACCOUNT: &str = "acct-test";

fn fr_safe(b: u8) -> [u8; 32] {
    let mut v = [b; 32];
    v[0] = 0;
    v
}

/// Build a fully-signed `PlaceOrderRequest` for `order_id`, signed by `key`.
/// Mirrors the `orders_surface` builder's happy path (zeroed test market, exact
/// collateral, zero fee), deserialized into the typed request the core takes.
fn signed_order(key: &SigningKey, order_id: [u8; 16]) -> PlaceOrderRequest {
    let salt = order_id[15];
    let amount = 10_000_000u64;
    let price_limit = 150_000_000u64;
    let note_amount = amount.saturating_mul(price_limit).max(1); // bid floor, no fee
    let owner_commitment = fr_safe(0x44);
    let note_inner_hash = fr_safe(0x55u8.wrapping_add(salt));
    let nullifier = [0x77u8.wrapping_add(salt); 32];
    let user_commitment = fr_safe(0x33);
    let viewing_pubkey = darkpool_crypto::ephemeral_public(&[0x21; 32]);
    let session_id = [0x5A; 32];
    let arrival_nonce = u64::from(salt);

    let opening = NoteOpening {
        token_mint: [0u8; 32],
        amount: note_amount,
        owner_commitment,
        inner_hash: note_inner_hash,
        nullifier,
    };
    let note_commitment = opening.commitment().expect("Fr-safe opening");

    let canonical = OrderCanonical {
        symbol: b"SOL-USDC",
        side: OrderSide::Bid,
        order_type: OrderType::Limit,
        amount,
        price_limit,
        min_fill_size: 0,
        expiry_slot: 4_000,
        order_id,
        note_commitment,
        user_commitment,
        arrival_nonce,
        viewing_pubkey,
        session_id,
    };
    let sig = key.sign(&canonical.digest().unwrap());

    let body = json!({
        "symbol": "SOL-USDC",
        "side": "bid",
        "order_type": "limit",
        "amount": amount,
        "price_limit": price_limit,
        "min_fill_size": 0,
        "expiry_slot": 4_000,
        "order_id": hex::encode(order_id),
        "note_commitment": hex::encode(note_commitment),
        "user_commitment": hex::encode(user_commitment),
        "arrival_nonce": arrival_nonce,
        "trading_key": hex::encode(key.verifying_key().to_bytes()),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "owner_commitment": hex::encode(owner_commitment),
        "note_inner_hash": hex::encode(note_inner_hash),
        "nullifier": hex::encode(nullifier),
        "merkle_root": hex::encode([0xDDu8; 32]),
        "valid_input_proof": hex::encode([0u8; 256]),
        "collateral_amount": serde_json::Value::Null,
        "viewing_pubkey": hex::encode(viewing_pubkey),
        "session_id": hex::encode(session_id),
    });
    serde_json::from_value(body).expect("valid PlaceOrderRequest")
}

fn signed_cancel(key: &SigningKey, order_id: [u8; 16], nonce: u64) -> CancelOrderRequest {
    let trading_key = key.verifying_key().to_bytes();
    let canonical = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce: nonce,
    };
    let sig = key.sign(&canonical.digest());
    serde_json::from_value(json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": nonce,
        "trading_key_signature": hex::encode(sig.to_bytes()),
    }))
    .unwrap()
}

fn oid(tag: u8) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = 0xAA;
    o[15] = tag;
    o
}

#[tokio::test]
async fn place_core_books_an_order_and_records_its_owner() {
    let state = Arc::new(ApiState::for_tests());
    let matcher = state.matcher.clone().unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let order_id = oid(1);

    let resp = place_core(&state, &matcher, &signed_order(&key, order_id), ACCOUNT)
        .await
        .expect("place ok");
    assert_eq!(resp.order_id, hex::encode(order_id));
    assert_eq!(resp.status, "accepted");

    // Booked...
    assert!(matcher.read().await.book().get(&order_id).is_some());
    // ...and routable to its account (the per-account WS routing key).
    assert_eq!(
        state.order_owner.read().await.get(&resp.order_id).cloned(),
        Some(ACCOUNT.to_string())
    );
}

#[tokio::test]
async fn cancel_core_requires_the_owner_signature() {
    let state = Arc::new(ApiState::for_tests());
    let matcher = state.matcher.clone().unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let order_id = oid(2);
    let oid_hex = hex::encode(order_id);

    place_core(&state, &matcher, &signed_order(&key, order_id), ACCOUNT)
        .await
        .unwrap();

    // A different key's signature is forbidden.
    let other = SigningKey::generate(&mut OsRng);
    let err = cancel_core(
        &state,
        &matcher,
        &oid_hex,
        &signed_cancel(&other, order_id, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(err.code, 1103); // not_owner
    assert!(
        matcher.read().await.book().get(&order_id).is_some(),
        "still resting"
    );

    // The owner's signature cancels it.
    let resp = cancel_core(
        &state,
        &matcher,
        &oid_hex,
        &signed_cancel(&key, order_id, 1),
    )
    .await
    .unwrap();
    assert_eq!(resp.status, "cancelled");
    assert!(matcher.read().await.book().get(&order_id).is_none());
    // Owner mapping dropped on cancel.
    assert!(state.order_owner.read().await.get(&oid_hex).is_none());
}

#[tokio::test]
async fn cancel_on_disconnect_sweeps_the_sessions_resting_orders_without_a_signature() {
    let state = Arc::new(ApiState::for_tests());
    let matcher = state.matcher.clone().unwrap();
    let key = SigningKey::generate(&mut OsRng);

    // Two orders placed on the "session".
    let a = oid(3);
    let b = oid(4);
    place_core(&state, &matcher, &signed_order(&key, a), ACCOUNT)
        .await
        .unwrap();
    place_core(&state, &matcher, &signed_order(&key, b), ACCOUNT)
        .await
        .unwrap();

    // Simulate the socket closing with cancel-on-disconnect on: the server
    // tears down each tracked order using its OWN booked key — no client sig.
    let session = [hex::encode(a), hex::encode(b)];
    for oid_hex in &session {
        assert!(cancel_resting_unchecked(&state, &matcher, oid_hex).await);
    }

    // Both gone; the book is empty.
    assert!(matcher.read().await.book().get(&a).is_none());
    assert!(matcher.read().await.book().get(&b).is_none());

    // A second sweep of the same ids is a harmless no-op (already terminal).
    assert!(!cancel_resting_unchecked(&state, &matcher, &session[0]).await);
}
