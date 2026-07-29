//! `/admin/drain` — the planned-stop control surface (audit finding T-06).
//!
//! Exercised through the real router so this covers the wiring, not just the
//! `settle::drain` decision logic its unit tests already pin: admin gating, the
//! shared journal handle, and the JSON shape an operator runbook reads.
//!
//! The property that matters is `safe_to_stop`. It must be computed from the
//! settle journal — the same durable state a restart would read — and never from
//! elapsed time. A drain that reports "ready" on a timer would give an operator
//! permission to stop a CVM mid-settlement, which is precisely the failure the
//! journal exists to survive.
//!
//! Run with: `cargo test -p darknyx-tee --test drain_endpoint`

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use darknyx_tee::api::auth::{TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE};
use darknyx_tee::api::orders::{place_core, PlaceOrderRequest};
use darknyx_tee::api::{build_router, ApiState};
use darknyx_tee::matcher::openings::NoteOpening;
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::OrderCanonical;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use tower::ServiceExt;

async fn token(state: Arc<ApiState>) -> String {
    let resp = build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "api_key":    TEST_API_KEY,
                        "api_secret": TEST_API_SECRET,
                        "passphrase": TEST_PASSPHRASE,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

async fn call(
    state: Arc<ApiState>,
    method: &str,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri("/admin/drain");
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let resp = build_router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn drain_requires_a_bearer_token() {
    let state = Arc::new(ApiState::for_tests());
    let (status, _) = call(state, "GET", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unauthenticated caller must not be able to read or drive a drain"
    );
}

#[tokio::test]
async fn an_idle_instance_is_not_safe_to_stop_until_it_is_draining() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (status, body) = call(Arc::clone(&state), "GET", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], false);
    assert_eq!(body["in_flight_settlements"], 0);
    assert_eq!(
        body["safe_to_stop"], false,
        "an empty journal is not permission to stop while trading is open — the \
         next matcher tick can enqueue a settlement"
    );
}

#[tokio::test]
async fn beginning_a_drain_closes_trading_and_reports_ready() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (status, body) = call(Arc::clone(&state), "POST", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], true);
    assert_eq!(
        body["safe_to_stop"], true,
        "trading closed and nothing in flight is the safe-to-stop condition"
    );

    // The gate really closed — not just the report.
    assert!(
        !state.trading_gate.is_open(),
        "a drain must actually close the trading gate"
    );
}

#[tokio::test]
async fn a_drain_can_be_abandoned_and_reopens_trading() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    call(Arc::clone(&state), "POST", Some(&t)).await;
    assert!(!state.trading_gate.is_open());

    let (status, body) = call(Arc::clone(&state), "DELETE", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], false);
    assert!(
        state.trading_gate.is_open(),
        "abandoning a planned stop must re-open trading"
    );
}

/// A drain is idempotent: a runbook that retries the POST after a timeout must
/// not get a different answer or double-count anything.
#[tokio::test]
async fn repeating_the_drain_request_is_idempotent() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (_, first) = call(Arc::clone(&state), "POST", Some(&t)).await;
    let (_, second) = call(Arc::clone(&state), "POST", Some(&t)).await;
    assert_eq!(first["draining"], true);
    assert_eq!(second["draining"], true);
    assert_eq!(second["safe_to_stop"], true);
}

/// `ApiState::for_tests()` has no state dir, so its journal is in-memory. The
/// status must SAY so rather than reporting a bare `safe_to_stop: true` that an
/// operator would read as "in-flight work is durable". Technically-true and
/// practically-misleading is the failure mode this whole slice keeps finding.
#[tokio::test]
async fn a_non_persistent_journal_is_disclosed_to_the_operator() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;
    let (_, body) = call(Arc::clone(&state), "GET", Some(&t)).await;
    let caveat = body["caveat"]
        .as_str()
        .expect("a non-persistent journal must be disclosed in the status");
    assert!(
        caveat.contains("not persistent"),
        "the caveat should name the problem; got: {caveat}"
    );
}

// ─────── the cancellation path, with a real resting order ───────────────────

fn fr_safe(b: u8) -> [u8; 32] {
    let mut v = [b; 32];
    v[0] = 0;
    v
}

/// A fully-signed order, mirroring the `ws_trading` builder (zeroed test market,
/// exact collateral, zero fee).
fn signed_order(key: &SigningKey, order_id: [u8; 16]) -> PlaceOrderRequest {
    let salt = order_id[15];
    let amount = 10_000_000u64;
    let price_limit = 150_000_000u64;
    let note_amount = amount.saturating_mul(price_limit).max(1);
    let owner_commitment = fr_safe(0x44);
    let note_inner_hash = fr_safe(0x55u8.wrapping_add(salt));
    let viewing_pubkey = darkpool_crypto::ephemeral_public(&[0x21; 32]);
    let session_id = [0x5A; 32];
    let opening = NoteOpening {
        token_mint: [0u8; 32],
        amount: note_amount,
        owner_commitment,
        inner_hash: note_inner_hash,
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
        arrival_nonce: u64::from(salt),
        viewing_pubkey,
        session_id,
    };
    let sig = key.sign(&canonical.digest().unwrap());
    serde_json::from_value(json!({
        "symbol": "SOL-USDC", "side": "bid", "order_type": "limit",
        "amount": amount, "price_limit": price_limit, "min_fill_size": 0,
        "expiry_slot": 4_000,
        "order_id": hex::encode(order_id),
        "note_commitment": hex::encode(note_commitment),
        "arrival_nonce": u64::from(salt),
        "trading_key": hex::encode(key.verifying_key().to_bytes()),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "owner_commitment": hex::encode(owner_commitment),
        "note_inner_hash": hex::encode(note_inner_hash),
        "merkle_root": hex::encode([0xDDu8; 32]),
        "valid_input_proof": hex::encode([0u8; 256]),
        "collateral_amount": serde_json::Value::Null,
        "viewing_pubkey": hex::encode(viewing_pubkey),
        "session_id": hex::encode(session_id),
    }))
    .expect("valid PlaceOrderRequest")
}

/// Drain must actually empty the book, not merely report a count.
///
/// This is the only test that drives the cancellation LOOP in `begin_drain`.
/// That loop snapshots order ids under a read guard and then cancels under a
/// write guard — holding the read guard across the cancels would deadlock, and
/// no amount of testing the drain helpers in isolation would reveal it.
#[tokio::test]
async fn draining_cancels_a_real_resting_order() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let key = SigningKey::from_bytes(&[0x77; 32]);
    let mut order_id = [0u8; 16];
    order_id[0] = 0xAA;
    order_id[15] = 1;
    let matcher = state
        .matcher_for_symbol("SOL-USDC")
        .expect("test state has a matcher");
    place_core(&state, &matcher, &signed_order(&key, order_id), "acct-test")
        .await
        .expect("order accepted");
    assert_eq!(
        matcher.read().await.book().len(),
        1,
        "precondition: one order resting"
    );

    let (status, body) = call(Arc::clone(&state), "POST", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["cancelled_resting"], 1,
        "drain must report the order it cancelled, got: {body}"
    );
    assert_eq!(
        matcher.read().await.book().len(),
        0,
        "the book must actually be empty — a reported count is not a cancellation"
    );
    assert_eq!(body["safe_to_stop"], true);
}
