//! End-to-end tests for the PR-4e.3 orders surface
//! (`POST /orders` + `DELETE /orders/{id}` + `GET /orders/{id}`).
//!
//! Drives the router via `tower::ServiceExt::oneshot` so we never
//! bind a real TCP port. Each test mints a fresh test JWT inline +
//! constructs a fresh signing keypair as the `trading_key`.
//!
//! Coverage:
//!   - Happy path: place → 202; the matcher's book contains the
//!     order (via GET status).
//!   - 400 on malformed hex / wrong-width fields / oversize symbol /
//!     non-BN254-Fr-safe user_commitment / zero order_id.
//!   - 403 on signature mismatch (wrong trading_key sigs the body).
//!   - 409 on duplicate order_id submission.
//!   - 401 on missing / invalid bearer.
//!   - Cancel: happy path; 403 if signed by a different trading_key;
//!     404 if order doesn't exist; replay protection via cancel_nonce
//!     being part of the canonical bytes.
//!   - GET 200 after submit, 404 after cancel.
//!
//! Run with: `cargo test -p nyx-tee --test orders_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::{CancelCanonical, OrderCanonical};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use nyx_tee::api::auth::{Claims, TEST_API_KEY, TEST_JWT_SECRET};
use nyx_tee::api::{build_router, ApiState};
use nyx_tee::matcher::openings::NoteOpening;
use nyx_tee::matcher::MatcherState;
use nyx_tee::oracle::cache::OracleCache;
use rand::rngs::OsRng;
use serde_json::json;
use std::sync::atomic::AtomicU64;
use tower::ServiceExt;

// ─── Shared fixtures ────────────────────────────────────────────────────────

fn state() -> Arc<ApiState> {
    Arc::new(ApiState::for_tests())
}

fn app_from(state: Arc<ApiState>) -> Router {
    build_router(state)
}

fn fresh_bearer() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: TEST_API_KEY.to_string(),
        iat: now,
        exp: now + 60,
        jti: "test-jti".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap()
}

fn fresh_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Build a valid place-order JSON body signed by `key`. Caller can
/// override fields via the `override_*` closures to break specific
/// invariants for negative-case tests.
struct PlaceOrderBuilder {
    symbol: Vec<u8>,
    side: OrderSide,
    order_type: OrderType,
    amount: u64,
    price_limit: u64,
    min_fill_size: u64,
    expiry_slot: u64,
    order_id: [u8; 16],
    user_commitment: [u8; 32],
    arrival_nonce: u64,
    // Input-note opening (4g.7a). The note_commitment is DERIVED from
    // these via NoteOpening::commitment() so the handler's intake
    // verification passes; tests that want to break the opening
    // override the emitted JSON directly.
    owner_commitment: [u8; 32],
    note_nonce: [u8; 32],
    note_blinding: [u8; 32],
    nullifier: [u8; 32],
}

impl PlaceOrderBuilder {
    fn new() -> Self {
        // Fr-safe opening fields (top byte zero so commitment_from_fields
        // accepts them).
        let fr_safe = |b: u8| {
            let mut v = [b; 32];
            v[0] = 0;
            v
        };
        Self {
            symbol: b"SOL-USDC".to_vec(),
            side: OrderSide::Bid,
            order_type: OrderType::Limit,
            amount: 10_000_000,
            price_limit: 150_000_000,
            min_fill_size: 0,
            expiry_slot: 1_000_000,
            order_id: {
                let mut o = [0u8; 16];
                o[0] = 0xAA;
                o[15] = 1;
                o
            },
            // BN254 Fr-safe: top byte zero. The handler rejects
            // non-zero top byte even before signature verification.
            user_commitment: {
                let mut u = [0x33; 32];
                u[0] = 0;
                u
            },
            arrival_nonce: 1,
            owner_commitment: fr_safe(0x44),
            note_nonce: fr_safe(0x55),
            note_blinding: fr_safe(0x66),
            nullifier: [0x77; 32],
        }
    }

    /// The note value the handler will derive for this order (bid →
    /// amount × price; ask → amount). MUST match the handler's
    /// formula so the opening's committed amount lines up.
    fn note_amount(&self) -> u64 {
        match self.side {
            OrderSide::Bid => self
                .amount
                .saturating_mul(self.price_limit)
                .max(self.amount)
                .max(1),
            OrderSide::Ask => self.amount.max(1),
        }
    }

    /// The opening the handler will reconstruct + verify. The test
    /// market (`MatcherState::new()`) has zeroed mints, so the
    /// collateral mint is `[0; 32]` for both sides.
    fn opening(&self) -> NoteOpening {
        NoteOpening {
            token_mint: [0u8; 32],
            amount: self.note_amount(),
            owner_commitment: self.owner_commitment,
            nonce: self.note_nonce,
            blinding: self.note_blinding,
            nullifier: self.nullifier,
        }
    }

    /// note_commitment derived from the opening — what the trading
    /// key signs and what the handler verifies the opening against.
    fn note_commitment(&self) -> [u8; 32] {
        self.opening()
            .commitment()
            .expect("test opening must be Fr-safe")
    }

    fn sign(&self, key: &SigningKey) -> serde_json::Value {
        let note_commitment = self.note_commitment();
        let canonical = OrderCanonical {
            symbol: &self.symbol,
            side: self.side,
            order_type: self.order_type,
            amount: self.amount,
            price_limit: self.price_limit,
            min_fill_size: self.min_fill_size,
            expiry_slot: self.expiry_slot,
            order_id: self.order_id,
            note_commitment,
            user_commitment: self.user_commitment,
            arrival_nonce: self.arrival_nonce,
        };
        let digest = canonical.digest().unwrap();
        let sig = key.sign(&digest);
        let trading_key = key.verifying_key().to_bytes();

        json!({
            "symbol": std::str::from_utf8(&self.symbol).unwrap(),
            "side": match self.side { OrderSide::Bid => "bid", OrderSide::Ask => "ask" },
            "order_type": match self.order_type {
                OrderType::Limit => "limit",
                OrderType::Ioc => "ioc",
                OrderType::Fok => "fok",
            },
            "amount": self.amount,
            "price_limit": self.price_limit,
            "min_fill_size": self.min_fill_size,
            "expiry_slot": self.expiry_slot,
            "order_id": hex::encode(self.order_id),
            "note_commitment": hex::encode(note_commitment),
            "user_commitment": hex::encode(self.user_commitment),
            "arrival_nonce": self.arrival_nonce,
            "trading_key": hex::encode(trading_key),
            "trading_key_signature": hex::encode(sig.to_bytes()),
            "owner_commitment": hex::encode(self.owner_commitment),
            "note_nonce": hex::encode(self.note_nonce),
            "note_blinding": hex::encode(self.note_blinding),
            "nullifier": hex::encode(self.nullifier),
            // VALID_INPUT proof relay (4g.7c). Intake stores these
            // opaquely (on-chain lock_note verifies the proof), so
            // dummy bytes are fine for the orders-surface tests.
            "merkle_root": hex::encode([0xDDu8; 32]),
            "valid_input_proof": hex::encode([0u8; 256]),
        })
    }
}

async fn place(app: &Router, bearer: &str, body: serde_json::Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get_order(app: &Router, bearer: &str, order_id_hex: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{order_id_hex}"))
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn cancel(
    app: &Router,
    bearer: &str,
    order_id_hex: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orders/{order_id_hex}"))
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn cancel_body(key: &SigningKey, order_id: [u8; 16], cancel_nonce: u64) -> serde_json::Value {
    let trading_key = key.verifying_key().to_bytes();
    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce,
    };
    let sig = key.sign(&cancel.digest());
    json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": cancel_nonce,
        "trading_key_signature": hex::encode(sig.to_bytes()),
    })
}

// ─── POST /orders — happy path + retrieval ──────────────────────────────────

#[tokio::test]
async fn place_happy_path_returns_202_and_lands_in_book() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let builder = PlaceOrderBuilder::new();
    let body = builder.sign(&key);

    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let json = read_json(resp).await;
    assert_eq!(json["status"], "accepted");
    assert_eq!(json["order_id"], hex::encode(builder.order_id));
    assert!(json["arrival_slot"].as_u64().is_some());

    // Confirm the order is in the book via GET.
    let get_resp = get_order(&app, &bearer, &hex::encode(builder.order_id)).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    let status_json = read_json(get_resp).await;
    assert_eq!(status_json["side"], "bid");
    assert_eq!(status_json["order_type"], "limit");
    assert_eq!(status_json["status"], "pending");
    assert_eq!(status_json["amount"], builder.amount);
}

#[tokio::test]
async fn place_populates_opening_store_keyed_by_commitment_and_cancel_clears_it() {
    // 4g.7c: a placed order's settle inputs (opening + order_id +
    // VALID_INPUT proof relay) land in the in-enclave store keyed by
    // the collateral note commitment, and a cancel drops them.
    let matcher_state = Arc::new(tokio::sync::RwLock::new(MatcherState::new()));
    let current_slot = Arc::new(AtomicU64::new(1));
    let api = ApiState::for_tests().with_matcher_runtime(
        matcher_state.clone(),
        current_slot,
        OracleCache::new(),
    );
    let app = app_from(Arc::new(api));
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let note_commitment = b.note_commitment();

    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    {
        let st = matcher_state.read().await;
        assert_eq!(st.openings().len(), 1);
        let rec = st
            .openings()
            .get(&note_commitment)
            .expect("opening stored under the collateral note commitment");
        assert_eq!(rec.order_id, b.order_id);
        assert_eq!(rec.expiry_slot, b.expiry_slot);
        assert_eq!(rec.opening.nullifier, b.nullifier);
    }

    let c = cancel(
        &app,
        &bearer,
        &hex::encode(b.order_id),
        cancel_body(&key, b.order_id, 1),
    )
    .await;
    assert_eq!(c.status(), StatusCode::OK);
    {
        let st = matcher_state.read().await;
        assert!(
            st.openings().is_empty(),
            "cancel must drop the in-enclave opening"
        );
    }
}

// ─── POST /orders — input validation ────────────────────────────────────────

#[tokio::test]
async fn place_rejects_zero_order_id() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    b.order_id = [0u8; 16];
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn place_rejects_zero_price_bid() {
    // A bid with price_limit == 0 is economically meaningless and its
    // collateral computation would silently fall back to base units.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    b.side = OrderSide::Bid;
    b.price_limit = 0;
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn place_rejects_non_fr_safe_user_commitment() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    b.user_commitment = [0xFF; 32]; // top byte non-zero
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Body is plain text via axum's (StatusCode, String) responder.
    // Spot-check the reason explains the constraint so future
    // refactors don't silently swap the error message.
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("BN254 Fr") || body_str.contains("top byte"),
        "400 body should explain the Fr-safety constraint; got: {body_str}"
    );
}

#[tokio::test]
async fn place_rejects_malformed_hex_order_id() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    body["order_id"] = json!("not-hex-xx");
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn place_rejects_wrong_width_note_commitment() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    // 31 bytes instead of 32.
    body["note_commitment"] = json!(hex::encode([0x22u8; 31]));
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn place_rejects_oversize_symbol() {
    // We can't go through PlaceOrderBuilder::sign() here — the
    // canonical encoder refuses to encode a > SYMBOL_MAX_LEN
    // symbol locally. The handler enforces the same cap BEFORE
    // attempting Ed25519 verify, so we can craft a JSON body with
    // an oversize symbol + an arbitrary 64-byte sig + a real
    // pubkey and expect a 400 at the length-check stage.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    b.symbol = vec![b'A'; SYMBOL_MAX_LEN_FOR_TEST]; // ≤ 32 so sign() works
    let mut body = b.sign(&key);
    // Now swap in an oversize symbol AFTER signing.
    body["symbol"] = json!(String::from_utf8(vec![b'X'; 64]).unwrap());
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

const SYMBOL_MAX_LEN_FOR_TEST: usize = 8; // "SOL-USDC" length

#[tokio::test]
async fn place_rejects_opening_not_matching_commitment() {
    // The opening fields are NOT part of the signed canonical body
    // (they're pinned via the commitment check instead). Tamper a
    // nonce after signing: the trading-key signature still verifies
    // (note_nonce isn't in the canonical digest), but the opening now
    // reconstructs to a different commitment than the signed one — so
    // intake must reject with 400.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    body["note_nonce"] = json!(hex::encode({
        let mut v = [0u8; 32];
        v[31] = 0xEE; // Fr-safe but different from the signed opening's nonce
        v
    }));
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("note opening does not match") || body_str.contains("note_commitment"),
        "400 body should explain the opening mismatch; got: {body_str}"
    );
}

// ─── POST /orders — signature checks ────────────────────────────────────────

#[tokio::test]
async fn place_rejects_signature_from_wrong_key() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let signer = fresh_signing_key();
    let impostor = fresh_signing_key();

    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&signer);
    // Swap in the impostor's pubkey while keeping the signer's
    // signature — the verify_strict call must reject this.
    body["trading_key"] = json!(hex::encode(impostor.verifying_key().to_bytes()));
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn place_rejects_tampered_amount_after_signing() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    // Bump amount after the signature was computed — the canonical
    // digest the server reconstructs no longer matches.
    body["amount"] = json!(b.amount + 1);
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn place_rejects_invalid_trading_key_bytes() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    // All-zero pubkey — not a valid Ed25519 point. VerifyingKey
    // construction rejects.
    body["trading_key"] = json!(hex::encode([0u8; 32]));
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── POST /orders — book conflicts + auth ───────────────────────────────────

#[tokio::test]
async fn place_rejects_duplicate_order_id_with_409() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let body = b.sign(&key);

    let r1 = place(&app, &bearer, body.clone()).await;
    assert_eq!(r1.status(), StatusCode::ACCEPTED);

    let r2 = place(&app, &bearer, body).await;
    assert_eq!(r2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn place_rejects_missing_bearer_with_401() {
    let app = app_from(state());
    let key = fresh_signing_key();
    let body = PlaceOrderBuilder::new().sign(&key);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn place_returns_503_when_matcher_uninitialised() {
    // Build a stripped-down state that mimics from_boot's pre-
    // matcher state (matcher = None). The auth path remains
    // available — we still want the orders 503 to surface the
    // matcher-readiness signal explicitly.
    let mut st = ApiState::for_tests();
    st.matcher = None;
    let app = app_from(Arc::new(st));

    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let body = PlaceOrderBuilder::new().sign(&key);

    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ─── DELETE /orders/{id} ────────────────────────────────────────────────────

#[tokio::test]
async fn cancel_happy_path_removes_from_book() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let body = b.sign(&key);

    let p = place(&app, &bearer, body).await;
    assert_eq!(p.status(), StatusCode::ACCEPTED);

    let resp = cancel(
        &app,
        &bearer,
        &hex::encode(b.order_id),
        cancel_body(&key, b.order_id, 1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["status"], "cancelled");

    // GET now 404s — order is gone.
    let g = get_order(&app, &bearer, &hex::encode(b.order_id)).await;
    assert_eq!(g.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_rejects_different_trading_key_with_403() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let owner = fresh_signing_key();
    let impostor = fresh_signing_key();

    let b = PlaceOrderBuilder::new();
    place(&app, &bearer, b.sign(&owner)).await;

    // Cancel signed by impostor — has a valid signature against
    // its own pubkey, but the book entry is owned by `owner`.
    // verify_sig PASSES (sig is internally consistent); book.cancel
    // returns NotOwner.
    let resp = cancel(
        &app,
        &bearer,
        &hex::encode(b.order_id),
        cancel_body(&impostor, b.order_id, 1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cancel_rejects_tampered_signature_with_403() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    place(&app, &bearer, b.sign(&key)).await;

    let mut body = cancel_body(&key, b.order_id, 1);
    // Bump cancel_nonce after signing — canonical digest now differs.
    body["cancel_nonce"] = json!(99);
    let resp = cancel(&app, &bearer, &hex::encode(b.order_id), body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cancel_returns_404_for_unknown_order() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let unknown = {
        let mut o = [0u8; 16];
        o[0] = 0xDE;
        o[15] = 1;
        o
    };
    let resp = cancel(
        &app,
        &bearer,
        &hex::encode(unknown),
        cancel_body(&key, unknown, 1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_rejects_missing_bearer_with_401() {
    let app = app_from(state());
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orders/{}", hex::encode(b.order_id)))
                .header("content-type", "application/json")
                .body(Body::from(cancel_body(&key, b.order_id, 1).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── GET /orders/{id} ───────────────────────────────────────────────────────

#[tokio::test]
async fn get_returns_404_when_not_in_book() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let unknown = {
        let mut o = [0u8; 16];
        o[0] = 0xCA;
        o[15] = 1;
        o
    };
    let resp = get_order(&app, &bearer, &hex::encode(unknown)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_rejects_malformed_path() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let resp = get_order(&app, &bearer, "not-hex").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_rejects_missing_bearer_with_401() {
    let app = app_from(state());
    let oid = [0xAAu8; 16];
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", hex::encode(oid)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
