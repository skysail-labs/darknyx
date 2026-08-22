//! End-to-end tests for the orders surface
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
//!     zero order_id.
//!   - 202 on an Fr-safe `owner_commitment` with a non-zero top byte (T-07).
//!   - 403 on signature mismatch (wrong trading_key sigs the body).
//!   - 409 on duplicate order_id submission.
//!   - 401 on missing / invalid bearer.
//!   - Cancel: happy path; 403 if signed by a different trading_key;
//!     404 if order doesn't exist; replay protection via cancel_nonce
//!     being part of the canonical bytes.
//!   - GET 200 after submit, 404 after cancel.
//!
//! Run with: `cargo test -p darknyx-tee --test orders_surface`

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use darknyx_tee::api::auth::{ApiCredentials, Claims, TEST_API_KEY, TEST_JWT_SECRET};
use darknyx_tee::api::instruments::InstrumentInfo;
use darknyx_tee::api::{build_router, ApiState};
use darknyx_tee::matcher::openings::NoteOpening;
use darknyx_tee::matcher::MatcherState;
use darknyx_tee::oracle::cache::OracleCache;
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::order_canonical::{CancelCanonical, OrderCanonical};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
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
    bearer_for(TEST_API_KEY, "test-jti")
}

/// The account id the ownership-privacy tests authenticate as when acting as
/// "somebody else".
const FOREIGN_ACCOUNT: &str = "foreign-account";

/// State with a SECOND registered account, for tests that need a caller who is
/// authenticated but is not the order's owner.
///
/// Token validation resolves the caller against the live registry, so an
/// identity has to actually exist for its token to be accepted — in production
/// one can only be minted through `POST /auth/token`, which requires the
/// account. Minting a token for an unregistered id is not a case that can
/// occur, and it is refused before any handler runs.
async fn state_with_foreign_account() -> Arc<ApiState> {
    let st = state();
    let creds = ApiCredentials::from_plaintext(FOREIGN_ACCOUNT, "foreign-s", "foreign-p", false)
        .expect("hash foreign account");
    st.accounts.write().await.register(creds);
    st
}

fn bearer_for(account_id: &str, jti: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: account_id.to_string(),
        iat: now,
        exp: now + 60,
        jti: jti.to_string(),
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
    arrival_nonce: u64,
    // Input-note opening. The note_commitment is DERIVED from
    // these via NoteOpening::commitment() so the handler's intake
    // verification passes; tests that want to break the opening
    // override the emitted JSON directly.
    owner_commitment: [u8; 32],
    note_inner_hash: [u8; 32],
    viewing_pubkey: [u8; 32],
    session_id: [u8; 32],
    /// Over-collateralization: when set, the collateral note carries this
    /// amount (≥ the derived floor) and the JSON declares `collateral_amount`.
    /// `None` ⇒ exact collateral (the opening amount == the derived floor).
    collateral_amount: Option<u64>,
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
            // Within MAX_LOCK_TTL_SLOTS (4_500, F-05) of the test current_slot (1).
            expiry_slot: 4_000,
            order_id: {
                let mut o = [0u8; 16];
                o[0] = 0xAA;
                o[15] = 1;
                o
            },
            arrival_nonce: 1,
            owner_commitment: fr_safe(0x44),
            note_inner_hash: fr_safe(0x55),
            viewing_pubkey: darkpool_crypto::ephemeral_public(&[0x21; 32]),
            session_id: [0x5A; 32],
            collateral_amount: None,
        }
    }

    /// Over-collateralize: the collateral note carries `c` (≥ the floor) and the
    /// JSON declares `collateral_amount: c`.
    fn with_collateral_amount(mut self, c: u64) -> Self {
        self.collateral_amount = Some(c);
        self
    }

    /// The minimum collateral the handler requires (bid → amount × price; ask →
    /// amount). MUST match the handler's `required` floor (the test market has a
    /// zero fee rate, so no fee term).
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

    /// The amount the collateral note actually carries — `collateral_amount`
    /// when over-collateralizing, else the floor. The opening + commitment are
    /// built against THIS, mirroring the handler's `note_amount`.
    fn effective_collateral(&self) -> u64 {
        self.collateral_amount.unwrap_or_else(|| self.note_amount())
    }

    /// The opening the handler will reconstruct + verify. The test
    /// market (`MatcherState::new()`) has zeroed mints, so the
    /// collateral mint is `[0; 32]` for both sides.
    fn opening(&self) -> NoteOpening {
        NoteOpening {
            token_mint: [0u8; 32],
            amount: self.effective_collateral(),
            owner_commitment: self.owner_commitment,
            inner_hash: self.note_inner_hash,
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
            arrival_nonce: self.arrival_nonce,
            viewing_pubkey: self.viewing_pubkey,
            session_id: self.session_id,
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
            "arrival_nonce": self.arrival_nonce,
            "trading_key": hex::encode(trading_key),
            "trading_key_signature": hex::encode(sig.to_bytes()),
            "owner_commitment": hex::encode(self.owner_commitment),
            "note_inner_hash": hex::encode(self.note_inner_hash),
            // VALID_INPUT proof relay. Intake stores these
            // opaquely (on-chain lock_note verifies the proof), so
            // dummy bytes are fine for the orders-surface tests.
            "merkle_root": hex::encode([0xDDu8; 32]),
            "valid_input_proof": hex::encode([0u8; 256]),
            // null when None (handler's `#[serde(default)]` → exact collateral).
            "collateral_amount": self.collateral_amount,
            "viewing_pubkey": hex::encode(self.viewing_pubkey),
            "session_id": hex::encode(self.session_id),
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

/// Matches `ApiState::for_tests()`'s boot session and the PlaceOrderBuilder.
const TEST_SESSION_ID: [u8; 32] = [0x5A; 32];

fn cancel_body(key: &SigningKey, order_id: [u8; 16], cancel_nonce: u64) -> serde_json::Value {
    let trading_key = key.verifying_key().to_bytes();
    let cancel = CancelCanonical {
        order_id,
        trading_key,
        cancel_nonce,
        session_id: TEST_SESSION_ID,
    };
    let sig = key.sign(&cancel.digest());
    json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": cancel_nonce,
        "session_id": hex::encode(TEST_SESSION_ID),
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
async fn place_accepts_over_collateralized_order() {
    // Over-collateralization: lock a note worth 50% more than the order needs.
    // Intake must accept it (the opening verifies against the signed commitment
    // for the larger amount); the surplus comes back as a change note at settle.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let builder = PlaceOrderBuilder::new();
    let floor = builder.note_amount();
    let over = builder.with_collateral_amount(floor + floor / 2);

    let resp = place(&app, &bearer, over.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = read_json(resp).await;
    assert_eq!(json["status"], "accepted");

    // The order is in the book; its order amount is unchanged (the extra
    // collateral does not change WHAT is traded, only the change returned).
    let get_resp = get_order(&app, &bearer, &hex::encode(over.order_id)).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(read_json(get_resp).await["amount"], over.amount);
}

#[tokio::test]
async fn place_rejects_collateral_below_the_required_floor() {
    // A declared collateral_amount below the order's required floor (it could
    // not pay its own fee / cover the trade) is rejected with 400 — BEFORE the
    // opening is even built (the signature is already verified by then).
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let builder = PlaceOrderBuilder::new();
    let floor = builder.note_amount();
    let under = builder.with_collateral_amount(floor - 1);

    let resp = place(&app, &bearer, under.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn place_populates_opening_store_keyed_by_commitment_and_cancel_clears_it() {
    // A placed order's settle inputs (opening + order_id +
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

#[tokio::test]
async fn symbols_route_to_independent_market_books() {
    let sol = Arc::new(tokio::sync::RwLock::new(MatcherState::new()));
    let btc = Arc::new(tokio::sync::RwLock::new(MatcherState::new()));
    let api = ApiState::for_tests()
        .with_instruments(vec![
            InstrumentInfo {
                symbol: "SOL-USDC".to_string(),
                base_mint: [0; 32],
                quote_mint: [0; 32],
                tick_size: 1,
                min_order_size: 0,
                oracle_feed_id: "aa".repeat(32),
            },
            InstrumentInfo {
                symbol: "BTC-USDC".to_string(),
                base_mint: [0; 32],
                quote_mint: [0; 32],
                tick_size: 1,
                min_order_size: 0,
                oracle_feed_id: "bb".repeat(32),
            },
        ])
        .with_market_runtimes(
            HashMap::from([
                ("SOL-USDC".to_string(), sol.clone()),
                ("BTC-USDC".to_string(), btc.clone()),
            ]),
            Arc::new(AtomicU64::new(1)),
            OracleCache::new(),
        );
    let app = app_from(Arc::new(api));
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let sol_order = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, sol_order.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    let mut btc_order = PlaceOrderBuilder::new();
    btc_order.symbol = b"BTC-USDC".to_vec();
    btc_order.order_id[0] = 0xBB;
    btc_order.arrival_nonce = 2;
    assert_eq!(
        place(&app, &bearer, btc_order.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    assert_eq!(sol.read().await.book().len(), 1);
    assert_eq!(btc.read().await.book().len(), 1);
    assert!(sol.read().await.book().get(&btc_order.order_id).is_none());
    assert!(btc.read().await.book().get(&sol_order.order_id).is_none());

    let mut cross_market_replacement = PlaceOrderBuilder::new();
    cross_market_replacement.symbol = b"BTC-USDC".to_vec();
    cross_market_replacement.order_id[0] = 0xCC;
    cross_market_replacement.arrival_nonce = 3;
    let response = modify(
        &app,
        &bearer,
        &hex::encode(sol_order.order_id),
        modify_body(
            &key,
            sol_order.order_id,
            1,
            cross_market_replacement.sign(&key),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        sol.read().await.book().len(),
        1,
        "cross-market modify must leave the original resting"
    );
}

#[tokio::test]
async fn oracle_pause_rejects_only_the_affected_market() {
    let sol = Arc::new(tokio::sync::RwLock::new(MatcherState::new()));
    let btc = Arc::new(tokio::sync::RwLock::new(MatcherState::new()));
    let api = ApiState::for_tests()
        .with_instruments(vec![
            InstrumentInfo {
                symbol: "SOL-USDC".to_string(),
                base_mint: [0; 32],
                quote_mint: [0; 32],
                tick_size: 1,
                min_order_size: 0,
                oracle_feed_id: "aa".repeat(32),
            },
            InstrumentInfo {
                symbol: "BTC-USDC".to_string(),
                base_mint: [0; 32],
                quote_mint: [0; 32],
                tick_size: 1,
                min_order_size: 0,
                oracle_feed_id: "bb".repeat(32),
            },
        ])
        .with_market_runtimes(
            HashMap::from([
                ("SOL-USDC".to_string(), sol.clone()),
                ("BTC-USDC".to_string(), btc.clone()),
            ]),
            Arc::new(AtomicU64::new(1)),
            OracleCache::new(),
        );
    let sol_gate = api.trading_gate_for_symbol("SOL-USDC").expect("SOL gate");
    let btc_gate = api.trading_gate_for_symbol("BTC-USDC").expect("BTC gate");
    sol_gate.pause_for(darknyx_tee::matcher::TradingPauseReason::Oracle);
    assert!(btc_gate.is_open(), "BTC must remain tradable");

    let app = app_from(Arc::new(api));
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let sol_order = PlaceOrderBuilder::new();
    let response = place(&app, &bearer, sol_order.sign(&key)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(sol.read().await.book().len(), 0);

    let mut btc_order = PlaceOrderBuilder::new();
    btc_order.symbol = b"BTC-USDC".to_vec();
    btc_order.order_id[0] = 0xBC;
    let response = place(&app, &bearer, btc_order.sign(&key)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(btc.read().await.book().len(), 1);
    assert!(
        sol_gate.is_paused_for(darknyx_tee::matcher::TradingPauseReason::Oracle),
        "healthy BTC intake cannot clear the SOL oracle pause"
    );
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
async fn place_enforces_governed_tick_and_keeps_zero_limit_market_asks() {
    let market = InstrumentInfo {
        symbol: "SOL-USDC".to_string(),
        base_mint: [0u8; 32],
        quote_mint: [0u8; 32],
        tick_size: 10,
        min_order_size: 0,
        oracle_feed_id: "feed".to_string(),
    };

    let app = app_from(Arc::new(
        ApiState::for_tests().with_instruments(vec![market.clone()]),
    ));
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut off_tick = PlaceOrderBuilder::new();
    off_tick.price_limit += 1;
    let resp = place(&app, &bearer, off_tick.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_json(resp).await["code"], 1009);

    let app = app_from(Arc::new(
        ApiState::for_tests().with_instruments(vec![market]),
    ));
    let mut market_ask = PlaceOrderBuilder::new();
    market_ask.side = OrderSide::Ask;
    market_ask.price_limit = 0;
    let resp = place(&app, &bearer, market_ask.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn governance_pause_rejects_place_but_keeps_cancel_available() {
    let state = state();
    let app = app_from(state.clone());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let order = PlaceOrderBuilder::new();

    let resp = place(&app, &bearer, order.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert!(state.trading_gate.pause());

    let mut replacement = PlaceOrderBuilder::new();
    replacement.order_id[15] = 2;
    replacement.arrival_nonce = 2;
    let resp = place(&app, &bearer, replacement.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(read_json(resp).await["code"], 5001);

    let resp = cancel(
        &app,
        &bearer,
        &hex::encode(order.order_id),
        cancel_body(&key, order.order_id, 1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn place_rejects_expiry_beyond_lock_ttl_cap() {
    // F-05: the settler stamps the note lock with the order's expiry_slot, and
    // the vault caps the lock window at MAX_LOCK_TTL_SLOTS. Intake rejects an
    // order whose expiry exceeds current_slot + cap up front (clean 400), so it
    // can't match only to fail later at settle-time lock_note.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    // Test state's current_slot is 1; MAX_LOCK_TTL_SLOTS is 4_500 — well past it.
    b.expiry_slot = 5_000_000;
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["code"], 1007); // expiry_too_far
                                    // And it never landed in the book.
    let get_resp = get_order(&app, &bearer, &hex::encode(b.order_id)).await;
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn place_rejects_expiry_inside_the_settlement_buffer() {
    // Test current_slot is 1 and SETTLEMENT_BUFFER_SLOTS is 20. Zero used to
    // return 202, enter the book, and disappear on the next tick, which made a
    // browser GTC order look accepted even though it could never settle.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    b.expiry_slot = 0;
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["code"], 1012);
    let get_resp = get_order(&app, &bearer, &hex::encode(b.order_id)).await;
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

/// T-07 regression, stated as the property that was BROKEN rather than the
/// check that was deleted.
///
/// Intake used to reject any order whose `user_commitment` had a non-zero top
/// byte, calling it "BN254 Fr safety". That is not what Fr-safety means: the
/// modulus begins `0x30`, so a canonical element's top byte is anything in
/// `0x00..=0x30`. Requiring exactly `0x00` rejected ~98% of legitimate values,
/// and the field was not hashed by anything anyway.
///
/// `owner_commitment` IS hashed (`NoteOpening::verify_commitment`), so it is the
/// honest test of the same band: a top byte of `0x2F` is comfortably below the
/// modulus and must be ACCEPTED. Under the old rule the analogous value was a
/// 400. Asserting acceptance — not the absence of an error string — is what
/// proves the band actually reopened.
#[tokio::test]
async fn place_accepts_an_fr_safe_owner_commitment_with_a_non_zero_top_byte() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut b = PlaceOrderBuilder::new();
    // 0x2F2F..2F < 0x3064...01 (the BN254 scalar modulus), so this is a
    // canonical field element that the pre-T-07 top-byte rule would have
    // rejected out of hand.
    b.owner_commitment = [0x2F; 32];
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a canonical Fr element with a non-zero top byte must be accepted"
    );

    // And it really booked — a 202 that did not reach the book would be the
    // same class of "passes without doing anything" this audit keeps finding.
    let get_resp = get_order(&app, &bearer, &hex::encode(b.order_id)).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
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
    // (they're pinned via the commitment check instead). Tamper the
    // inner_hash after signing: the trading-key signature still verifies
    // (note_inner_hash isn't in the canonical digest), but the opening now
    // reconstructs to a different commitment than the signed one — so
    // intake must reject with 400.
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    body["note_inner_hash"] = json!(hex::encode({
        let mut v = [0u8; 32];
        v[31] = 0xEE; // Fr-safe but different from the signed opening's inner_hash
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

#[tokio::test]
async fn place_rejects_viewing_key_tampered_after_signing() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let mut body = b.sign(&key);
    body["viewing_pubkey"] = json!(hex::encode(darkpool_crypto::ephemeral_public(&[0x22; 32])));
    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn place_rejects_low_order_viewing_key_and_stale_session() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let mut low = PlaceOrderBuilder::new();
    low.viewing_pubkey = [0u8; 32];
    let resp = place(&app, &bearer, low.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_json(resp).await["code"], 1008);

    let mut stale = PlaceOrderBuilder::new();
    stale.order_id[1] = 1;
    stale.session_id = [0x6B; 32];
    let resp = place(&app, &bearer, stale.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(read_json(resp).await["code"], 1205);
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
async fn place_is_idempotent_on_same_body_but_409s_on_a_different_body_reusing_the_id() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let body = b.sign(&key);

    // First accept.
    let r1 = place(&app, &bearer, body.clone()).await;
    assert_eq!(r1.status(), StatusCode::ACCEPTED);
    let j1 = read_json(r1).await;

    // A true retry (byte-identical signed body) is idempotent → 202 again with
    // the SAME order_id, not a 409.
    let r2 = place(&app, &bearer, body).await;
    assert_eq!(r2.status(), StatusCode::ACCEPTED);
    let j2 = read_json(r2).await;
    assert_eq!(j1["order_id"], j2["order_id"]);

    // A DIFFERENT order reusing the same order_id (changed amount, re-signed) is
    // a real conflict → 409, code 1201.
    let mut c = PlaceOrderBuilder::new();
    c.amount = b.amount + 1; // changes the canonical digest
    let r3 = place(&app, &bearer, c.sign(&key)).await;
    assert_eq!(r3.status(), StatusCode::CONFLICT);
    let j3 = read_json(r3).await;
    assert_eq!(j3["code"], 1201);
}

#[tokio::test]
async fn collateral_commitment_is_reserved_until_the_order_is_cancelled() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let a = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, a.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    // Different order id, byte-identical collateral opening. It must not
    // overwrite A's OpeningStore record.
    let mut b = PlaceOrderBuilder::new();
    b.order_id = [0xBB; 16];
    b.arrival_nonce = 2;
    let conflict = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(read_json(conflict).await["code"], 1204);
    assert_eq!(
        get_order(&app, &bearer, &hex::encode(a.order_id))
            .await
            .status(),
        StatusCode::OK,
        "the original reservation must remain intact"
    );

    // Cancellation releases both the book entry and its collateral
    // reservation, after which B can use the note.
    assert_eq!(
        cancel(
            &app,
            &bearer,
            &hex::encode(a.order_id),
            cancel_body(&key, a.order_id, 1),
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        place(&app, &bearer, b.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn arrival_nonce_strictly_increases_after_exact_idempotency() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let first = PlaceOrderBuilder::new();
    let exact = first.sign(&key);
    assert_eq!(
        place(&app, &bearer, exact.clone()).await.status(),
        StatusCode::ACCEPTED
    );
    // Exact retry is checked before the nonce high-water mark.
    assert_eq!(
        place(&app, &bearer, exact).await.status(),
        StatusCode::ACCEPTED
    );

    let mut stale = PlaceOrderBuilder::new();
    stale.order_id = [0xBC; 16];
    // Same key + same nonce, but a different canonical body.
    let resp = place(&app, &bearer, stale.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(read_json(resp).await["code"], 1202);

    stale.order_id = [0xBD; 16];
    stale.arrival_nonce = 2;
    // Give it distinct collateral so the replay check is the only conflict.
    stale.note_inner_hash[31] = 0x56;
    assert_eq!(
        place(&app, &bearer, stale.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );
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
async fn cancel_returns_the_same_404_for_foreign_and_unknown_orders() {
    let app = app_from(state_with_foreign_account().await);
    let owner_bearer = fresh_bearer();
    let foreign_bearer = bearer_for(FOREIGN_ACCOUNT, "foreign-cancel-jti");
    let key = fresh_signing_key();
    let order = PlaceOrderBuilder::new();
    let order_id_hex = hex::encode(order.order_id);

    assert_eq!(
        place(&app, &owner_bearer, order.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    let foreign = cancel(
        &app,
        &foreign_bearer,
        &order_id_hex,
        cancel_body(&key, order.order_id, 1),
    )
    .await;
    let unknown_id = [0xCC; 16];
    let unknown = cancel(
        &app,
        &foreign_bearer,
        &hex::encode(unknown_id),
        cancel_body(&key, unknown_id, 1),
    )
    .await;

    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(read_json(foreign).await, read_json(unknown).await);
    assert_eq!(
        get_order(&app, &owner_bearer, &order_id_hex).await.status(),
        StatusCode::OK,
        "a foreign cancel must not mutate the owner's order"
    );
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
async fn get_returns_the_same_404_for_foreign_and_unknown_orders() {
    let app = app_from(state_with_foreign_account().await);
    let owner_bearer = fresh_bearer();
    let foreign_bearer = bearer_for(FOREIGN_ACCOUNT, "foreign-jti");
    let key = fresh_signing_key();
    let order = PlaceOrderBuilder::new();
    let order_id_hex = hex::encode(order.order_id);

    assert_eq!(
        place(&app, &owner_bearer, order.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    let foreign = get_order(&app, &foreign_bearer, &order_id_hex).await;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let foreign_body = read_json(foreign).await;

    let unknown = get_order(&app, &foreign_bearer, &hex::encode([0xCC; 16])).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let unknown_body = read_json(unknown).await;

    assert_eq!(foreign_body, unknown_body);
    assert_eq!(foreign_body["code"], 1301);
    assert_eq!(foreign_body["message"], "order not found");
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

// ─── PUT /orders/{id} — atomic cancel + replace (modify) ────────────────────

async fn modify(
    app: &Router,
    bearer: &str,
    old_id_hex: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orders/{old_id_hex}"))
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn modify_body(
    key: &SigningKey,
    old_id: [u8; 16],
    cancel_nonce: u64,
    replacement: serde_json::Value,
) -> serde_json::Value {
    let trading_key = key.verifying_key().to_bytes();
    let cancel = CancelCanonical {
        order_id: old_id,
        trading_key,
        cancel_nonce,
        session_id: TEST_SESSION_ID,
    };
    let sig = key.sign(&cancel.digest());
    json!({
        "cancel_signature": hex::encode(sig.to_bytes()),
        "cancel_nonce": cancel_nonce,
        "replacement": replacement,
    })
}

#[tokio::test]
async fn modify_swaps_old_order_for_new_atomically() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let a = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, a.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    // Replacement B: new order_id + distinct note (different inner_hash).
    let mut b = PlaceOrderBuilder::new();
    b.order_id = {
        let mut o = [0u8; 16];
        o[0] = 0xBB;
        o[15] = 2;
        o
    };
    b.note_inner_hash = {
        let mut v = [0x56u8; 32];
        v[0] = 0;
        v
    };
    b.arrival_nonce = 2;

    let resp = modify(
        &app,
        &bearer,
        &hex::encode(a.order_id),
        modify_body(&key, a.order_id, 1, b.sign(&key)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["status"], "modified");
    assert_eq!(json["old_order_id"], hex::encode(a.order_id));
    assert_eq!(json["order_id"], hex::encode(b.order_id));

    // Old gone, new resting.
    assert_eq!(
        get_order(&app, &bearer, &hex::encode(a.order_id))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_order(&app, &bearer, &hex::encode(b.order_id))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn modify_reprice_in_place_keeps_the_same_id() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let a = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, a.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    // Same order_id, new price (a reprice). The note must cover the new
    // collateral, so keep price (and thus note_amount) unchanged here; bump the
    // min_fill instead to prove the canonical body was re-signed + re-committed.
    let mut b = PlaceOrderBuilder::new();
    b.min_fill_size = 1;
    b.arrival_nonce = 2;

    let resp = modify(
        &app,
        &bearer,
        &hex::encode(a.order_id),
        modify_body(&key, a.order_id, 1, b.sign(&key)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["order_id"], hex::encode(a.order_id), "same id reused");

    assert_eq!(
        get_order(&app, &bearer, &hex::encode(a.order_id))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn modify_non_owner_is_forbidden() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let owner = fresh_signing_key();
    let attacker = fresh_signing_key();

    let a = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, a.sign(&owner)).await.status(),
        StatusCode::ACCEPTED
    );

    // Attacker signs both the cancel + the replacement → cancel sig verifies, but
    // the booked order is owned by `owner`, so the swap is rejected (and nothing
    // is mutated — atomic precondition check).
    let mut b = PlaceOrderBuilder::new();
    b.order_id = {
        let mut o = [0u8; 16];
        o[0] = 0xCC;
        o
    };
    let resp = modify(
        &app,
        &bearer,
        &hex::encode(a.order_id),
        modify_body(&attacker, a.order_id, 1, b.sign(&attacker)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Old order untouched.
    assert_eq!(
        get_order(&app, &bearer, &hex::encode(a.order_id))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn modify_returns_the_same_404_for_foreign_and_unknown_orders() {
    let app = app_from(state_with_foreign_account().await);
    let owner_bearer = fresh_bearer();
    let foreign_bearer = bearer_for(FOREIGN_ACCOUNT, "foreign-modify-jti");
    let key = fresh_signing_key();
    let original = PlaceOrderBuilder::new();
    let original_id_hex = hex::encode(original.order_id);

    assert_eq!(
        place(&app, &owner_bearer, original.sign(&key))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let mut replacement = PlaceOrderBuilder::new();
    replacement.order_id = [0xDD; 16];
    replacement.arrival_nonce = 2;
    let foreign = modify(
        &app,
        &foreign_bearer,
        &original_id_hex,
        modify_body(&key, original.order_id, 1, replacement.sign(&key)),
    )
    .await;

    let unknown_id = [0xCC; 16];
    let unknown = modify(
        &app,
        &foreign_bearer,
        &hex::encode(unknown_id),
        modify_body(&key, unknown_id, 1, replacement.sign(&key)),
    )
    .await;

    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(read_json(foreign).await, read_json(unknown).await);
    assert_eq!(
        get_order(&app, &owner_bearer, &original_id_hex)
            .await
            .status(),
        StatusCode::OK,
        "a foreign modify must not mutate the owner's order"
    );
}

#[tokio::test]
async fn modify_collateral_conflict_leaves_both_existing_orders_untouched() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let a = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, a.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    let mut b = PlaceOrderBuilder::new();
    b.order_id = [0xB2; 16];
    b.note_inner_hash = {
        let mut inner = [0x62; 32];
        inner[0] = 0;
        inner
    };
    b.arrival_nonce = 2;
    assert_eq!(
        place(&app, &bearer, b.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );

    // C targets B's already-reserved collateral. The modify must reject before
    // cancelling A, preserving the atomic cancel+replace contract.
    let mut c = PlaceOrderBuilder::new();
    c.order_id = [0xC3; 16];
    c.note_inner_hash = b.note_inner_hash;
    c.arrival_nonce = 3;
    let resp = modify(
        &app,
        &bearer,
        &hex::encode(a.order_id),
        modify_body(&key, a.order_id, 1, c.sign(&key)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(read_json(resp).await["code"], 1204);

    for id in [a.order_id, b.order_id] {
        assert_eq!(
            get_order(&app, &bearer, &hex::encode(id)).await.status(),
            StatusCode::OK
        );
    }
}

// ─── error envelope + request-id correlation ────────────────────────────────

#[tokio::test]
async fn error_responses_use_the_structured_envelope_with_a_numeric_code() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    // A bid with the reserved all-zero order_id → 400 with the `malformed`
    // code (1001) and the message preserved in the JSON body.
    //
    // This used to drive the envelope with a non-Fr-safe `user_commitment`
    // (code 1002). T-07 deleted that check and the field; 1002 is retired.
    // Re-pointed at a live 400 rather than deleted, because what is under test
    // here is the ENVELOPE — numeric code, message passthrough, request-id
    // correlation — not the particular validation that produced it.
    let mut b = PlaceOrderBuilder::new();
    b.order_id = [0u8; 16]; // reserved RELOCK_ORDER_ID_NONE sentinel
    let resp = place(&app, &bearer, b.sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Every response carries a correlation id.
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "x-request-id header missing on error"
    );
    let j = read_json(resp).await;
    assert_eq!(j["code"], 1001, "malformed numeric code");
    assert!(
        j["message"].as_str().unwrap().contains("all-zero"),
        "message text preserved in the envelope: {j}"
    );
}

#[tokio::test]
async fn order_below_market_minimum_is_rejected_with_min_notional() {
    // A market whose minimum exceeds the builder's default amount (10_000_000).
    let st = ApiState::for_tests().with_instruments(vec![InstrumentInfo {
        symbol: "SOL-USDC".to_string(),
        base_mint: [0u8; 32],
        quote_mint: [0u8; 32],
        tick_size: 1,
        min_order_size: 20_000_000,
        oracle_feed_id: "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
            .to_string(),
    }]);
    let app = app_from(Arc::new(st));
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    // Default amount 10_000_000 < 20_000_000 minimum → 400, code 1004.
    let resp = place(&app, &bearer, PlaceOrderBuilder::new().sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = read_json(resp).await;
    assert_eq!(j["code"], 1004, "min_notional code");
}

#[tokio::test]
async fn success_responses_also_carry_a_request_id_header() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    let resp = place(&app, &bearer, PlaceOrderBuilder::new().sign(&key)).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "x-request-id header missing on success"
    );
    // Success bodies are NOT wrapped — still the plain typed shape.
    let j = read_json(resp).await;
    assert_eq!(j["status"], "accepted");
    assert!(
        j.get("code").is_none(),
        "success body must not be enveloped"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// S-02 (audit 2026-07-25) — intake verifies the relayed VALID_INPUT proof.
//
// Before this, `merkle_root` and `valid_input_proof` were decoded, stored, and
// handed to `lock_note` at settle time without ever being checked. Any
// credentialed client could book an order backed by a wholly fabricated note:
// the matcher would cross it against a real resting order, the honest side's
// lock would land, the fake side's would be rejected on-chain, and the batch
// would die — pinning an innocent counterparty's note under a NoteLock for up
// to MAX_LOCK_TTL_SLOTS at zero cost to the attacker.
//
// The checks are gated on `settle_enabled` because that is the same switch
// deciding whether these proofs ever reach the chain; the third test pins that
// the placeholder/loadgen path (stub proofs by design) is unaffected.
// ─────────────────────────────────────────────────────────────────────────────

/// A state that can actually settle — the configuration where an unverified
/// proof does real damage.
fn settling_state() -> Arc<ApiState> {
    Arc::new(ApiState::for_tests().with_settle_enabled(true))
}

#[tokio::test]
async fn place_rejects_stale_merkle_root_when_settlement_is_live() {
    // The builder's synthetic root was never in this mirror, so the cheap
    // recency check must reject before any pairing work happens.
    let app = app_from(settling_state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let body = PlaceOrderBuilder::new().sign(&key);

    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = read_json(resp).await;
    assert_eq!(
        j["code"], 1010,
        "an unknown merkle_root must surface as stale_merkle_root, got: {j}"
    );
}

#[tokio::test]
async fn place_rejects_stub_valid_input_proof_when_settlement_is_live() {
    // Give the mirror a real root so the recency gate passes and the PROOF
    // check is the thing under test. The all-zero stub proof the test harness
    // (and the loadgen) sends must not verify.
    let state = settling_state();
    let known_root = {
        let mirror = state.merkle_mirror(0);
        let mut m = mirror.write().await;
        let mut leaf = [0u8; 32];
        leaf[31] = 0x11;
        leaf[1] = 0x5A; // Fr-safe
        m.append_leaf(leaf).expect("seed the mirror");
        m.root()
    };

    let app = app_from(state);
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let mut body = PlaceOrderBuilder::new().sign(&key);
    // `merkle_root` is not part of the signed canonical body, so overriding it
    // after signing leaves the trading-key signature valid.
    body["merkle_root"] = json!(hex::encode(known_root));

    let resp = place(&app, &bearer, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = read_json(resp).await;
    assert_eq!(
        j["code"], 1011,
        "a stub proof over a known root must surface as invalid_input_proof, got: {j}"
    );
}

#[tokio::test]
async fn place_accepts_stub_proof_when_settlement_is_disabled() {
    // Placeholder/loadgen mode (U-09): no live settle driver, so the relayed
    // proof can never produce a lock_note and verifying it would only reject
    // traffic that is harmless by construction. This pins that the S-02 gate
    // did not break the loadgen regime.
    let app = app_from(state()); // for_tests() => settle_enabled == false
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let body = PlaceOrderBuilder::new().sign(&key);

    let resp = place(&app, &bearer, body).await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "stub proofs must still be accepted when settlement is disabled"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// S-07 (audit 2026-07-25) — cancel signatures are scoped and non-replayable.
//
// `OrderCanonical` was hardened with a boot session + monotonic nonce by
// CS-11; `CancelCanonical` was not. A captured cancel signature was therefore
// valid FOREVER, in ANY boot session, for its (order_id, trading_key,
// cancel_nonce) triple. Because order_ids are deterministic HD values clients
// are expected to re-derive, a stored cancel body could kill a legitimately
// re-placed order after a CVM restart — and anyone who ever handled that body
// (a logging proxy, a compromised client host, an operator's request logs, a
// backup) kept that ability indefinitely.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cancel_from_a_different_boot_session_is_rejected() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();
    let b = PlaceOrderBuilder::new();
    let body = b.sign(&key);
    assert_eq!(
        place(&app, &bearer, body).await.status(),
        StatusCode::ACCEPTED
    );

    // A cancel signed against a DIFFERENT boot session — the captured-body
    // scenario, replayed after a restart.
    let trading_key = key.verifying_key().to_bytes();
    let foreign_session = [0xA7u8; 32];
    let foreign_cancel = CancelCanonical {
        order_id: b.order_id,
        trading_key,
        cancel_nonce: 1,
        session_id: foreign_session,
    };
    let sig = key.sign(&foreign_cancel.digest());
    let body = json!({
        "trading_key": hex::encode(trading_key),
        "cancel_nonce": 1,
        "session_id": hex::encode(foreign_session),
        "trading_key_signature": hex::encode(sig.to_bytes()),
    });

    let resp = cancel(&app, &bearer, &hex::encode(b.order_id), body).await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a cancel bound to another boot session must not be honoured"
    );
    let j = read_json(resp).await;
    assert_eq!(j["code"], 1205, "expected stale_session, got: {j}");
}

#[tokio::test]
async fn cancel_nonce_must_strictly_increase_per_trading_key() {
    let app = app_from(state());
    let bearer = fresh_bearer();
    let key = fresh_signing_key();

    // First order + cancel at nonce 5.
    let b1 = PlaceOrderBuilder::new();
    assert_eq!(
        place(&app, &bearer, b1.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );
    let c1 = cancel(
        &app,
        &bearer,
        &hex::encode(b1.order_id),
        cancel_body(&key, b1.order_id, 5),
    )
    .await;
    assert_eq!(c1.status(), StatusCode::OK);

    // A second order, then a REPLAY of the same nonce. Session binding alone
    // would not stop this — it is the monotonic nonce that does.
    let mut b2 = PlaceOrderBuilder::new();
    b2.order_id = [0xC2; 16];
    b2.arrival_nonce = b1.arrival_nonce + 1;
    assert_eq!(
        place(&app, &bearer, b2.sign(&key)).await.status(),
        StatusCode::ACCEPTED
    );
    let replay = cancel(
        &app,
        &bearer,
        &hex::encode(b2.order_id),
        cancel_body(&key, b2.order_id, 5),
    )
    .await;
    assert_eq!(
        replay.status(),
        StatusCode::CONFLICT,
        "a reused cancel_nonce must be rejected"
    );

    // A strictly greater nonce still works.
    let ok = cancel(
        &app,
        &bearer,
        &hex::encode(b2.order_id),
        cancel_body(&key, b2.order_id, 6),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}
