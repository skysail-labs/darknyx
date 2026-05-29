//! End-to-end PR-4e.4 verification: POST /orders × 2 (crossing
//! bid + ask) → matcher tick → match arrives on the settle
//! channel.
//!
//! This is the load-bearing integration that proves all four
//! pieces of PR 4e are wired together:
//!
//!   - 4e.1 canonical encoding + 4e.3 signature verify accept the
//!     HTTP submit,
//!   - 4e.3 orders handler inserts into the shared `MatcherState`,
//!   - 4e.4's tick (driven manually here for determinism, the
//!     production loop is identical) reads the same state +
//!     produces a `RunBatchOutput`,
//!   - the matches mpsc channel that `main.rs` hands to the
//!     drainer carries the output through.
//!
//! Why drive `tick()` manually rather than spawning the time
//! loop: same reason `tests/matcher_tick.rs` documented — tokio
//! virtual time + a `.recv().await` deadlocks; advancing real
//! time is flaky in CI. Calling `tick()` directly is byte-for-byte
//! the same code-path the time loop runs (`run() { loop {
//! ticker.tick().await; self.tick().await? } }`), so this test
//! covers every production code path except the timer fires.
//!
//! Run with: `cargo test -p nyx-tee --test order_to_match`

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use darkpool_matcher::book::{OrderSide, OrderType};
use darkpool_matcher::config::MatchConfig;
use darkpool_matcher::order_canonical::OrderCanonical;
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{encode, EncodingKey, Header};
use nyx_tee::api::auth::{Claims, TEST_API_KEY, TEST_JWT_SECRET};
use nyx_tee::api::{build_router, ApiState};
use nyx_tee::matcher::openings::NoteOpening;
use nyx_tee::matcher::{DriverConfig, MatcherDriver, MatcherState, DEFAULT_MAX_ORACLE_AGE_MS};
use nyx_tee::oracle::cache::{CachedPrice, OracleCache};
use rand::rngs::OsRng;
use serde_json::json;
use tokio::sync::{mpsc, RwLock};
use tower::ServiceExt;

const FEED_ID: &str = "ef0d8b6fdac3e4cba65d8c1be8ea3b6b88c1d4e2c9d4d9b5e1d4a8e9f0a1b2c3";

// ─── Builders (mirror tests/orders_surface.rs, with explicit
// trading_key + crossing price/side knobs) ──────────────────────────────────

fn fresh_bearer() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: TEST_API_KEY.to_string(),
        iat: now,
        exp: now + 60,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap()
}

fn sign_order(
    key: &SigningKey,
    side: OrderSide,
    price_limit: u64,
    order_id_first_byte: u8,
    arrival_nonce: u64,
) -> serde_json::Value {
    let order_id = {
        let mut o = [0u8; 16];
        o[0] = order_id_first_byte;
        o[15] = 1;
        o
    };
    let user_commitment = {
        let mut u = [0x33; 32];
        u[0] = 0; // BN254 Fr-safe
        u
    };

    // Input-note opening (4g.7a). The matcher (MatcherState::new() →
    // zeroed mints in this test) verifies the opening against the
    // signed commitment, so derive note_commitment from the opening.
    let amount = 10_000_000u64;
    let note_amount = match side {
        OrderSide::Bid => amount.saturating_mul(price_limit).max(amount).max(1),
        OrderSide::Ask => amount.max(1),
    };
    let fr_safe = |b: u8| {
        let mut v = [b; 32];
        v[0] = 0;
        v
    };
    let opening = NoteOpening {
        token_mint: [0u8; 32],
        amount: note_amount,
        owner_commitment: fr_safe(0x44),
        nonce: fr_safe(0x55),
        blinding: fr_safe(0x66),
        nullifier: [0x77; 32],
    };
    let note_commitment = opening.commitment().expect("Fr-safe opening");

    let canonical = OrderCanonical {
        symbol: b"SOL-USDC",
        side,
        order_type: OrderType::Limit,
        amount: 10_000_000,
        price_limit,
        min_fill_size: 0,
        expiry_slot: 1_000_000,
        order_id,
        note_commitment,
        user_commitment,
        arrival_nonce,
    };
    let digest = canonical.digest().unwrap();
    let sig = key.sign(&digest);
    let trading_key = key.verifying_key().to_bytes();

    json!({
        "symbol": "SOL-USDC",
        "side": match side { OrderSide::Bid => "bid", OrderSide::Ask => "ask" },
        "order_type": "limit",
        "amount": 10_000_000u64,
        "price_limit": price_limit,
        "min_fill_size": 0u64,
        "expiry_slot": 1_000_000u64,
        "order_id": hex::encode(order_id),
        "note_commitment": hex::encode(note_commitment),
        "user_commitment": hex::encode(user_commitment),
        "arrival_nonce": arrival_nonce,
        "trading_key": hex::encode(trading_key),
        "trading_key_signature": hex::encode(sig.to_bytes()),
        "owner_commitment": hex::encode(opening.owner_commitment),
        "note_nonce": hex::encode(opening.nonce),
        "note_blinding": hex::encode(opening.blinding),
        "nullifier": hex::encode(opening.nullifier),
        "merkle_root": hex::encode([0xDDu8; 32]),
        "valid_input_proof": hex::encode([0u8; 256]),
    })
}

fn dev_match_config() -> MatchConfig {
    let mut base_mint = [0u8; 32];
    base_mint[0] = 1;
    base_mint[31] = 0xb1;
    let mut quote_mint = [0u8; 32];
    quote_mint[0] = 1;
    quote_mint[31] = 0x9e;
    MatchConfig {
        base_mint,
        quote_mint,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 100_000, // effectively disabled
        batch_ms: 2000,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}

// ─── The test ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_submit_two_crossing_orders_produces_match() {
    // 1. Build shared runtime exactly the way main.rs does — a
    //    fresh MatcherState + OracleCache + current_slot, with the
    //    matcher state threaded into the ApiState via
    //    with_matcher_runtime. The router operates on the same
    //    `Arc<RwLock<MatcherState>>` the driver below holds.
    let matcher_state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (matches_tx, mut matches_rx) =
        mpsc::channel::<darkpool_matcher::match_result::RunBatchOutput>(8);

    let api_state = ApiState::for_tests().with_matcher_runtime(
        matcher_state.clone(),
        current_slot.clone(),
        oracle.clone(),
    );
    let app = build_router(Arc::new(api_state));

    // 2. Seed the oracle. The matcher's freshness window
    //    (DEFAULT_MAX_ORACLE_AGE_MS = 5_000) reads
    //    `last_updated_ms` against the cache's monotonic clock;
    //    `upsert` stamps it to "now" so the entry is trivially
    //    fresh. Price is wide enough that both orders sit inside
    //    the circuit-breaker band.
    oracle
        .upsert(
            FEED_ID.to_string(),
            CachedPrice {
                twap: 150_000_000,
                confidence: 0,
                exponent: -8,
                publish_time_ms: 0,
                last_updated_ms: 0,
                vaa: Vec::new(),
            },
        )
        .await;

    // 3. Build the matcher driver. It points at the SAME
    //    Arc<RwLock<MatcherState>> the router writes into.
    let driver = MatcherDriver {
        state: matcher_state.clone(),
        oracle: oracle.clone(),
        current_slot: current_slot.clone(),
        matches_tx,
        cfg: DriverConfig {
            match_config: dev_match_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: DEFAULT_MAX_ORACLE_AGE_MS,
        },
    };

    // 4. Submit two orders via HTTP. Different trading keys (so no
    //    self-trade), crossing prices (bid_price >= ask_price).
    let bearer = fresh_bearer();
    let buyer = SigningKey::generate(&mut OsRng);
    let seller = SigningKey::generate(&mut OsRng);

    let buy_body = sign_order(&buyer, OrderSide::Bid, 151_000_000, 0xAA, 1);
    let sell_body = sign_order(&seller, OrderSide::Ask, 149_000_000, 0xBB, 2);

    for body in [&buy_body, &sell_body] {
        let resp = app
            .clone()
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
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "POST /orders for body {body} did not return 202"
        );
    }

    // Sanity-check: book has two orders.
    {
        let st = matcher_state.read().await;
        assert_eq!(st.book().len(), 2, "both orders should be in the book");
    }

    // 5. Drive one matcher tick. Same code-path the production
    //    `MatcherDriver::run` runs on every interval fire.
    driver
        .tick()
        .await
        .expect("matcher tick returned channel-closed before any match");

    // 6. The matches channel MUST have one RunBatchOutput on it.
    //    `try_recv` (not `recv().await`) fails fast — if tick
    //    silently swallowed an error (the historical failure mode
    //    documented in tests/matcher_tick.rs), this surfaces it
    //    instead of hanging.
    let output = matches_rx
        .try_recv()
        .expect("matcher should have pushed a RunBatchOutput onto the matches channel");
    assert!(
        !output.matches.is_empty(),
        "tick produced output but with zero matches — algorithm bug"
    );
    assert_eq!(
        output.matches.len(),
        1,
        "expected exactly one match (two equal-size crossing orders)"
    );
    // The matcher's uniform-clearing-price rule places the price
    // somewhere in the crossing band [ask_price, bid_price]. Exact
    // placement depends on the FIFO + oracle-band logic in
    // `darkpool_matcher::algorithm::compute_clearing_price`; what
    // matters for this end-to-end test is that the price IS in the
    // band, not which side of it.
    assert!(
        (149_000_000..=151_000_000).contains(&output.clearing_price),
        "clearing_price {} not in [ask_price, bid_price] = [149M, 151M]",
        output.clearing_price
    );
}

#[tokio::test]
async fn http_submit_without_crossing_produces_no_match() {
    // Same wiring but the two orders DON'T cross — book has both
    // but `tick()` produces an empty `matches` vec (matcher
    // returns Ok with no output → no channel send). The mpsc
    // receiver must therefore be empty after the tick. Asserting
    // this rules out the regression where every tick spuriously
    // emits a zero-match output.
    let matcher_state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (matches_tx, mut matches_rx) =
        mpsc::channel::<darkpool_matcher::match_result::RunBatchOutput>(8);

    let api_state = ApiState::for_tests().with_matcher_runtime(
        matcher_state.clone(),
        current_slot.clone(),
        oracle.clone(),
    );
    let app = build_router(Arc::new(api_state));

    oracle
        .upsert(
            FEED_ID.to_string(),
            CachedPrice {
                twap: 150_000_000,
                confidence: 0,
                exponent: -8,
                publish_time_ms: 0,
                last_updated_ms: 0,
                vaa: Vec::new(),
            },
        )
        .await;

    let driver = MatcherDriver {
        state: matcher_state.clone(),
        oracle: oracle.clone(),
        current_slot: current_slot.clone(),
        matches_tx,
        cfg: DriverConfig {
            match_config: dev_match_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: DEFAULT_MAX_ORACLE_AGE_MS,
        },
    };

    let bearer = fresh_bearer();
    let buyer = SigningKey::generate(&mut OsRng);
    let seller = SigningKey::generate(&mut OsRng);

    // Bid lower than ask → no cross.
    let buy_body = sign_order(&buyer, OrderSide::Bid, 140_000_000, 0xAA, 1);
    let sell_body = sign_order(&seller, OrderSide::Ask, 160_000_000, 0xBB, 2);

    for body in [&buy_body, &sell_body] {
        let resp = app
            .clone()
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
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    driver.tick().await.expect("matcher tick should not error");

    // No matches — the channel stays empty.
    assert!(
        matches_rx.try_recv().is_err(),
        "non-crossing book should not produce a RunBatchOutput"
    );

    // Both orders are still in the book waiting for a counterparty.
    let st = matcher_state.read().await;
    assert_eq!(st.book().len(), 2);
}
