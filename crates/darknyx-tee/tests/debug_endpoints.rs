//! Smoke tests for the feature-gated `/__debug/*` surface.
//!
//! Compiled only with `--features debug_endpoints`. The default
//! build (no feature) compiles this file as empty so it doesn't
//! emit a `no test target` error.
//!
//! Run with:
//!   cargo test -p darknyx-tee --features debug_endpoints --test debug_endpoints

#![cfg(feature = "debug_endpoints")]

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use darknyx_tee::api::{build_router, instruments::InstrumentInfo, ApiState};
use darknyx_tee::matcher::{MatcherState, TradingPauseReason};
use darknyx_tee::oracle::OracleCache;
use http_body_util::BodyExt;
use serde_json::json;
use tokio::sync::RwLock;
use tower::ServiceExt;

const TEST_FEED: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

#[tokio::test]
async fn debug_oracle_seed_writes_into_cache() {
    let state = ApiState::for_tests();
    state.trading_gate.pause_for(TradingPauseReason::Oracle);
    let trading_gate = state.trading_gate.clone();
    // `for_tests()` seeds `oracle: Some(OracleCache::new())` so the
    // handler should accept; pull a clone of the same cache so we
    // can verify the write end-to-end.
    let oracle = state
        .oracle
        .as_ref()
        .expect("for_tests seeds oracle")
        .clone();
    let app = build_router(Arc::new(state));

    let body = json!({
        "feed_id": TEST_FEED,
        "twap": 150_000_000u64,
        "confidence": 0u64,
        "exponent": -8,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__debug/oracle/seed")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cached = oracle.get(TEST_FEED).await.expect("entry written");
    assert_eq!(cached.twap, 150_000_000);
    assert_eq!(cached.exponent, -8);
    assert!(
        cached.last_updated_ms > 0,
        "upsert should stamp last_updated_ms to now()"
    );
    assert!(
        trading_gate.is_open(),
        "a fresh debug seed should clear the Oracle pause"
    );
}

#[tokio::test]
async fn debug_oracle_seed_does_not_clear_governance_pause() {
    let state = ApiState::for_tests();
    state.trading_gate.pause_for(TradingPauseReason::Governance);
    state.trading_gate.pause_for(TradingPauseReason::Oracle);
    let trading_gate = state.trading_gate.clone();
    let app = build_router(Arc::new(state));

    let body = json!({
        "feed_id": TEST_FEED,
        "twap": 150_000_000u64,
        "exponent": -8,
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__debug/oracle/seed")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(trading_gate.is_paused_for(TradingPauseReason::Governance));
    assert!(!trading_gate.is_paused_for(TradingPauseReason::Oracle));
    assert!(!trading_gate.is_open());
}

#[tokio::test]
async fn debug_oracle_seed_cannot_clear_another_markets_oracle_pause() {
    let other_feed = "bb".repeat(32);
    let state = ApiState::for_tests()
        .with_instruments(vec![
            InstrumentInfo {
                symbol: "SOL-USDC".to_string(),
                base_mint: [1; 32],
                quote_mint: [2; 32],
                tick_size: 1,
                min_order_size: 1,
                oracle_feed_id: TEST_FEED.to_string(),
            },
            InstrumentInfo {
                symbol: "BTC-USDC".to_string(),
                base_mint: [3; 32],
                quote_mint: [2; 32],
                tick_size: 1,
                min_order_size: 1,
                oracle_feed_id: other_feed,
            },
        ])
        .with_market_runtimes(
            HashMap::from([
                (
                    "SOL-USDC".to_string(),
                    Arc::new(RwLock::new(MatcherState::new())),
                ),
                (
                    "BTC-USDC".to_string(),
                    Arc::new(RwLock::new(MatcherState::new())),
                ),
            ]),
            Arc::new(AtomicU64::new(1)),
            OracleCache::new(),
        );
    let sol_gate = state.trading_gate_for_symbol("SOL-USDC").expect("SOL gate");
    let btc_gate = state.trading_gate_for_symbol("BTC-USDC").expect("BTC gate");
    sol_gate.pause_for(TradingPauseReason::Oracle);
    btc_gate.pause_for(TradingPauseReason::Oracle);
    let app = build_router(Arc::new(state));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__debug/oracle/seed")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "feed_id": TEST_FEED,
                        "twap": 150_000_000u64,
                        "exponent": -8,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(sol_gate.is_open(), "the seeded SOL market resumes");
    assert!(
        btc_gate.is_paused_for(TradingPauseReason::Oracle),
        "the unseeded BTC market remains paused"
    );
}

#[tokio::test]
async fn debug_oracle_seed_503_without_cache() {
    let mut state = ApiState::for_tests();
    state.oracle = None;
    let app = build_router(Arc::new(state));
    let body = json!({
        "feed_id": "abcd",
        "twap": 1u64,
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__debug/oracle/seed")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("oracle cache"));
}

#[tokio::test]
async fn debug_oracle_seed_rejects_malformed_body() {
    let app = build_router(Arc::new(ApiState::for_tests()));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__debug/oracle/seed")
                .header("content-type", "application/json")
                // Missing the required `twap` field.
                .body(Body::from(r#"{"feed_id":"abcd"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "expected 4xx for missing required field; got {}",
        resp.status()
    );
}
