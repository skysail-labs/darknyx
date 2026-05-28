//! Smoke tests for the feature-gated `/__debug/*` surface.
//!
//! Compiled only with `--features debug_endpoints`. The default
//! build (no feature) compiles this file as empty so it doesn't
//! emit a `no test target` error.
//!
//! Run with:
//!   cargo test -p nyx-tee --features debug_endpoints --test debug_endpoints

#![cfg(feature = "debug_endpoints")]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use nyx_tee::api::{build_router, ApiState};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn debug_oracle_seed_writes_into_cache() {
    let state = ApiState::for_tests();
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
        "feed_id": "ef0d8b6fdac3e4cba65d8c1be8ea3b6b88c1d4e2c9d4d9b5e1d4a8e9f0a1b2c3",
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

    let cached = oracle
        .get("ef0d8b6fdac3e4cba65d8c1be8ea3b6b88c1d4e2c9d4d9b5e1d4a8e9f0a1b2c3")
        .await
        .expect("entry written");
    assert_eq!(cached.twap, 150_000_000);
    assert_eq!(cached.exponent, -8);
    assert!(
        cached.last_updated_ms > 0,
        "upsert should stamp last_updated_ms to now()"
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
