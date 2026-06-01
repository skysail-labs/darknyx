//! Phase-2c surface tests: `/instruments` (public list + detail) and
//! the deliberately-deferred `/account` (bearer → 501). Driven via
//! `tower::ServiceExt::oneshot`.
//!
//! Run with: `cargo test -p nyx-tee --test instruments_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use nyx_tee::api::auth::{Claims, TEST_API_KEY, TEST_JWT_SECRET};
use nyx_tee::api::{build_router, ApiState};
use tower::ServiceExt;

fn app() -> axum::Router {
    build_router(Arc::new(ApiState::for_tests()))
}

fn bearer() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: TEST_API_KEY.to_string(),
        iat: now,
        exp: now + 60,
        jti: "instr-test".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap()
}

async fn read_json(resp: Response) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("valid JSON")
}

async fn get(app: &axum::Router, uri: &str, token: Option<&str>) -> Response {
    let mut req = Request::builder().uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn instruments_list_is_public() {
    let resp = get(&app(), "/instruments", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["symbol"], "SOL-USDC");
    // Mints render as base58 strings; sizes as decimal strings.
    assert!(arr[0]["base_mint"].as_str().is_some());
    assert_eq!(arr[0]["tick_size"], "1");
    assert_eq!(arr[0]["oracle"]["type"], "pyth_pull_v2");
}

#[tokio::test]
async fn instrument_detail_by_symbol() {
    let resp = get(&app(), "/instruments/SOL-USDC", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["symbol"], "SOL-USDC");
    assert_eq!(body["min_order_size"], "0");
}

#[tokio::test]
async fn instrument_unknown_symbol_404() {
    let resp = get(&app(), "/instruments/DOES-NOT-EXIST", None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn account_requires_bearer() {
    let resp = get(&app(), "/account", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_is_deferred_501() {
    // Authenticated, but the endpoint is deliberately not implemented:
    // per-account balances/notes are client-computed (privacy model).
    let resp = get(&app(), "/account", Some(&bearer())).await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
