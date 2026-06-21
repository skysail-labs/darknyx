//! End-to-end tests for `GET /fills/replay` (P7b) — the durable memo-replay
//! endpoint that restores self-healing fill recovery after amount-privacy made
//! the indexer a commitment-only locator.
//!
//! Drives the router via `tower::ServiceExt::oneshot` (no TCP). Memos are seeded
//! through `ApiState::route_fill` (the same path the live fills router uses), so
//! the test exercises the real append→persist→replay flow.
//!
//! Run with: `cargo test -p nyx-tee --test fills_replay_surface`

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
use nyx_tee::matcher::FillMemo;
use tower::ServiceExt;

/// A bearer whose `sub` (→ `auth.account_id`) is `account`.
fn bearer_for(account: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: account.to_string(),
        iat: now,
        exp: now + 60,
        jti: format!("replay-test-{account}"),
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

/// Route `n` memos for `order_id` (owned by `account`) through the real
/// `route_fill` path, so they land in the durable log with assigned seqs.
async fn seed_memos(state: &Arc<ApiState>, account: &str, order_id: [u8; 16], n: u8) {
    state
        .record_order_owner(hex::encode(order_id), account.to_string())
        .await;
    for i in 0..n {
        let memo = FillMemo::new(
            order_id,
            i as usize,
            100 + i as u64,
            [i.wrapping_add(1); 32],
            [0x11; 32],
            [0x22; 32],
        );
        state.route_fill(&memo).await;
    }
}

#[tokio::test]
async fn replay_returns_all_memos_for_a_fresh_cursor() {
    let state = Arc::new(ApiState::for_tests());
    seed_memos(&state, TEST_API_KEY, [0xAB; 16], 3).await;
    let app = build_router(state);

    let resp = get(
        &app,
        "/fills/replay?since=0",
        Some(&bearer_for(TEST_API_KEY)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let memos = body["memos"].as_array().unwrap();
    assert_eq!(memos.len(), 3);
    // 1-based seqs, oldest first; amounts preserved.
    assert_eq!(memos[0]["seq"], 1);
    assert_eq!(memos[0]["change_amount"], 100);
    assert_eq!(memos[2]["seq"], 3);
    assert_eq!(memos[2]["change_amount"], 102);
    // next_cursor is the max seq returned (the client stores it).
    assert_eq!(body["next_cursor"], 3);
}

#[tokio::test]
async fn replay_since_cursor_returns_only_newer() {
    let state = Arc::new(ApiState::for_tests());
    seed_memos(&state, TEST_API_KEY, [0xAB; 16], 3).await;
    let app = build_router(state);

    // Client already has seq 1,2 → asks for >2.
    let resp = get(
        &app,
        "/fills/replay?since=2",
        Some(&bearer_for(TEST_API_KEY)),
    )
    .await;
    let body = read_json(resp).await;
    let memos = body["memos"].as_array().unwrap();
    assert_eq!(memos.len(), 1);
    assert_eq!(memos[0]["seq"], 3);

    // Caught up → empty, and next_cursor echoes the request's since.
    let resp = get(
        &app,
        "/fills/replay?since=3",
        Some(&bearer_for(TEST_API_KEY)),
    )
    .await;
    let body = read_json(resp).await;
    assert!(body["memos"].as_array().unwrap().is_empty());
    assert_eq!(body["next_cursor"], 3);
}

#[tokio::test]
async fn replay_is_per_account_isolated() {
    let state = Arc::new(ApiState::for_tests());
    // The default test registry knows TEST_API_KEY; register a 2nd account so its
    // bearer authenticates, then seed memos ONLY for TEST_API_KEY.
    {
        let other = nyx_tee::api::auth::ApiCredentials::from_plaintext("intruder", "s", "p", false)
            .expect("hash");
        assert!(state.accounts.write().await.register(other));
    }
    seed_memos(&state, TEST_API_KEY, [0xAB; 16], 2).await;
    let app = build_router(state);

    // The intruder account has no memos of its own and must NOT see TEST's.
    let resp = get(&app, "/fills/replay?since=0", Some(&bearer_for("intruder"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert!(
        body["memos"].as_array().unwrap().is_empty(),
        "account isolation breach: intruder saw another account's memos"
    );
}

#[tokio::test]
async fn replay_requires_bearer() {
    let state = Arc::new(ApiState::for_tests());
    let app = build_router(state);
    let resp = get(&app, "/fills/replay?since=0", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_defaults_since_to_zero_when_absent() {
    let state = Arc::new(ApiState::for_tests());
    seed_memos(&state, TEST_API_KEY, [0xAB; 16], 1).await;
    let app = build_router(state);
    // No ?since= → treated as 0 → returns everything.
    let resp = get(&app, "/fills/replay", Some(&bearer_for(TEST_API_KEY))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["memos"].as_array().unwrap().len(), 1);
}
