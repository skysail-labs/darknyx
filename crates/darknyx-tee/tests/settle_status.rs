//! HTTP integration test for the PR 4g.1 status endpoint
//! (`GET /settlement/status/{batch_id}`).
//!
//! Coverage:
//!   - 503 when no settle scheduler is wired (ApiState::for_tests
//!     intentionally leaves `settle_state = None`).
//!   - 401 when missing bearer (route is under the protected
//!     sub-router).
//!   - 404 when the batch is unknown.
//!   - 200 + JSON body listing jobs after a RunBatchOutput has
//!     been enqueued. Stage = "queued" for every job since no
//!     stage workers exist yet (those land in 4g.3 / 4g.5 / 4g.6).
//!
//! Run with: `cargo test -p darknyx-tee --test settle_status`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use darknyx_tee::api::auth::{Claims, TEST_API_KEY, TEST_JWT_SECRET};
use darknyx_tee::api::{build_router, ApiState};
use darknyx_tee::settle::SettleScheduler;
use darkpool_matcher::match_result::{MatchPair, MatchStatus, RunBatchOutput};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use tokio::sync::mpsc;
use tower::ServiceExt;

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

fn dummy_match() -> MatchPair {
    MatchPair {
        note_buyer: [0x11; 32],
        note_seller: [0x22; 32],
        note_e_commitment: [0; 32],
        note_f_commitment: [0; 32],
        owner_buyer: [0x55; 32],
        owner_seller: [0x66; 32],
        buyer_note_value: 100,
        seller_note_value: 10,
        base_amt: 10,
        quote_amt: 100,
        buyer_change_amt: 0,
        seller_change_amt: 0,
        buyer_fee_amt: 0,
        seller_fee_amt: 0,
        buyer_relock_order_id: [0; 16],
        buyer_relock_expiry: 0,
        seller_relock_order_id: [0; 16],
        seller_relock_expiry: 0,
        price: 10,
        pyth_at_match: 10,
        batch_slot: 1,
        match_id: 0,
        status: MatchStatus::Filled,
    }
}

#[tokio::test]
async fn status_returns_503_when_scheduler_unwired() {
    // `ApiState::for_tests()` leaves `settle_state = None` so the
    // handler must surface the unwired condition explicitly.
    let app = build_router(Arc::new(ApiState::for_tests()));
    let bearer = fresh_bearer();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/settlement/status/0")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn status_returns_401_without_bearer() {
    let app = build_router(Arc::new(ApiState::for_tests()));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/settlement/status/0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_returns_404_for_unknown_batch() {
    // Spin up a real scheduler (so settle_state is Some) but
    // never feed it — every batch_id should 404.
    let (_tx, rx) = mpsc::channel::<RunBatchOutput>(4);
    let (_handle, settle_state) = SettleScheduler::spawn(rx);
    let state = ApiState::for_tests().with_settle_state(settle_state);
    let app = build_router(Arc::new(state));
    let bearer = fresh_bearer();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/settlement/status/999")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn status_returns_jobs_after_enqueue() {
    let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
    let (_handle, settle_state) = SettleScheduler::spawn(rx);
    let state = ApiState::for_tests().with_settle_state(settle_state);
    let app = build_router(Arc::new(state));

    // Send a 2-match batch and let the scheduler ingest it.
    let mut output = RunBatchOutput::empty(1, 10, 0);
    output.matches = vec![dummy_match(), dummy_match()];
    tx.send(output).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let bearer = fresh_bearer();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/settlement/status/0")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["batch_id"], 0);
    let jobs = json["jobs"].as_array().expect("jobs array");
    assert_eq!(jobs.len(), 2);
    for (i, j) in jobs.iter().enumerate() {
        assert_eq!(j["batch_id"], 0);
        assert_eq!(j["match_idx"], i);
        assert_eq!(j["stage"], "queued");
        assert_eq!(j["outcome"]["kind"], "pending");
        // 4g.1 hasn't wired any stage worker, so no tx sigs.
        // JobStatus serialises None as omitted, so accessing
        // `lock_buyer_sig` returns Null rather than a string.
        assert!(j.get("lock_buyer_sig").is_none() || j["lock_buyer_sig"].is_null());
    }
}
