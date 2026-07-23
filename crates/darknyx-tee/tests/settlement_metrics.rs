//! Authorization and cursor coverage for the bounded settlement metrics API.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use darknyx_tee::api::auth::{ApiCredentials, Claims, TEST_API_KEY, TEST_JWT_SECRET};
use darknyx_tee::api::{build_router, ApiState};
use darknyx_tee::settle::SettleScheduler;
use darkpool_matcher::match_result::{MatchPair, MatchStatus, RunBatchOutput};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use tokio::sync::mpsc;
use tower::ServiceExt;

fn bearer(subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    encode(
        &Header::default(),
        &Claims {
            sub: subject.to_string(),
            iat: now,
            exp: now + 60,
            jti: format!("{subject}-jti"),
        },
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap()
}

fn dummy_match(match_id: u64) -> MatchPair {
    MatchPair {
        note_buyer: [0x11; 32],
        note_seller: [0x22; 32],
        note_e_commitment: [0; 32],
        note_f_commitment: [0; 32],
        owner_buyer: [0x55; 32],
        owner_seller: [0x66; 32],
        user_commitment_buyer: [0x77; 32],
        user_commitment_seller: [0x88; 32],
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
        match_id,
        status: MatchStatus::Filled,
    }
}

#[tokio::test]
async fn settlement_metrics_requires_bearer_and_live_admin_membership() {
    let state = ApiState::for_tests();
    assert!(state.accounts.write().await.register(
        ApiCredentials::from_plaintext("ordinary", "secret", "passphrase", false).unwrap(),
    ));
    let app = build_router(Arc::new(state));

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/metrics/settlement")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let non_admin = app
        .oneshot(
            Request::builder()
                .uri("/admin/metrics/settlement")
                .header("authorization", format!("Bearer {}", bearer("ordinary")))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(non_admin.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn settlement_metrics_reports_unwired_scheduler() {
    let app = build_router(Arc::new(ApiState::for_tests()));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/metrics/settlement")
                .header("authorization", format!("Bearer {}", bearer(TEST_API_KEY)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn settlement_metrics_exposes_only_bounded_batch_metadata() {
    let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
    let (_handle, settle_state) = SettleScheduler::spawn(rx);
    let app = build_router(Arc::new(
        ApiState::for_tests().with_settle_state(settle_state),
    ));

    let mut output = RunBatchOutput::empty(1, 10, 0);
    output.matches = vec![dummy_match(41), dummy_match(42)];
    tx.send(output).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/metrics/settlement?after_seq=0&limit=10")
                .header("authorization", format!("Bearer {}", bearer(TEST_API_KEY)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["queue"]["depth"], 1);
    assert_eq!(json["queue"]["waiting_batches"], 1);
    assert_eq!(
        json["queue"]["by_market"]["unconfigured"]["waiting_batches"],
        1
    );
    assert!(json["recent_batches"].as_array().unwrap().is_empty());

    let encoded = std::str::from_utf8(&body).unwrap();
    for private_name in [
        "note_buyer",
        "note_seller",
        "owner_buyer",
        "owner_seller",
        "base_amt",
        "quote_amt",
        "price",
        "\"witness\":",
    ] {
        assert!(
            !encoded.contains(private_name),
            "admin metrics leaked private field name {private_name}"
        );
    }
}
