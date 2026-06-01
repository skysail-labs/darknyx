//! Phase-2c surface test: `GET /transparency` (public). In test mode
//! there's no Solana RPC client, so `per_mint` reserves are empty — but
//! the mirror root/leaf_count, the engine identity, and the stats are
//! still served. Driven via `tower::ServiceExt::oneshot`.
//!
//! Run with: `cargo test -p nyx-tee --test transparency_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use nyx_tee::api::{build_router, ApiState};
use tower::ServiceExt;

fn fr_safe(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = 0;
    b
}

#[tokio::test]
async fn transparency_is_public_and_reports_mirror_and_identity() {
    let state = Arc::new(ApiState::for_tests());
    // Seed two leaves so leaf_count is non-trivial.
    {
        let mut m = state.merkle_mirror.write().await;
        m.append_leaf(fr_safe(1)).unwrap();
        m.append_leaf(fr_safe(2)).unwrap();
    }
    let app = build_router(state);

    // No bearer — /transparency is public.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/transparency")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Reserves: mirror root (64-hex) + leaf_count from the mirror.
    assert_eq!(v["reserves"]["merkle_root"].as_str().unwrap().len(), 64);
    assert_eq!(v["reserves"]["leaf_count"], 2);
    // No RPC client in test mode → per_mint reserves empty.
    assert_eq!(v["reserves"]["per_mint"].as_array().unwrap().len(), 0);

    // Engine identity present (stub values in test mode).
    assert!(v["tee"]["signer_pubkey"].as_str().is_some());
    assert!(v["tee"]["compose_hash"].as_str().is_some());

    // Stats present (zero in test mode — no scheduler wired).
    assert_eq!(v["stats"]["batches"], 0);
    assert_eq!(v["stats"]["jobs"], 0);
}
