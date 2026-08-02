//! End-to-end tests for the Phase-2a `/tree/*` indexer surface
//! (`GET /tree/root` public, `/tree/inclusion` + `/tree/leaves`
//! bearer). Drives the router via `tower::ServiceExt::oneshot` — no
//! TCP — and seeds the shared Merkle mirror directly through the
//! `Arc<RwLock<MerkleMirror>>` on `ApiState`.
//!
//! Run with: `cargo test -p darknyx-tee --test tree_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use darknyx_tee::api::auth::{Claims, TEST_API_KEY, TEST_JWT_SECRET};
use darknyx_tee::api::{build_router, ApiState};
use darknyx_tee::merkle::MerkleMirror;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use tokio::sync::RwLock;
use tower::ServiceExt;

/// A BN254-Fr-safe 32-byte leaf (top byte zero).
fn fr_safe(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = 0;
    b
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
        jti: "tree-test".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap()
}

/// Build a router whose mirror has been seeded with `n` Fr-safe
/// leaves (seeds `1..=n`). Returns the app + the leaf commitments.
async fn app_with_leaves(n: u8) -> (axum::Router, Vec<[u8; 32]>) {
    let state = Arc::new(ApiState::for_tests());
    let mut commits = Vec::new();
    {
        let mut mirror = state.merkle_mirror(0).write().await;
        for i in 1..=n {
            let c = fr_safe(i);
            mirror.append_leaf(c).unwrap();
            commits.push(c);
        }
    }
    (build_router(state), commits)
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
async fn tree_root_is_public_and_reports_leaf_count() {
    let (app, _) = app_with_leaves(5).await;
    // No bearer — /tree/root is public.
    let resp = get(&app, "/tree/root", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["leaf_count"], 5);
    // 32-byte hex root + a numeric on_chain_slot (0 until sync wires up).
    assert_eq!(body["merkle_root"].as_str().unwrap().len(), 64);
    assert_eq!(body["on_chain_slot"], 0);
}

#[tokio::test]
async fn inclusion_proof_happy_path() {
    let (app, commits) = app_with_leaves(7).await;
    let target = hex::encode(commits[3]); // leaf index 3
    let resp = get(
        &app,
        &format!("/tree/inclusion?commitment={target}"),
        Some(&bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["leaf_index"], 3);
    assert_eq!(body["note_commitment"], target);
    assert_eq!(body["siblings"].as_array().unwrap().len(), 20);
    // The proof's root matches /tree/root.
    let root_resp = get(&app, "/tree/root", None).await;
    let root_body = read_json(root_resp).await;
    assert_eq!(body["merkle_root"], root_body["merkle_root"]);
}

#[tokio::test]
async fn inclusion_requires_bearer() {
    let (app, commits) = app_with_leaves(3).await;
    let target = hex::encode(commits[0]);
    let resp = get(&app, &format!("/tree/inclusion?commitment={target}"), None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn inclusion_unknown_commitment_404() {
    let (app, _) = app_with_leaves(3).await;
    let unknown = hex::encode(fr_safe(200));
    let resp = get(
        &app,
        &format!("/tree/inclusion?commitment={unknown}"),
        Some(&bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn inclusion_bad_hex_400() {
    let (app, _) = app_with_leaves(3).await;
    // Wrong length (not 32 bytes).
    let resp = get(&app, "/tree/inclusion?commitment=deadbeef", Some(&bearer())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn leaves_pagination_happy_path() {
    let (app, commits) = app_with_leaves(5).await;
    let resp = get(&app, "/tree/leaves?from=1&to=4", Some(&bearer())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let leaves = body["leaves"].as_array().unwrap();
    assert_eq!(leaves.len(), 3); // [1,4)
    assert_eq!(leaves[0]["leaf_index"], 1);
    assert_eq!(leaves[0]["value"], hex::encode(commits[1]));
    assert_eq!(leaves[2]["leaf_index"], 3);
}

#[tokio::test]
async fn leaves_requires_bearer() {
    let (app, _) = app_with_leaves(3).await;
    let resp = get(&app, "/tree/leaves?from=0&to=2", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn leaves_inverted_range_400() {
    let (app, _) = app_with_leaves(3).await;
    let resp = get(&app, "/tree/leaves?from=3&to=1", Some(&bearer())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Fail-closed on a diverged mirror ────────────────────────────────────
//
// A mirror that disagrees with its on-chain `MerkleTree` holds a root the
// chain never had. Every answer derived from it is confidently wrong: an
// inclusion path folds to a root `lock_note` rejects, and a client cannot
// tell that from a good one until it has already spent a proof and a
// transaction. Divergence used to be one latched WARN with the endpoints
// still serving; these pin that it now stops.

/// Seed `n` leaves, then flag the shard the way `merkle::sync::reconcile`
/// does when it finds the mirror disagreeing with the chain.
async fn app_with_diverged_mirror(n: u8) -> axum::Router {
    let state = Arc::new(ApiState::for_tests());
    {
        let mut mirror = state.merkle_mirror(0).write().await;
        for i in 1..=n {
            mirror.append_leaf(fr_safe(i)).unwrap();
        }
        mirror.set_diverged(true);
    }
    build_router(state)
}

#[tokio::test]
async fn a_diverged_shard_refuses_every_tree_read() {
    let app = app_with_diverged_mirror(5).await;
    let target = hex::encode(fr_safe(3));
    for (uri, token) in [
        ("/tree/root".to_string(), None),
        (
            format!("/tree/inclusion?commitment={target}"),
            Some(bearer()),
        ),
        ("/tree/leaves?from=0&to=3".to_string(), Some(bearer())),
    ] {
        let resp = get(&app, &uri, token.as_deref()).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{uri} must fail closed while the shard is diverged"
        );
        // A distinct code from 5001 `degraded`: this is not "retry later",
        // it is "do not trust this view — read the tree from Solana".
        assert_eq!(read_json(resp).await["code"], 5002);
    }
}

#[tokio::test]
async fn a_healthy_shard_is_unaffected_by_another_shards_divergence() {
    // Shards are independent trees. Flagging one must not take down reads of
    // the others, or one poisoned shard becomes a whole-venue read outage.
    //
    // `for_tests()` builds a SINGLE shard, so the second one is added here on
    // purpose — an `if num_mirror_shards() < 2 { return }` guard would make
    // this test pass without ever exercising the isolation it claims to check.
    let mut state = ApiState::for_tests();
    state
        .merkle_mirrors
        .push(Arc::new(RwLock::new(MerkleMirror::new())));
    let state = Arc::new(state);
    assert_eq!(state.num_mirror_shards(), 2);

    state.merkle_mirror(0).write().await.set_diverged(true);
    state
        .merkle_mirror(1)
        .write()
        .await
        .append_leaf(fr_safe(9))
        .unwrap();
    let app = build_router(state);

    assert_eq!(
        get(&app, "/tree/root?tree_id=0", None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get(&app, "/tree/root?tree_id=1", None).await.status(),
        StatusCode::OK
    );
}
