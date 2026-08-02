//! Phase-2c surface test: `GET /transparency` (public). In test mode
//! there's no Solana RPC client, so `per_mint` reserves are empty — but
//! the mirror root/leaf_count, the engine identity, and the stats are
//! still served. Driven via `tower::ServiceExt::oneshot`.
//!
//! Run with: `cargo test -p darknyx-tee --test transparency_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use darknyx_tee::api::{build_router, ApiState};
use http_body_util::BodyExt;
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
        let mut m = state.merkle_mirror(0).write().await;
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

// ── SW-02: the public router is rate-limited ────────────────────────────
//
// It had no limit at all, while `/attestation` generates a TDX quote per
// request and `/transparency` issued 2xN Solana RPC calls per request against
// the same provider quota the settle pipeline depends on. Exhausting that quota
// is the first link in the sweep's chain: settle failures → SW-03's unbounded
// loop → SW-01's credential in an error string.

/// Drive one public GET through the real router.
async fn get_public(app: &axum::Router, uri: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_public_flood_is_throttled_with_retry_after() {
    let app = build_router(Arc::new(ApiState::for_tests()));

    // `/attestation` is the heaviest weight, so the burst drains fastest there.
    // It returns 503 in test mode (no dstack), which is fine — the rate limiter
    // runs BEFORE the handler, so we are observing the limiter either way.
    let mut throttled = None;
    for _ in 0..200 {
        let resp = get_public(&app, "/attestation").await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            throttled = Some(resp);
            break;
        }
    }
    let resp = throttled.expect("a sustained public flood must eventually be throttled");
    // Clients need to know how long to back off.
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 must carry Retry-After"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], 1401, "the stable rate-limit code");
}

#[tokio::test]
async fn an_unknown_path_is_404_not_429() {
    // The limiter is mounted with `route_layer`, so it never wraps the 404
    // fallback. With a plain `.layer(...)` an unknown path would consume budget
    // and report the wrong status — and a scanner hitting random paths could
    // throttle the whole venue without touching a real route.
    let app = build_router(Arc::new(ApiState::for_tests()));
    for _ in 0..300 {
        let resp = get_public(&app, "/no/such/route").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn honest_polling_is_not_throttled() {
    // A limit that stops legitimate clients is an outage wearing a control's
    // clothes. Cheap in-memory reads must stay comfortably inside the budget.
    let app = build_router(Arc::new(ApiState::for_tests()));
    for uri in ["/health", "/time", "/tree/root", "/system/status"] {
        for _ in 0..50 {
            let resp = get_public(&app, uri).await;
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "{uri} must not throttle under ordinary polling"
            );
        }
    }
}

/// A mock Solana RPC that counts `getAccountInfo` calls, so a test can prove
/// the reserve cache actually collapses repeated requests.
async fn spawn_counting_rpc() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn handle(State(count): State<Arc<AtomicUsize>>, Json(req): Json<Value>) -> Json<Value> {
        let id = req.get("id").cloned().unwrap_or(json!(1));
        if req.get("method").and_then(|m| m.as_str()) == Some("getAccountInfo") {
            count.fetch_add(1, Ordering::SeqCst);
        }
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "context": { "slot": 1 }, "value": null },
        }))
    }

    let count = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", post(handle))
        .with_state(count.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), count)
}

#[tokio::test]
async fn repeated_transparency_reads_hit_the_chain_once_per_ttl() {
    use darknyx_tee::solana_rpc::SolanaRpcClient;
    use std::sync::atomic::Ordering;

    let (url, calls) = spawn_counting_rpc().await;
    let mut state = ApiState::for_tests();
    state.solana_rpc = Some(SolanaRpcClient::new(url).unwrap());
    // One market → two distinct mints → 2 accounts × 2 reads = 4 RPC calls per
    // UNCACHED render (outstanding + vault balance for each mint).
    let mut market = state
        .instruments
        .first()
        .cloned()
        .expect("for_tests seeds one placeholder instrument");
    market.base_mint = fr_safe(0xB1);
    market.quote_mint = fr_safe(0x9E);
    state.instruments = vec![market];
    let app = build_router(Arc::new(state));

    // First request populates the cache.
    assert_eq!(
        get_public(&app, "/transparency").await.status(),
        StatusCode::OK
    );
    let after_first = calls.load(Ordering::SeqCst);
    assert!(
        after_first > 0,
        "the first render must actually read the chain"
    );

    // Every subsequent request inside the TTL must add nothing. Before the
    // cache this was 2×N_mints RPC calls per request, from an unauthenticated
    // endpoint — the amplification SW-02 describes.
    for _ in 0..25 {
        assert_eq!(
            get_public(&app, "/transparency").await.status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        after_first,
        "25 further requests inside the TTL must not touch the chain again"
    );
}
