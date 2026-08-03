//! Phase-2c surface test: `GET /transparency` (public). In test mode
//! there's no Solana RPC client, so `per_mint` reserves are empty — but
//! the mirror root/leaf_count, the engine identity, and the stats are
//! still served. Driven via `tower::ServiceExt::oneshot`.
//!
//! Run with: `cargo test -p darknyx-tee --test transparency_surface`

use std::sync::Arc;
use std::time::Duration;

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

    // Reserves: per-shard roots + counts, plus the explicitly-named totals.
    //
    // The old assertions read `merkle_root` and `leaf_count` as a matched pair.
    // They never were: the root was shard 0's while the count was the all-shard
    // SUM, so a consumer folding one against the other got a root the tree
    // never had (SW-06). The names now say which is which.
    assert_eq!(
        v["reserves"]["shard0_merkle_root"].as_str().unwrap().len(),
        64
    );
    assert_eq!(v["reserves"]["total_leaf_count"], 2);
    let shards = v["reserves"]["shards"].as_array().unwrap();
    assert_eq!(shards.len(), 1, "for_tests builds a single shard");
    assert_eq!(shards[0]["tree_id"], 0);
    assert_eq!(shards[0]["leaf_count"], 2);
    assert_eq!(shards[0]["merkle_root"].as_str().unwrap().len(), 64);
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
    // Pin the TTL well beyond this test's own runtime. The production value is
    // ~one slot (400 ms) and the test itself takes ~0.5 s, so asserting "all of
    // these were served from cache" against the real TTL would be a race on a
    // loaded runner — a flaky test, or worse a silently vacuous one.
    state.reserve_cache_ttl = Duration::from_secs(3600);
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

#[tokio::test]
async fn an_expired_reserve_cache_reads_the_chain_again() {
    use darknyx_tee::solana_rpc::SolanaRpcClient;
    use std::sync::atomic::Ordering;

    // The other half of the contract: the cache must not pin a stale answer.
    // A zero TTL makes every entry expired on inspection, which is exact —
    // no sleeping, no timing assumptions.
    let (url, calls) = spawn_counting_rpc().await;
    let mut state = ApiState::for_tests();
    state.solana_rpc = Some(SolanaRpcClient::new(url).unwrap());
    state.reserve_cache_ttl = Duration::ZERO;
    let mut market = state
        .instruments
        .first()
        .cloned()
        .expect("for_tests seeds one placeholder instrument");
    market.base_mint = fr_safe(0xB1);
    market.quote_mint = fr_safe(0x9E);
    state.instruments = vec![market];
    let app = build_router(Arc::new(state));

    assert_eq!(
        get_public(&app, "/transparency").await.status(),
        StatusCode::OK
    );
    let after_first = calls.load(Ordering::SeqCst);
    assert!(after_first > 0);

    assert_eq!(
        get_public(&app, "/transparency").await.status(),
        StatusCode::OK
    );
    assert!(
        calls.load(Ordering::SeqCst) > after_first,
        "an expired entry must be refreshed, not served"
    );
}

/// SW-05 — `/transparency` publishes a solvency claim, so a read that is not
/// provably from the vault's own account must report `stale`, not a fabricated
/// zero. The addresses are PDA-derived so this is not currently exploitable;
/// the point is that `stale` should mean what its documentation says.
#[tokio::test]
async fn reserves_are_stale_when_an_account_is_not_the_vaults() {
    use darknyx_tee::solana_rpc::SolanaRpcClient;

    // A mock that returns a well-formed account owned by SOMEONE ELSE, with
    // enough bytes to satisfy the offset reads.
    async fn spawn_foreign_owner_rpc() -> String {
        use axum::{routing::post, Json, Router};
        use base64::Engine as _;
        use serde_json::{json, Value};

        async fn handle(Json(req): Json<Value>) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let data = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 200]);
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "context": { "slot": 1 },
                    "value": {
                        "lamports": 1u64,
                        // Not the vault, not the token program.
                        "owner": "11111111111111111111111111111111",
                        "data": [data, "base64"],
                        "executable": false,
                        "rentEpoch": 0u64,
                    }
                },
            }))
        }
        let app = Router::new().route("/", post(handle));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    let mut state = ApiState::for_tests();
    state.solana_rpc = Some(SolanaRpcClient::new(spawn_foreign_owner_rpc().await).unwrap());
    let app = build_router(Arc::new(state));

    let resp = get_public(&app, "/transparency").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let per_mint = v["reserves"]["per_mint"].as_array().unwrap();
    assert!(!per_mint.is_empty(), "the placeholder market has mints");
    for row in per_mint {
        assert_eq!(
            row["stale"], true,
            "a foreign-owned account must read as stale, not as a real 0: {row}"
        );
    }
}
