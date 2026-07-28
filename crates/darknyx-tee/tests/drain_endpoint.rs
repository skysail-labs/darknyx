//! `/admin/drain` — the planned-stop control surface (audit finding T-06).
//!
//! Exercised through the real router so this covers the wiring, not just the
//! `settle::drain` decision logic its unit tests already pin: admin gating, the
//! shared journal handle, and the JSON shape an operator runbook reads.
//!
//! The property that matters is `safe_to_stop`. It must be computed from the
//! settle journal — the same durable state a restart would read — and never from
//! elapsed time. A drain that reports "ready" on a timer would give an operator
//! permission to stop a CVM mid-settlement, which is precisely the failure the
//! journal exists to survive.
//!
//! Run with: `cargo test -p darknyx-tee --test drain_endpoint`

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use darknyx_tee::api::auth::{TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE};
use darknyx_tee::api::{build_router, ApiState};
use serde_json::json;
use tower::ServiceExt;

async fn token(state: Arc<ApiState>) -> String {
    let resp = build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "api_key":    TEST_API_KEY,
                        "api_secret": TEST_API_SECRET,
                        "passphrase": TEST_PASSPHRASE,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

async fn call(
    state: Arc<ApiState>,
    method: &str,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri("/admin/drain");
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let resp = build_router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn drain_requires_a_bearer_token() {
    let state = Arc::new(ApiState::for_tests());
    let (status, _) = call(state, "GET", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unauthenticated caller must not be able to read or drive a drain"
    );
}

#[tokio::test]
async fn an_idle_instance_is_not_safe_to_stop_until_it_is_draining() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (status, body) = call(Arc::clone(&state), "GET", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], false);
    assert_eq!(body["in_flight_settlements"], 0);
    assert_eq!(
        body["safe_to_stop"], false,
        "an empty journal is not permission to stop while trading is open — the \
         next matcher tick can enqueue a settlement"
    );
}

#[tokio::test]
async fn beginning_a_drain_closes_trading_and_reports_ready() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (status, body) = call(Arc::clone(&state), "POST", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], true);
    assert_eq!(
        body["safe_to_stop"], true,
        "trading closed and nothing in flight is the safe-to-stop condition"
    );

    // The gate really closed — not just the report.
    assert!(
        !state.trading_gate.is_open(),
        "a drain must actually close the trading gate"
    );
}

#[tokio::test]
async fn a_drain_can_be_abandoned_and_reopens_trading() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    call(Arc::clone(&state), "POST", Some(&t)).await;
    assert!(!state.trading_gate.is_open());

    let (status, body) = call(Arc::clone(&state), "DELETE", Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["draining"], false);
    assert!(
        state.trading_gate.is_open(),
        "abandoning a planned stop must re-open trading"
    );
}

/// A drain is idempotent: a runbook that retries the POST after a timeout must
/// not get a different answer or double-count anything.
#[tokio::test]
async fn repeating_the_drain_request_is_idempotent() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;

    let (_, first) = call(Arc::clone(&state), "POST", Some(&t)).await;
    let (_, second) = call(Arc::clone(&state), "POST", Some(&t)).await;
    assert_eq!(first["draining"], true);
    assert_eq!(second["draining"], true);
    assert_eq!(second["safe_to_stop"], true);
}

/// `ApiState::for_tests()` has no state dir, so its journal is in-memory. The
/// status must SAY so rather than reporting a bare `safe_to_stop: true` that an
/// operator would read as "in-flight work is durable". Technically-true and
/// practically-misleading is the failure mode this whole slice keeps finding.
#[tokio::test]
async fn a_non_persistent_journal_is_disclosed_to_the_operator() {
    let state = Arc::new(ApiState::for_tests());
    let t = token(Arc::clone(&state)).await;
    let (_, body) = call(Arc::clone(&state), "GET", Some(&t)).await;
    let caveat = body["caveat"]
        .as_str()
        .expect("a non-persistent journal must be disclosed in the status");
    assert!(
        caveat.contains("not persistent"),
        "the caveat should name the problem; got: {caveat}"
    );
}
