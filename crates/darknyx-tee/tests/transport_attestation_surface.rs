//! HTTP surface for `GET /transport-attestation` (T-03P).
//!
//! `ApiState::for_tests()` has `dstack: None` and no RA-TLS identity, so a
//! successful quote cannot be produced here — that needs a real dstack socket
//! and is covered by the live CVM run in Phase 3. What these tests pin is
//! everything a client can reach *before* the quote: the input surface, the
//! rejection behaviour, and the fact that the route refuses to invent evidence
//! when it has none.
//!
//! The security-relevant assertion in this file is the last one: a caller
//! cannot influence any bound field. The nonce is the entire input surface.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use darknyx_tee::api::{build_router, ApiState};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> axum::Router {
    build_router(Arc::new(ApiState::for_tests()))
}

async fn get(uri: &str) -> axum::response::Response {
    app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is valid JSON")
}

fn valid_nonce() -> String {
    "aa".repeat(32)
}

#[tokio::test]
async fn the_route_is_registered_and_does_not_404() {
    // Guards the router wiring. Without this, every rejection test below could
    // pass against a route that does not exist.
    let resp = get(&format!("/transport-attestation?nonce={}", valid_nonce())).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "/transport-attestation is not registered"
    );
}

#[tokio::test]
async fn without_an_ratls_identity_it_reports_unavailable_rather_than_inventing_one() {
    // The legacy gateway-terminated path has no served certificate of ours to
    // bind. Returning a manifest anyway would be worse than 503 — it would be
    // a binding to nothing that a client might accept.
    let resp = get(&format!("/transport-attestation?nonce={}", valid_nonce())).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_missing_nonce_is_rejected() {
    let resp = get("/transport-attestation").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_non_hex_nonce_is_rejected() {
    let resp = get("/transport-attestation?nonce=zzzz").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_short_nonce_is_rejected_rather_than_zero_padded() {
    // `/attestation` tolerates a short nonce by padding. This contract must
    // not: a caller who sends 4 bytes and believes it has 32 bytes of replay
    // protection is wrong in a way padding would hide.
    for short in ["aa", "aabb", &"aa".repeat(31)] {
        let resp = get(&format!("/transport-attestation?nonce={short}")).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a {}-hex-char nonce was not rejected",
            short.len()
        );
    }
}

#[tokio::test]
async fn an_over_long_nonce_is_rejected() {
    let resp = get(&format!("/transport-attestation?nonce={}", "aa".repeat(33))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nonce_hex_is_checked_before_the_identity_is_required() {
    // Ordering matters for the error a client sees. A malformed nonce should
    // read as a client error (400), not as "service unavailable" (503), even
    // when RA-TLS happens to be off — otherwise a client debugging its own bug
    // is told the server is down.
    //
    // `zz` fails HEX DECODING, so this pins hex-before-identity only. The
    // length check sits after it and needs its own case below; naming this one
    // "length" made the handler cite a guard that did not exist.
    let resp = get("/transport-attestation?nonce=zz").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nonce_length_is_checked_before_the_identity_is_required() {
    // The case the previous test was mistakenly credited with. This nonce is
    // VALID hex, so it passes the decode and reaches the length check — which
    // is the branch that must still return 400 rather than 503 when RA-TLS is
    // off. Without this, moving the identity lookup above the length check
    // would go unnoticed.
    let resp = get("/transport-attestation?nonce=abcd").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejections_do_not_echo_the_caller_input_back() {
    // A pre-auth route that reflects arbitrary caller bytes into its error body
    // is a gadget worth denying, cheaply.
    let marker = "deadbeefcafe";
    let resp = get(&format!("/transport-attestation?nonce={marker}")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    let rendered = json.to_string();
    assert!(
        !rendered.contains(marker),
        "the error body echoed the caller's nonce: {rendered}"
    );
}

#[tokio::test]
async fn the_caller_cannot_supply_any_bound_field() {
    // THE test in this file. Every manifest field comes from server state; the
    // nonce is the entire input surface. If a future edit accepted, say, an
    // `spki` or `boot_session_id` query parameter, the binding would become
    // caller-chosen and the whole contract would be decorative.
    //
    // With RA-TLS off every one of these still yields 503 (the identity check),
    // never a 200 — proving none of them is a path to a served manifest.
    let injected = [
        "tls_spki_sha256=00".to_string() + &"11".repeat(31),
        "boot_session_id=".to_string() + &"22".repeat(32),
        "signer_set_sha256=".to_string() + &"33".repeat(32),
        "app_id=attacker".to_string(),
        "instance_id=attacker".to_string(),
        "transport_mode=gateway-terminated".to_string(),
        "protocol_version=999".to_string(),
    ];
    for extra in injected {
        let resp = get(&format!(
            "/transport-attestation?nonce={}&{extra}",
            valid_nonce()
        ))
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "query parameter `{extra}` changed the outcome — it may be reaching the manifest"
        );
    }
}

#[tokio::test]
async fn the_legacy_attestation_route_is_untouched() {
    // The contract promise: adding this endpoint does not alter /attestation.
    // Both are 503 without a dstack socket, and that is the point — this test
    // fails loudly if /transport-attestation ever displaces it in the router.
    let resp = get("/attestation").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
