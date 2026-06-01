//! End-to-end tests for the PR-4e.2 auth surface (`POST /auth/token`
//! + `bearer_middleware`).
//!
//! Drives the router via `tower::ServiceExt::oneshot` so we never
//! bind a real TCP port. Same in-process pattern as
//! `tests/http_surface.rs`.
//!
//! Coverage:
//!   - `POST /auth/token` happy path returns a verifiable JWT.
//!   - 401 on wrong api_key / wrong api_secret / wrong passphrase /
//!     missing body fields.
//!   - `bearer_middleware` accepts a freshly-issued token + rejects:
//!       * no Authorization header,
//!       * wrong scheme,
//!       * tampered token (truncated / wrong signature),
//!       * expired token,
//!       * token signed with a different secret.
//!   - Phase 1a: `POST /auth/token/revoke` denylists a token's `jti`
//!     so the same token is rejected on the next request.
//!   - Phase 1a: admin-gated `POST /admin/accounts` registers a new
//!     argon2id-hashed account (which can then mint its own token),
//!     rejects a non-admin caller (403) + a duplicate api_key (409).
//!
//! Run with: `cargo test -p nyx-tee --test auth_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::from_fn_with_state,
    response::Response,
    routing::get,
    Extension, Router,
};
use http_body_util::BodyExt;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Header, Validation};
use nyx_tee::api::auth::{
    bearer_middleware, Authorized, Claims, TEST_API_KEY, TEST_API_SECRET, TEST_JWT_SECRET,
    TEST_PASSPHRASE,
};
use nyx_tee::api::{build_router, ApiState};
use serde_json::json;
use tower::ServiceExt;

fn state() -> Arc<ApiState> {
    Arc::new(ApiState::for_tests())
}

fn public_app() -> Router {
    build_router(state())
}

/// Build a tiny test router with one bearer-protected route that
/// echoes the authenticated `account_id`. We use this in place of
/// `POST /orders` (which lands in PR 4e.3) to exercise
/// `bearer_middleware` in isolation.
fn protected_app() -> Router {
    let st = state();
    async fn whoami(Extension(auth): Extension<Authorized>) -> axum::Json<serde_json::Value> {
        axum::Json(json!({ "account_id": auth.account_id }))
    }
    Router::new()
        .route("/whoami", get(whoami))
        .layer(from_fn_with_state(st.clone(), bearer_middleware))
        .with_state(st)
}

async fn read_json(resp: Response) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("response body is valid JSON")
}

async fn token_request(app: &Router, body: serde_json::Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ─────── POST /auth/token ───────────────────────────────────────────────────

#[tokio::test]
async fn token_happy_path_returns_verifiable_jwt() {
    let app = public_app();
    let resp = token_request(
        &app,
        json!({
            "api_key":    TEST_API_KEY,
            "api_secret": TEST_API_SECRET,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = read_json(resp).await;
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_u64().is_some());
    let access_token = body["access_token"].as_str().expect("access_token present");

    // The TEE just minted this token. Decode it with the same
    // secret and assert the sub matches our test API key — this
    // proves the JWT plumbing end-to-end (encode → response →
    // decode), not just the wire shape.
    let claims = decode::<Claims>(
        access_token,
        &DecodingKey::from_secret(&TEST_JWT_SECRET),
        &Validation::default(),
    )
    .expect("decode token");
    assert_eq!(claims.claims.sub, TEST_API_KEY);
    assert!(claims.claims.exp > claims.claims.iat);
}

#[tokio::test]
async fn token_rejects_unknown_api_key() {
    let app = public_app();
    let resp = token_request(
        &app,
        json!({
            "api_key":    "nobody",
            "api_secret": TEST_API_SECRET,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_rejects_wrong_api_secret() {
    let app = public_app();
    let resp = token_request(
        &app,
        json!({
            "api_key":    TEST_API_KEY,
            "api_secret": "wrong",
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_rejects_wrong_passphrase() {
    let app = public_app();
    let resp = token_request(
        &app,
        json!({
            "api_key":    TEST_API_KEY,
            "api_secret": TEST_API_SECRET,
            "passphrase": "wrong",
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_rejects_missing_field() {
    let app = public_app();
    // No api_secret. Should fail at serde-Json-deserialise stage
    // → 4xx. axum returns 422 for this shape; accept either 4xx.
    let resp = token_request(
        &app,
        json!({
            "api_key":    TEST_API_KEY,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert!(
        resp.status().is_client_error(),
        "expected 4xx for missing field; got {}",
        resp.status()
    );
}

// ─────── bearer_middleware ──────────────────────────────────────────────────

fn mint_token(sub: &str, secret: &[u8; 32], exp_offset_secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = (now + exp_offset_secs).max(0) as u64;
    let iat = now.max(0) as u64;
    let claims = Claims {
        sub: sub.to_string(),
        iat,
        exp,
        // Unique per minted token so revoking one in the revocation
        // tests can't accidentally denylist another.
        jti: format!("jti-{}", rand::random::<u64>()),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

#[tokio::test]
async fn middleware_accepts_fresh_test_token() {
    let app = protected_app();
    let token = mint_token(TEST_API_KEY, &TEST_JWT_SECRET, 60);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["account_id"], TEST_API_KEY);
}

#[tokio::test]
async fn middleware_rejects_no_header() {
    let app = protected_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_wrong_scheme() {
    let app = protected_app();
    let token = mint_token(TEST_API_KEY, &TEST_JWT_SECRET, 60);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                // Basic instead of Bearer.
                .header("authorization", format!("Basic {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_truncated_token() {
    let app = protected_app();
    let token = mint_token(TEST_API_KEY, &TEST_JWT_SECRET, 60);
    let truncated = &token[..token.len().saturating_sub(5)];
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("authorization", format!("Bearer {truncated}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_expired_token() {
    let app = protected_app();
    // jsonwebtoken's `Validation::default()` permits 60 s of clock
    // leeway, so we need exp ≥ 60 s in the past to actually trigger
    // the expired branch. Use 5 min for headroom.
    let token = mint_token(TEST_API_KEY, &TEST_JWT_SECRET, -300);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_token_signed_with_other_secret() {
    let app = protected_app();
    // Token is well-formed but signed with a secret the server
    // doesn't know. This is the most realistic forgery-attempt
    // shape — an attacker who picked their own HS256 key.
    let foreign_secret = [0xAAu8; 32];
    let token = mint_token(TEST_API_KEY, &foreign_secret, 60);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_does_not_leak_secret_in_error_message() {
    // Defence in depth: the 401 body for an invalid token must
    // not include any bytes from the server secret. We don't
    // expect a JWT library to leak this — but a forwarding error
    // wrap could (`format!("invalid token: {e:?}")` does NOT
    // include secret bytes in jsonwebtoken's `Error: Debug` output;
    // pin that with a regression test).
    let app = protected_app();
    let foreign_secret = [0xAAu8; 32];
    let token = mint_token(TEST_API_KEY, &foreign_secret, 60);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    // Spot-check: no 4-byte hex prefix of TEST_JWT_SECRET appears.
    let hex_secret = TEST_JWT_SECRET
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(
        !body_str.contains(&hex_secret[..8]),
        "401 body should not include the server secret; got: {body_str}"
    );
}

// ─────── Phase 1a — revocation + admin registration ─────────────────────────

/// Exchange credentials for a bearer token via `POST /auth/token`.
/// Asserts 200 + returns the `access_token`.
async fn get_token(app: &Router, api_key: &str, api_secret: &str, passphrase: &str) -> String {
    let resp = token_request(
        app,
        json!({ "api_key": api_key, "api_secret": api_secret, "passphrase": passphrase }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token issuance should succeed"
    );
    read_json(resp).await["access_token"]
        .as_str()
        .expect("access_token present")
        .to_string()
}

async fn post_with_bearer(
    app: &Router,
    uri: &str,
    token: &str,
    body: serde_json::Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn revoke_denylists_the_token() {
    let app = public_app();
    let token = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;

    // First revoke succeeds (204) — the bearer is still valid here.
    let resp = post_with_bearer(&app, "/auth/token/revoke", &token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The SAME token is now denylisted: any bearer-protected route
    // (including revoke itself) rejects it with 401.
    let resp = post_with_bearer(&app, "/auth/token/revoke", &token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_can_register_account_that_then_authenticates() {
    let app = public_app();
    // TEST_API_KEY is seeded as an admin by `test_registry()`.
    let admin = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;

    let resp = post_with_bearer(
        &app,
        "/admin/accounts",
        &admin,
        json!({ "api_key": "bob", "api_secret": "bob-secret", "passphrase": "bob-pass" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = read_json(resp).await;
    assert_eq!(body["api_key"], "bob");
    assert_eq!(body["is_admin"], false);

    // The freshly-registered account can mint its own token.
    let bob = get_token(&app, "bob", "bob-secret", "bob-pass").await;
    assert!(!bob.is_empty());

    // Duplicate registration of the same api_key → 409.
    let resp = post_with_bearer(
        &app,
        "/admin/accounts",
        &admin,
        json!({ "api_key": "bob", "api_secret": "other", "passphrase": "other" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn non_admin_cannot_register() {
    let app = public_app();
    let admin = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;

    // Admin mints a NON-admin account.
    let resp = post_with_bearer(
        &app,
        "/admin/accounts",
        &admin,
        json!({ "api_key": "carol", "api_secret": "carol-secret", "passphrase": "carol-pass" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Carol authenticates, then tries to register someone — 403.
    let carol = get_token(&app, "carol", "carol-secret", "carol-pass").await;
    let resp = post_with_bearer(
        &app,
        "/admin/accounts",
        &carol,
        json!({ "api_key": "dave", "api_secret": "dave-secret", "passphrase": "dave-pass" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
