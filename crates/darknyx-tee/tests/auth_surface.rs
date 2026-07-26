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
//! Run with: `cargo test -p darknyx-tee --test auth_surface`

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::from_fn_with_state,
    response::Response,
    routing::get,
    Extension, Router,
};
use darknyx_tee::api::auth::{
    bearer_middleware, Authorized, Claims, TEST_API_KEY, TEST_API_SECRET, TEST_JWT_SECRET,
    TEST_PASSPHRASE,
};
use darknyx_tee::api::{build_router, ApiState};
use http_body_util::BodyExt;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Header, Validation};
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

// ─────── Account suspension + bulk token invalidation ───────────────────────

/// Register a non-admin account and return an app + that account's token.
async fn app_with_member(app: &Router, key: &str) -> String {
    let admin = get_token(app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    let resp = post_with_bearer(
        app,
        "/admin/accounts",
        &admin,
        json!({ "api_key": key, "api_secret": "s", "passphrase": "p" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    get_token(app, key, "s", "p").await
}

async fn admin_post(app: &Router, uri: &str) -> Response {
    let admin = get_token(app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    post_with_bearer(app, uri, &admin, json!({})).await
}

/// The core guarantee: a token that was valid a moment ago stops working the
/// instant its account is suspended — without waiting for the token to expire.
#[tokio::test]
async fn suspension_invalidates_an_already_issued_token() {
    let app = public_app();
    let member = app_with_member(&app, "mallory").await;

    // The token works before suspension.
    let resp = post_with_bearer(&app, "/auth/token/revoke", &member, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Re-authenticate (the previous token was just revoked by that call) and
    // then suspend the account.
    let member = get_token(&app, "mallory", "s", "p").await;
    assert_eq!(
        admin_post(&app, "/admin/accounts/mallory/disable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    // The SAME token is now refused, though its signature and expiry are intact.
    let resp = post_with_bearer(&app, "/auth/token/revoke", &member, json!({})).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Suspension also closes the front door: no new token can be minted.
#[tokio::test]
async fn suspended_account_cannot_obtain_a_new_token() {
    let app = public_app();
    let _ = app_with_member(&app, "mallory").await;
    admin_post(&app, "/admin/accounts/mallory/disable").await;

    let resp = token_request(
        &app,
        json!({ "api_key": "mallory", "api_secret": "s", "passphrase": "p" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enable_restores_a_suspended_account() {
    let app = public_app();
    let _ = app_with_member(&app, "mallory").await;
    admin_post(&app, "/admin/accounts/mallory/disable").await;
    assert_eq!(
        admin_post(&app, "/admin/accounts/mallory/enable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let token = get_token(&app, "mallory", "s", "p").await;
    let resp = post_with_bearer(&app, "/auth/token/revoke", &token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Bulk invalidation refuses everything issued earlier while leaving the
/// account able to authenticate again — the response to a suspected token leak
/// on an account that is otherwise in good standing.
#[tokio::test]
async fn bulk_invalidation_refuses_old_tokens_but_not_new_ones() {
    let app = public_app();
    let old = app_with_member(&app, "mallory").await;

    assert_eq!(
        admin_post(&app, "/admin/accounts/mallory/revoke-tokens")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let resp = post_with_bearer(&app, "/auth/token/revoke", &old, json!({})).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a token issued at or before the cutoff must be refused"
    );

    // The account itself is untouched: it can authenticate and carry on.
    //
    // Waiting past the one-second boundary is not incidental to the test — it
    // IS the contract. `iat` has one-second resolution and the comparison is
    // inclusive, so a token minted in the same second as the invalidation is
    // deliberately refused too. A client that re-authenticates instantly may
    // need one retry.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let fresh = get_token(&app, "mallory", "s", "p").await;
    let resp = post_with_bearer(&app, "/auth/token/revoke", &fresh, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn account_administration_is_admin_only() {
    let app = public_app();
    let member = app_with_member(&app, "carol").await;

    for uri in [
        "/admin/accounts/carol/disable",
        "/admin/accounts/carol/enable",
        "/admin/accounts/carol/revoke-tokens",
    ] {
        let resp = post_with_bearer(&app, uri, &member, json!({})).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{uri} must reject a non-admin caller"
        );
    }
}

#[tokio::test]
async fn administering_an_unknown_account_is_404() {
    let app = public_app();
    let resp = admin_post(&app, "/admin/accounts/nobody/disable").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─────── Authentication rate limiting + load shedding ───────────────────────

/// Authentication is charged to the account's own login bucket.
///
/// The bucket is drained directly rather than by looping real logins: argon2
/// makes each attempt slow enough that a loop races the refill, so a
/// wall-clock test would be inherently flaky. Draining the exact key the
/// handler charges also asserts the thing worth asserting — that login spends
/// from the account's *login* bucket, not from something else.
#[tokio::test]
async fn repeated_logins_are_rate_limited_per_account() {
    let st = state();
    let app = build_router(st.clone());

    // Set up the second account BEFORE draining anything — registering it needs
    // an admin token, which would itself be refused once the bucket is empty.
    let _ = app_with_member(&app, "quiet").await;

    // Empty the admin account's login bucket.
    let bucket = format!("login:{TEST_API_KEY}");
    while st.try_consume_rate(&bucket, 1.0).await.is_ok() {}

    let resp = token_request(
        &app,
        json!({
            "api_key": TEST_API_KEY,
            "api_secret": TEST_API_SECRET,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "authentication must be charged to the account's login bucket"
    );

    // The OTHER account is unaffected: the limit is per-account, so a noisy
    // client cannot lock anybody else out.
    let resp = token_request(
        &app,
        json!({ "api_key": "quiet", "api_secret": "s", "passphrase": "p" }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "one account exhausting its login bucket must not affect another"
    );
}

/// The load-bearing case: an outsider hammering the login endpoint with a key
/// that does not exist must NOT be able to throttle a real account.
///
/// This is what makes the limiter safe to key on the account rather than on a
/// caller-supplied value. A shared bucket, or one keyed on the submitted
/// api_key, would let anyone deny service to everyone else — the second by also
/// growing the bucket map without bound.
#[tokio::test]
async fn unknown_credentials_cannot_throttle_a_real_account() {
    let app = public_app();

    for i in 0..200 {
        let resp = token_request(
            &app,
            json!({
                "api_key": format!("does-not-exist-{i}"),
                "api_secret": "x",
                "passphrase": "y",
            }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unknown api_key is refused outright"
        );
    }

    // The legitimate account still authenticates on its first attempt.
    let token = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    assert!(!token.is_empty());
}

/// With every hashing permit held, authentication is refused immediately
/// instead of queueing behind the in-flight work.
#[tokio::test]
async fn login_sheds_load_when_the_hash_limiter_is_saturated() {
    let st = state();
    let app = build_router(st.clone());

    // Hold every permit for the duration of the request under test.
    let held = st
        .argon2_limiter
        .clone()
        .acquire_many_owned(st.argon2_limiter.available_permits() as u32)
        .await
        .expect("permits available");

    let resp = token_request(
        &app,
        json!({
            "api_key": TEST_API_KEY,
            "api_secret": TEST_API_SECRET,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a saturated hash limiter must shed, not queue"
    );

    drop(held);

    // Capacity restored — the same request now succeeds.
    let resp = token_request(
        &app,
        json!({
            "api_key": TEST_API_KEY,
            "api_secret": TEST_API_SECRET,
            "passphrase": TEST_PASSPHRASE,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─────── The shared validation entry point ──────────────────────────────────

/// Suspension is enforced in `validate_token`, which is the one function BOTH
/// transports authenticate through: the HTTP bearer middleware and the
/// `/v1/stream` login frame (`api/stream.rs`) each call it.
///
/// Driving it directly is what makes the streaming transport covered here. The
/// enforcement deliberately does not live in the HTTP middleware, because a
/// check placed there applies to HTTP alone — which is precisely how the
/// socket once escaped the per-account rate limiter. This test pins the
/// property at the point both paths share.
///
/// It does not, however, prove that the socket handler still routes through
/// this function; that would need a full WebSocket handshake harness, which
/// does not exist in this crate yet.
#[tokio::test]
async fn shared_validation_entry_point_enforces_suspension() {
    use darknyx_tee::api::auth::validate_token;

    let st = state();
    let app = build_router(st.clone());
    let token = app_with_member(&app, "mallory").await;

    // Accepted while the account is in good standing.
    let authorized = validate_token(&st, &token)
        .await
        .expect("a healthy account validates");
    assert_eq!(authorized.account_id, "mallory");

    // Suspend, then the same token no longer validates — on ANY transport.
    assert!(st.accounts.write().await.set_disabled("mallory", true));
    let err = validate_token(&st, &token)
        .await
        .expect_err("a suspended account must not validate");
    assert_eq!(err.status, StatusCode::FORBIDDEN);
}

/// Bulk invalidation is enforced at the same shared point.
#[tokio::test]
async fn shared_validation_entry_point_enforces_bulk_invalidation() {
    use darknyx_tee::api::auth::validate_token;

    let st = state();
    let app = build_router(st.clone());
    let token = app_with_member(&app, "mallory").await;

    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(st
        .accounts
        .write()
        .await
        .invalidate_tokens_before("mallory", cutoff));

    let err = validate_token(&st, &token)
        .await
        .expect_err("a token at or before the cutoff must not validate");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

/// The cutoff only moves forward, so a stale or replayed request cannot
/// reinstate tokens an earlier invalidation already refused.
#[tokio::test]
async fn bulk_invalidation_cutoff_never_moves_backwards() {
    let st = state();
    let app = build_router(st.clone());
    let _ = app_with_member(&app, "mallory").await;

    {
        let mut reg = st.accounts.write().await;
        assert!(reg.invalidate_tokens_before("mallory", 5_000));
        // An older cutoff must be ignored, not applied.
        assert!(reg.invalidate_tokens_before("mallory", 1_000));
        assert_eq!(
            reg.lookup("mallory").expect("account").tokens_valid_from,
            5_000
        );
    }
}

// ─────── Admin lockout guard ────────────────────────────────────────────────

/// Register an account with admin rights and return its token.
async fn app_with_admin(app: &Router, key: &str) -> String {
    let admin = get_token(app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    let resp = post_with_bearer(
        app,
        "/admin/accounts",
        &admin,
        json!({ "api_key": key, "api_secret": "s", "passphrase": "p", "is_admin": true }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    get_token(app, key, "s", "p").await
}

/// Suspending the only enabled admin is refused.
///
/// It would otherwise put every administrative route out of reach — including
/// the enable that reverses it — and a restart does not recover, because the
/// bootstrap seed only fires when its api_key is ABSENT, not when the account
/// it finds is suspended. Recovery would mean redeploying with a different
/// bootstrap key or wiping state, which is the outcome this endpoint exists to
/// make unnecessary.
#[tokio::test]
async fn cannot_suspend_the_last_enabled_admin() {
    let app = public_app();

    let resp = admin_post(&app, &format!("/admin/accounts/{TEST_API_KEY}/disable")).await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "suspending the only admin must be refused"
    );

    // And it really is still usable — the refusal was not partially applied.
    let token = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    let resp = post_with_bearer(&app, "/auth/token/revoke", &token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// With a second admin present the suspension is allowed — the guard bounds the
/// dangerous case without blocking the ordinary one.
#[tokio::test]
async fn a_redundant_admin_can_be_suspended() {
    let app = public_app();
    let _ = app_with_admin(&app, "admin-two").await;

    // Two enabled admins: suspending either is fine.
    let resp = admin_post(&app, "/admin/accounts/admin-two/disable").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Now only one remains, so the guard engages again.
    let resp = admin_post(&app, &format!("/admin/accounts/{TEST_API_KEY}/disable")).await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "the last remaining enabled admin is still protected"
    );
}

/// Non-admin accounts are unaffected by the guard, even as the only member.
#[tokio::test]
async fn the_guard_does_not_block_suspending_a_member() {
    let app = public_app();
    let _ = app_with_member(&app, "carol").await;
    let resp = admin_post(&app, "/admin/accounts/carol/disable").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Bulk token invalidation is NOT guarded, deliberately: the credentials still
/// work, so the last admin simply authenticates again.
#[tokio::test]
async fn the_last_admin_may_still_invalidate_its_own_tokens() {
    let app = public_app();
    let resp = admin_post(
        &app,
        &format!("/admin/accounts/{TEST_API_KEY}/revoke-tokens"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let token = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
    let resp = post_with_bearer(&app, "/auth/token/revoke", &token, json!({})).await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "the last admin recovers by re-authenticating"
    );
}

/// A token past `exp` is refused outright — no grace period.
///
/// `Validation::default()` ships `leeway: 60`, meant to absorb clock skew
/// between separate issuer and verifier hosts. Here they are the same process,
/// so the allowance bought nothing and cost two things: an expired token stayed
/// usable for another minute, and a REVOKED token could come back to life,
/// because the denylist drops an entry once its `exp` has passed while the
/// verifier still honoured the token inside the leeway.
#[tokio::test]
async fn a_token_past_expiry_is_refused_with_no_leeway() {
    let app = public_app();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: TEST_API_KEY.to_string(),
        iat: now - 120,
        exp: now - 10,
        jti: "leeway-probe".to_string(),
    };
    let expired = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&TEST_JWT_SECRET),
    )
    .unwrap();

    let resp = post_with_bearer(&app, "/auth/token/revoke", &expired, json!({})).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a token past exp must be refused; the default 60s leeway is disabled"
    );
}

/// A revoked token stays revoked for as long as it remains decodable, even as
/// later revocations prune the denylist around it.
#[tokio::test]
async fn revocation_survives_later_denylist_pruning() {
    let app = public_app();
    let victim = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;

    let resp = post_with_bearer(&app, "/auth/token/revoke", &victim, json!({})).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Several more revocations, each of which prunes the denylist.
    for _ in 0..3 {
        let other = get_token(&app, TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE).await;
        let resp = post_with_bearer(&app, "/auth/token/revoke", &other, json!({})).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    let resp = post_with_bearer(&app, "/auth/token/revoke", &victim, json!({})).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "pruning must not evict an entry whose token can still be decoded"
    );
}
