//! HTTP + WS surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! PR 4d landed `health`, `info`, `attestation` (the unauthenticated
//! introspection surface — enough for operators + the SDK's
//! `verifyTeeAttestation()` helper). The remaining modules are
//! still stubs awaiting:
//!   - PR 4e: `auth` (OAuth2 client_credentials) + `orders` (the
//!     authenticated POST/DELETE surface)
//!   - PR 4f: `ws` (multiplexed sessions + channels)
//!   - PR 4g: `account`, `tree`, `settlement`, `transparency`
//!     (read endpoints once the matcher + Merkle mirror + settle
//!     scheduler are wired)

pub mod account;
pub mod attestation;
pub mod auth;
pub mod health;
pub mod info;
pub mod orders;
pub mod settlement;
pub mod state;
pub mod transparency;
pub mod tree;
pub mod ws;

use std::sync::Arc;

use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post},
    Router,
};

pub use state::{ApiState, BootAppInfo};

/// Construct the production HTTP router. Production main.rs hands
/// the returned `Router` to `axum::serve(...)`. Integration tests
/// use the same builder + `tower::ServiceExt::oneshot(...)` to
/// drive requests in-process — no TCP, no port allocation.
///
/// Route map:
///
/// | Method | Path           | Auth          | Lands in |
/// |--------|----------------|---------------|----------|
/// | GET    | `/health`      | public        | PR 4d    |
/// | GET    | `/info`        | public        | PR 4d    |
/// | GET    | `/attestation` | public        | PR 4d    |
/// | POST   | `/auth/token`  | public        | PR 4e.2  |
/// | POST   | `/orders`      | bearer (4e.2) | PR 4e.3  |
/// | DELETE | `/orders/{id}` | bearer (4e.2) | PR 4e.3  |
/// | GET    | `/orders/{id}` | bearer (4e.2) | PR 4e.3  |
///
/// `POST /auth/token` is intentionally public (rate-limited at the
/// reverse-proxy layer in production); everything inside the
/// session bearer-token scope is mounted via
/// [`build_protected_router`] in PR 4e.3.
pub fn build_router(state: Arc<ApiState>) -> Router {
    let public = Router::new()
        .route("/health", get(health::handler))
        .route("/info", get(info::handler))
        .route("/attestation", get(attestation::handler))
        .route("/auth/token", post(auth::token_handler));

    // Bearer-protected sub-router. `from_fn_with_state` requires the
    // state to be visible on the inner router, so we attach it
    // there + on the outer merge target. Both halves share the
    // same `Arc<ApiState>` so request handlers see identical state.
    let protected = build_protected_router(state.clone());

    public.merge(protected).with_state(state)
}

/// The bearer-protected sub-router. Mounts the per-order
/// (Layer B) routes; PR 4f will add `/account/*` here too.
/// Exposed `pub` so integration tests can mount additional
/// test-only routes alongside the production ones.
pub fn build_protected_router(state: Arc<ApiState>) -> Router<Arc<ApiState>> {
    // axum 0.7 path-capture syntax is `:name`, not `{name}` (which
    // is axum 0.8's matchit syntax). Bumping axum is a separate
    // PR — until then stick with `:order_id`.
    //
    // `route_layer` (not `layer`) so the bearer check runs ONLY on
    // declared routes. With plain `.layer(...)` the middleware
    // wraps the whole router including the 404 fallback, which
    // surfaces as `401 Unauthorized` on every unknown path — not
    // what we want.
    Router::new()
        .route("/orders", post(orders::place_order))
        .route("/orders/:order_id", delete(orders::cancel_order))
        .route("/orders/:order_id", get(orders::get_order))
        .route_layer(from_fn_with_state(state, auth::bearer_middleware))
}
