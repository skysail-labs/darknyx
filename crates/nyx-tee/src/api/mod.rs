//! HTTP + WS surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! Landed: `health`, `info`, `attestation` (PR 4d); `auth` + `orders`
//! (PR 4e); `settlement` (PR 4g.1); `auth/token/revoke` + admin
//! `account` registration (Phase 1a); `tree/*` over the Merkle mirror
//! (Phase 2a/2b); `instruments` + `transparency` (Phase 2c). `account`
//! is mounted but deferred-by-design (501 — see `api::account`).
//! Remaining: `ws` (multiplexed sessions + channels, incl. the live
//! `tree` channel).

pub mod account;
pub mod attestation;
pub mod auth;
#[cfg(feature = "debug_endpoints")]
pub mod debug;
pub mod health;
pub mod info;
pub mod instruments;
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
/// | GET    | `/settlement/status/{batch_id}` | bearer | PR 4g.1 |
/// | POST   | `/auth/token/revoke` | bearer   | Phase 1a |
/// | POST   | `/admin/accounts` | bearer+admin | Phase 1a |
/// | GET    | `/tree/root`   | public        | Phase 2a |
/// | GET    | `/tree/inclusion` | bearer     | Phase 2a |
/// | GET    | `/tree/leaves` | bearer        | Phase 2a |
/// | GET    | `/instruments` | public        | Phase 2c |
/// | GET    | `/instruments/{symbol}` | public | Phase 2c |
/// | GET    | `/account`     | bearer (501)  | Phase 2c |
/// | GET    | `/transparency` | public       | Phase 2c |
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
        .route("/auth/token", post(auth::token_handler))
        // Merkle mirror root — public convenience read (clients can
        // always cross-check VaultConfig.current_root on Solana).
        .route("/tree/root", get(tree::get_root))
        // Public market metadata.
        .route("/instruments", get(instruments::list_instruments))
        .route("/instruments/:symbol", get(instruments::get_instrument))
        // Public proof-of-reserves + engine identity + stats.
        .route("/transparency", get(transparency::get_transparency));

    // Debug endpoints — only compiled in when the `debug_endpoints`
    // cargo feature is on. Used by `nyx-tee-loadgen` (PR 4f) for
    // deterministic local-simulator runs; MUST be off in any
    // production build. See `api::debug` for the security
    // implications.
    #[cfg(feature = "debug_endpoints")]
    let public = public.route("/__debug/oracle/seed", post(debug::seed_oracle));

    // Bearer-protected sub-router. `from_fn_with_state` requires the
    // state to be visible on the inner router, so we attach it
    // there + on the outer merge target. Both halves share the
    // same `Arc<ApiState>` so request handlers see identical state.
    let protected = build_protected_router(state.clone());

    public.merge(protected).with_state(state)
}

/// The bearer-protected sub-router. Mounts the per-order
/// (Layer B) routes + the Phase 1a account-management routes
/// (`/auth/token/revoke`, admin-gated `/admin/accounts`).
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
    let router = Router::new()
        .route("/orders", post(orders::place_order))
        .route("/orders/:order_id", delete(orders::cancel_order))
        .route("/orders/:order_id", get(orders::get_order))
        // Anchor-pool top-up (Phase 7): replenish a drained pool so the
        // matcher resumes the paused residual.
        .route("/orders/:order_id/anchors", post(orders::topup_anchors))
        .route("/settlement/status/:batch_id", get(settlement::get_status))
        // Merkle mirror — bearer-protected reads (inclusion proof +
        // leaf pagination). Root is public above.
        .route("/tree/inclusion", get(tree::get_inclusion))
        .route("/tree/leaves", get(tree::get_leaves))
        // Account snapshot — bearer, but deferred by design (501): the
        // TEE can't compute per-account balances/notes without a
        // spending key it never sees. See api::account.
        .route("/account", get(account::get_account))
        // Layer A account management — bearer-protected. `revoke`
        // denylists the caller's own token; `/admin/accounts` is
        // further admin-gated inside the handler (see auth.rs).
        .route("/auth/token/revoke", post(auth::revoke_token_handler))
        .route("/admin/accounts", post(auth::register_account_handler));

    // Fill-memo WebSocket (Phase 7). The stream is currently UNFILTERED —
    // every subscriber sees every order's memos — so it is FAIL-CLOSED on
    // hardened builds: only compiled in under `debug_endpoints` (the same
    // gate as `/__debug/oracle/seed`). It MUST stay off until per-account
    // (per-bearer) filtering lands; production clients reconstruct change
    // notes deterministically from their seed + the Merkle mirror meanwhile.
    #[cfg(feature = "debug_endpoints")]
    let router = router.route("/ws/fills", get(ws::fills_ws));

    router.route_layer(from_fn_with_state(state, auth::bearer_middleware))
}
