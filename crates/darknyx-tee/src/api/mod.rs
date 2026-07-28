//! HTTP + WS surface. Wire contract: `docs/tee-api-openapi.yaml`.
//!
//! Landed: `health`, `info`, `attestation` (PR 4d); `auth` + `orders`
//! (PR 4e); `settlement` (PR 4g.1); `auth/token/revoke` + admin
//! `account` registration (Phase 1a); `tree/*` over the Merkle mirror
//! (Phase 2a/2b); `instruments` + `transparency` + the open-order account
//! snapshot (Phase 2c).
//! WebSockets are consolidated on the in-band-authenticated `/v1/stream`
//! multiplexed session (orders, fills, trading ops, and live tree events).

pub mod account;
pub mod attestation;
pub mod auth;
pub mod conn_limit;
#[cfg(feature = "debug_endpoints")]
pub mod debug;
pub mod drain;
pub mod error;
pub mod fills_router;
pub mod health;
pub mod info;
pub mod instruments;
pub mod metrics;
pub mod order_router;
pub mod orders;
pub mod rate_limit;
pub mod settlement;
pub mod state;
pub mod stream;
pub mod system;
pub mod transparency;
pub mod tree;

use std::sync::Arc;

use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
    Router,
};

pub use error::ApiError;
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
/// | GET    | `/account`     | bearer        | Phase 2c |
/// | GET    | `/transparency` | public       | Phase 2c |
/// | GET    | `/admin/metrics/settlement` | bearer+admin | benchmark telemetry |
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
        .route("/transparency", get(transparency::get_transparency))
        // Liveness/degraded-mode snapshot + server time (for GTT slot conversion).
        .route("/system/status", get(system::get_status))
        .route("/time", get(system::get_time))
        // The sole WebSocket surface. Auth is IN-BAND (`op: login`), then one
        // session multiplexes orders/fills/tree subscriptions and trading ops.
        .route("/v1/stream", get(stream::stream_ws));

    // Debug endpoints — only compiled in when the `debug_endpoints`
    // cargo feature is on. Used by `darknyx-tee-loadgen` (PR 4f) for
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

    // Stamp every response (success, error, and 404 fallback) with an
    // `x-request-id` correlation header. Layered on the merged router so it
    // wraps the whole surface.
    public
        .merge(protected)
        .layer(axum::middleware::from_fn(error::request_id_middleware))
        .with_state(state)
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
        // Atomic cancel + replace (modify) — same path, PUT.
        .route("/orders/:order_id", put(orders::modify_order))
        .route("/settlement/status/:batch_id", get(settlement::get_status))
        // Merkle mirror — bearer-protected reads (inclusion proof +
        // leaf pagination). Root is public above.
        .route("/tree/inclusion", get(tree::get_inclusion))
        .route("/tree/leaves", get(tree::get_leaves))
        // Account snapshot — bearer. Returns the caller's open orders (the
        // slice the TEE legitimately holds); balances/notes stay client-side.
        .route("/account", get(account::get_account))
        // Per-account settings (cancel-on-disconnect default, …).
        .route(
            "/account/settings",
            get(account::get_settings).put(account::put_settings),
        )
        // Layer A account management — bearer-protected. `revoke`
        // denylists the caller's own token; `/admin/accounts` is
        // further admin-gated inside the handler (see auth.rs).
        .route("/auth/token/revoke", post(auth::revoke_token_handler))
        .route("/admin/accounts", post(auth::register_account_handler))
        // Planned-stop control (T-06). `GET` answers "is it safe to stop the
        // CVM?" from the settle journal — the same state a restart would read.
        .route(
            "/admin/drain",
            get(drain::get_drain)
                .post(drain::begin_drain)
                .delete(drain::cancel_drain),
        )
        // Account suspension + bulk token invalidation. Admin-gated inside the
        // handlers, same as `/admin/accounts`. Enforcement lives in
        // `auth::validate_token`, not in a middleware, so it covers the
        // streaming transport as well as HTTP.
        .route(
            "/admin/accounts/:api_key/disable",
            post(auth::disable_account_handler),
        )
        .route(
            "/admin/accounts/:api_key/enable",
            post(auth::enable_account_handler),
        )
        .route(
            "/admin/accounts/:api_key/revoke-tokens",
            post(auth::revoke_account_tokens_handler),
        )
        .route(
            "/admin/metrics/settlement",
            get(metrics::get_settlement_metrics),
        );

    // Two route_layers. The LAST-added is OUTERMOST, so `bearer_middleware`
    // runs first (injecting `Authorized`), then `rate_limit_middleware` runs
    // with the account in hand. Reads + auth ops are cheap-weighted; place /
    // cancel / modify carry the real cost.
    router
        .route_layer(from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .route_layer(from_fn_with_state(state, auth::bearer_middleware))
}
