//! The enclave's HTTP and WebSocket surface.
//!
//! The wire contract is `docs/tee-api-openapi.yaml`; the auth model is
//! `docs/tee-architecture.md` §11. This module is where every external request
//! enters the TEE, which makes it the boundary that decides what a client may do
//! and what it may learn.
//!
//! # Three trust tiers
//!
//! Routes are mounted in one of three scopes, and which scope a route belongs to is
//! a security decision, not an organisational one:
//!
//!   - **Public** — `/health`, `/info`, `/attestation`, `/transport-attestation`,
//!     `/auth/token`, `/tree/root`, `/instruments`, `/transparency`,
//!     `/system/status`, `/time`. `/transport-attestation` is unauthenticated *by
//!     necessity*: a client must be able to verify the transport before it sends a
//!     credential, so it is rate-limited in the handler rather than gated.
//!   - **Bearer-protected** — orders, settlement status, Merkle inclusion and leaf
//!     reads, the account snapshot, token revocation. Attached with `route_layer`
//!     rather than `layer`, so the bearer check runs only on declared routes; with
//!     `layer` the middleware would also wrap the 404 fallback and answer `401` for
//!     every unknown path.
//!   - **Admin-gated** — `/admin/accounts` and the drain controls, gated inside
//!     their handlers on top of the bearer scope.
//!
//! `/v1/stream` is the sole WebSocket surface. It authenticates **in-band** via an
//! `op: login` frame, then multiplexes orders, fills, tree events, and trading ops
//! over one session.
//!
//! # Module map
//!
//! ```text
//!   mod.rs                  router assembly and the scope layering above
//!   auth.rs                 token issue/revoke, account registration, admin gate
//!   orders.rs               place / cancel / modify / get — the intake path
//!   order_router.rs         routes an order to its market's book
//!   stream.rs               the /v1/stream session and its channels
//!   fills_router.rs         per-account fills fan-out
//!   state.rs                ApiState — the shared handle every handler reads
//!   error.rs                the error type, and what it is allowed to disclose
//!   rate_limit.rs           per-account request metering
//!   conn_limit.rs           per-account and global connection caps
//!   account.rs              caller's open-order snapshot and settings
//!   instruments.rs          market metadata
//!   tree.rs                 Merkle mirror reads (root public, rest bearer)
//!   transparency.rs         proof-of-reserves, engine identity, stats
//!   attestation.rs          the enclave quote
//!   transport_attestation.rs  binds the served TLS cert to this boot and signer set
//!   settlement.rs           settle job status by batch id
//!   system.rs, info.rs, health.rs, metrics.rs   liveness and identity reads
//!   drain.rs                planned-stop control
//!   debug.rs                feature-gated; must never be on in production
//! ```
//!
//! # What must not break
//!
//! Handlers must not widen what leaves the enclave. Settle failures are served as a
//! closed set of labels, never their diagnostic text; the account snapshot returns
//! only the caller's open orders, with balances and note openings staying
//! client-side; and errors are mapped through [`error`] rather than formatted from
//! internal values. Each of these has leaked a credential or an amount at least
//! once — see [`error`] and [`crate::settle::job::SettleFailureKind`].
//!
//! `debug.rs` compiles only under the `debug_endpoints` cargo feature and is
//! verified off by `scripts/check-no-debug-endpoints.sh`.

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
pub mod transport_attestation;
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
/// | Method | Path | Auth | Notes |
/// |--------|------|------|-------|
/// | GET    | `/health` | public | |
/// | GET    | `/info` | public | primary shard signer |
/// | GET    | `/attestation` | public | enclave quote |
/// | GET    | `/transport-attestation` | public | must precede any credential |
/// | POST   | `/auth/token` | public | metered in-handler, not by the bearer layer |
/// | GET    | `/tree/root` | public | cross-checkable against `VaultConfig` on Solana |
/// | GET    | `/instruments`, `/instruments/{symbol}` | public | market metadata |
/// | GET    | `/transparency` | public | proof-of-reserves + engine identity |
/// | GET    | `/system/status` | public | liveness / degraded mode |
/// | GET    | `/time` | public | server slot, for GTT conversion |
/// | GET    | `/v1/stream` | in-band | `op: login`; the only WebSocket |
/// | POST   | `/orders` | bearer | |
/// | PUT/DELETE/GET | `/orders/{id}` | bearer | PUT is atomic cancel + replace |
/// | GET    | `/settlement/status/{batch_id}` | bearer | closed-set failure labels only |
/// | GET    | `/tree/inclusion`, `/tree/leaves` | bearer | |
/// | GET    | `/account` | bearer | caller's open orders only |
/// | POST   | `/auth/token/revoke` | bearer | denylists the caller's own token |
/// | POST   | `/admin/accounts` | bearer + admin | |
/// | GET    | `/admin/metrics/settlement` | bearer + admin | benchmark telemetry |
/// | GET/POST | `/admin/drain` | bearer + admin | planned stop |
///
/// `POST /auth/token` is public by necessity — it is how a client obtains the
/// bearer token everything else requires. It is metered inside the handler
/// rather than by the bearer layer it sits outside of. The rest of the session
/// scope is mounted via [`build_protected_router`].
pub fn build_router(state: Arc<ApiState>) -> Router {
    let public = Router::new()
        .route("/health", get(health::handler))
        .route("/info", get(info::handler))
        .route("/attestation", get(attestation::handler))
        // T-03P: binds the served TLS certificate to this enclave/boot/signer set.
        // Unauthenticated by necessity — a client must verify the transport
        // BEFORE it sends a credential. Rate-limited in the handler.
        .route(
            "/transport-attestation",
            get(transport_attestation::handler),
        )
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
    // cargo feature is on. Used by `darknyx-tee-loadgen` for
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
    // SW-02: bound the UNAUTHENTICATED surface. `route_layer` (not `layer`) so
    // the limiter runs only on declared public routes and never on the 404
    // fallback — otherwise an unknown path would consume budget and, worse,
    // report `429` instead of `404`.
    let public = public.route_layer(axum::middleware::from_fn_with_state(
        state.clone(),
        rate_limit::public_rate_limit_middleware,
    ));

    public
        .merge(protected)
        .layer(axum::middleware::from_fn(error::request_id_middleware))
        .with_state(state)
}

/// The bearer-protected sub-router. Mounts the per-order routes and the
/// account-management routes (`/auth/token/revoke`, and `/admin/accounts`,
/// which is admin-gated inside its handler).
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
        // Account management — bearer-protected. `revoke`
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
