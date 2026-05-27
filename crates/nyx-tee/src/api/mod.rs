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

use axum::{routing::get, Router};

pub use state::{ApiState, BootAppInfo};

/// Construct the production HTTP router. Production main.rs hands
/// the returned `Router` to `axum::serve(...)`. Integration tests
/// use the same builder + `tower::ServiceExt::oneshot(...)` to
/// drive requests in-process — no TCP, no port allocation.
pub fn build_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .route("/info", get(info::handler))
        .route("/attestation", get(attestation::handler))
        .with_state(state)
}
