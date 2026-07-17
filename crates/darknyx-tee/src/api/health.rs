//! `GET /health` — minimal liveness check. Always returns 200.
//!
//! Used by:
//!   - the Phala-side load balancer to detect stuck CVMs
//!   - the smoke-test harness post-deploy
//!   - integration tests as the "is the server up?" probe
//!
//! Intentionally cheap — no I/O, no locks. The handler reads only
//! `ApiState.start` (an `Instant`) and serializes a small JSON
//! response.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;

use super::state::ApiState;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the binary is serving. Future PRs may
    /// extend this to `"degraded"` if dstack / Solana RPC /
    /// oracle sync are unhealthy — for now binary-is-up is the
    /// only signal.
    pub status: &'static str,
    /// Milliseconds since the API server bound its listener.
    /// Useful for "did this CVM restart silently?" debugging.
    pub uptime_ms: u64,
    /// `darknyx-tee` build version. Operators cross-reference against
    /// the compose-hash that's allowlisted on Phala.
    pub version: &'static str,
}

pub async fn handler(State(state): State<Arc<ApiState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_ms: state.start.elapsed().as_millis() as u64,
        version: state.version,
    })
}
