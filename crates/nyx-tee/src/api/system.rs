//! `GET /system/status` — liveness / degraded-mode snapshot, and `GET /time` —
//! the server's current slot + unix time (so clients can convert a wall-clock
//! GTT expiry into an `expiry_slot` without their own RPC).
//!
//! Both are public, unauthenticated reads (no order/account data).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Json};
use serde::Serialize;

use super::state::ApiState;

#[derive(Debug, Serialize)]
pub struct SystemStatus {
    /// `false` when any core subsystem is down (matching or settle).
    pub degraded: bool,
    /// The matching tick is running (orders can be accepted + matched).
    pub matcher_running: bool,
    /// The on-chain settle pipeline is wired (matches will settle).
    pub settle_enabled: bool,
    /// An oracle cache is attached (the clearing-price reference). Per-feed
    /// staleness is the matcher's own policy; this only reports presence.
    pub oracle_configured: bool,
    /// The TEE's current view of the Solana slot (drives expiry sweeps).
    pub current_slot: u64,
    pub nyx_version: &'static str,
}

pub async fn get_status(State(state): State<Arc<ApiState>>) -> Json<SystemStatus> {
    let matcher_running = state.matcher.is_some();
    let settle_enabled = state.settle_state.is_some();
    Json(SystemStatus {
        degraded: !(matcher_running && settle_enabled),
        matcher_running,
        settle_enabled,
        oracle_configured: state.oracle.is_some(),
        current_slot: state.current_slot.load(Ordering::Relaxed),
        nyx_version: state.nyx_version,
    })
}

#[derive(Debug, Serialize)]
pub struct ServerTime {
    /// The TEE's current Solana slot.
    pub slot: u64,
    /// Server unix time, milliseconds.
    pub unix_ms: u64,
}

pub async fn get_time(State(state): State<Arc<ApiState>>) -> Json<ServerTime> {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Json(ServerTime {
        slot: state.current_slot.load(Ordering::Relaxed),
        unix_ms,
    })
}
