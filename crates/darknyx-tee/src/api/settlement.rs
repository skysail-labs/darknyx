//! `GET /settlement/status/{batch_id}` — read-only status for one
//! settle-pipeline batch.
//!
//! Authenticated via the bearer middleware, but **not scoped by account**: any
//! authenticated caller can query any batch. The reasoning is that a matcher
//! batch is a global event rather than user-specific.
//!
//! Be precise about what that exposes. Stage labels, the closed-set failure
//! label, and the transaction signatures are all observable on-chain anyway. The
//! `created_at_ms` and `last_transition_at_ms` timestamps are **not** — they are
//! enclave-internal wall-clock at millisecond resolution, finer than block time,
//! and they are served to every authenticated account. Treat them as the part of
//! this response whose disclosure is not already implied by the chain.
//!
//! Returns:
//!   200 + `BatchSettleStatus` JSON when the batch exists.
//!   404 when the batch is unknown to the scheduler (either it
//!     never happened or it was evicted — see the scheduler's retention bound).
//!   503 when no scheduler is wired (for example, in tests
//!     that opt out of spawning the scheduler).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Serialize;

use super::auth::Authorized;
use super::state::ApiState;
use crate::settle::job::JobStatus;

#[derive(Debug, Serialize)]
pub struct BatchSettleStatus {
    pub batch_id: u64,
    /// Per-match job statuses, ordered by `match_idx` ascending.
    pub jobs: Vec<JobStatus>,
}

pub async fn get_status(
    State(state): State<Arc<ApiState>>,
    Extension(_auth): Extension<Authorized>,
    Path(batch_id): Path<u64>,
) -> Result<Json<BatchSettleStatus>, super::error::ApiError> {
    let scheduler_state = state.settle_state.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "settle scheduler not initialised on this instance".to_string(),
    ))?;

    let st = scheduler_state.read().await;
    let jobs = st.status_for_batch(batch_id).ok_or((
        StatusCode::NOT_FOUND,
        format!("no batch with id {batch_id}"),
    ))?;

    Ok(Json(BatchSettleStatus { batch_id, jobs }))
}
