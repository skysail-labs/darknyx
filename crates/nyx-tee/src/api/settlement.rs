//! `GET /settlement/status/{batch_id}` — read-only status for one
//! settle-pipeline batch.
//!
//! Authenticated via the bearer middleware (PR 4e.2). Same scope
//! as `/orders` — any authenticated caller can query any batch.
//! Per-account scoping isn't a meaningful security boundary here:
//! the matcher's batch is a global event, not user-specific, and
//! the response leaks only stage labels + tx signatures (which are
//! observable on-chain anyway).
//!
//! Returns:
//!   200 + `BatchSettleStatus` JSON when the batch exists.
//!   404 when the batch is unknown to the scheduler (either it
//!     never happened or it was evicted — see 4g.6 retention).
//!   503 when no scheduler is wired (degraded boot, or in tests
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
