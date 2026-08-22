//! `GET /admin/metrics/settlement` — settle benchmark telemetry.
//!
//! Serves the aggregated snapshot held by [`crate::settle::metrics`]: per-batch
//! timing, queue depth, prover configuration, and terminal outcome counts.
//!
//! Admin-gated on top of the bearer scope, because throughput telemetry is
//! operator data rather than client data. The underlying record type is the
//! boundary that keeps prices, amounts, and note identities out of this surface —
//! see [`crate::settle::metrics`] before adding a field here.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use super::auth::Authorized;
use super::state::ApiState;
use crate::settle::SettlementMetricsSnapshot;

#[derive(Debug, Default, Deserialize)]
pub struct SettlementMetricsQuery {
    pub after_seq: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SettlementMetricsResponse {
    pub boot_session_id: String,
    pub app_id: String,
    pub compose_hash: String,
    pub version: &'static str,
    #[serde(flatten)]
    pub snapshot: SettlementMetricsSnapshot,
}

pub async fn get_settlement_metrics(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Query(query): Query<SettlementMetricsQuery>,
) -> Result<Json<SettlementMetricsResponse>, super::error::ApiError> {
    // Re-check the live registry instead of trusting a long-lived JWT claim.
    // Admin demotion therefore takes effect immediately.
    let caller_is_admin = state
        .accounts
        .read()
        .await
        .lookup(&auth.account_id)
        .is_some_and(|credentials| credentials.is_admin);
    if !caller_is_admin {
        return Err(super::error::ApiError::forbidden(
            "admin privileges required",
        ));
    }

    let scheduler = state.settle_state.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "settle scheduler not initialised on this instance".to_string(),
    ))?;
    let snapshot = scheduler
        .read()
        .await
        .metrics_snapshot(query.after_seq, query.limit.unwrap_or(100));

    Ok(Json(SettlementMetricsResponse {
        boot_session_id: hex::encode(state.boot_session_id),
        app_id: state.app_info.app_id.clone(),
        compose_hash: state.app_info.compose_hash.clone(),
        version: state.version,
        snapshot,
    }))
}
