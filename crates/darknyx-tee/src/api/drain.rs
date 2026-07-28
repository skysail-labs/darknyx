//! `GET|POST|DELETE /admin/drain` — operator control for a planned stop (T-06).
//!
//! Admin-gated, like the rest of `/admin/*`. Three verbs, each doing exactly one
//! thing so an operator runbook cannot express an ambiguous intent:
//!
//!   * `POST`   — begin draining: close new trading and cancel resting orders.
//!   * `GET`    — observe: is it safe to stop the CVM yet?
//!   * `DELETE` — abandon the drain and re-open trading.
//!
//! `safe_to_stop` is the whole point of the endpoint. It is computed from the
//! settle journal, which is the same thing a restart would read, rather than from
//! a timer — a "waited long enough" answer would report readiness that no durable
//! state supports.
//!
//! Draining is NOT a substitute for the write-ahead journal and must not be
//! described as one in any runbook. It only helps when someone chooses to stop;
//! a crash or an involuntary migration gets none of it.

use std::sync::Arc;

use axum::{extract::State, Extension, Json};

use super::auth::Authorized;
use super::error::ApiError;
use super::state::ApiState;
use crate::settle::drain::{self, DrainStatus};

/// `POST /admin/drain` — close trading and cancel resting orders.
pub async fn begin_drain(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
) -> Result<Json<DrainStatus>, ApiError> {
    super::auth::require_admin_pub(&state, &auth).await?;

    let newly = drain::begin(&state.trading_gate);

    // Cancel what is resting, so clients learn explicitly instead of finding an
    // empty book after the redeploy. Their collateral is not locked on-chain at
    // this stage, so this frees nothing and costs a re-place — the same trade
    // cancel-on-disconnect already makes.
    let mut cancelled = 0usize;
    for matcher in state.all_matchers() {
        // Snapshot the ids first, then cancel: `cancel_resting_unchecked` takes
        // the matcher's write lock, so holding a read guard across the loop
        // would deadlock. `snapshot()` returns only Pending orders, which is
        // exactly the resting set.
        let order_ids: Vec<String> = {
            let m = matcher.read().await;
            m.book()
                .snapshot()
                .orders
                .iter()
                .map(|o| hex::encode(o.order_id))
                .collect()
        };
        for oid in &order_ids {
            if super::orders::cancel_resting_unchecked(&state, &matcher, oid).await {
                cancelled += 1;
            }
        }
    }

    tracing::warn!(
        newly_requested = newly,
        cancelled_resting = cancelled,
        "drain requested: new trading closed, resting orders cancelled"
    );

    let status = drain::status(&state.trading_gate, &state.settle_journal, cancelled).await;
    Ok(Json(status))
}

/// `GET /admin/drain` — is it safe to stop the CVM?
pub async fn get_drain(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
) -> Result<Json<DrainStatus>, ApiError> {
    super::auth::require_admin_pub(&state, &auth).await?;
    Ok(Json(
        drain::status(&state.trading_gate, &state.settle_journal, 0).await,
    ))
}

/// `DELETE /admin/drain` — abandon the drain and re-open trading.
pub async fn cancel_drain(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
) -> Result<Json<DrainStatus>, ApiError> {
    super::auth::require_admin_pub(&state, &auth).await?;
    let reopened = drain::cancel(&state.trading_gate);
    tracing::warn!(gate_fully_reopened = reopened, "drain abandoned");
    Ok(Json(
        drain::status(&state.trading_gate, &state.settle_journal, 0).await,
    ))
}
