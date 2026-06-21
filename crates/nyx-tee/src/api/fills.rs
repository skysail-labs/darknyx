//! Fill-memo replay — the durable "backfill" half of "backfill then tail".
//!
//! `GET /fills/replay?since=<seq>` (bearer) returns the caller account's
//! persisted `FillMemo`s with `seq > since`, oldest first. This is what makes
//! fill delivery self-healing after amount-privacy (P4) made the off-TEE
//! indexer a commitment-only locator: a client that was offline (or whose CVM
//! restarted) when a fill settled recovers the change-note amount + opening here
//! instead of the (now amount-free) indexer.
//!
//! Cursor: the client passes `since = 0` for a first/no-cursor sync (every real
//! memo has `seq >= 1`), then `since = <max seq it has stored>` thereafter.
//! Integrity is the client's job — each returned memo runs the same
//! `verifyFillMemo` (Vuln-4) guard as a live one, so a replayed memo is trusted
//! no more than a live one.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use super::auth::Authorized;
use super::state::ApiState;
use crate::matcher::FillMemo;

/// `?since=<seq>` — the client's last-seen sequence. Defaults to 0 ("give me
/// everything"). Extra/garbage params are ignored by serde.
#[derive(Debug, Deserialize, Default)]
pub struct ReplayQuery {
    #[serde(default)]
    pub since: u64,
}

/// `GET /fills/replay` response.
#[derive(Debug, Serialize)]
pub struct ReplayResponse {
    /// Memos with `seq > since`, oldest first. Each carries its `seq` so the
    /// client can advance its cursor to `memos.last().seq`.
    pub memos: Vec<FillMemo>,
    /// The highest `seq` returned (the cursor to pass next time), or the
    /// request's `since` when nothing was newer — so the client can always
    /// store `next_cursor` verbatim.
    pub next_cursor: u64,
}

/// `GET /fills/replay?since=<seq>` — bearer. Per-account: the JWT identifies the
/// account, and only that account's memos are returned (same isolation as the
/// live `/ws/fills` channel).
pub async fn replay_fills(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Query(q): Query<ReplayQuery>,
) -> Result<Json<ReplayResponse>, super::error::ApiError> {
    let memos = state.replay_fills(&auth.account_id, q.since).await;
    let next_cursor = memos.iter().filter_map(|m| m.seq).max().unwrap_or(q.since);
    Ok(Json(ReplayResponse { memos, next_cursor }))
}
