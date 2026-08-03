//! Fills router: fan the matcher's global `FillMemo` broadcast out to
//! per-account channels.
//!
//! The matcher is account-agnostic (it keys memos by `order_id`, mirroring the
//! chain, which has no notion of "account"). This task bridges that to the auth
//! layer: it looks up each memo's owning account via the intake-time
//! `order_id → account` map and forwards to that account's channel. Keeping the
//! join here means the matcher never learns account identities and the
//! per-account leak guard lives in one place.

use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;

use super::state::ApiState;

/// Spawn the router task. No-op (returns without spawning) when there is no
/// matcher (isolated test state) — there are no memos to route.
pub fn spawn_fills_router(state: Arc<ApiState>) {
    for matcher in state.all_matchers() {
        let state = state.clone();
        tokio::spawn(async move {
            let mut rx = matcher.read().await.subscribe_fills();
            loop {
                match rx.recv().await {
                    Ok(memo) => {
                        state.route_fill(&memo).await;
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        // The messages are gone before any per-account channel
                        // saw them, so no client is slow and none would be
                        // closed — every connected session would silently hold
                        // an incomplete view (SW-31). Bump the epoch so the
                        // sessions close 1011 and re-derive from the chain.
                        tracing::error!(
                            skipped,
                            "fills router lagged on the matcher broadcast; \
                             signalling every session to resync"
                        );
                        state
                            .resync_epoch
                            .fetch_add(1, std::sync::atomic::Ordering::Release);
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }
}
