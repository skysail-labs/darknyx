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
    /// Versioned boot-selected oracle producer/trust boundary.
    pub oracle_mode: Option<&'static str>,
    pub oracle_max_age_ms: Option<u64>,
    /// The TEE's current view of the Solana slot (drives expiry sweeps).
    pub current_slot: u64,
    pub version: &'static str,
}

pub async fn get_status(State(state): State<Arc<ApiState>>) -> Json<SystemStatus> {
    let matcher_running = !state.all_matchers().is_empty() && state.any_market_open();
    let all_markets_ready = state.all_markets_open();
    let settle_enabled = state.settle_enabled;
    Json(SystemStatus {
        // Partial oracle degradation remains visible even while another market
        // is healthy enough for `matcher_running=true`.
        degraded: !(all_markets_ready && settle_enabled),
        matcher_running,
        settle_enabled,
        oracle_configured: state.oracle.is_some(),
        oracle_mode: state.oracle_mode.map(|mode| mode.as_str()),
        oracle_max_age_ms: state.oracle_mode.map(|mode| mode.freshness().max_age_ms),
        current_slot: state.current_slot.load(Ordering::Relaxed),
        version: state.version,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::instruments::InstrumentInfo;
    use crate::matcher::{MatcherState, TradingPauseReason};
    use crate::oracle::OracleCache;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn oracle_status_fields_match_the_sdk_wire_contract() {
        for (mode, expected_name, expected_age) in [
            (
                Some(crate::oracle::OracleMode::PythSolanaPushV1),
                Some("pyth-solana-push-v1"),
                Some(420_000),
            ),
            (
                Some(crate::oracle::OracleMode::PythRouterQuorumV1),
                Some("pyth-router-quorum-v1"),
                Some(5_000),
            ),
            (None, None, None),
        ] {
            let state = match mode {
                Some(mode) => ApiState::for_tests().with_oracle_mode(mode),
                None => ApiState::for_tests(),
            };
            let Json(status) = get_status(State(Arc::new(state))).await;
            let wire = serde_json::to_value(status).unwrap();
            assert_eq!(
                wire["oracle_mode"],
                serde_json::to_value(expected_name).unwrap()
            );
            assert_eq!(
                wire["oracle_max_age_ms"],
                serde_json::to_value(expected_age).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn partial_market_pause_is_available_but_degraded() {
        let state = ApiState::for_tests()
            .with_instruments(vec![
                InstrumentInfo {
                    symbol: "SOL-USDC".to_string(),
                    base_mint: [1; 32],
                    quote_mint: [2; 32],
                    tick_size: 1,
                    min_order_size: 1,
                    oracle_feed_id: "aa".repeat(32),
                },
                InstrumentInfo {
                    symbol: "BTC-USDC".to_string(),
                    base_mint: [3; 32],
                    quote_mint: [2; 32],
                    tick_size: 1,
                    min_order_size: 1,
                    oracle_feed_id: "bb".repeat(32),
                },
            ])
            .with_market_runtimes(
                HashMap::from([
                    (
                        "SOL-USDC".to_string(),
                        Arc::new(RwLock::new(MatcherState::new())),
                    ),
                    (
                        "BTC-USDC".to_string(),
                        Arc::new(RwLock::new(MatcherState::new())),
                    ),
                ]),
                Arc::new(AtomicU64::new(1)),
                OracleCache::new(),
            )
            .with_settle_enabled(true);
        state
            .trading_gate_for_symbol("SOL-USDC")
            .unwrap()
            .pause_for(TradingPauseReason::Oracle);

        let Json(status) = get_status(State(Arc::new(state))).await;
        assert!(
            status.matcher_running,
            "the healthy BTC market remains available"
        );
        assert!(
            status.degraded,
            "partial oracle failure remains visible to operators and clients"
        );
    }
}
