//! Debug endpoints gated by the `debug_endpoints` cargo feature.
//!
//! These routes exist so `darknyx-tee-loadgen` (PR 4f) can run
//! end-to-end smoke benchmarks against a local-simulator `darknyx-tee`
//! without depending on real Pyth Hermes network traffic. The
//! feature MUST be off in production builds — there is no auth on
//! these routes, so a feature-on production deploy would allow
//! anyone reaching the HTTP port to rewrite the matcher's price
//! view.
//!
//! Routes (all under `/__debug/`):
//!
//! - `POST /__debug/oracle/seed` — writes a `CachedPrice` into the
//!   in-process `OracleCache`. Returns 200 on success, 503 when no
//!   cache is attached (matcher-less test state), 400 on malformed body.
//!
//! Compilation is gated at the module-declaration site
//! (`api/mod.rs`'s `#[cfg(feature = "debug_endpoints")] pub mod
//! debug;`) — no inner `#![cfg(...)]` here so we don't double-gate.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

use super::state::ApiState;
use crate::oracle::{vaa::TrustProfile, CachedPrice};

#[derive(Debug, Deserialize)]
pub struct OracleSeedRequest {
    /// Pyth feed id — 64-char hex string. Must match the
    /// `feed_id` the `MatcherDriver` is reading.
    pub feed_id: String,
    /// EMA price ("TWAP proxy") in Pyth-native fixed point per
    /// `exponent`. The handler trusts this value verbatim; the
    /// debug endpoint exists to bypass the Hermes/VAA verification
    /// path for benchmarks.
    pub twap: u64,
    /// Pyth confidence interval, same units as `twap`. Defaults
    /// to 0 (perfectly precise) so the matcher's circuit-breaker
    /// band is at its narrowest.
    #[serde(default)]
    pub confidence: u64,
    /// Pyth exponent (negative power of 10). -8 covers SOL-USDC.
    #[serde(default = "default_exponent")]
    pub exponent: i32,
}

fn default_exponent() -> i32 {
    -8
}

/// `POST /__debug/oracle/seed`.
pub async fn seed_oracle(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<OracleSeedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let oracle = state.oracle.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "oracle cache not initialised on this instance".to_string(),
    ))?;

    let feed_id = req.feed_id;
    oracle
        .seed_unverified(
            feed_id.clone(),
            CachedPrice {
                twap: req.twap,
                confidence: req.confidence,
                exponent: req.exponent,
                publish_time_ms: 0,
                vaa_sequence: 0,
                trust_profile: TrustProfile::LegacyWormholeV1,
                // `seed_unverified` stamps this to `now_ms()` before insert,
                // so the entry is fresh by construction. The matcher's
                // freshness check then passes for the configured
                // `max_oracle_age_ms` window.
                last_updated_ms: 0,
                // No VAA backing — this is the whole point of the
                // debug route. The matcher tick reads `twap` /
                // `confidence` / `exponent` and doesn't look at the
                // VAA; the v3 on-chain re-verify path would, but
                // that's behind a `verify_match_batch` ix the loadgen
                // doesn't exercise.
                vaa: Vec::new(),
            },
        )
        .await;

    // Debug/load-test parity with the authenticated sync path: a freshly seeded
    // oracle makes only markets bound to this feed healthy again. The helper
    // cannot clear another feed's pause or an independent venue-wide
    // governance/drain reason.
    state.resume_oracle_for_feed(&feed_id);

    Ok(StatusCode::OK)
}
