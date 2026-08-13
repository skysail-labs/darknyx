//! `/instruments` — public market metadata. Wire contract:
//! `docs/tee-api-openapi.yaml`.
//!
//! - `GET /instruments` — list every tradable instrument.
//! - `GET /instruments/{symbol}` — one instrument, 404 if unknown.
//!
//! The data is static for the CVM's lifetime, captured on `ApiState` at boot
//! from the governed market config + operator-owned display symbol/feed.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;

use super::state::ApiState;
use crate::oracle::{derive_push_feed_address, OracleMode};

/// One market's metadata, captured at boot. Raw bytes / integers; the
/// handler renders them into the openapi `Instrument` shape (base58
/// mints, decimal-string sizes).
#[derive(Debug, Clone)]
pub struct InstrumentInfo {
    pub symbol: String,
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub tick_size: u64,
    pub min_order_size: u64,
    /// Pyth feed id (hex). The boot-selected adapter resolves it either through
    /// the upgraded router or its derived sponsored push-account PDA.
    pub oracle_feed_id: String,
}

#[derive(Debug, Serialize)]
pub struct OracleInfo {
    #[serde(rename = "type")]
    pub kind: String,
    /// The Pyth feed id (hex). Named `pubkey` to match the openapi
    /// `Instrument.oracle` field.
    pub pubkey: String,
    /// Versioned producer/trust boundary selected at CVM boot.
    pub source: String,
    /// Derived upgraded Pyth push account when the Solana source is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub publish_time_ms: Option<u64>,
    pub age_ms: Option<u64>,
    pub max_age_ms: Option<u64>,
}

/// openapi `Instrument` shape.
#[derive(Debug, Serialize)]
pub struct Instrument {
    pub symbol: String,
    pub base_mint: String,
    pub quote_mint: String,
    pub tick_size: String,
    pub min_order_size: String,
    /// Current fail-closed readiness for new place/modify/match operations on
    /// this market. Cancellation, reads, and reconciliation remain available.
    pub trading_enabled: bool,
    pub oracle: OracleInfo,
}

impl Instrument {
    fn from_info(
        i: &InstrumentInfo,
        trading_enabled: bool,
        mode: Option<OracleMode>,
        cached: Option<crate::oracle::CachedPrice>,
    ) -> Self {
        let publish_time_ms = cached.as_ref().map(|price| price.publish_time_ms);
        let source = mode
            .map(|value| value.as_str())
            .or_else(|| cached.as_ref().map(|price| price.source.as_str()))
            .unwrap_or("unconfigured")
            .to_string();
        let account = (mode == Some(OracleMode::PythSolanaPushV1))
            .then(|| {
                hex::decode(&i.oracle_feed_id)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .and_then(|feed_id| derive_push_feed_address(&feed_id).ok())
                    .map(|address| address.to_string())
            })
            .flatten();
        Instrument {
            symbol: i.symbol.clone(),
            base_mint: bs58::encode(i.base_mint).into_string(),
            quote_mint: bs58::encode(i.quote_mint).into_string(),
            tick_size: i.tick_size.to_string(),
            min_order_size: i.min_order_size.to_string(),
            trading_enabled,
            oracle: OracleInfo {
                kind: "pyth_pull_v2".to_string(),
                pubkey: i.oracle_feed_id.clone(),
                source,
                account,
                publish_time_ms,
                age_ms: publish_time_ms
                    .map(|published| crate::oracle::cache::now_ms().saturating_sub(published)),
                max_age_ms: mode.map(|value| value.freshness().max_age_ms),
            },
        }
    }
}

/// `GET /instruments` — public.
pub async fn list_instruments(State(state): State<Arc<ApiState>>) -> Json<Vec<Instrument>> {
    let mut instruments = Vec::with_capacity(state.instruments.len());
    for info in &state.instruments {
        let enabled = state
            .trading_gate_for_symbol(&info.symbol)
            .is_some_and(|gate| gate.is_open());
        let cached = match &state.oracle {
            Some(cache) => cache.get(&info.oracle_feed_id).await,
            None => None,
        };
        instruments.push(Instrument::from_info(
            info,
            enabled,
            state.oracle_mode,
            cached,
        ));
    }
    Json(instruments)
}

/// `GET /instruments/{symbol}` — public. 404 if the symbol is unknown.
pub async fn get_instrument(
    State(state): State<Arc<ApiState>>,
    Path(symbol): Path<String>,
) -> Result<Json<Instrument>, super::error::ApiError> {
    let (info, enabled) = state
        .instruments
        .iter()
        .find(|i| i.symbol == symbol)
        .map(|i| {
            let enabled = state
                .trading_gate_for_symbol(&i.symbol)
                .is_some_and(|gate| gate.is_open());
            (i, enabled)
        })
        .ok_or_else(|| {
            super::error::ApiError::not_found(format!("unknown instrument '{symbol}'"))
        })?;
    let cached = match &state.oracle {
        Some(cache) => cache.get(&info.oracle_feed_id).await,
        None => None,
    };
    Ok(Json(Instrument::from_info(
        info,
        enabled,
        state.oracle_mode,
        cached,
    )))
}
