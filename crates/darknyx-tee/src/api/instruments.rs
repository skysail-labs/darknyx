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
    /// Pyth Hermes feed id (hex) the matcher pulls its price from. The
    /// TEE uses Pyth-pull (Hermes), not an on-chain oracle account, so
    /// this is the feed identifier rather than a Solana pubkey.
    pub oracle_feed_id: String,
}

#[derive(Debug, Serialize)]
pub struct OracleInfo {
    #[serde(rename = "type")]
    pub kind: String,
    /// The Pyth feed id (hex). Named `pubkey` to match the openapi
    /// `Instrument.oracle` field.
    pub pubkey: String,
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
    fn from_info(i: &InstrumentInfo, trading_enabled: bool) -> Self {
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
            },
        }
    }
}

/// `GET /instruments` — public.
pub async fn list_instruments(State(state): State<Arc<ApiState>>) -> Json<Vec<Instrument>> {
    Json(
        state
            .instruments
            .iter()
            .map(|info| {
                let enabled = state
                    .trading_gate_for_symbol(&info.symbol)
                    .is_some_and(|gate| gate.is_open());
                Instrument::from_info(info, enabled)
            })
            .collect(),
    )
}

/// `GET /instruments/{symbol}` — public. 404 if the symbol is unknown.
pub async fn get_instrument(
    State(state): State<Arc<ApiState>>,
    Path(symbol): Path<String>,
) -> Result<Json<Instrument>, super::error::ApiError> {
    state
        .instruments
        .iter()
        .find(|i| i.symbol == symbol)
        .map(|i| {
            let enabled = state
                .trading_gate_for_symbol(&i.symbol)
                .is_some_and(|gate| gate.is_open());
            Json(Instrument::from_info(i, enabled))
        })
        .ok_or_else(|| super::error::ApiError::not_found(format!("unknown instrument '{symbol}'")))
}
