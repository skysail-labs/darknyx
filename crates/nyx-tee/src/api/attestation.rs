//! `GET /attestation?reportData=<hex>` — fresh TDX attestation
//! quote.
//!
//! Unauthenticated. Clients call this with a freshly-generated
//! 32-byte nonce in `reportData` to prove the quote was produced
//! for THEIR request (replay protection). The TEE wraps the
//! caller bytes into the standard layout documented in
//! `docs/tee-attestation-flow.md` §2:
//!
//! ```text
//!   report_data[0..32]  = caller-supplied bytes (nonce, etc.)
//!   report_data[32..64] = SHA-256(pk_0 ‖ pk_1 ‖ … ‖ pk_{K-1})
//! ```
//!
//! The right-half binds the SHA-256 of the FULL K-shard signer set
//! (`/info.tee_pubkeys`, raw pubkeys concatenated in shard order).
//! This lets a client tie EVERY settle-authorizing key — not just
//! shard 0 — to this quote, closing the "attestation covers 1/K
//! keys" gap. For a single-shard TEE it is exactly `SHA-256(pk_0)`.
//!
//! Failure modes:
//!   - dstack socket unreachable (degraded boot / test mode)
//!     → 503 Service Unavailable
//!   - `reportData` query param is malformed hex / too long
//!     → 400 Bad Request
//!   - dstack `get_quote()` errors → 500 Internal Server Error

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use super::state::ApiState;

#[derive(Debug, Deserialize)]
pub struct AttestationParams {
    /// Hex-encoded caller bytes. Up to 32 bytes — anything beyond
    /// goes into the right-half slot and clobbers the pubkey
    /// binding, so we reject longer inputs at parse time. Empty /
    /// missing → use 32 zeros as the nonce slot.
    #[serde(rename = "reportData")]
    pub report_data: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    /// Hex-encoded TDX quote.
    pub quote: String,
    /// The dstack event log as a **JSON string** (an array of measured
    /// events — NOT hex-encoded). A client replays it against the
    /// DCAP-verified quote's RTMR3 to bind the compose-hash + instance-id
    /// + key-provider. See `packages/sdk/src/tee/verify-core.ts`.
    pub event_log: String,
    /// Hex of the 64-byte `report_data` field embedded in the
    /// quote. Layout as documented above.
    pub report_data: String,
    /// Base58 of the TEE's Ed25519 signer pubkey. The right-half
    /// of `report_data` is `SHA-256` of THIS — the caller can
    /// verify the binding without an out-of-band lookup.
    pub tee_pubkey: String,
}

pub async fn handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<AttestationParams>,
) -> Result<Json<AttestationResponse>, super::error::ApiError> {
    // 1. Degraded-boot check.
    let dstack = state.dstack.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "dstack socket not reachable; attestation unavailable in this build".to_string(),
        )
    })?;

    // 2. Parse + bound the caller-supplied bytes.
    let caller_bytes = match params.report_data {
        Some(hex_str) if !hex_str.is_empty() => {
            let bytes = hex::decode(&hex_str).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("reportData is not valid hex: {e}"),
                )
            })?;
            if bytes.len() > 32 {
                return Err(super::error::ApiError::malformed(format!(
                    "reportData is {} bytes; max 32 (the right half is reserved for tee_pubkey binding)",
                    bytes.len()
                )));
            }
            bytes
        }
        _ => Vec::new(),
    };

    // 3. Build the 64-byte report_data layout: caller bytes
    //    (zero-padded on the right to 32) || SHA-256(the FULL K-shard signer
    //    set, concatenated in shard order). Binding the whole set — not just
    //    shard 0 — lets a client tie EVERY settle-authorizing key to this
    //    DCAP-verified quote (see `packages/sdk/src/tee/verify-core.ts`). For a
    //    single-shard TEE this is exactly SHA-256(pk_0).
    let mut report_data = [0u8; 64];
    report_data[..caller_bytes.len()].copy_from_slice(&caller_bytes);
    report_data[32..].copy_from_slice(&state.signer_set_hash);

    // 4. Fetch the quote.
    let quote = dstack.get_quote(report_data.to_vec()).await.map_err(|e| {
        tracing::error!(error = %e, "attestation: dstack get_quote failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error".to_string(),
        )
    })?;

    Ok(Json(AttestationResponse {
        quote: quote.quote,
        event_log: quote.event_log,
        report_data: hex::encode(report_data),
        tee_pubkey: state.signer_pubkey_base58.clone(),
    }))
}
