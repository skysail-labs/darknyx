//! `GET /info` — application + instance metadata.
//!
//! Shape mirrors the OpenAPI `AppInfo` schema in
//! `docs/tee-api-openapi.yaml`. The SDK's `verifyTeeAttestation()`
//! helper hits this endpoint at session start to:
//!
//!   1. Cross-check `compose_hash` against its baked-in
//!      `EXPECTED_COMPOSE_HASH` constant (proves the running
//!      image is the audited one).
//!   2. Surface `tee_pubkey` so the caller can verify on-chain
//!      `vault_config.tee_pubkey == this.tee_pubkey`.
//!
//! All fields here are boot-time snapshots. None of them change
//! for the lifetime of the CVM, so we don't re-fetch
//! `dstack.info()` per request.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;

use super::state::ApiState;

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub app_id: String,
    pub instance_id: String,
    pub app_name: String,
    pub device_id: String,
    /// SHA-256 of canonicalised `app-compose.json`. The SDK's
    /// `EXPECTED_COMPOSE_HASH` constant must equal this for the
    /// attestation check to pass.
    pub compose_hash: String,
    pub tcb_info: TcbInfo,
    /// Solana base58 of the Ed25519 signer pubkey. Equal to
    /// on-chain `vault_config.tee_pubkey` after the most recent
    /// multisig rotation.
    pub tee_pubkey: String,
    /// `nyx-tee` build version (Cargo `version` field).
    pub nyx_version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct TcbInfo {
    /// SHA-384 of the initial Trust Domain measurement —
    /// covers OVMF/firmware. Verifies against the dstack-OS
    /// image hash whitelisted in governance.
    pub mrtd: String,
}

pub async fn handler(State(state): State<Arc<ApiState>>) -> Json<InfoResponse> {
    Json(InfoResponse {
        app_id: state.app_info.app_id.clone(),
        instance_id: state.app_info.instance_id.clone(),
        app_name: state.app_info.app_name.clone(),
        device_id: state.app_info.device_id.clone(),
        compose_hash: state.app_info.compose_hash.clone(),
        tcb_info: TcbInfo {
            mrtd: state.app_info.mrtd.clone(),
        },
        tee_pubkey: state.signer_pubkey_base58.clone(),
        nyx_version: state.nyx_version,
    })
}
