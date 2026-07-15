//! `GET /info` — application + instance metadata.
//!
//! Shape mirrors the OpenAPI `AppInfo` schema in
//! `docs/tee-api-openapi.yaml`. A client's attestation verifier hits
//! this endpoint at session start to:
//!
//!   1. Cross-check `compose_hash` — but ONLY as a convenience: the
//!      authoritative compose hash is derived from the DCAP-verified
//!      quote's RTMR3 event log, NOT trusted from this field (a
//!      malicious gateway can put anything here). See
//!      `packages/sdk/src/tee/verify-core.ts`.
//!   2. Surface `tee_pubkeys` — the FULL K-shard signer set (shard
//!      order) so the caller can verify on-chain
//!      `vault_config.tee_pubkeys` matches the set the enclave holds.
//!      `tee_pubkey` (singular) is kept as the shard-0 primary for
//!      back-compat.
//!
//! `/info` is UNAUTHENTICATED-adjacent metadata and is NOT a trust
//! root on its own — the quote + event log from `/attestation` are.
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
    /// Fresh 32-byte process-boot session id, hex. Every order signature binds
    /// it so pre-reboot requests cannot be replayed.
    pub boot_session_id: String,
    pub tcb_info: TcbInfo,
    /// Solana base58 of the shard-0 (primary) Ed25519 signer pubkey.
    /// Kept for back-compat; prefer `tee_pubkeys` for the full set.
    pub tee_pubkey: String,
    /// The FULL K-shard TEE signer set (base58, shard order). The vault
    /// accepts settle payloads from EVERY one of these
    /// (`vault_config.tee_pubkeys`), so a client cross-checks the whole
    /// set against on-chain governance — attestation over shard 0 alone
    /// covers only 1/K of the settle-authorizing keys.
    pub tee_pubkeys: Vec<String>,
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
        boot_session_id: hex::encode(state.boot_session_id),
        tcb_info: TcbInfo {
            mrtd: state.app_info.mrtd.clone(),
        },
        tee_pubkey: state.signer_pubkey_base58.clone(),
        tee_pubkeys: state.signer_pubkeys_base58.clone(),
        nyx_version: state.nyx_version,
    })
}
