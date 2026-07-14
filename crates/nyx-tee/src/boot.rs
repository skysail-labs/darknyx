//! Boot-time dstack handshake.
//!
//! Stages (per `docs/tee-architecture.md` §3):
//!   1. Connect to the dstack socket (`DSTACK_SIMULATOR_ENDPOINT` in
//!      local dev; `/var/run/dstack.sock` in a real CVM — the
//!      `DstackClient::new(None)` picks the right one).
//!   2. `info()` → app_id, instance_id, compose_hash, MRTD.
//!   3. Derive the Ed25519 signer via
//!      `dstack.get_key("nyx/ed25519-signer/v1")` →
//!      `SigningKey::from_bytes(seed)`.
//!   4. Log the resulting Solana base58 pubkey so an operator can
//!      cross-check against the on-chain `vault_config.tee_pubkey`
//!      before running the rotation ceremony.
//!
//! Returns the derived signer to `main.rs`, which threads it
//! through to the settle-pipeline + the API server's `/info`
//! endpoint.
//!
//! A failed handshake is returned to `main`, which fails production startup.
//! Only an explicitly configured local simulator test mode may substitute test
//! state after this function returns an error.

use anyhow::Result;

use crate::keys::ed25519::{self, DerivedSigner};

/// Connect to dstack + derive the signer. Logs all the
/// human-readable fields (app_id, compose_hash, signer pubkey).
/// Returns the derived signer on success.
pub async fn probe_dstack() -> Result<DerivedSigner> {
    // DstackClient::new(None) picks up DSTACK_SIMULATOR_ENDPOINT
    // from the env if set; otherwise falls back to
    // /var/run/dstack.sock.
    let client = dstack_sdk::dstack_client::DstackClient::new(None);

    let info = match client.info().await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(
                error = %e,
                "dstack.info() failed; production startup must terminate. \
                 Local development requires a running simulator and explicit \
                 NYX_TEE_ALLOW_TEST_AUTH=1 for test-state fallback."
            );
            anyhow::bail!("dstack unreachable: {}", e);
        }
    };

    tracing::info!(
        app_id = %info.app_id,
        instance_id = %info.instance_id,
        app_name = %info.app_name,
        device_id = %info.device_id,
        compose_hash = %info.compose_hash,
        mrtd = %info.tcb_info.mrtd,
        "dstack handshake — info() succeeded"
    );

    // Shard 0's signer. The full K-signer set (one fee-payer per shard) is
    // derived in `main.rs` via `ed25519::derive_set` once `num_trees` is known;
    // this primary is what `/info` advertises + the operator cross-checks.
    let signer = ed25519::derive(&client, 0).await?;

    // Logging the signer pubkey on boot is intentional — it's what
    // an operator pastes into the multisig rotation proposal at
    // image-upgrade time. The PRIVATE half (signer.key) is never
    // logged.
    tracing::info!(
        path = %ed25519::signer_path(0),
        pubkey_base58 = %signer.pubkey_base58,
        pubkey_hex = %signer.pubkey_hex,
        "dstack handshake — derived shard-0 Ed25519 signer (register the full set in vault_config.tee_pubkeys)"
    );

    Ok(signer)
}
