//! `nyx-tee` — the in-TEE matching engine.
//!
//! Production entry point. All real module logic lives in the
//! sibling `lib.rs` so integration tests can exercise it without
//! the binary boot path. This file orchestrates startup:
//!
//!   1. Init tracing.
//!   2. Load config from env.
//!   3. Dstack handshake (PR 4a) → derive signer + capture
//!      app_id / instance_id / compose_hash / MRTD.
//!   4. Build the API state from the boot snapshot.
//!   5. Bind the configured HTTP socket + serve (PR 4d).
//!
//! Future PRs add: oracle sync task (PR 4b is in place; needs
//! wiring here), matcher driver (PR 4c — needs wiring), settle
//! scheduler, Solana RPC poller. Each gets `tokio::spawn`'d as a
//! sibling task to the axum server before we hit
//! `axum::serve(...).await`.
//!
//! Degraded boot: if the dstack socket isn't reachable we serve
//! /health + a stub /info anyway. /attestation returns 503. This
//! lets developers run the binary on a normal dev machine without
//! a simulator just to poke at the routes.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use dstack_sdk::dstack_client::DstackClient;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("nyx-tee starting");

    let cfg = nyx_tee::config::Config::from_env()?;
    tracing::info!(?cfg, "loaded config");

    // ─── 1. dstack handshake ──────────────────────────────────────────
    // Returns Some(state) on success, None if the socket isn't
    // reachable (degraded boot — still serve /health + /info stub).
    let api_state = match nyx_tee::boot::probe_dstack().await {
        Ok(signer) => {
            // Re-fetch info() so we can stash it for /info handlers.
            // Could thread it out of probe_dstack, but keeping that
            // fn single-purpose (derive the signer + log) is worth
            // one extra round-trip at boot.
            let client = DstackClient::new(None);
            let info = client.info().await?;

            // Derive the bearer-JWT secret from dstack while the
            // client is still in scope. Distinct path from the
            // Ed25519 signer so a compromise of one key material
            // doesn't trivially leak the other.
            let jwt_secret = derive_jwt_secret(&client).await?;

            let dstack = Arc::new(client);
            let boot_info = nyx_tee::api::BootAppInfo {
                app_id: info.app_id,
                instance_id: info.instance_id,
                app_name: info.app_name,
                device_id: info.device_id,
                compose_hash: info.compose_hash,
                mrtd: info.tcb_info.mrtd,
            };
            nyx_tee::api::ApiState::from_boot(boot_info, &signer, dstack, jwt_secret)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "dstack probe failed; entering degraded boot. /health + /info \
                 will serve stub data; /attestation returns 503. This is the \
                 expected dev-machine experience without a running simulator."
            );
            nyx_tee::api::ApiState::for_tests()
        }
    };

    // ─── 2. Build router + bind listener ──────────────────────────────
    let app = nyx_tee::api::build_router(Arc::new(api_state));
    let addr: SocketAddr = cfg
        .http_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid NYX_TEE_HTTP_BIND={:?}: {e}", cfg.http_bind))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        local_addr = %listener.local_addr().unwrap_or(addr),
        "nyx-tee HTTP listening — /health /info /attestation"
    );

    // ─── 3. Serve ─────────────────────────────────────────────────────
    // Returns only when the listener is dropped or Ctrl-C is received
    // by the runtime. Future PRs will run this alongside the matcher
    // tick + oracle sync via tokio::join!.
    axum::serve(listener, app).await?;

    tracing::info!("nyx-tee exiting");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("NYX_TEE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,nyx_tee=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// Derive the bearer-JWT HS256 secret from dstack. Uses a path
/// distinct from the Ed25519 signer so the two key materials are
/// independent (compromise of one shouldn't trivially leak the
/// other). Same path → same secret across CVM restarts on the
/// same `app_id`, so bearer tokens issued before a restart remain
/// valid until they expire.
async fn derive_jwt_secret(client: &DstackClient) -> anyhow::Result<[u8; 32]> {
    // Same shape as `keys::ed25519::derive` — Some(path), None for
    // purpose — so the two key-material derivations stay
    // structurally identical and either can be swapped in tests.
    let resp = client
        .get_key(Some("nyx/jwt-secret/v1".to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("dstack.get_key('nyx/jwt-secret/v1') failed: {e}"))?;
    let bytes = resp
        .decode_key()
        .map_err(|e| anyhow::anyhow!("dstack.get_key returned undecodable JWT key: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "dstack returned {} bytes for JWT secret; expected 32",
            bytes.len()
        )
    })?;
    Ok(arr)
}
