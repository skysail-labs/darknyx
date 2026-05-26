//! `nyx-tee` — the in-TEE matching engine.
//!
//! See `docs/tee-architecture.md` for the full design. This file is
//! the boot harness only; everything substantive lives in the
//! sub-modules.
//!
//! # Phase-1 status
//!
//! - Compiles, starts a tokio runtime, logs that it's alive.
//! - Connects to `/var/run/dstack.sock` (or `DSTACK_SIMULATOR_ENDPOINT`
//!   if set) and prints `info()`.
//! - Every other module is stubbed; matching / settle / prover /
//!   API server come later.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod api;
mod boot;
mod config;
mod keys;
mod matcher;
mod merkle;
mod persistence;
mod prover;
mod settle;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("nyx-tee starting (phase-1 skeleton)");

    let cfg = config::Config::from_env()?;
    tracing::info!(?cfg, "loaded config");

    // Phase-1 smoke: just probe the dstack socket and log what's
    // there. Real work (key derivation, attestation, API server)
    // arrives in subsequent PRs.
    boot::probe_dstack().await?;

    tracing::info!("nyx-tee phase-1 skeleton: exiting cleanly");
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
