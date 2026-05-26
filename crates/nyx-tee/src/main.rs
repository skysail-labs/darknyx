//! `nyx-tee` — the in-TEE matching engine.
//!
//! See `docs/tee-architecture.md` for the full design. This file is
//! the boot harness only; everything substantive lives in the
//! sub-modules.
//!
//! # Status
//!
//! - Phase-1 (committed): boots cleanly, modules stubbed.
//! - PR 4a (this commit): dstack handshake — calls `info()`,
//!   derives the Ed25519 signer via `get_key("nyx/ed25519-signer/v1")`,
//!   logs the resulting Solana pubkey. If the dstack socket is
//!   unreachable (no simulator + not running in a real CVM), boot
//!   exits cleanly with a warning so we can build/run the binary
//!   from a normal dev machine without setup ceremony.
//! - PR 4b-d (upcoming): oracle sync, matcher tick, HTTP surface.

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

    // PR-4a: dstack handshake. Returns a `DerivedSigner` we'll
    // thread into the settle pipeline + API surface as later PRs
    // land. If the socket isn't reachable (no simulator running),
    // we log and exit cleanly — running the binary on a dev
    // machine without setup should not be a hard error.
    let _signer = match boot::probe_dstack().await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "dstack probe failed; exiting boot harness early");
            tracing::info!("nyx-tee exiting (no dstack socket reachable)");
            return Ok(());
        }
    };

    tracing::info!(
        "nyx-tee boot complete — signer derived; awaiting PR 4b+ to start oracle sync + matching"
    );
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
