//! `nyx-tee` — the in-TEE matching engine.
//!
//! Production entry point. All real module logic lives in the
//! sibling `lib.rs` so integration tests can exercise it without
//! the binary boot path. This file just initializes tracing, loads
//! config, runs the boot handshake, and exits (until PR 4c+ where
//! the matching loop / API server stay alive).
//!
//! See `docs/tee-architecture.md` for the full design.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

// Modules the binary uses directly. They also live under the
// library crate (`nyx_tee::...`) for integration tests, but the
// binary references them via local `mod` declarations to keep the
// hot-path tree compact.
mod api;
mod matcher;
mod merkle;
mod persistence;
mod prover;
mod settle;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("nyx-tee starting");

    let cfg = nyx_tee::config::Config::from_env()?;
    tracing::info!(?cfg, "loaded config");

    // PR-4a: dstack handshake. Returns a `DerivedSigner` we'll
    // thread into the settle pipeline + API surface as later PRs
    // land. If the socket isn't reachable (no simulator running),
    // we log and exit cleanly — running the binary on a dev
    // machine without setup should not be a hard error.
    let _signer = match nyx_tee::boot::probe_dstack().await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "dstack probe failed; exiting boot harness early");
            tracing::info!("nyx-tee exiting (no dstack socket reachable)");
            return Ok(());
        }
    };

    tracing::info!(
        "nyx-tee boot complete — signer derived; awaiting PR 4c+ to start oracle sync + matching"
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
