//! `nyx-tee-loadgen` binary entry point.
//!
//! ```text
//! cargo run -p nyx-tee-loadgen -- \
//!     --endpoint http://127.0.0.1:8080 \
//!     --traders 100 \
//!     --orders-per-trader-per-sec 5 \
//!     --duration-secs 60 \
//!     --workload uniform \
//!     --cancel-rate 0.20 \
//!     --auth-mode per-trader \
//!     --seed-oracle \
//!     --report BENCHMARK.md
//! ```

use anyhow::Result;
use clap::Parser;
use nyx_tee_loadgen::{run_load_gen, RunConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cfg = RunConfig::parse();
    cfg.validate()?;

    // Real on-chain settle path (opt-in) — a single REAL crossing pair through
    // the live CVM, not the synthetic load.
    if cfg.real_settle {
        #[cfg(feature = "real-settle-chain")]
        {
            use nyx_tee_loadgen::real_settle::run::{run_real_settle, RealSettleParams};
            tracing::info!(endpoint = cfg.endpoint, "starting --real-settle round");
            run_real_settle(RealSettleParams::from_config(&cfg)?).await?;
            return Ok(());
        }
        #[cfg(not(feature = "real-settle-chain"))]
        anyhow::bail!("--real-settle requires building with --features real-settle-chain");
    }

    tracing::info!(
        endpoint = cfg.endpoint,
        traders = cfg.traders,
        rate = cfg.orders_per_trader_per_sec,
        duration_s = cfg.duration_secs,
        "starting nyx-tee-loadgen"
    );

    let outcome = run_load_gen(cfg.clone()).await?;

    println!("\n{}", outcome.markdown_report);

    if let Some(path) = cfg.report.as_ref() {
        std::fs::write(path, &outcome.markdown_report)?;
        tracing::info!(?path, "wrote markdown report");
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("NYX_LOADGEN_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,nyx_tee_loadgen=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
