//! Run configuration — validated CLI args.
//!
//! Defaults match the recommendations in `docs/tee-architecture.md`
//! §13.4: uniform workload, 20% cancel rate, per-trader bearer
//! (each virtual trader holds its own JWT — exercises the
//! `POST /auth/token` + bearer-middleware code paths under load).
//!
//! The CLI in `main.rs` derives directly from this struct via
//! `clap::Parser`, so any new field automatically becomes a flag.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "nyx-tee-loadgen",
    about = "Synthetic order traffic generator for nyx-tee. \
             See docs/tee-architecture.md §13.4."
)]
pub struct RunConfig {
    /// Base URL of the running `nyx-tee` instance. Examples:
    /// `http://127.0.0.1:8080` (local simulator) or
    /// `https://nyx-tee-spike.example.com` (Phala devnet CVM).
    #[arg(long)]
    pub endpoint: String,

    /// Number of virtual traders running in parallel.
    #[arg(long, default_value_t = 10)]
    pub traders: usize,

    /// Target orders per second per trader. Aggregate run rate
    /// is `traders * orders_per_trader_per_sec`. The driver uses
    /// a per-trader `tokio::time::interval` so the actual rate
    /// is closer to `floor` than `ceil`.
    #[arg(long, default_value_t = 5.0)]
    pub orders_per_trader_per_sec: f64,

    /// Total run duration. Each trader stops submitting after
    /// this elapses; the report is rendered immediately after.
    #[arg(long, default_value_t = 30, value_name = "SECONDS")]
    pub duration_secs: u64,

    /// Workload distribution.
    #[arg(long, value_enum, default_value_t = WorkloadKind::Uniform)]
    pub workload: WorkloadKind,

    /// Probability a placed order gets cancelled before fill,
    /// in `[0.0, 1.0]`. `0.20` ≈ real-world darkpool flow.
    #[arg(long, default_value_t = 0.20)]
    pub cancel_rate: f64,

    /// Bearer-token mode.
    #[arg(long, value_enum, default_value_t = AuthMode::PerTrader)]
    pub auth_mode: AuthMode,

    /// Comma-separated Pyth feed id the loadgen seeds (when
    /// `--seed-oracle` is set) and the matcher reads. Defaults to
    /// the canonical SOL-USDC mainnet feed id. Must match the
    /// `feed_id` the TEE's `MatcherDriver` was started with.
    #[arg(
        long,
        default_value = "ef0d8b6fdac3e4cba65d8c1be8ea3b6b88c1d4e2c9d4d9b5e1d4a8e9f0a1b2c3"
    )]
    pub feed_id: String,

    /// If set, the loadgen hits `POST /__debug/oracle/seed` before
    /// starting (TEE must be built with `--features debug_endpoints`).
    /// Use against a local-simulator instance where no real Hermes
    /// traffic is available. Skip against Phala devnet — the
    /// production CVM doesn't expose this route.
    #[arg(long, default_value_t = false)]
    pub seed_oracle: bool,

    /// Oracle midpoint the workload generator targets (Pyth-native
    /// fixed point per `oracle_exponent`). The same value is
    /// written to the cache when `--seed-oracle` is set.
    #[arg(long, default_value_t = 150_000_000)]
    pub oracle_twap: u64,

    /// Pyth exponent — informational. Default -8 for SOL-USDC.
    #[arg(long, default_value_t = -8, allow_hyphen_values = true)]
    pub oracle_exponent: i32,

    /// Output path for the markdown report. If unset, no report
    /// file is written — the summary still prints to stdout.
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Override `api_key` used for bearer acquisition. Defaults
    /// to the seeded test account; overrideable so the same
    /// binary can target a production CVM where credentials were
    /// registered out of band.
    #[arg(long, default_value = "nyx-test-api-key")]
    pub api_key: String,

    /// Override `api_secret`. Plaintext on the CLI is fine for
    /// dev-machine runs against a local simulator — for Phala
    /// devnet runs, read from a file via shell expansion
    /// (`--api-secret "$(cat secret.txt)"`).
    #[arg(long, default_value = "nyx-test-secret")]
    pub api_secret: String,

    /// Override `passphrase`.
    #[arg(long, default_value = "nyx-test-passphrase")]
    pub passphrase: String,

    /// Protocol fee rate (bps) the target CVM is running
    /// (`NYX_TEE_FEE_RATE_BPS`). The loadgen folds this into each
    /// order's collateral note (`nominal + nominal * bps / 10_000`) so
    /// the synthetic note_commitment matches intake's fee-inclusive
    /// re-derivation; a mismatch → 400 (opening != commitment). MUST
    /// equal the CVM's rate. Default 30 mirrors the TEE default; set 0
    /// when targeting a fee-free CVM.
    #[arg(long, default_value_t = 30)]
    pub fee_rate_bps: u16,

    /// Slot every generated order expires at. The TEE matcher sweeps
    /// orders whose `expiry_slot < current_slot`, where `current_slot`
    /// is the REAL Solana slot from the TEE's slot poller (~466M+ on
    /// devnet). So this MUST sit comfortably above the live slot for
    /// the whole run, else every order is swept as expired before it
    /// can match (0 matches, though intake still 2xx-accepts them).
    /// Default 2_000_000_000 is ~19 years out at devnet cadence; bump
    /// it before ~2040 or when targeting a faster cluster.
    #[arg(long, default_value_t = 2_000_000_000)]
    pub expiry_slot: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum WorkloadKind {
    /// Side coin-flip; price drawn uniformly in `oracle_twap *
    /// [0.95, 1.05]`; size lognormal around `1.0 SOL`. This is
    /// the default for v1 and the only variant implemented.
    Uniform,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum AuthMode {
    /// One bearer for all traders. Simpler; doesn't stress the
    /// `POST /auth/token` issuance path. Useful for isolating
    /// orders-handler throughput from auth throughput.
    Shared,
    /// Each trader acquires its own bearer at startup. All
    /// bearers authenticate against the SAME `api_key` (test
    /// account), so per-account rate limits would all surface as
    /// contention against that account. The realistic mode for
    /// throughput numbers we'd quote.
    PerTrader,
}

impl RunConfig {
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.duration_secs)
    }

    /// Per-trader interval between submits. `1.0 / rate` seconds.
    /// Cap at 10 ms to avoid pathological tight loops; floor at
    /// 1 µs (we never serve faster than that).
    pub fn submit_interval(&self) -> Duration {
        let raw = 1.0 / self.orders_per_trader_per_sec.max(1e-3);
        let clamped = raw.clamp(1e-6, 60.0);
        Duration::from_secs_f64(clamped)
    }

    pub fn aggregate_target_rate(&self) -> f64 {
        self.traders as f64 * self.orders_per_trader_per_sec
    }

    /// Reject nonsensical CLI values at the parse boundary so they
    /// never reach the run loop (where they'd silently produce
    /// garbage benchmark numbers rather than a clear error).
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.orders_per_trader_per_sec.is_finite() || self.orders_per_trader_per_sec <= 0.0 {
            anyhow::bail!(
                "--orders-per-trader-per-sec must be finite and > 0 (got {})",
                self.orders_per_trader_per_sec
            );
        }
        if !(0.0..=1.0).contains(&self.cancel_rate) {
            anyhow::bail!(
                "--cancel-rate must be a probability in [0, 1] (got {})",
                self.cancel_rate
            );
        }
        if self.traders == 0 {
            anyhow::bail!("--traders must be > 0");
        }
        Ok(())
    }
}
