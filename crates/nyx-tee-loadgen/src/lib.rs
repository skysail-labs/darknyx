//! `nyx-tee-loadgen` library surface.
//!
//! See the crate-level `[package].description` in `Cargo.toml` +
//! `docs/tee-architecture.md` §13.4 for what this crate does and
//! why it exists. Module split:
//!
//! - [`config`] — `RunConfig` (validated CLI args, default values
//!   centralised so the binary and the smoke test agree).
//! - [`auth`] — bearer acquisition + per-order signing. The
//!   bearer is acquired once per trader and held for the run's
//!   duration (test JWT TTL = 3600s, way longer than any
//!   reasonable bench window).
//! - [`workload`] — order generators. v1 ships `uniform`
//!   (price drawn uniformly around an oracle midpoint; size
//!   lognormal). Future variants land here without touching
//!   `trader`.
//! - [`trader`] — the per-virtual-trader state machine. Submits
//!   orders, sometimes cancels them, records latencies.
//! - [`metrics`] — shared `hdrhistogram`-backed counters. One
//!   `Arc<RunMetrics>` is cloned into each trader; updates use
//!   sub-µs locking.
//! - [`report`] — emits a `BENCHMARK.md` markdown table at run
//!   end.
//! - [`run`] — the top-level entry: spawn N traders, wait for
//!   the duration, drain, return metrics.

pub mod auth;
pub mod config;
pub mod metrics;
pub mod report;
pub mod run;
pub mod trader;
pub mod workload;

pub use config::{AuthMode, RunConfig, Scenario};
pub use metrics::RunMetrics;
pub use run::run_load_gen;
