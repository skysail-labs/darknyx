//! Settle scheduler. Drives the v3.5 pipeline:
//!   verify_match_batch → per-batch ALT → N × tee_forced_settle_batched
//!   → close_batch_validity_marker.
//!
//! Re-uses the helper sequence currently in
//! `packages/sdk/tests/helpers/batched-settle.ts`, ported to Rust.
//! See `docs/tee-architecture.md` §6.

pub mod alt;
pub mod payload;
pub mod pipeline;
pub mod sign;
