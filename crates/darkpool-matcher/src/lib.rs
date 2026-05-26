//! Pure matching algorithm for the Nyx dark pool.
//!
//! Uniform-clearing-price batch auction with FIFO tie-break and
//! Pyth-band circuit breaker. The same algorithm currently lives in
//! `programs/matching_engine/src/instructions/run_batch.rs`. This
//! crate is the v2 lift target: the algorithm moves here, both the
//! existing litesvm `run_batch` test AND the new in-TEE matcher
//! (`crates/nyx-tee`) consume this single source of truth.
//!
//! # Status
//!
//! **PR 1 — type surface only.** The public Borsh types are stable
//! and byte-equivalent to their on-chain counterparts (PR-2 ports
//! the algorithm body; PR-3 cuts the on-chain ix over to call this
//! crate).
//!
//! # Invariants the lift must preserve
//!
//! See `programs/matching_engine/src/instructions/run_batch.rs` for
//! the authoritative implementation. When lifting (PR 2):
//!
//! * Uniform clearing price across the batch.
//! * FIFO tie-break at each price level.
//! * Pyth-TWAP circuit breaker (`circuit_breaker_bps`).
//! * Fee accumulator drain rules from `state/fee_accumulator.rs`.
//! * Change-note construction parity with `change_note::derive_*`
//!   (byte-equality with both the on-chain Rust AND the TS port
//!   in `packages/sdk/tests/helpers/e2e-helpers.ts`).
//! * No floating point anywhere.
//! * Deterministic across runs given the same inputs (no clock
//!   reads inside the matcher; pass `current_slot` as input).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod book;
pub mod change_note;
pub mod config;
pub mod error;
pub mod fee;
pub mod match_result;

pub use book::{
    Order, OrderBook, OrderSide, OrderStatus, OrderType, OrderUpdate, OrderUpdateKind, Price,
    Quantity,
};
pub use config::{MatchConfig, OracleSnapshot, SETTLEMENT_BUFFER_SLOTS};
pub use error::MatchError;
pub use fee::FeeBucket;
pub use match_result::{MatchPair, MatchStatus, RunBatchOutput, RELOCK_ORDER_ID_NONE};

/// The single public entry point. Given a book snapshot + oracle
/// reading + market config + the current slot, produce up to N
/// matches (where N is the on-chain VALID_MATCH_BATCH instantiation
/// size — currently 16) plus the post-match updates the caller must
/// apply.
///
/// **PR-1 STUB.** Returns an empty batch. The full lift is gated
/// by the `parity_against_litesvm_run_batch` test in
/// `tests/parity.rs`, which arrives in PR 2.
pub fn run_batch(
    _book: &OrderBook,
    _oracle: &OracleSnapshot,
    _config: &MatchConfig,
    current_slot: u64,
) -> Result<RunBatchOutput, MatchError> {
    // TODO(PR-2): lift programs/matching_engine/src/instructions/run_batch.rs.
    // Until then, the parity test in tests/parity.rs is #[ignore]d.
    Ok(RunBatchOutput::empty(current_slot, 0, 0))
}
