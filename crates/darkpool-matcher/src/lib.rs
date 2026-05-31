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

pub mod algorithm;
pub mod book;
pub mod change_note;
pub mod config;
pub mod error;
pub mod fee;
pub mod match_result;
pub mod order_canonical;

pub use book::{
    Order, OrderBook, OrderSide, OrderStatus, OrderType, OrderUpdate, OrderUpdateKind, Price,
    Quantity,
};
pub use config::{MatchConfig, OracleSnapshot, SETTLEMENT_BUFFER_SLOTS};
pub use error::MatchError;
pub use fee::FeeBucket;
pub use match_result::{MatchPair, MatchStatus, RunBatchOutput, RELOCK_ORDER_ID_NONE};
pub use order_canonical::{
    CancelCanonical, CanonicalError, OrderCanonical, CANCEL_DOMAIN, ORDER_DOMAIN, SYMBOL_MAX_LEN,
};

/// The single public entry point. Given a book snapshot + oracle
/// reading + market config + the current slot + a starting match-id
/// counter, produce all matches the uniform-clearing-price auction
/// can extract from this book + the per-order updates the caller
/// must apply.
///
/// Steps (mirror the on-chain `run_batch_handler` exactly):
///
///   1. Validate the oracle is non-zero (else refuse to clear).
///   2. Partition the book into bids / asks / expired / below-min,
///      collect inclusion-leaf commitments.
///   3. Sort bids descending-by-price (FIFO at ties), asks
///      ascending-by-price (FIFO at ties).
///   4. Reset the two fee buckets bound to (base_mint, quote_mint).
///   5. Compute the uniform clearing price.
///   6. Circuit-breaker check against `oracle.twap`. If tripped,
///      skip matching, return cb_tripped=1 + match_count=0.
///   7. Otherwise call `generate_matches`, accumulating matches +
///      fees.
///   8. Compute the SHA-256 inclusion root over the participants'
///      `order_inclusion_commitment`s.
///   9. Emit `OrderUpdate`s for full-fills, partial-fills, IOC
///      residuals, FOK sentinels, and expired orders.
///  10. Optionally flush the fee accumulators into protocol-owned
///      change notes (only if `protocol_owner_commitment != [0;32]`
///      AND circuit breaker did NOT trip — matches the on-chain
///      gating).
///  11. Return everything packaged in `RunBatchOutput`.
///
/// `start_match_id` is the value of `BatchResults.next_match_id`
/// before this batch — the caller increments it past the highest
/// `match_id` emitted in `output.matches` after this returns.
/// Match-all convenience wrapper: runs the batch auction with no cap on
/// the number of matches produced. Signature-identical to the original
/// so the byte-equality parity tests (`tests/parity.rs`,
/// `tests/change_note_parity.rs`) are unaffected. Production callers —
/// the in-TEE matcher and the on-chain `run_batch` adapter — use
/// [`run_batch_capped`] with the N=16 circuit bound instead.
pub fn run_batch(
    book: &OrderBook,
    oracle: &OracleSnapshot,
    config: &MatchConfig,
    current_slot: u64,
    start_match_id: u64,
) -> Result<RunBatchOutput, MatchError> {
    run_batch_capped(
        book,
        oracle,
        config,
        current_slot,
        start_match_id,
        usize::MAX,
        false,
    )
}

/// Batch auction bounded to at most `max_matches` matches per call.
///
/// The N=16 VALID_MATCH_BATCH circuit settles at most N matches per
/// batch, so the matcher must never emit more than N in one
/// `RunBatchOutput` (the loadgen caught a 50-match tick being dropped by
/// the settle assembler). The uniform clearing price P* is still
/// computed over the WHOLE crossing book — the cap only bounds how many
/// fills are produced AT P*, in price-time priority — so the price is
/// identical regardless of the cap. Unmatched-but-crossable orders are
/// left untouched in the book (no `OrderUpdate` emitted) and drained by
/// a later call ("paged matching": the in-TEE matcher loops this within
/// a tick; the on-chain adapter pages across `run_batch` calls).
///
/// `inclusion_root` is unaffected by the cap — it is the Merkle root of
/// all *eligible orders* (a transparency root from `partition_book`),
/// not of the matches. `fee_buckets` accumulate only over the matches
/// actually produced this call, which is correct: the remaining matches
/// accrue their fees on the call that produces them.
///
/// `single_fill_per_order` (the in-TEE matcher passes `true`) caps each
/// order to one fill per batch — no intra-batch relock chain — so every
/// match consumes an original input note whose opening + nullifier are
/// in the settle store, never a TEE-created change note (whose nullifier
/// needs the user spending key the TEE doesn't hold). The on-chain
/// matcher passes `false`.
pub fn run_batch_capped(
    book: &OrderBook,
    oracle: &OracleSnapshot,
    config: &MatchConfig,
    current_slot: u64,
    start_match_id: u64,
    max_matches: usize,
    single_fill_per_order: bool,
) -> Result<RunBatchOutput, MatchError> {
    // Step 1 — oracle validity gate. Matches the on-chain
    // `require!(pyth_twap > 0, MatchingError::OracleZeroPrice)`.
    if oracle.twap == 0 {
        return Err(MatchError::OracleStale {
            publish: oracle.publish_slot,
            now: current_slot,
        });
    }

    // Step 2 — partition. Yields (bids, asks, expired_idxs,
    // inclusion_leaves). expired_idxs feed OrderUpdate::Expired
    // emissions below.
    let (mut bids, mut asks, expired_idxs, inclusion_leaves) =
        algorithm::partition_book(&book.orders, current_slot, config.min_order_size);

    // Step 4 — fee buckets. Step 3 (sort) happened inside
    // partition_book.
    let mut fee_buckets = algorithm::reset_fee_buckets(config, current_slot);

    let mut matches = Vec::new();
    let mut order_updates = Vec::new();
    let mut cb_tripped: u8 = 0;
    let clearing_price;

    // Step 5 + 6 — clearing price + circuit breaker.
    if let Some((p_star, _matched)) = algorithm::compute_clearing_price(&bids, &asks) {
        if algorithm::deviates_by_more_than_bps(p_star, oracle.twap, config.circuit_breaker_bps) {
            cb_tripped = 1;
            clearing_price = 0;
        } else {
            clearing_price = p_star;
            // Step 7 — generate_matches. Mutates bids/asks/
            // fee_buckets in place; appends to `matches`.
            algorithm::generate_matches(
                &mut bids,
                &mut asks,
                p_star,
                oracle.twap,
                current_slot,
                &config.base_mint,
                &config.quote_mint,
                config.fee_rate_bps as u64,
                start_match_id,
                max_matches,
                single_fill_per_order,
                &mut matches,
                &mut fee_buckets,
            )?;
        }
    } else {
        clearing_price = 0;
    }

    // Step 8 — inclusion root. Done regardless of CB state — the
    // on-chain code publishes it on every batch.
    let inclusion_root = algorithm::merkle_root_sha256(&inclusion_leaves);

    // Step 9 — OrderUpdates. Two passes:
    //   (a) algorithm::apply_slot_updates for bid/ask participants,
    //   (b) explicit Expired emissions for orders drained in step 2.
    algorithm::apply_slot_updates(&bids, &asks, &book.orders, &mut order_updates);
    for &idx in &expired_idxs {
        let o = &book.orders[idx];
        order_updates.push(crate::book::OrderUpdate {
            trading_key: o.trading_key,
            order_id: o.order_id,
            kind: crate::book::OrderUpdateKind::Expired,
        });
    }

    // Step 10 — fee-note flush. Only when CB didn't trip AND a
    // protocol owner commitment is configured (matches the on-chain
    // `if protocol_owner_commitment != [0; 32] && cb_tripped == 0`).
    if cb_tripped == 0 && config.protocol_owner_commitment != [0u8; 32] {
        algorithm::flush_fee_notes(
            &mut fee_buckets,
            &config.base_mint,
            &config.quote_mint,
            &config.protocol_owner_commitment,
            current_slot,
        )?;
    }

    // Step 11 — pack and return.
    Ok(RunBatchOutput {
        matches,
        order_updates,
        clearing_price,
        circuit_breaker_tripped: cb_tripped,
        inclusion_root,
        fee_buckets,
        batch_slot: current_slot,
    })
}
