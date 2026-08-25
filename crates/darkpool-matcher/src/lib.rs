//! Pure matching algorithm for the Darknyx dark pool.
//!
//! Uniform-clearing-price batch auction with FIFO tie-break and a Pyth-band circuit
//! breaker. This crate is the single source of truth for matching, consumed by the
//! in-TEE matcher (`crates/darknyx-tee`).
//!
//! # Two entry points, and production uses only one
//!
//! **The enclave matches through [`PreparedMatchTick`]** — [`PreparedMatchTick::new`]
//! takes the book snapshot and the `MatchConfig`, and
//! [`PreparedMatchTick::next_page`] then pages through matches, filling each
//! order at most once per page. [`run_batch`] instead chains partial fills
//! within one batch and exists for tests and legacy callers; **production does
//! not use it.**
//!
//! Reasoning about matcher behaviour against `run_batch` therefore does not
//! transfer — the chaining is the difference (audit SW-28). Note that
//! `single_fill_per_order` is an internal parameter of the lower-level entry
//! points, not an argument to `next_page`.
//!
//! # Invariants
//!
//! * Uniform clearing price across the batch.
//! * FIFO tie-break at each price level.
//! * Pyth-TWAP circuit breaker (`circuit_breaker_bps`).
//! * Output inner-hash construction stays byte-identical to
//!   `darkpool_crypto::match_output` and its TypeScript port in
//!   `packages/sdk/src/utxo/match-output.ts`. ([`change_note`] holds the role
//!   constants only; its old `derive_inner` was retired with the v2 SHA-256
//!   construction.)
//! * No floating point anywhere.
//! * Deterministic given the same inputs — the matcher reads no clock;
//!   `current_slot` is an input.
//!
//! Determinism is not a preference here. The same batch is replayed by the settle
//! assembler and, transitively, by the circuit; a matcher that varied run-to-run
//! would produce a proof that does not correspond to the fills already reported.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use std::collections::HashMap;

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

#[derive(Clone, Copy, Debug)]
enum PreparedSide {
    Bid,
    Ask,
}

#[derive(Clone, Copy, Debug)]
struct PreparedLocation {
    side: PreparedSide,
    snapshot_idx: usize,
    book_idx: usize,
}

/// One immutable order-book snapshot prepared for every settlement page in a
/// matching tick. Sorting and price-level aggregation happen once. As pages
/// reserve or cancel orders, this structure removes their original quantities
/// from the aggregate curves and marks their snapshots inactive.
///
/// Orders submitted after construction intentionally wait for the next tick.
/// This gives every page in a tick one deterministic view while preserving the
/// existing per-page clearing-price recomputation over the remaining orders.
pub struct PreparedMatchTick {
    pre_batch: Vec<Order>,
    bids: Vec<algorithm::OrderSnapshot>,
    asks: Vec<algorithm::OrderSnapshot>,
    expired_idxs: Vec<usize>,
    active_by_book_idx: Vec<bool>,
    locations: HashMap<([u8; 32], [u8; 16]), PreparedLocation>,
    levels: algorithm::PriceLevelAggregates,
    config: MatchConfig,
    current_slot: u64,
    expired_emitted: bool,
}

impl PreparedMatchTick {
    /// Take ownership of a book snapshot and prepare its reusable sorted views
    /// and price-level aggregates. Ownership avoids a second full-book clone in
    /// the in-TEE driver.
    pub fn new(book: OrderBook, config: MatchConfig, current_slot: u64) -> Self {
        let pre_batch = book.orders;
        let (bids, asks, expired_idxs, _inclusion_leaves) = algorithm::partition_book(
            &pre_batch,
            current_slot,
            config.min_order_size,
            config.tick_size,
        );
        let levels = algorithm::PriceLevelAggregates::from_snapshots(&bids, &asks);
        let mut active_by_book_idx = vec![false; pre_batch.len()];
        let mut locations = HashMap::with_capacity(bids.len() + asks.len());

        for (snapshot_idx, order) in bids.iter().enumerate() {
            active_by_book_idx[order.book_idx] = true;
            locations.insert(
                (order.trading_key, order.order_id),
                PreparedLocation {
                    side: PreparedSide::Bid,
                    snapshot_idx,
                    book_idx: order.book_idx,
                },
            );
        }
        for (snapshot_idx, order) in asks.iter().enumerate() {
            active_by_book_idx[order.book_idx] = true;
            locations.insert(
                (order.trading_key, order.order_id),
                PreparedLocation {
                    side: PreparedSide::Ask,
                    snapshot_idx,
                    book_idx: order.book_idx,
                },
            );
        }

        Self {
            pre_batch,
            bids,
            asks,
            expired_idxs,
            active_by_book_idx,
            locations,
            levels,
            config,
            current_slot,
            expired_emitted: false,
        }
    }

    /// Number of orders in the frozen source snapshot, including ineligible
    /// orders. Exposed for operational metrics and error logs.
    pub fn snapshot_len(&self) -> usize {
        self.pre_batch.len()
    }

    /// Produce the next N-bounded settlement page. Production semantics always
    /// allow at most one fill per order in a page; touched orders are removed
    /// from all later pages in this prepared tick, just as reserving them in the
    /// live book did before this optimization.
    pub fn next_page(
        &mut self,
        oracle: &OracleSnapshot,
        start_match_id: u64,
        max_matches: usize,
    ) -> Result<RunBatchOutput, MatchError> {
        validate_oracle(oracle, self.current_slot)?;

        let inclusion_leaves: Vec<[u8; 32]> = self
            .pre_batch
            .iter()
            .enumerate()
            .filter_map(|(idx, order)| {
                self.active_by_book_idx[idx].then_some(order.order_inclusion_commitment)
            })
            .collect();
        let expired_idxs = if self.expired_emitted {
            &[][..]
        } else {
            &self.expired_idxs
        };

        let output = run_partitioned_page(
            &self.pre_batch,
            &mut self.bids,
            &mut self.asks,
            expired_idxs,
            &inclusion_leaves,
            &self.levels,
            oracle,
            &self.config,
            self.current_slot,
            start_match_id,
            max_matches,
            true,
        )?;
        self.expired_emitted = true;
        self.deactivate_updates(&output.order_updates);
        Ok(output)
    }

    fn deactivate_updates(&mut self, updates: &[OrderUpdate]) {
        for update in updates {
            let Some(location) = self
                .locations
                .get(&(update.trading_key, update.order_id))
                .copied()
            else {
                // Expired orders never entered a bid/ask snapshot.
                continue;
            };

            let snapshot = match location.side {
                PreparedSide::Bid => &mut self.bids[location.snapshot_idx],
                PreparedSide::Ask => &mut self.asks[location.snapshot_idx],
            };
            if !snapshot.active {
                continue;
            }
            snapshot.active = false;
            self.active_by_book_idx[location.book_idx] = false;

            let original = &self.pre_batch[location.book_idx];
            match location.side {
                PreparedSide::Bid => self
                    .levels
                    .remove_bid(original.price_limit, original.amount),
                PreparedSide::Ask => self
                    .levels
                    .remove_ask(original.price_limit, original.amount),
            }
        }
    }
}

fn validate_oracle(oracle: &OracleSnapshot, _current_slot: u64) -> Result<(), MatchError> {
    let future_limit = oracle
        .observed_at_ms
        .saturating_add(oracle.max_future_skew_ms);
    let stale = oracle.twap == 0
        || oracle.publish_time_ms > future_limit
        || oracle.observed_at_ms.saturating_sub(oracle.publish_time_ms) > oracle.max_age_ms;
    if stale {
        return Err(MatchError::OracleStale {
            publish_ms: oracle.publish_time_ms,
            observed_ms: oracle.observed_at_ms,
        });
    }
    Ok(())
}

/// The single public entry point. Given a book snapshot + oracle
/// reading + market config + the current slot + a starting match-id
/// counter, produce all matches the uniform-clearing-price auction
/// can extract from this book + the per-order updates the caller
/// must apply.
///
/// Steps:
///
///   1. Validate the oracle is non-zero and signed-time fresh.
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
///  10. Return everything packaged in `RunBatchOutput`; fee buckets are
///      metrics only because settlement creates per-match fee notes.
///
/// `start_match_id` is the caller's durable counter before this batch;
/// the caller increments it past the highest
/// `match_id` emitted in `output.matches` after this returns.
/// Match-all convenience wrapper: runs the batch auction with no cap on
/// the number of matches produced. Signature-identical to the original
/// so the byte-equality parity tests (`tests/parity.rs`,
/// `tests/change_note_parity.rs`) are unaffected. Production callers —
/// the in-TEE matcher uses [`run_batch_capped`] with the N=16 circuit
/// bound instead.
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
/// a tick).
///
/// `inclusion_root` is unaffected by the cap — it is the Merkle root of
/// all *eligible orders* (a transparency root from `partition_book`),
/// not of the matches. `fee_buckets` are accounting summaries only;
/// settlement creates one fee note per match from that match's consumed input.
///
/// `single_fill_per_order` (the in-TEE matcher passes `true`) caps each
/// order to one fill per batch — no intra-batch relock chain — so every
/// match consumes an original input note whose opening + VALID_INPUT proof are
/// in the settle store, never a TEE-created change note for which the client
/// has not supplied a lock proof. The uncapped
/// compatibility wrapper passes `false`.
pub fn run_batch_capped(
    book: &OrderBook,
    oracle: &OracleSnapshot,
    config: &MatchConfig,
    current_slot: u64,
    start_match_id: u64,
    max_matches: usize,
    single_fill_per_order: bool,
) -> Result<RunBatchOutput, MatchError> {
    // Step 1 — oracle validity gate.
    validate_oracle(oracle, current_slot)?;

    // Step 2 — partition. Yields (bids, asks, expired_idxs,
    // inclusion_leaves). expired_idxs feed OrderUpdate::Expired
    // emissions below.
    let (mut bids, mut asks, expired_idxs, inclusion_leaves) = algorithm::partition_book(
        &book.orders,
        current_slot,
        config.min_order_size,
        config.tick_size,
    );
    let levels = algorithm::PriceLevelAggregates::from_snapshots(&bids, &asks);

    run_partitioned_page(
        &book.orders,
        &mut bids,
        &mut asks,
        &expired_idxs,
        &inclusion_leaves,
        &levels,
        oracle,
        config,
        current_slot,
        start_match_id,
        max_matches,
        single_fill_per_order,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_partitioned_page(
    pre_batch: &[Order],
    bids: &mut [algorithm::OrderSnapshot],
    asks: &mut [algorithm::OrderSnapshot],
    expired_idxs: &[usize],
    inclusion_leaves: &[[u8; 32]],
    levels: &algorithm::PriceLevelAggregates,
    oracle: &OracleSnapshot,
    config: &MatchConfig,
    current_slot: u64,
    start_match_id: u64,
    max_matches: usize,
    single_fill_per_order: bool,
) -> Result<RunBatchOutput, MatchError> {
    // Step 4 — fee buckets. Step 3 (sort) happened inside
    // partition_book.
    let mut fee_buckets = algorithm::reset_fee_buckets(config, current_slot);

    let mut matches = Vec::new();
    let mut order_updates = Vec::new();
    let mut cb_tripped: u8 = 0;
    let clearing_price;

    // Step 5 + 6 — clearing price + circuit breaker.
    if let Some((p_star, _matched)) = levels.clearing_price() {
        if algorithm::deviates_by_more_than_bps(p_star, oracle.twap, config.circuit_breaker_bps) {
            cb_tripped = 1;
            clearing_price = 0;
        } else {
            clearing_price = p_star;
            // Step 7 — generate_matches. Mutates bids/asks/
            // fee_buckets in place; appends to `matches`.
            algorithm::generate_matches(
                bids,
                asks,
                p_star,
                oracle.twap,
                current_slot,
                config.price_scale,
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

    // Step 8 — inclusion root. Done regardless of CB state.
    let inclusion_root = algorithm::merkle_root_sha256(inclusion_leaves);

    // Step 9 — OrderUpdates. Two passes:
    //   (a) algorithm::apply_slot_updates for bid/ask participants,
    //   (b) explicit Expired emissions for orders drained in step 2.
    algorithm::apply_slot_updates(bids, asks, pre_batch, &mut order_updates);
    for &idx in expired_idxs {
        let o = &pre_batch[idx];
        order_updates.push(crate::book::OrderUpdate {
            trading_key: o.trading_key,
            order_id: o.order_id,
            kind: crate::book::OrderUpdateKind::Expired,
        });
    }

    // Step 10 — pack and return. Fee commitments are deliberately absent here:
    // settlement derives each one from that match's consumed input commitment.
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
