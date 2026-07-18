//! The matching algorithm itself. Pure functions over the
//! `darkpool_matcher::book` + `darkpool_matcher::match_result` types.
//!
//! This is the single source of truth consumed by the in-TEE matcher.
//! Behaviour is gated by per-function unit tests in this module and
//! end-to-end auction scenarios in `tests/parity.rs`.
//!
//! No Anchor / no `solana_program` imports. The one place the
//! on-chain code used `solana_program::hash::hashv` was inside
//! `merkle_root_sha256`; the port uses `sha2::Sha256` instead and
//! a parity test pins the byte-equivalence.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::book::{Order, OrderSide, OrderType, OrderUpdate, OrderUpdateKind};
use crate::change_note;
use crate::config::MatchConfig;
use crate::error::MatchError;
use crate::fee::FeeBucket;
use crate::match_result::{MatchPair, MatchStatus, RELOCK_ORDER_ID_NONE};
use darkpool_crypto::note::commitment_from_fields_v2;

// ─────── Constants ──────────────────────────────────────────────────────────

// `SETTLEMENT_BUFFER_SLOTS` lives in `crate::config` — the single
// source of truth shared by the matcher + re-exported at the crate
// root. Import it here rather than redefining (the two copies could
// silently diverge).
use crate::config::SETTLEMENT_BUFFER_SLOTS;

// ─────── deviates_by_more_than_bps ──────────────────────────────────────────

/// Circuit-breaker primitive: returns true iff `|p − reference| / reference`
/// strictly exceeds `bps` basis points. Lifted verbatim from
/// `run_batch::deviates_by_more_than_bps`.
///
/// `reference == 0` is treated as "always deviates" — the on-chain
/// code refuses to run when the oracle is zero, and we keep the
/// same defensive behaviour here.
pub fn deviates_by_more_than_bps(p: u64, reference: u64, bps: u64) -> bool {
    if reference == 0 {
        return true;
    }
    let diff = p.abs_diff(reference);
    (diff as u128).saturating_mul(10_000) > (reference as u128).saturating_mul(bps as u128)
}

// ─────── merkle_root_sha256 ─────────────────────────────────────────────────

/// SHA-256 binary Merkle root over `leaves`. Pads the last leaf
/// upward until `leaves.len()` is a power of two. Lifted from
/// `run_batch::merkle_root_sha256` but with the `solana_program::
/// hash::hashv` backend swapped for `sha2::Sha256` so this crate
/// stays Anchor-free.
///
/// **NOT the v3.5 Poseidon batch root** that VALID_MATCH_BATCH
/// attests to. That root lives in `programs/vault/src/merkle.rs`
/// and uses Poseidon over a Light-Protocol incremental tree. THIS
/// root is returned as an audit log over the per-batch
/// `order_inclusion_commitment`s so
/// users can prove the matcher accepted their order — entirely
/// separate from the ZK circuit's Merkle.
pub fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    // Round up to the next power of two by duplicating the last
    // leaf. This matches `run_batch`'s padding scheme exactly so the
    // inclusion-root parity test (scenario 7) passes byte-for-byte.
    let mut target = 1usize;
    while target < level.len() {
        target *= 2;
    }
    while level.len() < target {
        level.push(*level.last().unwrap());
    }

    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(pair[1]);
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

// ─────── OrderSnapshot — internal working type ──────────────────────────────
//
// `generate_matches` operates on a flat copy of the relevant order
// fields so it can sort / mutate without needing a mutable
// reference to the source `OrderBook`. The on-chain code calls this
// type `OrderSnapshot` too (it carries a `rem_idx` instead of our
// `book_idx` since the on-chain ix indexes into
// ctx.remaining_accounts; we index into `book.orders[]`).
//
// `pub(crate)` so `lib.rs::run_batch` can construct it; intentionally
// not exposed in the public API.

#[derive(Clone, Copy, Debug)]
pub(crate) struct OrderSnapshot {
    /// Index back into the original `OrderBook.orders` Vec. Used by
    /// `apply_slot_updates` to identify the source order in the
    /// emitted `OrderUpdate`.
    pub book_idx: usize,

    // `side` was on the on-chain `OrderSnapshot` too — used during
    // the initial bids/asks partition. Once partitioned we know
    // which slice we're in, so the field is never read again.
    // Tracking it here would just be Debug-output ballast.
    pub order_type: OrderType,
    pub arrival_slot: u64,
    pub expiry_slot: u64,
    pub price_limit: u64,
    pub amount: u64,
    pub min_fill_qty: u64,
    pub note_amount: u64,
    pub collateral_note: [u8; 32],
    pub user_commitment: [u8; 32],
    /// Note-bound owner identity (see `book::Order::owner_commitment`) — the
    /// self-trade key.
    pub owner_commitment: [u8; 32],
    pub trading_key: [u8; 32],
    pub order_id: [u8; 16],
    pub inclusion: [u8; 32],

    /// Prepared ticks retain one sorted snapshot across every settlement page.
    /// Orders touched by an earlier page are marked inactive instead of being
    /// cloned, partitioned, and sorted again.
    pub active: bool,

    /// Sentinel for FOK-too-small (and any other "this slot is now a
    /// cancellation"). Set to `true` when `generate_matches`
    /// decides to abandon a slot rather than fill it. `apply_slot_updates`
    /// translates this into `OrderUpdateKind::Cancelled`.
    pub cancelled_sentinel: bool,
}

impl OrderSnapshot {
    pub(crate) fn from_order(book_idx: usize, o: &Order) -> Self {
        Self {
            book_idx,
            order_type: o.order_type,
            arrival_slot: o.arrival_slot,
            expiry_slot: o.expiry_slot,
            price_limit: o.price_limit,
            amount: o.amount,
            min_fill_qty: o.min_fill_qty,
            note_amount: o.note_amount,
            collateral_note: o.collateral_note,
            user_commitment: o.user_commitment,
            owner_commitment: o.owner_commitment,
            trading_key: o.trading_key,
            order_id: o.order_id,
            inclusion: o.order_inclusion_commitment,
            active: true,
            cancelled_sentinel: false,
        }
    }
}

// ─────── compute_clearing_price ─────────────────────────────────────────────

/// Mutable price-level totals for one prepared matching tick. Totals use u128
/// internally so removing an order after a saturated u64 aggregate recovers the
/// exact remaining level instead of under-counting it.
#[derive(Clone, Debug, Default)]
pub(crate) struct PriceLevelAggregates {
    bids: BTreeMap<u64, u128>,
    asks: BTreeMap<u64, u128>,
}

impl PriceLevelAggregates {
    pub(crate) fn from_snapshots(bids: &[OrderSnapshot], asks: &[OrderSnapshot]) -> Self {
        let mut levels = Self::default();
        for bid in bids.iter().filter(|order| order.active) {
            let total = levels.bids.entry(bid.price_limit).or_default();
            *total = total.saturating_add(bid.amount as u128);
        }
        for ask in asks.iter().filter(|order| order.active) {
            let total = levels.asks.entry(ask.price_limit).or_default();
            *total = total.saturating_add(ask.amount as u128);
        }
        levels
    }

    pub(crate) fn remove_bid(&mut self, price: u64, amount: u64) {
        Self::remove(&mut self.bids, price, amount);
    }

    pub(crate) fn remove_ask(&mut self, price: u64, amount: u64) {
        Self::remove(&mut self.asks, price, amount);
    }

    fn remove(levels: &mut BTreeMap<u64, u128>, price: u64, amount: u64) {
        if let Some(total) = levels.get_mut(&price) {
            *total = total.saturating_sub(amount as u128);
            if *total == 0 {
                levels.remove(&price);
            }
        }
    }

    /// Evaluate all candidate prices in ascending order with one suffix-demand
    /// and prefix-supply sweep. Every distinct level is visited at most once;
    /// the old implementation rescanned every order for every candidate.
    pub(crate) fn clearing_price(&self) -> Option<(u64, u64)> {
        if self.bids.is_empty() || self.asks.is_empty() {
            return None;
        }

        let mut demand = self
            .bids
            .values()
            .fold(0u128, |sum, amount| sum.saturating_add(*amount));
        let mut supply = 0u128;
        let mut bid_levels = self.bids.iter().peekable();
        let mut ask_levels = self.asks.iter().peekable();
        let mut bid_candidates = self.bids.keys().copied().peekable();
        let mut ask_candidates = self
            .asks
            .keys()
            .copied()
            .filter(|price| *price > 0)
            .peekable();
        let mut best_price = None;
        let mut best_matched = 0u64;

        loop {
            let price = match (
                bid_candidates.peek().copied(),
                ask_candidates.peek().copied(),
            ) {
                (Some(bid), Some(ask)) => match bid.cmp(&ask) {
                    Ordering::Less => bid_candidates.next().expect("peeked bid candidate"),
                    Ordering::Greater => ask_candidates.next().expect("peeked ask candidate"),
                    Ordering::Equal => {
                        bid_candidates.next();
                        ask_candidates.next().expect("peeked equal ask candidate")
                    }
                },
                (Some(_), None) => bid_candidates.next().expect("peeked bid candidate"),
                (None, Some(_)) => ask_candidates.next().expect("peeked ask candidate"),
                (None, None) => break,
            };

            while bid_levels
                .peek()
                .is_some_and(|(bid_price, _)| **bid_price < price)
            {
                let (_, amount) = bid_levels.next().expect("peeked bid level");
                demand = demand.saturating_sub(*amount);
            }
            while ask_levels
                .peek()
                .is_some_and(|(ask_price, _)| **ask_price <= price)
            {
                let (_, amount) = ask_levels.next().expect("peeked ask level");
                supply = supply.saturating_add(*amount);
            }

            let matched = demand.min(supply).min(u64::MAX as u128) as u64;
            if matched > best_matched {
                best_matched = matched;
                best_price = Some(price);
            }
        }

        best_price.map(|price| (price, best_matched))
    }
}

/// Uniform-clearing-price computation. Returns `Some((p*, matched))`
/// where p* is the price that maximises `min(demand, supply)` across
/// all distinct bid limits and positive ask limits, with ties broken
/// by the lowest price (deterministic).
///
/// A zero-limit ask is a market sell: it remains eligible supply at
/// every positive candidate price, but zero itself is not a candidate.
/// Including zero would let a bid at 150 and market ask at 0 clear at
/// zero under the lowest-price tie-break, creating a free fill.
///
/// `None` iff either side is empty (no crossing possible).
///
/// Lifted verbatim from `run_batch::compute_clearing_price` —
/// algorithm is pure, no Anchor / Solana types involved.
///
/// `pub(crate)` because the signature takes the internal
/// `OrderSnapshot` type; external callers go through `run_batch`.
#[cfg(test)]
pub(crate) fn compute_clearing_price(
    bids: &[OrderSnapshot],
    asks: &[OrderSnapshot],
) -> Option<(u64, u64)> {
    PriceLevelAggregates::from_snapshots(bids, asks).clearing_price()
}

// ─────── generate_matches ──────────────────────────────────────────────────
//
// The core. Walks through pre-sorted `bids` (descending by price,
// FIFO at ties) and `asks` (ascending by price, FIFO at ties),
// produces `MatchPair`s at the uniform clearing price `p_star`, and
// accumulates per-leg fees into the two `fee_buckets`. Mutates the
// snapshot vectors in place to reflect post-fill state (decremented
// `amount`, rotated `collateral_note`, FOK-too-small sentinels).
// `apply_slot_updates` then derives the public-API `OrderUpdate`s
// from the resulting snapshot vectors.
//
// Returns the number of `MatchPair`s appended to `out_matches` so
// the caller can update its match-id counter.
//
// Lifted from `run_batch::generate_matches` with:
//   - `ctx.accounts.batch_results.load_*` reads/writes replaced by
//     `match_id_counter` + `fee_buckets[]` arguments threaded from
//     `lib.rs::run_batch`.
//   - `Pubkey` swapped for `[u8; 32]`.
//   - `error!(...)` / `require!(...)` swapped for `Err(MatchError::...)`.
//   - `commitment_from_fields` already lives in `darkpool-crypto` —
//     no swap needed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_matches(
    bids: &mut [OrderSnapshot],
    asks: &mut [OrderSnapshot],
    p_star: u64,
    pyth_twap: u64,
    now_slot: u64,
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    price_scale: u64,
    fee_rate_bps: u64,
    start_match_id: u64,
    // Stop after this many matches (paged matching — see
    // `run_batch_capped`). The N highest price-time-priority crossing
    // pairs are produced; the rest stay unmatched in `bids`/`asks` (no
    // OrderUpdate emitted for them) and are drained by a later call.
    max_matches: usize,
    // When true, advance BOTH sides after every match so each order
    // fills at most once per batch (no intra-batch relock chain). The
    // in-TEE matcher needs this: a chained match would consume a change
    // note (note_e) whose nullifier the TEE can't produce (no spending
    // key), and the settle assembler has no opening for it. The residual
    // of a partially-filled order still relocks on-chain (note_e) and is
    // dropped from the in-TEE book to await client re-submission. The
    // uncapped compatibility wrapper passes `false` (chaining behaviour).
    single_fill_per_order: bool,
    out_matches: &mut Vec<MatchPair>,
    fee_buckets: &mut [FeeBucket; 2],
) -> Result<usize, MatchError> {
    let mut produced: usize = 0;
    let mut bi = 0usize;
    let mut ai = 0usize;
    let mut next_match_id = start_match_id;

    while produced < max_matches && bi < bids.len() && ai < asks.len() {
        while bi < bids.len() && !bids[bi].active {
            bi += 1;
        }
        while ai < asks.len() && !asks[ai].active {
            ai += 1;
        }
        if bi >= bids.len() || ai >= asks.len() {
            break;
        }

        // Price-limit crossing must hold at P*.
        if bids[bi].price_limit < p_star || asks[ai].price_limit > p_star {
            if bids[bi].price_limit < p_star {
                bi += 1;
            }
            if ai < asks.len() && asks[ai].price_limit > p_star {
                ai += 1;
            }
            continue;
        }

        // Self-trade prevention: never match two orders from the same owner — a
        // wash trade that would waste a settle on a no-op. Keyed on the
        // note-BOUND `owner_commitment` (`Poseidon2(spending_key, r_owner)`):
        // intake pins it to the collateral note via `verify_commitment`, so —
        // unlike the client-asserted `user_commitment` — a settling wash CANNOT
        // lie about it (the only way to present two different `owner_commitment`s
        // is two genuinely different note owners). It is reused across all of a
        // user's notes, so it catches the case a `trading_key`-only check misses:
        // one user trading under TWO trading keys (the trading key is freely
        // re-derived by `offset` and is deliberately NOT part of the owner). The
        // `trading_key` equality is kept as a cheap belt-and-suspenders. The
        // `!= [0;32]` guard keeps zero-identity test/degenerate orders from
        // colliding (a real `owner_commitment` is a non-zero Poseidon output).
        // Skip the pair, advancing the SMALLER side (ties → advance the ask,
        // keeping the bid resting so an external taker can still hit it this
        // pass). The skipped order is NOT cancelled — it stays in the book so the
        // other side can still match a non-self counterparty and the deferred
        // order is reconsidered next tick. (A single greedy pass can't try
        // `bid vs next-ask` AND `next-bid vs ask` simultaneously, so a rare
        // multi-self-order config may defer one legitimate match to the next tick
        // — acceptable; the safety property, no wash trade, always holds. NOTE:
        // still best-effort in a pseudonymous pool — a user can register a SECOND
        // wallet (a distinct `owner_commitment`, or deposit notes under a
        // different `r_owner`) and wash across the two; that Sybil case is out of
        // scope for any matcher rule.)
        let same_owner = bids[bi].owner_commitment != [0u8; 32]
            && bids[bi].owner_commitment == asks[ai].owner_commitment;
        if bids[bi].trading_key == asks[ai].trading_key || same_owner {
            if asks[ai].amount <= bids[bi].amount {
                ai += 1;
            } else {
                bi += 1;
            }
            continue;
        }

        let crossable = bids[bi].amount.min(asks[ai].amount);

        // FOK enforcement: if the entire bid can't fill at P*, cancel
        // it via the sentinel and advance. Same for the ask side.
        if bids[bi].order_type == OrderType::Fok && crossable < bids[bi].amount {
            bids[bi].amount = 0;
            bids[bi].cancelled_sentinel = true;
            bi += 1;
            continue;
        }
        if asks[ai].order_type == OrderType::Fok && crossable < asks[ai].amount {
            asks[ai].amount = 0;
            asks[ai].cancelled_sentinel = true;
            ai += 1;
            continue;
        }

        // min_fill_qty: if neither side accepts a partial below its
        // floor, skip the smaller side and try the next pair.
        if crossable < bids[bi].min_fill_qty || crossable < asks[ai].min_fill_qty {
            if bids[bi].amount <= asks[ai].amount {
                bi += 1;
            } else {
                ai += 1;
            }
            continue;
        }

        // Trade legs.
        if price_scale == 0 {
            return Err(MatchError::Internal("price scale is zero"));
        }
        let quote_numerator = (crossable as u128)
            .checked_mul(p_star as u128)
            .ok_or(MatchError::Internal("notional overflow"))?;
        let quote_amt_u128 = quote_numerator / price_scale as u128;
        if quote_amt_u128 > u64::MAX as u128 {
            return Err(MatchError::Internal("notional overflow (u64)"));
        }
        let quote_amt = quote_amt_u128 as u64;

        // U-06 (companion to the U-03 circuit gate): a clear whose notional
        // floors to zero quote would mint a zero-amount quote note (`note_d`)
        // that `withdraw` (`amount > 0`) can never spend — permanent dead Merkle
        // weight. VALID_MATCH_BATCH now also rejects `quote_amount == 0` on an
        // active slot, so producing this match would fail to prove regardless.
        // Skip the pair (advance the smaller side, mirroring the min_fill_qty
        // skip above); both orders stay in the book to be reconsidered against
        // other counterparties next tick.
        if quote_amt == 0 {
            if bids[bi].amount <= asks[ai].amount {
                bi += 1;
            } else {
                ai += 1;
            }
            continue;
        }

        // fee = amount * bps / 10_000. With the on-chain invariant
        // `fee_rate_bps <= 10_000` (enforced by set_protocol_config)
        // the result is <= the amount and always fits u64 — but make
        // the narrowing fallible anyway, matching the checked
        // `quote_amt` conversion above, so a bad config can never
        // silently truncate fee accounting.
        let buyer_fee_amt = u64::try_from((quote_amt as u128) * fee_rate_bps as u128 / 10_000u128)
            .map_err(|_| MatchError::Internal("buyer fee overflow (u64)"))?;
        let seller_fee_amt = u64::try_from((crossable as u128) * fee_rate_bps as u128 / 10_000u128)
            .map_err(|_| MatchError::Internal("seller fee overflow (u64)"))?;

        let buyer_charge = quote_amt
            .checked_add(buyer_fee_amt)
            .ok_or(MatchError::Internal("fee overflow"))?;
        let seller_charge = crossable
            .checked_add(seller_fee_amt)
            .ok_or(MatchError::Internal("fee overflow"))?;
        let buyer_change_amt =
            bids[bi]
                .note_amount
                .checked_sub(buyer_charge)
                .ok_or(MatchError::Conservation {
                    slot: bi,
                    in_amt: bids[bi].note_amount,
                    out_amt: buyer_charge,
                })?;
        let seller_change_amt =
            asks[ai]
                .note_amount
                .checked_sub(seller_charge)
                .ok_or(MatchError::Conservation {
                    slot: ai,
                    in_amt: asks[ai].note_amount,
                    out_amt: seller_charge,
                })?;

        let match_id = next_match_id;

        // Change-note commitments bind to the identity proven by the input
        // note opening. `user_commitment` is client-asserted metadata and can
        // differ; settlement reconstructs outputs from `owner_commitment`.
        let note_e_commitment = if buyer_change_amt > 0 {
            let inner = change_note::derive_inner(match_id, change_note::CHANGE_ROLE_BUYER);
            commitment_from_fields_v2(
                quote_mint,
                buyer_change_amt,
                &bids[bi].owner_commitment,
                &inner,
            )
            .map_err(|_| MatchError::Internal("Poseidon failed for buyer change note"))?
        } else {
            [0u8; 32]
        };
        let note_f_commitment = if seller_change_amt > 0 {
            let inner = change_note::derive_inner(match_id, change_note::CHANGE_ROLE_SELLER);
            commitment_from_fields_v2(
                base_mint,
                seller_change_amt,
                &asks[ai].owner_commitment,
                &inner,
            )
            .map_err(|_| MatchError::Internal("Poseidon failed for seller change note"))?
        } else {
            [0u8; 32]
        };

        let b_remaining_after = bids[bi].amount.saturating_sub(crossable);
        let a_remaining_after = asks[ai].amount.saturating_sub(crossable);
        // Only LIMIT orders relock; IOC/FOK residuals cancel.
        let buyer_relock = b_remaining_after > 0
            && bids[bi].order_type == OrderType::Limit
            && buyer_change_amt > 0;
        let seller_relock = a_remaining_after > 0
            && asks[ai].order_type == OrderType::Limit
            && seller_change_amt > 0;

        let (buyer_relock_order_id, buyer_relock_expiry) = if buyer_relock {
            (bids[bi].order_id, bids[bi].expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };
        let (seller_relock_order_id, seller_relock_expiry) = if seller_relock {
            (asks[ai].order_id, asks[ai].expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };

        out_matches.push(MatchPair {
            note_buyer: bids[bi].collateral_note,
            note_seller: asks[ai].collateral_note,
            note_e_commitment,
            note_f_commitment,
            owner_buyer: bids[bi].trading_key,
            owner_seller: asks[ai].trading_key,
            user_commitment_buyer: bids[bi].user_commitment,
            user_commitment_seller: asks[ai].user_commitment,
            buyer_note_value: bids[bi].note_amount,
            seller_note_value: asks[ai].note_amount,
            base_amt: crossable,
            quote_amt,
            buyer_change_amt,
            seller_change_amt,
            buyer_fee_amt,
            seller_fee_amt,
            buyer_relock_order_id,
            buyer_relock_expiry,
            seller_relock_order_id,
            seller_relock_expiry,
            price: p_star,
            pyth_at_match: pyth_twap,
            batch_slot: now_slot,
            match_id,
            status: MatchStatus::Filled,
        });
        next_match_id = next_match_id.saturating_add(1);

        // Fee buckets: bucket 0 = base (seller-side fee), bucket 1 =
        // quote (buyer-side fee).
        fee_buckets[0].add(seller_fee_amt);
        fee_buckets[1].add(buyer_fee_amt);

        // Update local snapshots — the public OrderUpdates are
        // derived from these in `apply_slot_updates`.
        bids[bi].amount = b_remaining_after;
        if buyer_relock {
            bids[bi].collateral_note = note_e_commitment;
            bids[bi].note_amount = buyer_change_amt;
        }
        asks[ai].amount = a_remaining_after;
        if seller_relock {
            asks[ai].collateral_note = note_f_commitment;
            asks[ai].note_amount = seller_change_amt;
        }

        produced += 1;

        if single_fill_per_order {
            // Each order fills at most once per batch: advance both
            // sides regardless of residual. A partially-filled side has
            // already relocked (note_e) above; it is NOT re-matched here
            // (which would consume a change note the TEE can't nullify).
            bi += 1;
            ai += 1;
        } else {
            // Default (on-chain) behaviour: advance whichever side filled
            // entirely; a partially-filled side stays to match the next
            // counterparty (intra-batch relock chain).
            if b_remaining_after == 0 {
                bi += 1;
            }
            if a_remaining_after == 0 {
                ai += 1;
            }
        }
    }

    Ok(produced)
}

// ─────── apply_slot_updates ─────────────────────────────────────────────────
//
// Walk the (post-match) snapshot vectors + the pre-batch order book
// snapshot, emit one `OrderUpdate` per touched order. The caller
// applies these to its source of truth.
//
// Mirrors the four cases in `run_batch::apply_slot_updates`:
//   - cancelled_sentinel → Cancelled
//   - amount == 0       → FullyFilled
//   - amount < original → PartiallyFilled (with IOC residual = Cancelled)
//   - otherwise          → no update emitted
pub(crate) fn apply_slot_updates(
    bids: &[OrderSnapshot],
    asks: &[OrderSnapshot],
    pre_batch: &[Order],
    out: &mut Vec<OrderUpdate>,
) {
    for s in bids.iter().chain(asks.iter()) {
        if !s.active {
            continue;
        }
        let pre = &pre_batch[s.book_idx];

        // FOK / cancellation sentinel set during generate_matches.
        if s.cancelled_sentinel {
            out.push(OrderUpdate {
                trading_key: s.trading_key,
                order_id: s.order_id,
                kind: OrderUpdateKind::Cancelled,
            });
            continue;
        }

        if s.amount == 0 {
            // Full fill — total_quantity filled, slot wiped.
            out.push(OrderUpdate {
                trading_key: s.trading_key,
                order_id: s.order_id,
                kind: OrderUpdateKind::FullyFilled {
                    filled_quantity: pre.total_quantity,
                },
            });
            continue;
        }

        if s.amount < pre.amount {
            // Partial fill. Compute the delta filled this batch and
            // emit either a PartiallyFilled (Limit) or a Cancelled
            // (IOC) — matching the on-chain branch where IOC
            // residual is wiped to Cancelled.
            let delta = pre.amount.saturating_sub(s.amount);
            let filled = pre.filled_quantity.saturating_add(delta);
            match s.order_type {
                OrderType::Ioc => {
                    out.push(OrderUpdate {
                        trading_key: s.trading_key,
                        order_id: s.order_id,
                        kind: OrderUpdateKind::Cancelled,
                    });
                }
                _ => {
                    out.push(OrderUpdate {
                        trading_key: s.trading_key,
                        order_id: s.order_id,
                        kind: OrderUpdateKind::PartiallyFilled {
                            new_amount: s.amount,
                            new_collateral_note: s.collateral_note,
                            new_note_amount: s.note_amount,
                            filled_quantity: filled,
                        },
                    });
                }
            }
        }
        // else: untouched — slot.amount unchanged. No OrderUpdate.
    }
}

// ─────── partition_into_bids_asks_and_expired ───────────────────────────────
//
// Pre-matching pass: walks the book, splits into bids / asks /
// expired-orders / below-min-size, populates the inclusion-leaf
// vector. Lifted from the first half of `run_batch_handler`.
//
// Returns: (bids, asks, expired_book_idxs, inclusion_leaves).
pub(crate) fn partition_book(
    book: &[Order],
    now_slot: u64,
    min_order_size: u64,
) -> (
    Vec<OrderSnapshot>,
    Vec<OrderSnapshot>,
    Vec<usize>,
    Vec<[u8; 32]>,
) {
    let mut bids = Vec::new();
    let mut asks = Vec::new();
    let mut expired = Vec::new();
    let mut inclusion_leaves = Vec::new();

    for (i, o) in book.iter().enumerate() {
        // Skip non-Pending orders entirely — they're not eligible
        // for matching and the on-chain code also skips them.
        if o.status != crate::book::OrderStatus::Pending {
            continue;
        }

        // Pre-expire: any order whose expiry is within
        // SETTLEMENT_BUFFER_SLOTS of now is drained.
        if o.expiry_slot <= now_slot.saturating_add(SETTLEMENT_BUFFER_SLOTS) {
            expired.push(i);
            continue;
        }

        // Below min_order_size — skip without expiring. The
        // client may resubmit at a higher amount or the admin may
        // lower the floor.
        if min_order_size > 0 && o.amount < min_order_size {
            continue;
        }

        let snap = OrderSnapshot::from_order(i, o);
        inclusion_leaves.push(snap.inclusion);
        match o.side {
            OrderSide::Bid => bids.push(snap),
            OrderSide::Ask => asks.push(snap),
        }
    }

    // Bids: descending price; asks: ascending. FIFO tie-break by
    // arrival_slot in both cases — older arrival wins.
    bids.sort_by(|a, b| {
        b.price_limit
            .cmp(&a.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });
    asks.sort_by(|a, b| {
        a.price_limit
            .cmp(&b.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });

    (bids, asks, expired, inclusion_leaves)
}

// ─────── reset_fee_buckets ──────────────────────────────────────────────────

/// Convenience: zero-init the two-bucket array with `base_mint`
/// / `quote_mint` bound and `accumulated_fees = 0`. Called at the
/// top of every `run_batch` tick.
pub(crate) fn reset_fee_buckets(config: &MatchConfig, now_slot: u64) -> [FeeBucket; 2] {
    [
        FeeBucket::new(config.base_mint, now_slot),
        FeeBucket::new(config.quote_mint, now_slot),
    ]
}

// ─────── Tests ──────────────────────────────────────────────────────────────
//
// These mirror the 5 inline tests in run_batch.rs's
// `#[cfg(test)] mod tests` — porting them HERE before the algorithm
// body lands gives us granular signal: if any of these fail, the
// helper is wrong, not the larger `generate_matches`.

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ─── deviates_by_more_than_bps ──────────────────────────────────────

    #[test]
    fn deviation_check_within_bounds_is_false() {
        // 0.5% deviation, 50 bps band → not over.
        assert!(!deviates_by_more_than_bps(1005, 1000, 50));
    }

    #[test]
    fn deviation_check_outside_bounds_is_true() {
        // 10% deviation, 50 bps band → over.
        assert!(deviates_by_more_than_bps(1100, 1000, 50));
    }

    #[test]
    fn deviation_check_exact_300bps_boundary() {
        // Spec §20.6 step 73 is 300 bps. Exactly 3% must NOT trip
        // (strict `>` comparison); 3.001% must trip.
        assert!(!deviates_by_more_than_bps(1030, 1000, 300));
        assert!(deviates_by_more_than_bps(1031, 1000, 300));
    }

    #[test]
    fn deviation_check_zero_reference_always_trips() {
        // Defensive: oracle returning 0 must be treated as a failure
        // mode so the matcher never clears.
        assert!(deviates_by_more_than_bps(100, 0, 50));
    }

    // ─── merkle_root_sha256 ─────────────────────────────────────────────

    #[test]
    fn merkle_root_empty_is_zero() {
        assert_eq!(merkle_root_sha256(&[]), [0u8; 32]);
    }

    #[test]
    fn merkle_root_single_leaf_is_itself() {
        // One leaf: nothing to hash, level[0] is just the leaf.
        let leaf = [42u8; 32];
        assert_eq!(merkle_root_sha256(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        // Plain SHA-256 of leaf0 || leaf1.
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let mut h = Sha256::new();
        h.update(l0);
        h.update(l1);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(merkle_root_sha256(&[l0, l1]), expected);
    }

    #[test]
    fn merkle_root_three_leaves_pads_last() {
        // Three-leaf tree: l0, l1, l2, padded to l0, l1, l2, l2.
        // SHA-256(l0 || l1) and SHA-256(l2 || l2) then root.
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        let h01 = {
            let mut h = Sha256::new();
            h.update(l0);
            h.update(l1);
            <[u8; 32]>::from(h.finalize())
        };
        let h23 = {
            let mut h = Sha256::new();
            h.update(l2);
            h.update(l2);
            <[u8; 32]>::from(h.finalize())
        };
        let expected = {
            let mut h = Sha256::new();
            h.update(h01);
            h.update(h23);
            <[u8; 32]>::from(h.finalize())
        };
        assert_eq!(merkle_root_sha256(&[l0, l1, l2]), expected);
    }

    // ─── compute_clearing_price ─────────────────────────────────────────

    fn snap(_side: OrderSide, price: u64, amount: u64) -> OrderSnapshot {
        OrderSnapshot {
            book_idx: 0,
            order_type: OrderType::Limit,
            arrival_slot: 0,
            expiry_slot: u64::MAX,
            price_limit: price,
            amount,
            min_fill_qty: 0,
            note_amount: amount.saturating_mul(price).max(1),
            collateral_note: [0; 32],
            user_commitment: [0; 32],
            owner_commitment: [0; 32],
            trading_key: [0; 32],
            order_id: [0; 16],
            inclusion: [0; 32],
            active: true,
            cancelled_sentinel: false,
        }
    }

    /// Independent copy of the pre-P-03 O(prices × orders) algorithm. Keep it
    /// deliberately straightforward: it is the semantic oracle for the level
    /// sweep, not another implementation of the optimized path.
    fn reference_clearing_price(
        bids: &[OrderSnapshot],
        asks: &[OrderSnapshot],
    ) -> Option<(u64, u64)> {
        let mut candidates = Vec::with_capacity(bids.len() + asks.len());
        candidates.extend(
            bids.iter()
                .filter(|order| order.active)
                .map(|order| order.price_limit),
        );
        candidates.extend(
            asks.iter()
                .filter(|order| order.active && order.price_limit > 0)
                .map(|order| order.price_limit),
        );
        candidates.sort_unstable();
        candidates.dedup();

        let mut best_price = None;
        let mut best_matched = 0u64;
        for price in candidates {
            let demand = bids
                .iter()
                .filter(|bid| bid.active && bid.price_limit >= price)
                .fold(0u64, |sum, bid| sum.saturating_add(bid.amount));
            let supply = asks
                .iter()
                .filter(|ask| ask.active && ask.price_limit <= price)
                .fold(0u64, |sum, ask| sum.saturating_add(ask.amount));
            let matched = demand.min(supply);
            if matched > best_matched {
                best_matched = matched;
                best_price = Some(price);
            }
        }
        best_price.map(|price| (price, best_matched))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn price_level_sweep_matches_quadratic_reference(
            bid_specs in prop::collection::vec((0u16..=500, any::<u64>(), any::<bool>()), 0..80),
            ask_specs in prop::collection::vec((0u16..=500, any::<u64>(), any::<bool>()), 0..80),
        ) {
            let bids: Vec<_> = bid_specs
                .into_iter()
                .map(|(price, amount, active)| {
                    let mut order = snap(OrderSide::Bid, price as u64, amount);
                    order.active = active;
                    order
                })
                .collect();
            let asks: Vec<_> = ask_specs
                .into_iter()
                .map(|(price, amount, active)| {
                    let mut order = snap(OrderSide::Ask, price as u64, amount);
                    order.active = active;
                    order
                })
                .collect();

            prop_assert_eq!(
                PriceLevelAggregates::from_snapshots(&bids, &asks).clearing_price(),
                reference_clearing_price(&bids, &asks),
            );
        }
    }

    #[test]
    fn level_sweep_work_scales_with_levels_not_prices_times_orders() {
        let bids: Vec<_> = (0..10_000)
            .map(|idx| snap(OrderSide::Bid, 1_000 + idx % 100, 1))
            .collect();
        let asks: Vec<_> = (0..10_000)
            .map(|idx| snap(OrderSide::Ask, 1_000 + idx % 100, 1))
            .collect();
        let levels = PriceLevelAggregates::from_snapshots(&bids, &asks);

        assert_eq!(
            levels.clearing_price(),
            reference_clearing_price(&bids, &asks)
        );

        let candidate_count = 100usize;
        let legacy_order_checks = candidate_count * (bids.len() + asks.len());
        let level_sweep_visits = candidate_count + levels.bids.len() + levels.asks.len();
        assert!(
            legacy_order_checks > level_sweep_visits * 1_000,
            "fixture must retain a three-order-of-magnitude work reduction"
        );
    }

    /// Manual wall-clock evidence for the exact P-03 hotspot. The deterministic
    /// operation-count assertion above is the portable CI guard; this ignored
    /// test records host-specific release-mode measurements for the PR.
    #[test]
    #[ignore = "manual matcher performance measurement"]
    fn benchmark_level_sweep_against_quadratic_reference() {
        use std::hint::black_box;
        use std::time::Instant;

        let bids: Vec<_> = (0..40_000)
            .map(|idx| snap(OrderSide::Bid, 1_000 + idx % 512, 1))
            .collect();
        let asks: Vec<_> = (0..40_000)
            .map(|idx| snap(OrderSide::Ask, 1_000 + idx % 512, 1))
            .collect();

        let reference_started = Instant::now();
        let expected = black_box(reference_clearing_price(&bids, &asks));
        let reference_elapsed = reference_started.elapsed();

        let sweep_started = Instant::now();
        let actual = black_box(PriceLevelAggregates::from_snapshots(&bids, &asks).clearing_price());
        let sweep_elapsed = sweep_started.elapsed();

        assert_eq!(actual, expected);
        eprintln!(
            "clearing-price benchmark: orders={} levels=512 quadratic_ms={:.3} level_sweep_ms={:.3} speedup={:.2}x",
            bids.len() + asks.len(),
            reference_elapsed.as_secs_f64() * 1_000.0,
            sweep_elapsed.as_secs_f64() * 1_000.0,
            reference_elapsed.as_secs_f64() / sweep_elapsed.as_secs_f64(),
        );
    }

    #[test]
    fn clearing_price_empty_side_returns_none() {
        let bids = vec![snap(OrderSide::Bid, 100, 10)];
        let asks: Vec<OrderSnapshot> = vec![];
        assert!(compute_clearing_price(&bids, &asks).is_none());
        assert!(compute_clearing_price(&asks, &bids).is_none());
    }

    #[test]
    fn clearing_price_no_crossing_returns_zero_matched() {
        // Bid below ask → matched = 0 at every candidate price.
        // compute_clearing_price returns None because best_matched
        // never improves over the initial 0.
        let bids = vec![snap(OrderSide::Bid, 90, 10)];
        let asks = vec![snap(OrderSide::Ask, 100, 10)];
        assert_eq!(compute_clearing_price(&bids, &asks), None);
    }

    #[test]
    fn clearing_price_picks_lowest_max_matched_tie() {
        // Bid @100 amount=10; Ask @100 amount=10. Only candidate
        // is 100, matched = 10. Result: (100, 10).
        let bids = vec![snap(OrderSide::Bid, 100, 10)];
        let asks = vec![snap(OrderSide::Ask, 100, 10)];
        assert_eq!(compute_clearing_price(&bids, &asks), Some((100, 10)));
    }

    #[test]
    fn zero_limit_market_ask_is_eligible_but_not_a_price_candidate() {
        // Both p=0 and p=150 would match all 10 units if zero were admitted as
        // a candidate. The deterministic lowest-price tie-break would then
        // choose zero. A market ask instead contributes supply at the bid's
        // positive candidate, so the pair clears at 150.
        let bids = vec![snap(OrderSide::Bid, 150, 10)];
        let asks = vec![snap(OrderSide::Ask, 0, 10)];
        assert_eq!(compute_clearing_price(&bids, &asks), Some((150, 10)));
    }

    #[test]
    fn clearing_price_uniform_across_book() {
        // Mirrors the public uniform-clearing-price scenario:
        // 5 bids @150..146 + 3 asks @144..146, amount=10 each.
        // At p=146: demand = 50, supply = 30 → matched = 30.
        // At p=145: demand = 40, supply = 20 → matched = 20.
        // Highest-matched price wins: (146, 30).
        let bids: Vec<_> = [150, 149, 148, 147, 146]
            .iter()
            .map(|p| snap(OrderSide::Bid, *p, 10))
            .collect();
        let asks: Vec<_> = [144, 145, 146]
            .iter()
            .map(|p| snap(OrderSide::Ask, *p, 10))
            .collect();
        assert_eq!(compute_clearing_price(&bids, &asks), Some((146, 30)));
    }

    // ─── U-06: skip zero-quote clears ───────────────────────────────────

    /// One crossing bid/ask with distinct trading keys (so the self-trade
    /// guard doesn't fire first) at `price`/`amount`.
    fn crossing_pair(price: u64, amount: u64) -> (Vec<OrderSnapshot>, Vec<OrderSnapshot>) {
        let mut bid = snap(OrderSide::Bid, price, amount);
        bid.trading_key = [1u8; 32];
        let mut ask = snap(OrderSide::Ask, price, amount);
        ask.trading_key = [2u8; 32];
        (vec![bid], vec![ask])
    }

    fn run_pair(price_scale: u64) -> (usize, Vec<MatchPair>) {
        let base_mint = [0xBBu8; 32];
        let quote_mint = [0xCCu8; 32];
        let (mut bids, mut asks) = crossing_pair(1, 1);
        let mut out = Vec::new();
        let mut fee_buckets = [FeeBucket::new(base_mint, 0), FeeBucket::new(quote_mint, 0)];
        let n = generate_matches(
            &mut bids,
            &mut asks,
            /* p_star */ 1,
            /* pyth_twap */ 1,
            /* now_slot */ 0,
            &base_mint,
            &quote_mint,
            price_scale,
            /* fee_rate_bps */ 0,
            /* start_match_id */ 0,
            /* max_matches */ 16,
            /* single_fill_per_order */ true,
            &mut out,
            &mut fee_buckets,
        )
        .expect("generate_matches");
        (n, out)
    }

    #[test]
    fn generate_matches_skips_zero_quote_clear() {
        // floor(crossable(1) * p_star(1) / price_scale(1_000_000)) == 0 → the
        // clear would mint an unspendable zero-amount quote note. U-06 must
        // skip it and produce NO match.
        let (n, out) = run_pair(1_000_000);
        assert_eq!(n, 0, "zero-quote clear must not produce a match");
        assert!(out.is_empty());
    }

    #[test]
    fn generate_matches_allows_positive_quote_clear() {
        // Same pair with price_scale=1 → quote = 1 (positive) → one match. The
        // guard is specific to the zero-quote degenerate case.
        let (n, out) = run_pair(1);
        assert_eq!(n, 1, "positive-quote clear must still match");
        assert_eq!(out.len(), 1);
    }
}
