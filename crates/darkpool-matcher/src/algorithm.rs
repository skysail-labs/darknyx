//! The matching algorithm itself. Pure functions over the
//! `darkpool_matcher::book` + `darkpool_matcher::match_result` types.
//!
//! Lifted from
//! `programs/matching_engine/src/instructions/run_batch.rs`. The lift
//! is gated by:
//!   * Per-function unit tests in this module (the same 5 inline
//!     tests that lived under `#[cfg(test)] mod tests` in run_batch.rs)
//!   * Integration scenarios in `tests/parity.rs` (8 scenarios
//!     translated from `programs/matching_engine/tests/run_batch.rs`)
//!
//! No Anchor / no `solana_program` imports. The one place the
//! on-chain code used `solana_program::hash::hashv` was inside
//! `merkle_root_sha256`; the port uses `sha2::Sha256` instead and
//! a parity test pins the byte-equivalence.

use sha2::{Digest, Sha256};

use crate::book::{Order, OrderSide, OrderType, OrderUpdate, OrderUpdateKind};
use crate::change_note;
use crate::config::MatchConfig;
use crate::error::MatchError;
use crate::fee::FeeBucket;
use crate::match_result::{MatchPair, MatchStatus, RELOCK_ORDER_ID_NONE};
use darkpool_crypto::note::commitment_from_fields;

// Fee role tags. Mirrored inline in the on-chain `run_batch.rs` —
// they fall under the same cross-language byte-equality contract as
// `change_note::CHANGE_ROLE_*` (CLAUDE.md §6). The TS-side mirror
// lives at `packages/sdk/tests/helpers/e2e-helpers.ts`.
const FEE_ROLE_BASE: u8 = 0xfb;
const FEE_ROLE_QUOTE: u8 = 0xfc;

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
/// root is published in `BatchResults.last_inclusion_root` as an
/// audit log over the per-batch `order_inclusion_commitment`s so
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
    pub trading_key: [u8; 32],
    pub order_id: [u8; 16],
    pub inclusion: [u8; 32],

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
            trading_key: o.trading_key,
            order_id: o.order_id,
            inclusion: o.order_inclusion_commitment,
            cancelled_sentinel: false,
        }
    }
}

// ─────── compute_clearing_price ─────────────────────────────────────────────

/// Uniform-clearing-price computation. Returns `Some((p*, matched))`
/// where p* is the price that maximises `min(demand, supply)` across
/// the candidate-price set `{all distinct bid/ask price_limits}`,
/// with ties broken by the lowest price (deterministic).
///
/// `None` iff either side is empty (no crossing possible).
///
/// Lifted verbatim from `run_batch::compute_clearing_price` —
/// algorithm is pure, no Anchor / Solana types involved.
///
/// `pub(crate)` because the signature takes the internal
/// `OrderSnapshot` type; external callers go through `run_batch`.
pub(crate) fn compute_clearing_price(
    bids: &[OrderSnapshot],
    asks: &[OrderSnapshot],
) -> Option<(u64, u64)> {
    if bids.is_empty() || asks.is_empty() {
        return None;
    }
    let mut candidates: Vec<u64> = Vec::with_capacity(bids.len() + asks.len());
    for b in bids.iter() {
        candidates.push(b.price_limit);
    }
    for a in asks.iter() {
        candidates.push(a.price_limit);
    }
    candidates.sort();
    candidates.dedup();

    let mut best_p: Option<u64> = None;
    let mut best_matched: u64 = 0;
    for &p in candidates.iter() {
        let demand: u64 = bids
            .iter()
            .filter(|b| b.price_limit >= p)
            .fold(0u64, |a, b| a.saturating_add(b.amount));
        let supply: u64 = asks
            .iter()
            .filter(|a_| a_.price_limit <= p)
            .fold(0u64, |a, b| a.saturating_add(b.amount));
        let matched = demand.min(supply);
        if matched > best_matched {
            best_matched = matched;
            best_p = Some(p);
        }
    }
    best_p.map(|p| (p, best_matched))
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
    fee_rate_bps: u64,
    start_match_id: u64,
    out_matches: &mut Vec<MatchPair>,
    fee_buckets: &mut [FeeBucket; 2],
) -> Result<usize, MatchError> {
    let mut produced: usize = 0;
    let mut bi = 0usize;
    let mut ai = 0usize;
    let mut next_match_id = start_match_id;

    while bi < bids.len() && ai < asks.len() {
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
        let quote_amt_u128 = (crossable as u128)
            .checked_mul(p_star as u128)
            .ok_or(MatchError::Internal("notional overflow"))?;
        if quote_amt_u128 > u64::MAX as u128 {
            return Err(MatchError::Internal("notional overflow (u64)"));
        }
        let quote_amt = quote_amt_u128 as u64;

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

        // Change-note commitments. Bytes match the on-chain Poseidon
        // construction because `commitment_from_fields` is shared
        // via the `darkpool-crypto` crate AND `change_note::derive_*`
        // is byte-equal to the on-chain hashv version (gated by
        // `tests/change_note_parity.rs`).
        let note_e_commitment = if buyer_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_BUYER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_BUYER);
            commitment_from_fields(
                quote_mint,
                buyer_change_amt,
                &bids[bi].user_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| MatchError::Internal("Poseidon failed for buyer change note"))?
        } else {
            [0u8; 32]
        };
        let note_f_commitment = if seller_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_SELLER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_SELLER);
            commitment_from_fields(
                base_mint,
                seller_change_amt,
                &asks[ai].user_commitment,
                &nonce,
                &r,
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

        // Fee buckets: bucket 0 = base (seller side fee), bucket 1 =
        // quote (buyer side fee). Matches the on-chain layout in
        // BatchResults.fee_accumulators[].
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

        // Advance whichever side filled entirely.
        if b_remaining_after == 0 {
            bi += 1;
        }
        if a_remaining_after == 0 {
            ai += 1;
        }
    }

    Ok(produced)
}

// ─────── apply_slot_updates ─────────────────────────────────────────────────
//
// Walk the (post-match) snapshot vectors + the pre-batch order book
// snapshot, emit one `OrderUpdate` per touched order. The caller
// (on-chain ix in PR 3 / in-TEE matcher) applies these to the source
// of truth (PendingOrder PDAs or in-memory book).
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

// ─────── flush_fee_notes ────────────────────────────────────────────────────
//
// Compute the Poseidon commitments for the protocol-owned fee notes
// at batch close. Matches the on-chain block:
//   - protocol_owner_commitment != [0;32]
//   - circuit breaker did NOT trip
// for both base + quote sides. Mutates `fee_buckets[].flushed_commitment`
// in place; returns `Ok(())` on success.
//
// Caller (`lib.rs::run_batch`) decides when to call this — same
// gating as on-chain.
pub(crate) fn flush_fee_notes(
    fee_buckets: &mut [FeeBucket; 2],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
    protocol_owner_commitment: &[u8; 32],
    now_slot: u64,
) -> Result<(), MatchError> {
    if fee_buckets[0].accumulated_fees > 0 {
        let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_BASE);
        let r = change_note::derive_blinding(now_slot, FEE_ROLE_BASE);
        let c = commitment_from_fields(
            base_mint,
            fee_buckets[0].accumulated_fees,
            protocol_owner_commitment,
            &nonce,
            &r,
        )
        .map_err(|_| MatchError::Internal("Poseidon failed for base fee note"))?;
        fee_buckets[0].flushed_commitment = c;
    }
    if fee_buckets[1].accumulated_fees > 0 {
        let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_QUOTE);
        let r = change_note::derive_blinding(now_slot, FEE_ROLE_QUOTE);
        let c = commitment_from_fields(
            quote_mint,
            fee_buckets[1].accumulated_fees,
            protocol_owner_commitment,
            &nonce,
            &r,
        )
        .map_err(|_| MatchError::Internal("Poseidon failed for quote fee note"))?;
        fee_buckets[1].flushed_commitment = c;
    }
    Ok(())
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
            trading_key: [0; 32],
            order_id: [0; 16],
            inclusion: [0; 32],
            cancelled_sentinel: false,
        }
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
    fn clearing_price_uniform_across_book() {
        // Mirrors the public scenario in
        // programs/matching_engine/tests/run_batch.rs::
        //   test_uniform_clearing_price:
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
}
