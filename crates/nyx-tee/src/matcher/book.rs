//! Per-market in-memory order book. Re-uses the
//! `darkpool_matcher::book::Order` type so the snapshot we hand
//! to `darkpool_matcher::run_batch(...)` requires no field
//! conversion — same struct on both sides of the boundary.
//!
//! Indices:
//!   - `bids` / `asks`: BTreeMap<Price, FifoQueue> for the
//!     matcher's "best-price-first FIFO" priority.
//!   - `by_id`: HashMap<order_id, Order> — canonical storage +
//!     cancel-by-id lookup.
//!   - `by_trader`: HashMap<trading_key, HashSet<order_id>> for
//!     cancel-by-owner + future self-trade prevention.
//!   - `by_expiry`: BTreeMap<expiry_slot, HashSet<order_id>> for
//!     the expiry sweep (cheap range-scan on the slot we just
//!     crossed).
//!
//! Concurrency: this struct is wrapped in an `Arc<RwLock<...>>`
//! by `MatcherState` (see `interval.rs`). The matcher tick takes
//! a brief write lock to apply OrderUpdates; submitters take a
//! brief write lock to insert.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use darkpool_matcher::book::{Order, OrderBook as MatcherOrderBook, OrderUpdate, OrderUpdateKind};

pub type OrderId = [u8; 16];
pub type TradingKey = [u8; 32];
pub type Price = u64;
pub type Slot = u64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BookError {
    #[error("order_id is all-zero (sentinel value reserved for 'no re-lock')")]
    ZeroOrderId,
    #[error("order_id {} already exists for trading_key {}", hex::encode(.0), hex::encode(.1))]
    Duplicate(OrderId, TradingKey),
    #[error("no order with id {}", hex::encode(.0))]
    NotFound(OrderId),
    #[error("trading_key mismatch on cancel: order owned by {} but caller is {}",
            hex::encode(.0), hex::encode(.1))]
    NotOwner(TradingKey, TradingKey),
    #[error("order {} is pending settlement and cannot be cancelled or modified", hex::encode(.0))]
    PendingSettlement(OrderId),
    #[error("order {} is not resting and cannot be reserved", hex::encode(.0))]
    NotResting(OrderId),
}

#[derive(Default, Debug)]
struct FifoQueue {
    ids: VecDeque<OrderId>,
}

impl FifoQueue {
    fn push(&mut self, id: OrderId) {
        self.ids.push_back(id);
    }
    fn remove(&mut self, id: &OrderId) -> bool {
        if let Some(pos) = self.ids.iter().position(|x| x == id) {
            self.ids.remove(pos);
            true
        } else {
            false
        }
    }
    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[derive(Default, Debug)]
pub struct OrderBook {
    by_id: HashMap<OrderId, Order>,
    bids: BTreeMap<Price, FifoQueue>,
    asks: BTreeMap<Price, FifoQueue>,
    by_trader: HashMap<TradingKey, HashSet<OrderId>>,
    by_expiry: BTreeMap<Slot, HashSet<OrderId>>,
}

impl OrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    // ─── Mutating ops ──────────────────────────────────────────────

    /// Insert a new order. Rejects:
    ///   - all-zero order_id (matches `RELOCK_ORDER_ID_NONE`
    ///     sentinel — would collide with the matcher's "no re-lock"
    ///     marker).
    ///   - duplicate (trading_key, order_id) — clients must use
    ///     unique ids per submission.
    pub fn submit(&mut self, order: Order) -> Result<(), BookError> {
        if order.order_id == [0u8; 16] {
            return Err(BookError::ZeroOrderId);
        }
        if self.by_id.contains_key(&order.order_id) {
            return Err(BookError::Duplicate(order.order_id, order.trading_key));
        }

        let oid = order.order_id;
        let tk = order.trading_key;
        let price = order.price_limit;
        let expiry = order.expiry_slot;
        let side_book = match order.side {
            darkpool_matcher::book::OrderSide::Bid => &mut self.bids,
            darkpool_matcher::book::OrderSide::Ask => &mut self.asks,
        };
        side_book.entry(price).or_default().push(oid);

        self.by_trader.entry(tk).or_default().insert(oid);
        self.by_expiry.entry(expiry).or_default().insert(oid);

        self.by_id.insert(oid, order);
        Ok(())
    }

    /// Cancel an order by id. Verifies the caller's trading_key
    /// matches the order's — protects against cross-trader cancels
    /// (the on-chain analogue is the PDA seed check on
    /// `cancel_order`).
    pub fn cancel(
        &mut self,
        trading_key: TradingKey,
        order_id: OrderId,
    ) -> Result<Order, BookError> {
        let order = self
            .by_id
            .get(&order_id)
            .ok_or(BookError::NotFound(order_id))?;
        if order.trading_key != trading_key {
            return Err(BookError::NotOwner(order.trading_key, trading_key));
        }
        if order.status == darkpool_matcher::book::OrderStatus::Matched {
            return Err(BookError::PendingSettlement(order_id));
        }
        Ok(self
            .remove_internal(&order_id)
            .expect("by_id said it exists"))
    }

    /// Atomically reserve every order participating in a settlement batch.
    /// Reserved orders remain queryable but the pure matcher skips them because
    /// their status is `Matched`. No quantities or collateral pointers change
    /// until their individual Tx D outcome is confirmed.
    pub fn reserve_for_settlement(&mut self, order_ids: &[OrderId]) -> Result<(), BookError> {
        for order_id in order_ids {
            let order = self
                .by_id
                .get(order_id)
                .ok_or(BookError::NotFound(*order_id))?;
            if order.status != darkpool_matcher::book::OrderStatus::Pending {
                return Err(BookError::NotResting(*order_id));
            }
        }
        for order_id in order_ids {
            if let Some(order) = self.by_id.get_mut(order_id) {
                order.status = darkpool_matcher::book::OrderStatus::Matched;
            }
        }
        Ok(())
    }

    /// Remove a definitively failed settlement from the book without applying
    /// its proposed fill. The opening reservation is managed separately and is
    /// retained until the input lock expires.
    pub fn remove_pending_settlement(&mut self, order_id: &OrderId) -> Option<Order> {
        match self.by_id.get(order_id) {
            Some(order) if order.status == darkpool_matcher::book::OrderStatus::Matched => {
                self.remove_internal(order_id)
            }
            _ => None,
        }
    }

    /// Apply the matcher's emitted updates to the book. Mirrors
    /// the on-chain `apply_slot_updates` shell — same four
    /// variants of `OrderUpdateKind`.
    pub fn apply_updates(&mut self, updates: &[OrderUpdate]) {
        for upd in updates {
            match &upd.kind {
                OrderUpdateKind::FullyFilled { .. }
                | OrderUpdateKind::Cancelled
                | OrderUpdateKind::Expired => {
                    // Hard removal: remove from all indices.
                    let _ = self.remove_internal(&upd.order_id);
                }
                OrderUpdateKind::PartiallyFilled {
                    new_amount,
                    new_collateral_note,
                    new_note_amount,
                    filled_quantity,
                } => {
                    // The residual relocks to a change note whose inner is
                    // derived from the consumed input inner. The confirmed-
                    // settlement commit has inserted that opening; here we
                    // rotate the in-book collateral pointer. Price + expiry
                    // are unchanged, so only the `by_id` fields rotate.
                    if let Some(order) = self.by_id.get_mut(&upd.order_id) {
                        order.amount = *new_amount;
                        order.collateral_note = *new_collateral_note;
                        order.note_amount = *new_note_amount;
                        order.filled_quantity = *filled_quantity;
                        order.status = darkpool_matcher::book::OrderStatus::Pending;
                    }
                }
            }
        }
    }

    /// Drop expired orders at or before `now_slot`. Returns the
    /// expired order_ids so the caller can emit `Expired`
    /// events on the WS channel (later PR).
    pub fn sweep_expired(&mut self, now_slot: Slot) -> Vec<OrderId> {
        // Drain everything in by_expiry up to and including now_slot.
        let mut expired: Vec<OrderId> = Vec::new();
        // BTreeMap split: collect keys ≤ now_slot.
        let to_drop: Vec<Slot> = self.by_expiry.range(..=now_slot).map(|(s, _)| *s).collect();
        for slot_key in to_drop {
            if let Some(ids) = self.by_expiry.remove(&slot_key) {
                for id in ids {
                    expired.push(id);
                }
            }
        }
        let mut retained_pending_settlement = Vec::new();
        for id in &expired {
            if self
                .by_id
                .get(id)
                .is_some_and(|order| order.status == darkpool_matcher::book::OrderStatus::Matched)
            {
                retained_pending_settlement.push(*id);
            } else {
                let _ = self.remove_internal(id);
            }
        }
        for id in &retained_pending_settlement {
            if let Some(order) = self.by_id.get(id) {
                self.by_expiry
                    .entry(order.expiry_slot)
                    .or_default()
                    .insert(*id);
            }
        }
        expired
            .into_iter()
            .filter(|id| !retained_pending_settlement.contains(id))
            .collect()
    }

    /// Snapshot the entire book as a matcher input. Order in the
    /// returned Vec is: bids descending by price, asks ascending by
    /// price, with FIFO tie-break. (The matcher re-sorts internally
    /// via `partition_book`, so order here is informational — but
    /// matching it cuts work.)
    pub fn snapshot(&self) -> MatcherOrderBook {
        let mut orders: Vec<Order> = Vec::with_capacity(self.by_id.len());
        // Bids descending.
        for (_price, q) in self.bids.iter().rev() {
            for id in &q.ids {
                if let Some(o) = self.by_id.get(id) {
                    if o.status == darkpool_matcher::book::OrderStatus::Pending {
                        orders.push(o.clone());
                    }
                }
            }
        }
        // Asks ascending.
        for (_price, q) in self.asks.iter() {
            for id in &q.ids {
                if let Some(o) = self.by_id.get(id) {
                    if o.status == darkpool_matcher::book::OrderStatus::Pending {
                        orders.push(o.clone());
                    }
                }
            }
        }
        MatcherOrderBook { orders }
    }

    /// Look up an order by id (read-only).
    pub fn get(&self, order_id: &OrderId) -> Option<&Order> {
        self.by_id.get(order_id)
    }

    // ─── Private helpers ─────────────────────────────────────────────

    /// Remove from `by_id` + all indices. Idempotent: returns the
    /// removed Order if found, None if it didn't exist.
    fn remove_internal(&mut self, id: &OrderId) -> Option<Order> {
        let order = self.by_id.remove(id)?;
        let side_book = match order.side {
            darkpool_matcher::book::OrderSide::Bid => &mut self.bids,
            darkpool_matcher::book::OrderSide::Ask => &mut self.asks,
        };
        if let Some(q) = side_book.get_mut(&order.price_limit) {
            q.remove(id);
            if q.is_empty() {
                side_book.remove(&order.price_limit);
            }
        }
        if let Some(set) = self.by_trader.get_mut(&order.trading_key) {
            set.remove(id);
            if set.is_empty() {
                self.by_trader.remove(&order.trading_key);
            }
        }
        if let Some(set) = self.by_expiry.get_mut(&order.expiry_slot) {
            set.remove(id);
            if set.is_empty() {
                self.by_expiry.remove(&order.expiry_slot);
            }
        }
        Some(order)
    }
}

// ─────── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_matcher::book::{OrderSide, OrderStatus, OrderType};

    fn mk_order(side: OrderSide, idx: u8, price: u64, amount: u64) -> Order {
        let mut tk = [0u8; 32];
        tk[0] = idx;
        let mut oid = [0u8; 16];
        oid[0] = idx;
        oid[15] = 1; // never zero
                     // user_commitment top byte must be 0 — the matcher
                     // Poseidon-hashes it during change-note construction and
                     // requires BN254-Fr-safe inputs. Matches the on-chain
                     // `make_pending_seed`'s `user_commitment[0] = 0` step.
        let user_commitment = {
            let mut u = [idx ^ 0xab; 32];
            u[0] = 0;
            u
        };
        Order {
            trading_key: tk,
            side,
            order_type: OrderType::Limit,
            status: OrderStatus::Pending,
            arrival_slot: 1,
            expiry_slot: 1_000_000,
            price_limit: price,
            amount,
            total_quantity: amount,
            filled_quantity: 0,
            min_fill_qty: 0,
            note_amount: amount.saturating_mul(price).max(amount).max(1),
            collateral_note: [idx; 32],
            user_commitment,
            owner_commitment: user_commitment, // same owner identity, keyed on idx
            order_id: oid,
            order_inclusion_commitment: [idx ^ 0xcd; 32],
        }
    }

    #[test]
    fn submit_and_snapshot_preserves_orders() {
        let mut book = OrderBook::new();
        book.submit(mk_order(OrderSide::Bid, 1, 100, 5)).unwrap();
        book.submit(mk_order(OrderSide::Ask, 2, 100, 5)).unwrap();
        let snap = book.snapshot();
        assert_eq!(snap.orders.len(), 2);
    }

    #[test]
    fn submit_rejects_zero_order_id() {
        let mut o = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 5);
        o.order_id = [0u8; 16];
        let mut book = OrderBook::new();
        assert_eq!(book.submit(o).unwrap_err(), BookError::ZeroOrderId);
    }

    #[test]
    fn submit_rejects_duplicate_order_id() {
        let mut book = OrderBook::new();
        let o = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 5);
        book.submit(o.clone()).unwrap();
        let err = book.submit(o.clone()).unwrap_err();
        assert!(matches!(err, BookError::Duplicate(_, _)));
    }

    #[test]
    fn cancel_requires_matching_trading_key() {
        let mut book = OrderBook::new();
        let order = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 5);
        let oid = order.order_id;
        book.submit(order).unwrap();
        // Wrong trading_key: should error.
        let wrong_tk = [99u8; 32];
        assert!(matches!(
            book.cancel(wrong_tk, oid).unwrap_err(),
            BookError::NotOwner(_, _)
        ));
        // Right trading_key: should succeed.
        let mut right_tk = [0u8; 32];
        right_tk[0] = 1;
        let cancelled = book.cancel(right_tk, oid).unwrap();
        assert_eq!(cancelled.order_id, oid);
        assert!(book.is_empty());
    }

    #[test]
    fn sweep_expired_removes_only_past_slots() {
        let mut book = OrderBook::new();
        let mut a = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 5);
        a.expiry_slot = 10;
        let mut b = mk_order(darkpool_matcher::book::OrderSide::Ask, 2, 100, 5);
        b.expiry_slot = 100;
        book.submit(a.clone()).unwrap();
        book.submit(b.clone()).unwrap();
        let expired = book.sweep_expired(50);
        assert_eq!(expired, vec![a.order_id]);
        assert_eq!(book.len(), 1);
        assert!(book.get(&b.order_id).is_some());
    }

    #[test]
    fn apply_updates_partial_fill_rotates_and_keeps() {
        // Continuation: a partial fill rotates the residual's collateral to
        // the consumed-input-derived change note and
        // KEEPS it in the book (Pending), so it re-matches without a client
        // roundtrip. (Pre-continuation this removed the order — "Option A".)
        let mut book = OrderBook::new();
        let o = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 20);
        let oid = o.order_id;
        book.submit(o).unwrap();
        book.apply_updates(&[OrderUpdate {
            trading_key: book.get(&oid).unwrap().trading_key,
            order_id: oid,
            kind: OrderUpdateKind::PartiallyFilled {
                new_amount: 15,
                new_collateral_note: [42u8; 32],
                new_note_amount: 1500,
                filled_quantity: 5,
            },
        }]);
        let kept = book.get(&oid).expect("residual must stay in the book");
        assert_eq!(kept.amount, 15, "amount decremented to the residual");
        assert_eq!(
            kept.collateral_note, [42u8; 32],
            "collateral rotated to the change note"
        );
        assert_eq!(kept.note_amount, 1500, "note_amount rotated");
        assert_eq!(kept.filled_quantity, 5);
        assert_eq!(
            kept.status,
            darkpool_matcher::book::OrderStatus::Pending,
            "residual stays matchable"
        );
        assert!(!book.is_empty());
    }

    #[test]
    fn apply_updates_full_fill_removes_order() {
        let mut book = OrderBook::new();
        let o = mk_order(darkpool_matcher::book::OrderSide::Bid, 1, 100, 5);
        let oid = o.order_id;
        let tk = o.trading_key;
        book.submit(o).unwrap();
        book.apply_updates(&[OrderUpdate {
            trading_key: tk,
            order_id: oid,
            kind: OrderUpdateKind::FullyFilled { filled_quantity: 5 },
        }]);
        assert!(book.is_empty());
    }

    #[test]
    fn settlement_reservation_is_atomic_skipped_and_not_cancellable() {
        let mut book = OrderBook::new();
        let a = mk_order(OrderSide::Bid, 1, 100, 5);
        let b = mk_order(OrderSide::Ask, 2, 100, 5);
        book.submit(a.clone()).unwrap();
        book.submit(b.clone()).unwrap();
        book.reserve_for_settlement(&[a.order_id, b.order_id])
            .unwrap();

        assert!(book.snapshot().orders.is_empty());
        assert_eq!(book.get(&a.order_id).unwrap().amount, 5);
        assert_eq!(
            book.cancel(a.trading_key, a.order_id).unwrap_err(),
            BookError::PendingSettlement(a.order_id)
        );

        let missing = [0xFE; 16];
        let mut second = OrderBook::new();
        second.submit(a.clone()).unwrap();
        assert_eq!(
            second
                .reserve_for_settlement(&[a.order_id, missing])
                .unwrap_err(),
            BookError::NotFound(missing)
        );
        assert_eq!(
            second.get(&a.order_id).unwrap().status,
            darkpool_matcher::book::OrderStatus::Pending,
            "failed reservation partially mutated the book"
        );
    }
}
