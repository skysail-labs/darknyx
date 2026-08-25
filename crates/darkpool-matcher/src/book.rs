//! Order-book primitives. Pure data — no async, no I/O, no Anchor.
//!
//! Borsh on the wire. `OrderSide`, `OrderType`, and `OrderStatus` carry
//! `#[borsh(use_discriminant = true)]`, which is what makes Borsh emit each
//! variant's explicit `= N` value as the wire byte instead of its positional
//! index; `#[repr(u8)]` alone would not. The values are chosen to equal the
//! on-chain `u8` constants.
//!
//! Reordering variants is therefore safe — the tags travel with the values.
//! **Changing a value is not**: the SDK, the enclave, and the on-chain program
//! all decode these bytes, so a tag change must land in all three together or
//! existing orders are silently reinterpreted as a different variant.

use borsh::{BorshDeserialize, BorshSerialize};

pub type Price = u64;
pub type Quantity = u64;

// ─────── Enums — discriminants match the on-chain u8 constants ──────────────

/// On-chain mapping: `PENDING_SIDE_BID = 0`, `PENDING_SIDE_ASK = 1`.
/// `#[borsh(use_discriminant = true)]` makes Borsh use the explicit
/// `= 0` / `= 1` values as the wire byte, matching the on-chain u8
/// constant exactly (rather than the default sequential index).
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum OrderSide {
    Bid = 0,
    Ask = 1,
}

/// On-chain mapping: `PENDING_TYPE_LIMIT = 0`, `_IOC = 1`, `_FOK = 2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum OrderType {
    Limit = 0,
    Ioc = 1,
    Fok = 2,
}

/// On-chain mapping: `PENDING_STATUS_EMPTY = 0`, `_PENDING = 1`,
/// `_MATCHED = 2`, `_EXPIRED = 3`, `_CANCELLED = 4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum OrderStatus {
    Empty = 0,
    Pending = 1,
    Matched = 2,
    Expired = 3,
    Cancelled = 4,
}

// ─────── Order ──────────────────────────────────────────────────────────────

/// A single open order. The matcher consumes a `Vec<Order>` (via
/// `OrderBook`), produces matches, and emits a `Vec<OrderUpdate>`
/// telling the caller how to mutate the originals.
///
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Order {
    // ─── Identity ───────────────────────────────────────────────
    /// Owner trading key (a Solana Ed25519 pubkey as raw bytes).
    /// Used for self-trade prevention + as the `owner_buyer` /
    /// `owner_seller` field on the resulting MatchResult.
    pub trading_key: [u8; 32],

    // ─── Status flags ───────────────────────────────────────────
    pub side: OrderSide,
    pub order_type: OrderType,
    pub status: OrderStatus,

    // ─── Slot timing ────────────────────────────────────────────
    /// Solana slot at which the order was accepted by the matcher.
    /// Drives FIFO tie-break inside `compute_clearing_price`.
    pub arrival_slot: u64,
    /// Slot past which the order auto-expires. Orders whose
    /// `expiry_slot <= current_slot + SETTLEMENT_BUFFER_SLOTS` are
    /// dropped before matching starts.
    pub expiry_slot: u64,

    // ─── Pricing + quantities ───────────────────────────────────
    pub price_limit: Price,
    /// Remaining order size. Decremented in place on partial fills.
    pub amount: Quantity,
    /// Original full order size — frozen at submit time.
    pub total_quantity: Quantity,
    /// Cumulative filled qty across all partial fills.
    pub filled_quantity: Quantity,
    /// Minimum fill threshold. 0 = any partial allowed.
    pub min_fill_qty: Quantity,
    /// Full value of the note currently collateralising this order
    /// (BUY: quote units; SELL: base units). Rotates on partial-fill
    /// re-lock to equal the change-note value.
    pub note_amount: Quantity,

    // ─── Cryptographic bindings ─────────────────────────────────
    /// Poseidon6 commitment of the collateral note. Rotates on
    /// partial-fill re-lock to the change-note commitment.
    pub collateral_note: [u8; 32],
    /// The owner identity BOUND to this order's collateral note: intake
    /// re-derives `collateral_note` from `(mint, amount, owner_commitment,
    /// inner_hash)` and rejects a mismatch (`verify_commitment`), so it cannot
    /// be spoofed for a note the caller doesn't own. Shared by every note
    /// carrying this owner commitment, so it's the identity the self-trade check
    /// keys on (see `algorithm::generate_matches`) and the one output notes
    /// derive back to. A user can still create a distinct spending key and
    /// therefore a distinct owner identity, so this catches wash trades across
    /// rotated trading keys, not across deliberately split wallets.
    /// `generate_matches` also compares `trading_key` independently, as a
    /// cheaper belt-and-suspenders.
    ///
    /// This is the only NOTE-BOUND owner identity an order carries. A separate
    /// client-asserted `user_commitment` rode alongside it until audit
    /// 2026-07-25 (T-07 / PF-10); nothing ever read it. If you are about to
    /// re-add a caller-supplied identity here, make it something intake
    /// verifies — an unverified one is worse than none, because it reads as a
    /// binding.
    pub owner_commitment: [u8; 32],
    /// Client-supplied 16-byte id. Used by cancel-by-id, by the
    /// `NoteLock` PDA seed at settle time, and by the matcher's
    /// re-lock instruction.
    pub order_id: [u8; 16],
    /// `SHA-256(arrival_slot || collateral_note_at_submit || trading_key)`.
    /// Anchored at submit; never rotated. The matcher's per-batch
    /// inclusion-root computation hashes these.
    pub order_inclusion_commitment: [u8; 32],
}

// ─────── OrderBook — the matcher's input collection ─────────────────────────

/// Flat `Vec<Order>` snapshot consumed directly by the matching algorithm.
/// The in-TEE matcher (`crates/darknyx-tee`) builds one by snapshotting
/// its long-lived `BTreeMap<Price, FifoQueue<OrderId>>` at each
/// batch tick — see `docs/tee-architecture.md` §5.1.
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct OrderBook {
    pub orders: Vec<Order>,
}

impl OrderBook {
    pub fn new() -> Self {
        Self { orders: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            orders: Vec::with_capacity(cap),
        }
    }

    pub fn insert(&mut self, order: Order) {
        self.orders.push(order);
    }

    pub fn len(&self) -> usize {
        self.orders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orders.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Order> {
        self.orders.iter()
    }
}

// ─────── OrderUpdate — matcher output instruction ───────────────────────────

/// Tells the caller what to do with each `Order` after matching. The
/// in-TEE matcher applies these directly to the in-memory book.
///
/// Carries the order's `trading_key + order_id` so the caller can
/// look up the source PDA (or in-memory book entry) without
/// relying on a positional index that could shift between
/// matcher calls.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OrderUpdate {
    pub trading_key: [u8; 32],
    pub order_id: [u8; 16],
    pub kind: OrderUpdateKind,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum OrderUpdateKind {
    /// Order matched fully — set status to Matched, zero amount,
    /// zero collateral_note, etc. Mirrors the on-chain "full fill"
    /// branch of `apply_slot_updates`.
    FullyFilled { filled_quantity: Quantity },
    /// Partial fill, order stays Pending — rotate collateral_note
    /// to the change-note commitment, decrement amount, update
    /// note_amount.
    PartiallyFilled {
        new_amount: Quantity,
        new_collateral_note: [u8; 32],
        new_note_amount: Quantity,
        filled_quantity: Quantity,
    },
    /// IOC residual — cancel the unfilled remainder.
    Cancelled,
    /// Expiry-sweep result — order's `expiry_slot` was within the
    /// settlement buffer.
    Expired,
}
