//! Order-book primitives. Pure data; no async, no I/O, no Anchor.
//!
//! Wire format: Borsh. `OrderSide` / `OrderType` / `OrderStatus` are
//! `#[repr(u8)]` so their discriminants remain explicit and stable.

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
    /// `Poseidon2(spending_key, r_owner)` — used to derive change
    /// notes back to the same owner.
    pub user_commitment: [u8; 32],
    /// The owner identity BOUND to this order's collateral note: intake
    /// re-derives `collateral_note` from `(mint, amount, owner_commitment,
    /// inner_hash)` and rejects a mismatch (`verify_commitment`), so unlike the
    /// client-asserted `user_commitment` this cannot be spoofed for a note the
    /// caller doesn't own. Reused across all of a user's notes, so it's the
    /// identity the self-trade check keys on (see `algorithm::generate_matches`).
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
