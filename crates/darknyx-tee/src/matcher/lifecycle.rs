//! TEE-local order lifecycle events.
//!
//! `darkpool_matcher::OrderUpdate` describes the quantity mutation that follows
//! a successful match. The TEE also needs two settlement states that are not
//! matcher-algorithm outputs: `pending_settlement` when both orders are
//! reserved, and terminal `settlement_failed` when Tx D definitively rejects.
//! Keeping this wrapper local avoids changing the byte-critical matcher crate.

use darkpool_matcher::book::{OrderUpdate, OrderUpdateKind};

#[derive(Clone, Debug)]
pub enum OrderLifecycleKind {
    PendingSettlement {
        lock_expiry_slot: u64,
    },
    Settled(OrderUpdateKind),
    SettlementFailed {
        reason: String,
        lock_expiry_slot: u64,
    },
}

#[derive(Clone, Debug)]
pub struct OrderLifecycleEvent {
    pub trading_key: [u8; 32],
    pub order_id: [u8; 16],
    /// Base58 `MarketConfig` PDA. This is the canonical market identity used
    /// for both metrics correlation and future multi-market routing.
    pub market_id: String,
    /// Match identifier when the lifecycle transition belongs to settlement.
    /// Immediate expiry/FOK cancellation events have no match.
    pub match_id: Option<u64>,
    pub kind: OrderLifecycleKind,
}

impl OrderLifecycleEvent {
    pub fn settled(update: OrderUpdate, market_id: String, match_id: Option<u64>) -> Self {
        Self {
            trading_key: update.trading_key,
            order_id: update.order_id,
            market_id,
            match_id,
            kind: OrderLifecycleKind::Settled(update.kind),
        }
    }
}
