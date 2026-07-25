//! Order-lifecycle router: fan the matcher's global `OrderUpdate` broadcast out
//! to per-account `orders` subscriptions on `/v1/stream`.
//!
//! Same bridge as [`super::fills_router`]: the matcher is account-agnostic
//! (keys updates by `order_id`); this task maps each to its owning account via
//! the intake-time `order_id → account` map and forwards. It also bounds that
//! map — after routing a TERMINAL update (fully-filled / cancelled / expired)
//! the order will never produce another order event, so we archive its owner in
//! the bounded terminal routing cache. That cache lets the independent fills
//! router deliver a final change memo even if this task wins the race.

use std::sync::Arc;

use darkpool_matcher::book::OrderUpdateKind;
use tokio::sync::broadcast::error::RecvError;

use super::state::{ApiState, OrderUpdateMsg};
use crate::matcher::{OrderLifecycleEvent, OrderLifecycleKind};

/// Convert a matcher `OrderUpdate` into its wire form. Returns the hex order id
/// (the `order_owner` routing key) alongside the message, and whether the
/// update is TERMINAL (the order leaves the book).
fn to_msg(u: &OrderLifecycleEvent) -> (String, OrderUpdateMsg, bool) {
    let order_id = hex::encode(u.order_id);
    let market_id = u.market_id.clone();
    let match_id = u.match_id.map(|value| value.to_string());
    let server_time_ms = crate::settle::metrics::unix_ms();
    let (msg, terminal) = match &u.kind {
        OrderLifecycleKind::PendingSettlement { lock_expiry_slot } => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id: market_id.clone(),
                match_id: match_id.clone(),
                server_time_ms,
                kind: "pending_settlement",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
                reason: None,
                lock_expiry_slot: Some(*lock_expiry_slot),
            },
            false,
        ),
        OrderLifecycleKind::SettlementFailed {
            reason,
            lock_expiry_slot,
        } => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id: market_id.clone(),
                match_id: match_id.clone(),
                server_time_ms,
                kind: "settlement_failed",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
                reason: Some(reason.clone()),
                lock_expiry_slot: Some(*lock_expiry_slot),
            },
            true,
        ),
        OrderLifecycleKind::Settled(OrderUpdateKind::FullyFilled { filled_quantity }) => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id: market_id.clone(),
                match_id: match_id.clone(),
                server_time_ms,
                kind: "fully_filled",
                filled_quantity: Some(*filled_quantity),
                new_amount: None,
                new_note_amount: None,
                reason: None,
                lock_expiry_slot: None,
            },
            true,
        ),
        OrderLifecycleKind::Settled(OrderUpdateKind::PartiallyFilled {
            new_amount,
            new_note_amount,
            filled_quantity,
            ..
        }) => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id: market_id.clone(),
                match_id: match_id.clone(),
                server_time_ms,
                kind: "partially_filled",
                filled_quantity: Some(*filled_quantity),
                new_amount: Some(*new_amount),
                new_note_amount: Some(*new_note_amount),
                reason: None,
                lock_expiry_slot: None,
            },
            false,
        ),
        OrderLifecycleKind::Settled(OrderUpdateKind::Cancelled) => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id: market_id.clone(),
                match_id: match_id.clone(),
                server_time_ms,
                kind: "cancelled",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
                reason: None,
                lock_expiry_slot: None,
            },
            true,
        ),
        OrderLifecycleKind::Settled(OrderUpdateKind::Expired) => (
            OrderUpdateMsg {
                order_id: order_id.clone(),
                market_id,
                match_id,
                server_time_ms,
                kind: "expired",
                filled_quantity: None,
                new_amount: None,
                new_note_amount: None,
                reason: None,
                lock_expiry_slot: None,
            },
            true,
        ),
    };
    (order_id, msg, terminal)
}

/// Spawn the order-update router. No-op in matcher-less test state.
pub fn spawn_order_router(state: Arc<ApiState>) {
    let Some(matcher) = state.matcher.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut rx = matcher.read().await.subscribe_order_updates();
        loop {
            match rx.recv().await {
                Ok(update) => {
                    let (order_id, msg, terminal) = to_msg(&update);
                    state.route_order_update(&order_id, &msg).await;
                    // Archive before removing the live ownership entry so the
                    // independent fills router cannot observe a routing gap.
                    if terminal {
                        state.archive_order_owner(&order_id).await;
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "order router lagged on matcher broadcast");
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(kind: OrderUpdateKind) -> OrderLifecycleEvent {
        OrderLifecycleEvent {
            trading_key: [9u8; 32],
            order_id: [0xAB; 16],
            market_id: "market-pda".to_string(),
            match_id: Some(17),
            kind: OrderLifecycleKind::Settled(kind),
        }
    }

    #[test]
    fn maps_each_kind_and_terminal_flag() {
        let (oid, m, term) = to_msg(&upd(OrderUpdateKind::FullyFilled { filled_quantity: 7 }));
        assert_eq!(oid, "ab".repeat(16));
        assert_eq!(m.kind, "fully_filled");
        assert_eq!(m.filled_quantity, Some(7));
        assert!(term);

        let (_, m, term) = to_msg(&upd(OrderUpdateKind::PartiallyFilled {
            new_amount: 5,
            new_collateral_note: [0; 32],
            new_note_amount: 11,
            filled_quantity: 3,
        }));
        assert_eq!(m.kind, "partially_filled");
        assert_eq!(m.filled_quantity, Some(3));
        assert_eq!(m.new_amount, Some(5));
        assert_eq!(m.new_note_amount, Some(11));
        assert!(!term, "a partial fill keeps the order resting");

        for (k, name) in [
            (OrderUpdateKind::Cancelled, "cancelled"),
            (OrderUpdateKind::Expired, "expired"),
        ] {
            let (_, m, term) = to_msg(&upd(k));
            assert_eq!(m.kind, name);
            assert!(term);
            assert!(m.filled_quantity.is_none());
        }

        let pending = OrderLifecycleEvent {
            trading_key: [9; 32],
            order_id: [0xAB; 16],
            market_id: "market-pda".to_string(),
            match_id: Some(17),
            kind: OrderLifecycleKind::PendingSettlement {
                lock_expiry_slot: 77,
            },
        };
        let (_, m, terminal) = to_msg(&pending);
        assert_eq!(m.kind, "pending_settlement");
        assert_eq!(m.lock_expiry_slot, Some(77));
        assert!(!terminal);

        let failed = OrderLifecycleEvent {
            trading_key: [9; 32],
            order_id: [0xAB; 16],
            market_id: "market-pda".to_string(),
            match_id: Some(17),
            kind: OrderLifecycleKind::SettlementFailed {
                reason: "reverted".to_string(),
                lock_expiry_slot: 88,
            },
        };
        let (_, m, terminal) = to_msg(&failed);
        assert_eq!(m.kind, "settlement_failed");
        assert_eq!(m.reason.as_deref(), Some("reverted"));
        assert_eq!(m.lock_expiry_slot, Some(88));
        assert!(terminal);
    }
}
