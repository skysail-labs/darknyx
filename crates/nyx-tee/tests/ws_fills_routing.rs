//! Per-account fills routing — the leak guard.
//!
//! The old `/ws/fills` was a single global broadcast: every authenticated
//! subscriber saw every account's fill memos (a privacy leak), so it shipped
//! fail-closed behind `debug_endpoints`. The routing now keys memos by
//! `order_id → account` (recorded at intake) and fans them to per-account
//! channels. These tests prove the isolation directly on `ApiState`'s routing
//! methods (the exact code the WS handler subscribes through).

use std::sync::Arc;

use nyx_tee::api::ApiState;
use nyx_tee::matcher::FillMemo;

fn memo(order_id: &str) -> FillMemo {
    FillMemo {
        order_id: order_id.to_string(),
        anchor_index: 0,
        change_amount: 100,
        change_note_commitment: "ab".repeat(32),
        mint: "cd".repeat(32),
        inner_hash: "ef".repeat(32),
    }
}

#[tokio::test]
async fn fills_route_to_the_owning_account_only() {
    let state = Arc::new(ApiState::for_tests());
    state
        .record_order_owner("order_a".into(), "acct_a".into())
        .await;
    state
        .record_order_owner("order_b".into(), "acct_b".into())
        .await;

    let mut rx_a = state.subscribe_account_fills("acct_a").await;
    let mut rx_b = state.subscribe_account_fills("acct_b").await;

    // A fill for account A's order...
    assert!(state.route_fill(&memo("order_a")).await);
    assert_eq!(
        rx_a.try_recv().expect("A receives its own memo").order_id,
        "order_a"
    );
    // ...must NOT reach account B. THIS is the leak guard.
    assert!(
        rx_b.try_recv().is_err(),
        "account B saw account A's memo — leak!"
    );

    // And symmetrically for B.
    assert!(state.route_fill(&memo("order_b")).await);
    assert_eq!(
        rx_b.try_recv().expect("B receives its own memo").order_id,
        "order_b"
    );
    assert!(
        rx_a.try_recv().is_err(),
        "account A saw account B's memo — leak!"
    );
}

#[tokio::test]
async fn unknown_order_is_dropped_not_broadcast() {
    let state = Arc::new(ApiState::for_tests());
    state
        .record_order_owner("order_a".into(), "acct_a".into())
        .await;
    let mut rx_a = state.subscribe_account_fills("acct_a").await;

    // A memo for an order with no recorded owner is not delivered anywhere.
    assert!(!state.route_fill(&memo("order_unknown")).await);
    assert!(rx_a.try_recv().is_err());
}

#[tokio::test]
async fn forgetting_an_order_stops_its_routing() {
    let state = Arc::new(ApiState::for_tests());
    state
        .record_order_owner("order_a".into(), "acct_a".into())
        .await;
    let mut rx_a = state.subscribe_account_fills("acct_a").await;

    state.forget_order("order_a").await;
    assert!(!state.route_fill(&memo("order_a")).await);
    assert!(rx_a.try_recv().is_err());
}

#[tokio::test]
async fn no_subscriber_means_no_delivery_but_no_error() {
    let state = Arc::new(ApiState::for_tests());
    state
        .record_order_owner("order_a".into(), "acct_a".into())
        .await;
    // Owner known, but no /ws/fills client attached → not delivered (the client
    // will backfill from the indexer), and routing does not panic.
    assert!(!state.route_fill(&memo("order_a")).await);
}
