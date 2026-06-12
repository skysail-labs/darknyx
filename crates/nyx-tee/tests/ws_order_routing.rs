//! Per-account order-lifecycle routing — the same leak guard `/ws/fills` has,
//! for `/ws/orders`. Exercises `ApiState`'s routing methods directly (the exact
//! code the WS handler + the order router subscribe through).

use std::sync::Arc;

use nyx_tee::api::state::OrderUpdateMsg;
use nyx_tee::api::ApiState;

fn cancelled(order_id: &str) -> OrderUpdateMsg {
    OrderUpdateMsg {
        order_id: order_id.to_string(),
        kind: "cancelled",
        filled_quantity: None,
        new_amount: None,
        new_note_amount: None,
    }
}

#[tokio::test]
async fn order_updates_route_to_the_owning_account_only() {
    let state = Arc::new(ApiState::for_tests());
    state
        .record_order_owner("oid_a".into(), "acct_a".into())
        .await;
    state
        .record_order_owner("oid_b".into(), "acct_b".into())
        .await;

    let mut rx_a = state.subscribe_account_order_updates("acct_a").await;
    let mut rx_b = state.subscribe_account_order_updates("acct_b").await;

    // An update for account A's order...
    assert!(state.route_order_update("oid_a", &cancelled("oid_a")).await);
    assert_eq!(
        rx_a.try_recv().expect("A receives its own update").order_id,
        "oid_a"
    );
    // ...must NOT reach account B.
    assert!(
        rx_b.try_recv().is_err(),
        "account B saw account A's update — leak!"
    );

    // Symmetric for B.
    assert!(state.route_order_update("oid_b", &cancelled("oid_b")).await);
    assert_eq!(
        rx_b.try_recv().expect("B receives its own").order_id,
        "oid_b"
    );
    assert!(rx_a.try_recv().is_err());
}

#[tokio::test]
async fn unknown_order_is_dropped_not_broadcast() {
    let state = Arc::new(ApiState::for_tests());
    let mut rx = state.subscribe_account_order_updates("acct_a").await;
    // An update for an order with no recorded owner is delivered nowhere.
    assert!(
        !state
            .route_order_update("unknown", &cancelled("unknown"))
            .await
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn disconnected_order_channels_are_gc_d_on_next_subscribe() {
    let state = Arc::new(ApiState::for_tests());
    {
        let _rx = state.subscribe_account_order_updates("acct_a").await;
    }
    assert!(state.order_routes.read().await.contains_key("acct_a"));

    let _rx_live = state.subscribe_account_order_updates("acct_live").await;
    let _rx_b = state.subscribe_account_order_updates("acct_b").await;

    let routes = state.order_routes.read().await;
    assert!(!routes.contains_key("acct_a"), "disconnected acct_a GC'd");
    assert!(routes.contains_key("acct_live"));
    assert!(routes.contains_key("acct_b"));
}
