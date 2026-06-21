//! The live `tree` channel of the multiplexed `/v1/stream` socket.
//!
//! Unlike fills/orders (per-account routed — see `ws_fills_routing.rs`), the
//! `tree` channel is GLOBAL: every appended leaf is already on-chain (public),
//! so EVERY subscriber sees EVERY leaf. These tests prove that directly on
//! `ApiState`'s tree-channel plumbing (the exact methods the `/v1/stream`
//! handler subscribes + the Merkle sync publishes through).

use std::sync::Arc;

use nyx_tee::api::ApiState;
use nyx_tee::merkle::TreeAppendEvent;

fn ev(tree_id: u8, leaf_index: u64) -> TreeAppendEvent {
    TreeAppendEvent {
        channel: "tree",
        tree_id,
        leaf_index,
        commitment: "ab".repeat(32),
    }
}

#[tokio::test]
async fn tree_appends_fan_out_to_every_subscriber() {
    let state = Arc::new(ApiState::for_tests());

    // Two independent subscribers (different sessions / accounts).
    let mut rx1 = state.subscribe_tree_appends();
    let mut rx2 = state.subscribe_tree_appends();

    // The sync task publishes via the Sender clone.
    let tx = state.tree_publisher();
    assert!(tx.send(ev(0, 0)).is_ok());
    assert!(tx.send(ev(1, 0)).is_ok());

    // BOTH subscribers see BOTH leaves, in order — the channel is global.
    for rx in [&mut rx1, &mut rx2] {
        let a = rx.try_recv().expect("leaf 1 delivered");
        let b = rx.try_recv().expect("leaf 2 delivered");
        assert_eq!((a.tree_id, a.leaf_index), (0, 0));
        assert_eq!((b.tree_id, b.leaf_index), (1, 0));
    }
}

#[tokio::test]
async fn publish_with_no_subscribers_is_a_noop() {
    // The cold-boot bulk replay broadcasts before any client connects: a send
    // with zero subscribers returns Err(NoSubscribers) and must NOT panic.
    let state = Arc::new(ApiState::for_tests());
    let tx = state.tree_publisher();
    // No receiver subscribed → send is a benign error the sync path ignores.
    assert!(tx.send(ev(0, 0)).is_err());

    // Once someone subscribes, subsequent appends ARE delivered (only events
    // after the subscribe — earlier leaves come from /tree/leaves).
    let mut rx = state.subscribe_tree_appends();
    assert!(tx.send(ev(0, 1)).is_ok());
    assert_eq!(rx.try_recv().unwrap().leaf_index, 1);
}
