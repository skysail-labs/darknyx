//! Self-trade prevention.
//!
//! TODO(PR-4d): implement. The current `OrderBook` already tracks
//! per-trader order ids via the `by_trader` index, so the lookup
//! is cheap. The policy choice (cancel-newest, cancel-oldest,
//! cancel-both, reject-on-submit) is mirrored from godarkdex
//! and a few other dark pools — leaving the call until after the
//! WS layer lands so we can also surface STP rejections on the
//! right event channel.
