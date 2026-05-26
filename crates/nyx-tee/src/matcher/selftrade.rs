//! Self-trade prevention. The trading-key signature on each order
//! gives us a stable identity to compare. Phase 2 will reject
//! matches whose buy + sell were submitted under the same
//! trading_pubkey.
