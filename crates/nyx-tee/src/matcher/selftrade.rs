//! Self-trade prevention.
//!
//! Implemented (baseline) in the matching algorithm itself, not here: a single
//! behavior — two orders sharing a `trading_key` are never matched against each
//! other (a wash trade / no-op settle). See
//! `darkpool_matcher::algorithm::generate_matches`, where the self-pair is
//! skipped (advancing the smaller side) so each order can still match a non-self
//! counterparty and a deferred order is reconsidered next tick.
//!
//! Why a single behavior (not cancel-taker/maker/both like a continuous CLOB):
//! our tick is a uniform-clearing-price batch auction, so there is no
//! maker/taker ordering *within* a tick for those modes to act on. The skip
//! never cancels the resting order, so there's nothing to surface on the
//! `/ws/orders` channel beyond the normal lifecycle events.
