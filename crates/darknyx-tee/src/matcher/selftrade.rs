//! Self-trade prevention.
//!
//! Implemented in the matching algorithm itself, not here: a single behavior —
//! two orders from the same OWNER are never matched against each other (a wash
//! trade / no-op settle). The owner identity is the order's note-BOUND
//! `owner_commitment` (`Poseidon2(spending_key, r_owner)`): intake pins it to the
//! collateral note via `verify_commitment`, so — unlike the client-asserted
//! `user_commitment` — a *settling* wash cannot lie about it (the only way to
//! present two different owners is two genuinely different note owners). It is
//! reused across all of a user's notes, so the skip catches the case a
//! `trading_key`-only check missed: one user trading under two trading keys (the
//! trading key is freely re-derived by `offset` and is deliberately NOT part of
//! the owner identity). The `trading_key` equality is kept as a cheap
//! belt-and-suspenders. See `darkpool_matcher::algorithm::generate_matches`,
//! where the self-pair is skipped (advancing the smaller side) so each order can
//! still match a non-self counterparty and a deferred order is reconsidered next
//! tick.
//!
//! Still best-effort, not a hard guarantee: a determined user can register a
//! SECOND wallet (a distinct `owner_commitment`, or deposit notes under a
//! different `r_owner`) and wash across the two — that Sybil case is
//! fundamentally out of scope for any matcher rule in a pseudonymous pool.
//!
//! Why a single behavior (not cancel-taker/maker/both like a continuous CLOB):
//! our tick is a uniform-clearing-price batch auction, so there is no
//! maker/taker ordering *within* a tick for those modes to act on. The skip
//! never cancels the resting order, so there's nothing to surface on the
//! `orders` channel beyond the normal lifecycle events.
