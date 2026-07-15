//! Market + oracle config inputs to `run_batch`. Frozen for the
//! duration of one batch — the matcher must be deterministic given
//! these inputs.
//!
//! Field-for-field mirrors the on-chain types that supply them:
//!   * `MatchConfig` ← mint-pair `MarketConfig` (mints, price scale,
//!     tick, minimum size, circuit breaker) PLUS `vault_config.fee_rate_bps` +
//!     `vault_config.protocol_owner_commitment`.
//!   * `OracleSnapshot` ← output of `read_oracle_price()`. Pyth
//!     EMA or our mock — at this layer it's just a u64.

use borsh::{BorshDeserialize, BorshSerialize};

/// Orders whose `expiry_slot` is within this many slots of the
/// matcher's `current_slot` are drained before matching, not
/// included in any match. Gives the follow-up settle pipeline
/// enough runway to confirm before the implicit settle deadline.
pub const SETTLEMENT_BUFFER_SLOTS: u64 = 20;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct MatchConfig {
    // ─── Market identity ───────────────────────────────────────
    /// Base-asset mint (32 bytes, matches Pubkey wire format).
    /// The matcher only uses this to feed
    /// `commitment_from_fields` when constructing change notes,
    /// so the byte layout MUST equal `Pubkey::to_bytes()`.
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    /// Fixed-point denominator for scaled clearing-price arithmetic. The v3
    /// circuit consumes this directly; the current matcher carries it as
    /// governed market identity without changing its comparison arithmetic.
    pub price_scale: u64,

    // ─── Per-market matching params ────────────────────────────
    /// Smallest price increment, in base units. 0 = unchecked at
    /// matcher level (the on-chain ix may still enforce it at
    /// submit time).
    pub tick_size: u64,
    /// Minimum order size in base units. Orders below this are
    /// dropped at intake (the matcher skips them, mirroring the
    /// on-chain "below min_order_size → skip" branch).
    pub min_order_size: u64,
    /// Max |clearing_price − pyth_twap| / pyth_twap in basis
    /// points. Going outside this band trips the circuit breaker
    /// and aborts matching for the batch.
    pub circuit_breaker_bps: u64,

    // ─── Cadence (D5) ──────────────────────────────────────────
    /// Tick cadence in milliseconds. The matcher itself doesn't
    /// sleep; the TEE driver / on-chain ix-caller enforces this.
    /// Default `2000` per `docs/tee-architecture.md` §5.4. Per-
    /// market tunable.
    pub batch_ms: u32,

    // ─── Fee parameters (from vault_config) ────────────────────
    /// Protocol fee in basis points of notional, applied per leg.
    pub fee_rate_bps: u16,
    /// Protocol-owned shielded identity. Every per-match fee note is bound to
    /// this commitment so the protocol treasury can later VALID_SPEND it.
    pub protocol_owner_commitment: [u8; 32],
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OracleSnapshot {
    /// Pyth EMA / TWAP in quote-units-per-base, fixed-point using the market's
    /// `price_scale`. **Must be > 0** — the matcher rejects zero/
    /// negative TWAPs as stale and refuses to compute a clearing
    /// price.
    pub twap: u64,
    /// Pyth confidence interval, same units as `twap`. Currently
    /// informational; reserved for later VALID_PRICE binding work.
    pub confidence: u64,
    /// Negative power of 10. Informational at matcher layer —
    /// the on-chain ix and the matcher use the same fixed-point
    /// scale that the rest of the system has agreed on.
    pub exponent: i32,
    /// Publish-time slot from Pyth. The matcher rejects oracle
    /// snapshots older than its `current_slot` by more than a
    /// configurable freshness budget (PR-2 wiring).
    pub publish_slot: u64,
}
