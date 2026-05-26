//! Output types of `run_batch`. Field-for-field byte-equivalent to
//! `programs/matching_engine/src/state/match_result.rs::MatchResult`,
//! so the PR-3 on-chain adapter is `impl From<MatchPair> for MatchResult`
//! and nothing more.
//!
//! Cross-language byte equality is pinned by:
//!   * `tests/parity.rs` (this crate, in PR 2) — matcher ↔ on-chain
//!     Rust.
//!   * `packages/sdk/tests/settle-builder-batched.test.ts` — TS ↔
//!     on-chain Rust.
//!   * `programs/vault/src/lib.rs::canonical_payload_hash_fixed_vector`
//!     — pins the wire bytes byte-for-byte.
//!
//! Change any field order / type / alignment here and at least one
//! of those three tests fails. **Cardinal rule from CLAUDE.md §6.**

use borsh::{BorshDeserialize, BorshSerialize};

/// On-chain mapping: `MATCH_RESULT_STATUS_EMPTY = 0`, `_FILLED = 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MatchStatus {
    Empty = 0,
    Filled = 1,
}

/// Sentinel for "no re-lock requested". On-chain: an order_id of
/// `[0u8;16]` — `submit_order` rejects zero-id submissions at
/// intake, so this cannot collide with a legitimate active order.
pub const RELOCK_ORDER_ID_NONE: [u8; 16] = [0u8; 16];

// ─────── MatchPair — the matcher-side equivalent of MatchResult ─────────────

/// One bid × ask crossing. Field order + types mirror the on-chain
/// `MatchResult` zero-copy struct exactly; the on-chain adapter
/// just constructs the Anchor type from a `MatchPair` field-by-field.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct MatchPair {
    // ─── Notes consumed ────────────────────────────────────────────
    /// Note commitment consumed by the buyer (locked quote → nullified).
    pub note_buyer: [u8; 32],
    /// Note commitment consumed by the seller (locked base → nullified).
    pub note_seller: [u8; 32],

    // ─── Change notes produced (zero-bytes when exact fill) ────────
    /// Change-note commitment returned to the buyer (quote-asset change).
    pub note_e_commitment: [u8; 32],
    /// Change-note commitment returned to the seller (base-asset change).
    pub note_f_commitment: [u8; 32],

    // ─── Counterparty identities ───────────────────────────────────
    /// Trading key of the BID-side order. Raw 32 bytes — matches
    /// the on-chain `Pubkey` Borsh layout exactly.
    pub owner_buyer: [u8; 32],
    /// Trading key of the ASK-side order.
    pub owner_seller: [u8; 32],
    /// Buyer's user_commitment (`Poseidon2(spending_key, r_owner)`).
    /// Required by settlement because `note_e_commitment` binds to
    /// this value via the change-note Poseidon construction.
    pub user_commitment_buyer: [u8; 32],
    /// Seller's user_commitment (symmetric to above).
    pub user_commitment_seller: [u8; 32],

    // ─── Input note values (for conservation) ──────────────────────
    /// Full value of the buyer's input note, quote units.
    pub buyer_note_value: u64,
    /// Full value of the seller's input note, base units.
    pub seller_note_value: u64,

    // ─── Trade legs ────────────────────────────────────────────────
    /// Base-asset qty transferred from seller → buyer.
    pub base_amt: u64,
    /// Quote-asset qty transferred from buyer → seller.
    pub quote_amt: u64,
    /// Quote-asset change returned to the buyer (0 if exact fill).
    /// Conservation: `buyer_note_value == quote_amt + buyer_change_amt
    /// + buyer_fee_amt`.
    pub buyer_change_amt: u64,
    /// Base-asset change returned to the seller (0 if exact fill).
    pub seller_change_amt: u64,

    // ─── Protocol fees ─────────────────────────────────────────────
    /// Fee deducted from the buyer's input note (quote units).
    pub buyer_fee_amt: u64,
    /// Fee deducted from the seller's input note (base units).
    pub seller_fee_amt: u64,

    // ─── Re-lock instructions for partial fills ────────────────────
    /// `RELOCK_ORDER_ID_NONE` = no re-lock; otherwise the order_id
    /// whose change note (`note_e`) should be atomically re-locked
    /// against this id at settle time so the residual of the
    /// partially-filled order can keep trading in the next batch.
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    /// Symmetric to `buyer_relock_order_id` for the seller's
    /// change note (`note_f`).
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,

    // ─── Batch metadata ────────────────────────────────────────────
    /// Uniform clearing price for the batch this match belongs to.
    pub price: u64,
    /// Pyth TWAP snapshot at match time — for the VALID_PRICE binding
    /// inside VALID_MATCH_BATCH.
    pub pyth_at_match: u64,
    /// Solana slot at which this match was generated.
    pub batch_slot: u64,
    /// Monotonic per-market match id. Seed input for nullifier
    /// derivation + change-note nonce/blinding.
    pub match_id: u64,

    pub status: MatchStatus,
}

// ─────── RunBatchOutput — what one matcher tick returns ─────────────────────

/// Carries everything one batch tick produces: the matches, the
/// post-match book mutations the caller must apply, and the
/// per-batch metadata (clearing price, circuit-breaker state,
/// inclusion root). Borsh-serializable so persistence + over-the-
/// wire transport are trivial.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RunBatchOutput {
    /// Matches in the order they were generated by the matcher.
    /// The on-chain ix writes these into `BatchResults.results[]`
    /// at consecutive `write_cursor` slots.
    pub matches: Vec<MatchPair>,

    /// Per-order updates the caller must apply to the orders that
    /// participated in this batch. Carries the `(trading_key, order_id)`
    /// so the caller can resolve back to its source row (PDA or
    /// in-memory book entry) without depending on a positional
    /// index.
    pub order_updates: Vec<crate::book::OrderUpdate>,

    /// Uniform clearing price across all matches in this batch.
    /// 0 if the circuit breaker tripped or no crossing existed.
    pub clearing_price: u64,

    /// 1 if `|clearing_price − pyth_twap|` exceeded
    /// `circuit_breaker_bps` of `pyth_twap`. Mirrors the on-chain
    /// u8 storage so the caller can write through to BatchResults
    /// without translating.
    pub circuit_breaker_tripped: u8,

    /// Merkle (SHA-256, NOT Poseidon — this is an audit log root,
    /// not a ZK input) root over the `order_inclusion_commitment`s
    /// of every order that participated in matching this batch.
    /// Distinct from the v3.5 Poseidon batch root attested by
    /// VALID_MATCH_BATCH; this one is for off-chain auditability.
    pub inclusion_root: [u8; 32],

    /// Per-mint fee totals accumulated this batch. The on-chain ix
    /// translates these into `FeeAccumulator` PDA writes; the
    /// in-TEE matcher emits them on the `account` WS channel and
    /// also feeds them into the change-note flush.
    pub fee_buckets: [crate::fee::FeeBucket; 2],

    /// Slot the matcher was invoked at — copied onto every emitted
    /// MatchPair as `batch_slot`.
    pub batch_slot: u64,
}

impl RunBatchOutput {
    /// Empty batch sentinel — no real matches this tick. Used when
    /// the book has no crossing OR when the circuit breaker tripped.
    pub fn empty(batch_slot: u64, clearing_price: u64, cb_tripped: u8) -> Self {
        Self {
            matches: Vec::new(),
            order_updates: Vec::new(),
            clearing_price,
            circuit_breaker_tripped: cb_tripped,
            inclusion_root: [0u8; 32],
            fee_buckets: [crate::fee::FeeBucket::EMPTY; 2],
            batch_slot,
        }
    }

    /// True iff the matcher produced at least one real match
    /// (excluding cancellations and expiries).
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }
}
