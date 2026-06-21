//! Per-mint fee accumulator used during one batch tick. Field-for-
//! field byte-equivalent to
//! `programs/matching_engine/src/state/fee_accumulator.rs::FeeAccumulator`
//! minus the Anchor zero-copy attributes, so the PR-3 on-chain
//! adapter is `impl From<FeeBucket> for FeeAccumulator` and back.
//!
//! Lifetime model: the matcher resets two buckets (one base, one
//! quote) at the start of every `run_batch` call, adds per-leg
//! `buyer_fee_amt` / `seller_fee_amt` as it generates matches, and
//! emits them on `RunBatchOutput.fee_buckets`. The caller decides
//! when to flush them into protocol-owned change notes (on-chain
//! ix does this inline; in-TEE matcher emits a flush event so the
//! settle scheduler can include the note in the next batch).

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
pub struct FeeBucket {
    /// SPL token mint whose fees this bucket tracks. Raw bytes —
    /// matches `Pubkey::to_bytes()` wire format. All-zero = unused.
    pub token_mint: [u8; 32],
    /// Cumulative fee for this mint across the current batch.
    /// Reset to 0 at the start of every `run_batch` call.
    pub accumulated_fees: u64,
    /// Batch slot this bucket was last touched at. The on-chain
    /// `FeeAccumulator` uses this to detect stale (older than
    /// `BatchResults.last_batch_slot`) values; we propagate it
    /// here so the on-chain adapter is field-for-field.
    pub batch_slot: u64,
    /// Poseidon commitment of the flushed fee note for this batch.
    /// Populated by the matcher iff `accumulated_fees > 0` AND
    /// `MatchConfig.protocol_owner_commitment != [0u8;32]` AND the
    /// circuit breaker did NOT trip. All-zero means "nothing to
    /// flush" (matches the on-chain `FeeAccumulator.flushed_commitment`
    /// semantics).
    pub flushed_commitment: [u8; 32],
}

impl FeeBucket {
    /// Default-constructed empty bucket. Used as the array filler
    /// in `RunBatchOutput::empty()`.
    pub const EMPTY: FeeBucket = FeeBucket {
        token_mint: [0u8; 32],
        accumulated_fees: 0,
        batch_slot: 0,
        flushed_commitment: [0u8; 32],
    };

    /// Initialise a bucket bound to `(mint, batch_slot)` with zero
    /// accumulated fees and no flush commitment yet.
    pub fn new(token_mint: [u8; 32], batch_slot: u64) -> Self {
        Self {
            token_mint,
            accumulated_fees: 0,
            batch_slot,
            flushed_commitment: [0u8; 32],
        }
    }

    /// Saturating add — matches the on-chain
    /// `accumulated_fees.saturating_add(seller_fee_amt)` semantics
    /// so overflow can't silently corrupt the accumulator (a
    /// u64-overflowing batch would already be a protocol bug
    /// elsewhere, but the saturating behaviour is the audited
    /// shape and we mirror it).
    pub fn add(&mut self, delta: u64) {
        self.accumulated_fees = self.accumulated_fees.saturating_add(delta);
    }
}
