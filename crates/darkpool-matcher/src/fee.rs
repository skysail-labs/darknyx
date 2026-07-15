//! Per-mint fee accounting summary used during one batch tick.
//!
//! Lifetime model: the matcher resets two buckets (one base, one
//! quote) at the start of every `run_batch` call, adds per-leg
//! `buyer_fee_amt` / `seller_fee_amt` as it generates matches, and
//! emits them on `RunBatchOutput.fee_buckets`. These totals are metrics only:
//! settlement issues per-match fee notes derived from each consumed input.

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
pub struct FeeBucket {
    /// SPL token mint whose fees this bucket tracks. Raw bytes —
    /// matches `Pubkey::to_bytes()` wire format. All-zero = unused.
    pub token_mint: [u8; 32],
    /// Cumulative fee for this mint across the current batch.
    /// Reset to 0 at the start of every `run_batch` call.
    pub accumulated_fees: u64,
    /// Batch slot this bucket was last touched at.
    pub batch_slot: u64,
}

impl FeeBucket {
    /// Default-constructed empty bucket. Used as the array filler
    /// in `RunBatchOutput::empty()`.
    pub const EMPTY: FeeBucket = FeeBucket {
        token_mint: [0u8; 32],
        accumulated_fees: 0,
        batch_slot: 0,
    };

    /// Initialise a metrics bucket bound to `(mint, batch_slot)` with zero
    /// accumulated fees.
    pub fn new(token_mint: [u8; 32], batch_slot: u64) -> Self {
        Self {
            token_mint,
            accumulated_fees: 0,
            batch_slot,
        }
    }

    /// Saturating add prevents overflow from wrapping fee accounting.
    pub fn add(&mut self, delta: u64) {
        self.accumulated_fees = self.accumulated_fees.saturating_add(delta);
    }
}
