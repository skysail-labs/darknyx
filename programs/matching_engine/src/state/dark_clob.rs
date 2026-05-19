//! On-PER DarkCLOB. Single PDA per market, delegated once at `init_market`
//! and never undelegated in normal operation.
//!
//! **Storage model.** The spec mental-model is
//! `BTreeMap<price, VecDeque<OrderRecord>>`. Our concrete layout is a
//! fixed-capacity array of OrderRecords; `run_batch` pulls active orders
//! into two temporary arrays (bids / asks) and sorts them in-function.
//! For `DARK_CLOB_CAPACITY ≤ 64` this is trivially within a single ix's
//! compute budget, and keeps the account layout zero-copy.
//!
//! Phase 4 bump: the per-order struct grew from 136 to 176 bytes, so we
//! dropped capacity from 64 to 48 to stay under the 10240-byte Anchor
//! init-CPI realloc limit.
//! Phase 5 bump: OrderRecord grew to 224 bytes (collateral_note rename +
//! total_quantity + filled_quantity + user_commitment + note_amount) so
//! capacity dropped from 48 to 45. Account size ≈ 10144 bytes.

use anchor_lang::prelude::*;

use crate::state::order_record::OrderRecord;

/// Order slots per market. Phase-5: 45 × 224B + 56B header + 8B disc =
/// 10144 bytes, under the 10240-byte CPI init cap.
pub const DARK_CLOB_CAPACITY: usize = 45;

#[account(zero_copy)]
#[repr(C)]
pub struct DarkCLOB {
    pub market: Pubkey,
    /// Monotonic order counter.
    pub next_seq: u64,
    /// Number of slots with `status != EMPTY`.
    pub order_count: u64,
    /// Fixed-capacity order storage. Real price-indexed heap deferred to
    /// Phase 5; Phase 4 sorts at batch time.
    pub orders: [OrderRecord; DARK_CLOB_CAPACITY],
    pub bump: u8,
    pub _padding: [u8; 7],
}

impl DarkCLOB {
    pub const SEED: &'static [u8] = b"dark_clob";

    pub fn find_empty_slot(&self) -> Option<usize> {
        self.orders.iter().position(|o| o.status == 0)
    }

    pub fn find_by_order_id(&self, trading_key: &Pubkey, order_id: &[u8; 16]) -> Option<usize> {
        self.orders
            .iter()
            .position(|o| o.status != 0 && o.trading_key == *trading_key && o.order_id == *order_id)
    }
}
