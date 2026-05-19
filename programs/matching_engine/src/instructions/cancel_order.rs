//! `cancel_order` — user resets their own pending PendingOrder slot.
//!
//! Privacy: like `submit_order`, this runs INSIDE the ER. The L1 sees no
//! cancellation event because the slot is delegated and only the slot's
//! status flag changes — there is no L1 transaction.
//!
//! The slot must be Pending. After cancel, the slot becomes Empty and
//! the user can immediately submit a new order through the same slot
//! without paying re-allocation rent.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;
use crate::state::{PendingOrder, PENDING_STATUS_CANCELLED, PENDING_STATUS_PENDING};

#[derive(Accounts)]
#[instruction(market: Pubkey, slot_idx: u8)]
pub struct CancelOrder<'info> {
    #[account(mut)]
    pub trading_key: Signer<'info>,

    #[account(
        mut,
        seeds = [
            PendingOrder::SEED,
            market.as_ref(),
            trading_key.key().as_ref(),
            core::slice::from_ref(&slot_idx),
        ],
        bump = pending_order.load()?.bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,
}

pub fn cancel_order_handler(ctx: Context<CancelOrder>, market: Pubkey, slot_idx: u8) -> Result<()> {
    let order_id;
    {
        let slot = ctx.accounts.pending_order.load()?;
        require!(
            slot.trading_key == ctx.accounts.trading_key.key(),
            MatchingError::UnauthorizedTradingKey
        );
        require!(slot.market == market, MatchingError::MarketMismatch);
        require!(slot.slot_idx == slot_idx, MatchingError::InvalidPendingSlot);
        require!(
            slot.status == PENDING_STATUS_PENDING,
            MatchingError::OrderNotFound
        );
        order_id = slot.order_id;
    }

    {
        let mut slot = ctx.accounts.pending_order.load_mut()?;
        slot.status = PENDING_STATUS_CANCELLED;
        // Wipe the order intent fields so a stale snapshot can't leak
        // anything. Identity (trading_key / market / slot_idx / bump) is
        // preserved so the next submit_order can reuse the slot.
        slot.amount = 0;
        slot.price_limit = 0;
        slot.note_amount = 0;
        slot.min_fill_qty = 0;
        slot.collateral_note = [0u8; 32];
        slot.user_commitment = [0u8; 32];
        slot.order_id = [0u8; 16];
    }

    emit!(OrderCancelled {
        market,
        trading_key: ctx.accounts.trading_key.key(),
        slot_idx,
        order_id,
    });
    Ok(())
}

#[event]
pub struct OrderCancelled {
    pub market: Pubkey,
    pub trading_key: Pubkey,
    pub slot_idx: u8,
    pub order_id: [u8; 16],
}
