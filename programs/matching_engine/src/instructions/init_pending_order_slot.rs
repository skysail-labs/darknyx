//! `init_pending_order_slot` — L1 setup, one PDA per (user, market,
//! slot_idx). Creates the slot in `Empty` state. Idempotent: if the PDA
//! already exists, the ix returns `Ok` without re-initialising.
//!
//! The user calls this once per slot they want to reserve, then calls
//! `delegate_pending_order` for each slot to hand it to the ER. After
//! delegation the slot is only mutated inside the rollup via
//! `submit_order` / `cancel_order` / `run_batch`.

use anchor_lang::prelude::*;
use core::mem::size_of;

use crate::errors::MatchingError;
use crate::state::{PendingOrder, MAX_PENDING_SLOTS_PER_USER, PENDING_STATUS_EMPTY};

#[derive(Accounts)]
#[instruction(market: Pubkey, slot_idx: u8)]
pub struct InitPendingOrderSlot<'info> {
    /// Owner trading key — fee-payer + the only key allowed to ever
    /// write this slot's order intent.
    #[account(mut)]
    pub trading_key: Signer<'info>,

    /// The PendingOrder PDA. Created here, then delegated.
    #[account(
        init_if_needed,
        payer = trading_key,
        space = 8 + size_of::<PendingOrder>(),
        seeds = [
            PendingOrder::SEED,
            market.as_ref(),
            trading_key.key().as_ref(),
            core::slice::from_ref(&slot_idx),
        ],
        bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,

    pub system_program: Program<'info, System>,
}

pub fn init_pending_order_slot_handler(
    ctx: Context<InitPendingOrderSlot>,
    market: Pubkey,
    slot_idx: u8,
) -> Result<()> {
    require!(
        slot_idx < MAX_PENDING_SLOTS_PER_USER,
        MatchingError::InvalidPendingSlot
    );

    // `init_if_needed` allocates fresh; if the PDA already exists Anchor
    // skips alloc but we still re-write the immutable header to prevent
    // half-initialised state confusing the matching engine. We use
    // `load_init` only for the freshly-allocated case — for existing
    // PDAs the data is already valid and we leave it alone.
    let mut data_was_zero = true;
    {
        let raw = ctx.accounts.pending_order.to_account_info();
        let data = raw.try_borrow_data()?;
        // Anchor reserves the first 8 bytes for the discriminator; if
        // those are non-zero the account has been initialised already.
        if data.len() >= 8 && data[..8] != [0u8; 8] {
            data_was_zero = false;
        }
    }

    if data_was_zero {
        let mut slot = ctx.accounts.pending_order.load_init()?;
        slot.trading_key = ctx.accounts.trading_key.key();
        slot.market = market;
        slot.slot_idx = slot_idx;
        slot.bump = ctx.bumps.pending_order;
        slot.status = PENDING_STATUS_EMPTY;
    } else {
        // Re-validate identity: caller can only re-init their own slot.
        let slot = ctx.accounts.pending_order.load()?;
        require!(
            slot.trading_key == ctx.accounts.trading_key.key(),
            MatchingError::UnauthorizedTradingKey
        );
        require!(slot.market == market, MatchingError::MarketMismatch);
        require!(slot.slot_idx == slot_idx, MatchingError::InvalidPendingSlot);
    }

    emit!(PendingOrderSlotInitialized {
        trading_key: ctx.accounts.trading_key.key(),
        market,
        slot_idx,
    });
    Ok(())
}

#[event]
pub struct PendingOrderSlotInitialized {
    pub trading_key: Pubkey,
    pub market: Pubkey,
    pub slot_idx: u8,
}
