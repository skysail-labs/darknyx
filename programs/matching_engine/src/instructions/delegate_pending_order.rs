//! `delegate_pending_order` — hand a PendingOrder slot PDA to the
//! MagicBlock ER validator so the user can write order intent inside
//! the TEE without ever touching L1.
//!
//! Privacy property: the L1 transaction that delegates the slot only
//! contains the slot's PDA pubkey + owner — NO order details. Once
//! delegated, all `submit_order` / `cancel_order` writes happen
//! inside the ER session.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::delegate;
use ephemeral_rollups_sdk::cpi::DelegateConfig;

use crate::errors::MatchingError;
use crate::state::MAX_PENDING_SLOTS_PER_USER;

#[delegate]
#[derive(Accounts)]
#[instruction(market: Pubkey, slot_idx: u8)]
pub struct DelegatePendingOrder<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The trading key authorising the delegation. Must equal the slot's
    /// `trading_key` field — enforced indirectly via the seed which uses
    /// `trading_key.key()`.
    pub trading_key: Signer<'info>,

    /// CHECK: Delegated to the ER validator via the #[delegate] macro.
    #[account(mut, del)]
    pub pda: AccountInfo<'info>,
}

pub fn delegate_pending_order_handler(
    ctx: Context<DelegatePendingOrder>,
    market: Pubkey,
    slot_idx: u8,
) -> Result<()> {
    require!(
        slot_idx < MAX_PENDING_SLOTS_PER_USER,
        MatchingError::InvalidPendingSlot
    );

    let trading_key = ctx.accounts.trading_key.key();
    let seed_refs: &[&[u8]] = &[
        crate::state::PendingOrder::SEED,
        market.as_ref(),
        trading_key.as_ref(),
        core::slice::from_ref(&slot_idx),
    ];
    ctx.accounts
        .delegate_pda(&ctx.accounts.payer, seed_refs, DelegateConfig::default())?;
    Ok(())
}
