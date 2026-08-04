use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(note_use_tag: [u8; 32])]
pub struct ReleaseLock<'info> {
    /// Any signer may trigger a release after expiry (rent refund goes to them).
    #[account(mut)]
    pub rent_receiver: Signer<'info>,

    #[account(
        mut,
        seeds = [NoteLock::SEED, note_use_tag.as_ref()],
        bump,
        close = rent_receiver,
    )]
    pub note_lock: AccountLoader<'info, NoteLock>,
}

pub fn release_lock_handler(ctx: Context<ReleaseLock>, _note_use_tag: [u8; 32]) -> Result<()> {
    let lock = ctx.accounts.note_lock.load()?;
    let clock = Clock::get()?;
    require!(clock.slot >= lock.expiry_slot, VaultError::LockNotExpired);

    emit!(NoteLockReleased {
        note_use_tag: lock.note_use_tag,
        order_id: lock.order_id,
    });
    Ok(())
}

#[event]
pub struct NoteLockReleased {
    pub note_use_tag: [u8; 32],
    pub order_id: [u8; 16],
}
