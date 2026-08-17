use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;

#[derive(Accounts)]
#[instruction(note_use_tag: [u8; 32])]
pub struct ReleaseLock {
    /// Any signer may trigger a release after expiry (rent refund goes to them).
    #[account(mut)]
    pub rent_receiver: Signer,

    #[account(
        mut,
        seeds = [NoteLock::SEED, note_use_tag.as_ref()],
        bump,
        close = rent_receiver,
    )]
    pub note_lock: Account<NoteLock>,
}

pub fn release_lock_handler(ctx: &mut Context<ReleaseLock>, _note_use_tag: [u8; 32]) -> Result<()> {
    let lock = ctx.accounts.note_lock;
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
