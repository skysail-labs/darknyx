//! v3.5 — close a `BatchValidityMarker` PDA after all matches in the
//! batch have settled (or the marker has expired and become unusable).
//!
//! Why this exists: `tee_forced_settle_batched` deliberately does NOT
//! close the marker — one marker covers all N matches in the batch
//! (it's keyed by the batch's Merkle root), so closing it after the
//! first match would brick matches 1..N-1. Instead a sweeper calls this ix once
//! at or after marker expiry to reclaim the ~49-byte rent.
//!
//! Authorisation: ANY signer may close only once the marker reaches its
//! `expiry_slot`. The original payer has no early-close privilege: allowing the
//! TEE payer to close while some Tx Ds are still pending can brick the rest of
//! the batch. Rent always returns to the recorded payer.
//!
//! Rent always flows back to `marker.payer` regardless of which
//! authority triggered the close (the `close = payer` Anchor
//! constraint + the `has_one = payer` check).

use crate::errors::VaultError;
use crate::state::BatchValidityMarker;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(merkle_root: [u8; 32])]
pub struct CloseBatchValidityMarker<'info> {
    /// Caller. Any signer may sweep once the marker has expired.
    pub authority: Signer<'info>,

    /// Refund target on close. MUST equal `marker.payer` (set by
    /// `verify_match_batch`). The `has_one = payer` constraint on
    /// the marker below enforces this.
    ///
    /// CHECK: Validated via Anchor's `has_one = payer` on `marker`.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,

    /// Marker PDA — closed to `payer`.
    #[account(
        mut,
        close = payer,
        seeds = [BatchValidityMarker::SEED, merkle_root.as_ref()],
        bump = marker.bump,
        has_one = payer,
    )]
    pub marker: Account<'info, BatchValidityMarker>,
}

pub fn close_batch_validity_marker_handler(
    ctx: Context<CloseBatchValidityMarker>,
    _merkle_root: [u8; 32],
) -> Result<()> {
    let marker = &ctx.accounts.marker;
    let authority = ctx.accounts.authority.key();
    let clock = Clock::get()?;
    // The marker is unusable by Tx D at E (`clock.slot < expiry_slot`), so it is
    // safe and unambiguous to reclaim at E. No signer, including the payer, has
    // an early-close path.
    require!(
        clock.slot >= marker.expiry_slot,
        VaultError::BatchValidityMarkerNotExpired,
    );

    emit!(BatchValidityMarkerClosed {
        payer: marker.payer,
        closed_by: authority,
        expiry_slot: marker.expiry_slot,
    });
    Ok(())
}

#[event]
pub struct BatchValidityMarkerClosed {
    pub payer: Pubkey,
    pub closed_by: Pubkey,
    pub expiry_slot: u64,
}
