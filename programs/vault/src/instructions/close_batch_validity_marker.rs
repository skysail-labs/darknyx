//! v3.5 — close a `BatchValidityMarker` PDA after all matches in the
//! batch have settled (or the marker has expired and become unusable).
//!
//! Why this exists: `tee_forced_settle_batched` deliberately does NOT
//! close the marker — one marker covers all N matches in the batch
//! (it's keyed by the batch's Merkle root), so closing it after the
//! first match would brick matches 1..N-1. Instead the matcher calls
//! this ix once, after the last settle, to reclaim the ~49-byte rent.
//!
//! Authorisation:
//!   - The marker's original `payer` (the address recorded by
//!     `verify_match_batch`) can close at ANY time. Typical flow:
//!     the matcher pays for `verify_match_batch`, lands all N
//!     `tee_forced_settle_batched` txs, then signs this ix to
//!     reclaim rent.
//!   - ANY signer can close ONCE the marker has passed its
//!     `expiry_slot`. This is the garbage-collection path — if the
//!     matcher crashes mid-batch and never reclaims, an expired
//!     marker can be swept by anyone (rent still goes to the
//!     original payer, so the sweeper just spends tx fees).
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
    /// Caller. Either equals `marker.payer` (close-anytime path) or
    /// any other signer (expiry-GC path — must be past `expiry_slot`).
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

    // Two valid paths:
    //   1) authority == marker.payer — original payer, can close
    //      immediately (matcher's expected fast-path after the last
    //      settle in the batch).
    //   2) authority != marker.payer — anyone else, allowed only
    //      after expiry as garbage collection.
    if authority != marker.payer {
        let clock = Clock::get()?;
        require!(
            clock.slot > marker.expiry_slot,
            VaultError::BatchValidityMarkerNotExpired,
        );
    }

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
