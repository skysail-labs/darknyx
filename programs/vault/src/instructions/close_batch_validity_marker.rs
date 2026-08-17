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
pub struct CloseBatchValidityMarker {
    /// Caller AND refund target, collapsed into one slot.
    ///
    /// v2 CHANGE, and it deliberately narrows behaviour. This used to be two
    /// slots — an `authority` signer plus a separate `mut` `payer` refund
    /// target bound by `has_one = payer` — so ANY signer could sweep an expired
    /// marker while the rent still went to the recorded payer.
    ///
    /// v2 rejects that shape in practice. The sweeper closes with
    /// `authority == payer == the primary shard key`
    /// (`darknyx-tee/src/settle/marker_sweep.rs`), so one address landed in two
    /// slots, one of them `mut`, and v2's duplicate-mutable-account check
    /// (guide §7.3) fails it BEFORE the handler runs with
    /// `ConstraintDuplicateMutableAccount` (2040). Confirmed against a deployed
    /// program on devnet, not only in litesvm.
    ///
    /// Collapsing the slots removes the alias structurally instead of waiving
    /// the check with `unsafe(dup)`, and drops an account from the tx — welcome
    /// on a path with ~59 B of headroom (CLAUDE.md §6).
    ///
    /// LOST: permissionless cleanup; only the recorded payer can close now.
    /// KEPT: the property §8.2 actually rests on — nobody, payer included, can
    /// close before expiry.
    #[account(mut)]
    pub authority: Signer,

    /// Marker PDA — closed to `authority`, which the constraint pins to the
    /// payer recorded by `verify_match_batch`. (`has_one` is deprecated in v2;
    /// this is its explicit equivalent.)
    #[account(
        mut,
        close = authority,
        seeds = [BatchValidityMarker::SEED, merkle_root.as_ref()],
        bump = marker.bump,
        constraint = marker.payer == *authority.address() @ VaultError::Unauthorized,
    )]
    pub marker: Account<BatchValidityMarker>,
}

pub fn close_batch_validity_marker_handler(
    ctx: &mut Context<CloseBatchValidityMarker>,
    _merkle_root: [u8; 32],
) -> Result<()> {
    let marker = &ctx.accounts.marker;
    let authority = *ctx.accounts.authority.address();
    let clock = Clock::get()?;
    // The marker is unusable by Tx D at E (`clock.slot < expiry_slot`), so it is
    // safe and unambiguous to reclaim at E. No signer, including the payer, has
    // an early-close path.
    require!(
        clock.slot >= marker.expiry_slot.get(),
        VaultError::BatchValidityMarkerNotExpired,
    );

    emit!(BatchValidityMarkerClosed {
        payer: marker.payer,
        closed_by: authority,
        expiry_slot: marker.expiry_slot.get(),
    });
    Ok(())
}

#[event]
pub struct BatchValidityMarkerClosed {
    pub payer: Address,
    pub closed_by: Address,
    pub expiry_slot: u64,
}
