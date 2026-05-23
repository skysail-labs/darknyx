//! DEPRECATED v3.5: superseded by `verify_match_batch`, which inlines
//! these same VALID_PRICE constraints into a single batched Groth16
//! proof covering up to N=16 matches. Kept on-chain for backwards
//! compatibility during the v3.5 confidence window; scheduled for
//! removal in Phase 1c-hard. See `docs/v3.5-migration.md` for the
//! retirement plan and migration timing.
//!
//! v3.1 — VALID_PRICE proof verification.
//!
//! The TEE (or any relayer) lands this ix BEFORE `tee_forced_settle`. It
//! verifies a Groth16 proof attesting that the TEE's clearing price is
//! consistent with the matched amounts — specifically:
//!
//!     quote_amount == base_amount * clearing_price   (exact integer)
//!     all three values in [0, 2^64)
//!     price_commitment == Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot)
//!
//! ...then writes a `ValidPriceMarker` PDA whose seed is the bound
//! `price_commitment` itself. `tee_forced_settle` recomputes the same
//! commitment from `payload.clearing_price + payload.batch_slot` and reads
//! the PDA as proof that VALID_PRICE was checked for THIS specific
//! (price, slot) pair.
//!
//! Why this ix is split out (not inline in `tee_forced_settle`): the
//! Groth16 proof bytes (~256 bytes) plus the 32-byte commitment plus
//! Anchor-Borsh framing pushed the settle tx over the 1232-byte cap
//! after the audit added VALID_PRICE. Splitting follows the same
//! pattern as `verify_valid_create`.
//!
//! Privacy: this ix reveals the `price_commitment` (a hash) and
//! `batch_slot`. `clearing_price` stays private inside the proof — it
//! does leak indirectly via the canonical_payload_hash signed by the
//! TEE in the settle tx (which already carries `clearing_price` in
//! clear), but verify_valid_price itself does not expand the leak.

use crate::errors::VaultError;
use crate::state::{ValidPriceMarker, MAX_PRICE_MARKER_TTL_SLOTS};
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_price::*, Groth16Proof};
use anchor_lang::prelude::*;

fn u64_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

#[derive(Accounts)]
#[instruction(price_commitment: [u8; 32], batch_slot: u64, expiry_slot: u64, proof: Groth16Proof)]
pub struct VerifyValidPrice<'info> {
    /// Anyone can pay rent + submit the proof. Authorization is implicit
    /// in the Groth16 verification — a forged proof simply fails and no
    /// marker is created.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Marker PDA. `init` ensures the same `price_commitment` can't
    /// be re-verified after the first call (the second `verify_valid_price`
    /// for the same (price, slot) pair would collide here). Once
    /// consumed by `tee_forced_settle`, the PDA is closed and the same
    /// commitment can be re-verified for a future settlement — but the
    /// canonical_payload_hash binds the settle to a specific batch_slot,
    /// so replay is bounded by uniqueness of (clearing_price, batch_slot)
    /// across batches.
    #[account(
        init,
        payer = payer,
        space = ValidPriceMarker::SPACE,
        seeds = [ValidPriceMarker::SEED, price_commitment.as_ref()],
        bump,
    )]
    pub marker: Account<'info, ValidPriceMarker>,

    pub system_program: Program<'info, System>,
}

pub fn verify_valid_price_handler(
    ctx: Context<VerifyValidPrice>,
    price_commitment: [u8; 32],
    batch_slot: u64,
    expiry_slot: u64,
    proof: Groth16Proof,
) -> Result<()> {
    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidMarkerExpiry);
    require!(
        expiry_slot <= clock.slot.saturating_add(MAX_PRICE_MARKER_TTL_SLOTS),
        VaultError::InvalidMarkerExpiry
    );

    // Public inputs in circuit wire order:
    //   wire 1: price_commitment (32 BE bytes — Poseidon output, already field-element-sized)
    //   wire 2: batch_slot       (u64 LE → BE-padded 32 bytes)
    let batch_slot_be32 = u64_be32(batch_slot);
    let public_inputs: [[u8; 32]; 2] = [price_commitment, batch_slot_be32];

    let vk = make_vk(
        &VALID_PRICE_ALPHA_G1,
        &VALID_PRICE_BETA_G2,
        &VALID_PRICE_GAMMA_G2,
        &VALID_PRICE_DELTA_G2,
        &VALID_PRICE_IC,
    );
    verify_groth16_proof::<2>(&vk, &proof, &public_inputs)?;

    let marker = &mut ctx.accounts.marker;
    marker.payer = ctx.accounts.payer.key();
    marker.expiry_slot = expiry_slot;
    marker.bump = ctx.bumps.marker;

    emit!(ValidPriceVerified {
        price_commitment,
        batch_slot,
        expiry_slot,
    });
    Ok(())
}

#[event]
pub struct ValidPriceVerified {
    pub price_commitment: [u8; 32],
    pub batch_slot: u64,
    pub expiry_slot: u64,
}
