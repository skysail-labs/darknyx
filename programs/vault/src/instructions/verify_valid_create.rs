//! DEPRECATED v3.5: superseded by `verify_match_batch`, which inlines
//! these same VALID_CREATE constraints into a single batched Groth16
//! proof covering up to N=16 matches. Kept on-chain for backwards
//! compatibility during the v3.5 confidence window; scheduled for
//! removal in Phase 1c-hard. See `docs/v3.5-migration.md` for the
//! retirement plan and migration timing.
//!
//! v3 — VALID_CREATE proof verification.
//!
//! The TEE (or any relayer) lands this ix BEFORE `tee_forced_settle`. It
//! verifies a Groth16 proof attesting that the TEE constructed the output
//! notes correctly (right mints, right amounts, addressed to the input
//! owners), then writes a `ValidCreateMarker` PDA whose seed encodes the
//! 14 bound values. `tee_forced_settle` later recomputes that seed from
//! its own view of the payload + the input locks' mints and reads the PDA
//! as proof that VALID_CREATE was checked.
//!
//! Privacy: only the input/output commitments, the two mints, and the six
//! u64 amounts are revealed by this ix. The buyer/seller owner_commitments
//! stay private inside the proof.

use crate::errors::VaultError;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_create::*, Groth16Proof};
use anchor_lang::prelude::*;

/// Split a 32-byte Solana pubkey into [lo_u128_be32, hi_u128_be32].
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    [lo, hi]
}

fn u64_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Compute the canonical VALID_CREATE binding hash. Used both by
/// `verify_valid_create` (as the PDA seed source) and by `tee_forced_settle`
/// (to look up the marker). Both sides MUST produce byte-identical output.
///
/// Domain-tagged SHA-256 over the 14 bound values, encoded as:
///   tag (16) || note_a..f (6 × 32) || quote_mint (32) || base_mint (32)
///   || amounts (6 × u64 LE)
///
/// Stable across versions — change the domain tag if the field set ever
/// changes.
pub fn valid_create_binding_hash(
    note_a_commitment: &[u8; 32],
    note_b_commitment: &[u8; 32],
    note_c_commitment: &[u8; 32],
    note_d_commitment: &[u8; 32],
    note_e_commitment: &[u8; 32],
    note_f_commitment: &[u8; 32],
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
    base_amount: u64,
    quote_amount: u64,
    buyer_change_amt: u64,
    seller_change_amt: u64,
    buyer_fee_amt: u64,
    seller_fee_amt: u64,
) -> [u8; 32] {
    use solana_program::hash::hashv;
    let base = base_amount.to_le_bytes();
    let quote = quote_amount.to_le_bytes();
    let buyer_change = buyer_change_amt.to_le_bytes();
    let seller_change = seller_change_amt.to_le_bytes();
    let buyer_fee = buyer_fee_amt.to_le_bytes();
    let seller_fee = seller_fee_amt.to_le_bytes();
    let quote_mint_bytes = quote_mint.to_bytes();
    let base_mint_bytes = base_mint.to_bytes();
    hashv(&[
        b"nyx-create-bind-v1",
        note_a_commitment.as_ref(),
        note_b_commitment.as_ref(),
        note_c_commitment.as_ref(),
        note_d_commitment.as_ref(),
        note_e_commitment.as_ref(),
        note_f_commitment.as_ref(),
        &quote_mint_bytes,
        &base_mint_bytes,
        &base,
        &quote,
        &buyer_change,
        &seller_change,
        &buyer_fee,
        &seller_fee,
    ])
    .to_bytes()
}

/// Pack the 16 public inputs into the BE-32 vector the on-chain Groth16
/// verifier expects, in the exact order the circuit declared them.
#[allow(clippy::too_many_arguments)]
fn pack_public_inputs(
    note_a_commitment: &[u8; 32],
    note_b_commitment: &[u8; 32],
    note_c_commitment: &[u8; 32],
    note_d_commitment: &[u8; 32],
    note_e_commitment: &[u8; 32],
    note_f_commitment: &[u8; 32],
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
    base_amount: u64,
    quote_amount: u64,
    buyer_change_amt: u64,
    seller_change_amt: u64,
    buyer_fee_amt: u64,
    seller_fee_amt: u64,
) -> [[u8; 32]; 16] {
    let [q_lo, q_hi] = pubkey_pair_be32(&quote_mint.to_bytes());
    let [b_lo, b_hi] = pubkey_pair_be32(&base_mint.to_bytes());
    [
        *note_a_commitment,
        *note_b_commitment,
        *note_c_commitment,
        *note_d_commitment,
        *note_e_commitment,
        *note_f_commitment,
        q_lo,
        q_hi,
        b_lo,
        b_hi,
        u64_be32(base_amount),
        u64_be32(quote_amount),
        u64_be32(buyer_change_amt),
        u64_be32(seller_change_amt),
        u64_be32(buyer_fee_amt),
        u64_be32(seller_fee_amt),
    ]
}

#[derive(Accounts)]
#[instruction(
    note_a_commitment: [u8; 32],
    note_b_commitment: [u8; 32],
    note_c_commitment: [u8; 32],
    note_d_commitment: [u8; 32],
    note_e_commitment: [u8; 32],
    note_f_commitment: [u8; 32],
    quote_mint: Pubkey,
    base_mint: Pubkey,
    base_amount: u64,
    quote_amount: u64,
    buyer_change_amt: u64,
    seller_change_amt: u64,
    buyer_fee_amt: u64,
    seller_fee_amt: u64,
    expiry_slot: u64,
    proof: Groth16Proof,
)]
pub struct VerifyValidCreate<'info> {
    /// Anyone can pay the rent + submit the proof. Authorization comes
    /// from the proof itself — a forged or stale proof simply fails Groth16
    /// verification and no marker is created.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The marker PDA. Init-on-success ensures we cannot replay the same
    /// binding twice (a second `verify_valid_create` for the same set of
    /// committed outputs would collide here).
    #[account(
        init,
        payer = payer,
        space = ValidCreateMarker::SPACE,
        seeds = [
            ValidCreateMarker::SEED,
            valid_create_binding_hash(
                &note_a_commitment, &note_b_commitment,
                &note_c_commitment, &note_d_commitment,
                &note_e_commitment, &note_f_commitment,
                &quote_mint, &base_mint,
                base_amount, quote_amount,
                buyer_change_amt, seller_change_amt,
                buyer_fee_amt, seller_fee_amt,
            ).as_ref(),
        ],
        bump,
    )]
    pub marker: Account<'info, ValidCreateMarker>,

    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_valid_create_handler(
    ctx: Context<VerifyValidCreate>,
    note_a_commitment: [u8; 32],
    note_b_commitment: [u8; 32],
    note_c_commitment: [u8; 32],
    note_d_commitment: [u8; 32],
    note_e_commitment: [u8; 32],
    note_f_commitment: [u8; 32],
    quote_mint: Pubkey,
    base_mint: Pubkey,
    base_amount: u64,
    quote_amount: u64,
    buyer_change_amt: u64,
    seller_change_amt: u64,
    buyer_fee_amt: u64,
    seller_fee_amt: u64,
    expiry_slot: u64,
    proof: Groth16Proof,
) -> Result<()> {
    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidMarkerExpiry);
    require!(
        expiry_slot <= clock.slot.saturating_add(MAX_CREATE_MARKER_TTL_SLOTS),
        VaultError::InvalidMarkerExpiry
    );

    let public_inputs = pack_public_inputs(
        &note_a_commitment,
        &note_b_commitment,
        &note_c_commitment,
        &note_d_commitment,
        &note_e_commitment,
        &note_f_commitment,
        &quote_mint,
        &base_mint,
        base_amount,
        quote_amount,
        buyer_change_amt,
        seller_change_amt,
        buyer_fee_amt,
        seller_fee_amt,
    );

    let vk = make_vk(
        &VALID_CREATE_ALPHA_G1,
        &VALID_CREATE_BETA_G2,
        &VALID_CREATE_GAMMA_G2,
        &VALID_CREATE_DELTA_G2,
        &VALID_CREATE_IC,
    );
    verify_groth16_proof::<16>(&vk, &proof, &public_inputs)?;

    let marker = &mut ctx.accounts.marker;
    marker.payer = ctx.accounts.payer.key();
    marker.expiry_slot = expiry_slot;
    marker.bump = ctx.bumps.marker;

    emit!(ValidCreateVerified {
        note_a_commitment,
        note_b_commitment,
        note_c_commitment,
        note_d_commitment,
        note_e_commitment,
        note_f_commitment,
        quote_mint,
        base_mint,
        base_amount,
        quote_amount,
        buyer_change_amt,
        seller_change_amt,
        buyer_fee_amt,
        seller_fee_amt,
        expiry_slot,
    });
    Ok(())
}

#[event]
pub struct ValidCreateVerified {
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub quote_mint: Pubkey,
    pub base_mint: Pubkey,
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,
    pub expiry_slot: u64,
}
