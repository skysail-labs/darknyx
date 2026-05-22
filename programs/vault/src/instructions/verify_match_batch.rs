//! v3.5 — VALID_MATCH_BATCH proof verification.
//!
//! The TEE (or any relayer) lands this ix BEFORE the N settle txs in
//! a batch. It verifies a single Groth16 proof attesting that the
//! VALID_CREATE + VALID_PRICE constraints hold for EVERY match in a
//! batch of N (N ∈ {2, 4, 16}; only N=16 is wired on-chain for now —
//! N=2 and N=4 are dev/test instances).
//!
//! Public input: the Merkle root over the per-slot leaves. The marker
//! PDA is seeded by that same root. Each subsequent `tee_forced_settle`
//! tx recomputes its own match's leaf from the payload and walks a
//! log2(N)-depth inclusion path up to the root, asserting the marker
//! exists at the derived PDA address.
//!
//! Why this exists: one batched proof + one marker replaces 2 × N
//! per-match markers (ValidCreateMarker + ValidPriceMarker per match)
//! and the corresponding 2 × N verify ixs. On a full N=16 batch that's
//! a 32× reduction in verify-overhead txs, plus a ~250× speedup in
//! TEE-side proof generation (one 6.7s proof instead of 64 × ~30s
//! per-match proofs).
//!
//! Anyone can pay rent + submit the proof — authorisation is implicit
//! in the Groth16 verification. A forged proof fails verification and
//! no marker is created (so the subsequent settle txs fail when they
//! can't find the marker).

use crate::errors::VaultError;
use crate::state::{BatchValidityMarker, MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS};
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_match_batch_n16::*, Groth16Proof};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(merkle_root: [u8; 32], expiry_slot: u64, proof: Groth16Proof)]
pub struct VerifyMatchBatch<'info> {
    /// Anyone can pay rent / submit the proof. Authorization is the proof itself —
    /// a forged proof simply fails Groth16 verification and no marker is created.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Marker PDA. `init` ensures the same `merkle_root` can't be re-verified
    /// after the first call (a second `verify_match_batch` for the same batch
    /// would collide here). Once consumed by N tee_forced_settle txs, the
    /// PDA is closed and the same root could in theory be re-verified for a
    /// future batch — but in practice the matcher's nonces + batch_slot bind
    /// each batch uniquely so this is a non-issue.
    #[account(
        init,
        payer = payer,
        space = BatchValidityMarker::SPACE,
        seeds = [BatchValidityMarker::SEED, merkle_root.as_ref()],
        bump,
    )]
    pub marker: Account<'info, BatchValidityMarker>,

    pub system_program: Program<'info, System>,
}

pub fn verify_match_batch_handler(
    ctx: Context<VerifyMatchBatch>,
    merkle_root: [u8; 32],
    expiry_slot: u64,
    proof: Groth16Proof,
) -> Result<()> {
    let clock = Clock::get()?;
    require!(expiry_slot > clock.slot, VaultError::InvalidMarkerExpiry);
    require!(
        expiry_slot
            <= clock
                .slot
                .saturating_add(MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS),
        VaultError::InvalidMarkerExpiry
    );

    // Single public input — the Merkle root the prover supplied as the
    // batch commitment. Already 32 BE bytes (Poseidon output), so we
    // can hand it directly to the verifier.
    let public_inputs: [[u8; 32]; 1] = [merkle_root];

    let vk = make_vk(
        &MATCH_BATCH_N16_ALPHA_G1,
        &MATCH_BATCH_N16_BETA_G2,
        &MATCH_BATCH_N16_GAMMA_G2,
        &MATCH_BATCH_N16_DELTA_G2,
        &MATCH_BATCH_N16_IC,
    );
    verify_groth16_proof::<1>(&vk, &proof, &public_inputs)?;

    let marker = &mut ctx.accounts.marker;
    marker.payer = ctx.accounts.payer.key();
    marker.expiry_slot = expiry_slot;
    marker.bump = ctx.bumps.marker;

    emit!(MatchBatchVerified {
        merkle_root,
        expiry_slot,
    });
    Ok(())
}

#[event]
pub struct MatchBatchVerified {
    pub merkle_root: [u8; 32],
    pub expiry_slot: u64,
}
