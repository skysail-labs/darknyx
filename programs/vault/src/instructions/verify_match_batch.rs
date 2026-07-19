//! v3 — VALID_MATCH_BATCH proof verification.
//!
//! The TEE (or any relayer) lands this ix BEFORE the N settle txs in
//! a batch. It verifies a single Groth16 proof attesting that the
//! VALID_CREATE + VALID_PRICE constraints hold for EVERY match in a
//! batch of N (N ∈ {2, 4, 16}; only N=16 is wired on-chain for now —
//! N=2 and N=4 are dev/test instances).
//!
//! Public inputs bind the Merkle root, fee config, market mint halves, and
//! fixed-point price scale. The marker PDA is seeded by the root. Each subsequent `tee_forced_settle`
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
use crate::state::{
    BatchValidityMarker, MarketConfig, VaultConfig, MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS,
};
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_match_batch_n16::*, Groth16Proof};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(merkle_root: [u8; 32], expiry_slot: u64, proof: Groth16Proof)]
pub struct VerifyMatchBatch<'info> {
    /// Anyone can pay rent / submit the proof. Authorization is the proof itself —
    /// a forged proof simply fails Groth16 verification and no marker is created.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Read-only — supplies `fee_rate_bps` as the circuit's 2nd PUBLIC input
    /// (amount-privacy, P1b): the prover proved the in-circuit exact fee at THIS
    /// rate, and binding it to the on-chain config prevents a prover-chosen rate.
    #[account(seeds = [VaultConfig::SEED], bump = vault_config.load()?.bump)]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// Governed market identity and fixed-point scale. These become public
    /// inputs 4..8, so every active slot is pinned to this exact mint pair.
    #[account(
        seeds = [
            MarketConfig::SEED,
            market_config.base_mint.as_ref(),
            market_config.quote_mint.as_ref(),
        ],
        bump = market_config.bump,
    )]
    pub market_config: Account<'info, MarketConfig>,

    /// Marker PDA. `init` ensures the same `merkle_root` can't be re-verified
    /// after the first call (a second `verify_match_batch` for the same batch
    /// would collide here). The marker is read-only during settlement and can
    /// be closed only after expiry. A root could then be re-verified, but the
    /// consumed-note PDAs independently prevent settled inputs from replaying.
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

    // Public inputs, in circuit order:
    // [root, fee_rate, owner, base_lo, base_hi, quote_lo, quote_hi, price_scale].
    let (fee_rate_bps, protocol_owner) = {
        let cfg = ctx.accounts.vault_config.load()?;
        (cfg.fee_rate_bps as u64, cfg.protocol_owner_commitment)
    };
    let mut fee_rate_be = [0u8; 32];
    fee_rate_be[24..32].copy_from_slice(&fee_rate_bps.to_be_bytes());
    let market = &ctx.accounts.market_config;
    require!(market.enabled, VaultError::MarketDisabled);
    require!(market.price_scale > 0, VaultError::InvalidMarketParameters);
    let (base_lo, base_hi) = pubkey_halves_be(&market.base_mint);
    let (quote_lo, quote_hi) = pubkey_halves_be(&market.quote_mint);
    let mut price_scale_be = [0u8; 32];
    price_scale_be[24..].copy_from_slice(&market.price_scale.to_be_bytes());
    let public_inputs: [[u8; 32]; 8] = [
        merkle_root,
        fee_rate_be,
        protocol_owner,
        base_lo,
        base_hi,
        quote_lo,
        quote_hi,
        price_scale_be,
    ];

    let vk = make_vk(
        &MATCH_BATCH_N16_ALPHA_G1,
        &MATCH_BATCH_N16_BETA_G2,
        &MATCH_BATCH_N16_GAMMA_G2,
        &MATCH_BATCH_N16_DELTA_G2,
        &MATCH_BATCH_N16_IC,
    );
    verify_groth16_proof::<8>(&vk, &proof, &public_inputs)?;

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

fn pubkey_halves_be(pubkey: &Pubkey) -> ([u8; 32], [u8; 32]) {
    let bytes = pubkey.to_bytes();
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&bytes[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&bytes[..16]);
    (lo, hi)
}

#[event]
pub struct MatchBatchVerified {
    pub merkle_root: [u8; 32],
    pub expiry_slot: u64,
}
