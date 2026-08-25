//! v3 — VALID_MATCH_BATCH proof verification.
//!
//! An authorized TEE lands this ix BEFORE the N settle txs in
//! a batch. It verifies a single Groth16 proof attesting that the
//! VALID_CREATE + VALID_PRICE constraints hold for EVERY match in a
//! batch of N (N ∈ {2, 4, 16}; only N=16 is wired on-chain for now —
//! N=2 and N=4 are dev/test instances).
//!
//! The two public inputs bind the Merkle root and a digest of the fee config,
//! market mint halves, and fixed-point price scale. The marker PDA is seeded by
//! the root. Each subsequent `tee_forced_settle` tx recomputes its own match's
//! leaf from the payload and walks a log2(N)-depth inclusion path up to the
//! root, asserting the marker exists at the derived PDA address.
//!
//! Why this exists: one batched proof + one marker replaces 2 × N
//! per-match markers (ValidCreateMarker + ValidPriceMarker per match)
//! and the corresponding 2 × N verify ixs. On a full N=16 batch that's
//! a 32× reduction in verify-overhead txs, plus a ~250× speedup in
//! TEE-side proof generation (one 6.7s proof instead of 64 × ~30s
//! per-match proofs).
//!
//! The payer must be a finalized authorized TEE signer because its transaction
//! signature authenticates the encrypted fee-recovery record carried by Tx B.
//! A forged proof still fails verification and creates no marker.

use crate::errors::VaultError;
use crate::state::{
    BatchValidityMarker, MarketConfig, VaultConfig, MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS,
};
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_match_batch_n16::*, Groth16Proof};
use anchor_lang::prelude::*;
use darkpool_crypto::match_config_digest;

#[derive(Accounts)]
#[instruction(merkle_root: [u8; 32])]
pub struct VerifyMatchBatch {
    /// Authorized TEE payer. Its transaction signature authenticates the
    /// fee-recovery ciphertext against front-running replacement.
    #[account(mut, constraint = vault_config.is_authorized_tee(payer.address()) @ VaultError::Unauthorized)]
    pub payer: Signer,

    /// Read-only — supplies the fee rate + protocol owner preimage for the
    /// circuit's public governed-config digest.
    #[account(seeds = [VaultConfig::SEED], bump = vault_config.bump)]
    pub vault_config: Account<VaultConfig>,

    /// Governed market identity and fixed-point scale. These join the vault
    /// fields in the public config digest, pinning every slot to this market.
    #[account(
        seeds = [
            MarketConfig::SEED,
            market_config.base_mint.as_ref(),
            market_config.quote_mint.as_ref(),
        ],
        bump = market_config.bump,
    )]
    pub market_config: Account<MarketConfig>,

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
    pub marker: Account<BatchValidityMarker>,

    pub system_program: Program<System>,
}

pub fn verify_match_batch_handler(
    ctx: &mut Context<VerifyMatchBatch>,
    merkle_root: [u8; 32],
    proof: Groth16Proof,
    fee_key_epoch: u64,
    _fee_recovery_ciphertext: [u8; 272],
) -> Result<()> {
    let clock = Clock::get()?;
    // S-04: the TTL is DERIVED, never supplied.
    //
    // A caller-supplied `expiry_slot`, even when bounded, gives any authorized
    // signer a lever to land the same proof with a one-slot TTL and make the
    // batch unusable after its locks have landed.
    //
    // Deriving it removes the degree of freedom entirely — nothing in the
    // protocol ever needed a caller-chosen TTL, and the constant was already
    // the ceiling. This is strictly LESS code than the two bounds it replaces.
    let expiry_slot = clock
        .slot
        .saturating_add(MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS);

    // Public inputs, in circuit order: [root, config_digest]. The digest is
    // recomputed from authoritative accounts, never accepted from the prover.
    let (fee_rate_bps, protocol_owner, fee_key_binding, governed_fee_key_epoch) = {
        let cfg = &ctx.accounts.vault_config;
        (
            cfg.fee_rate_bps.get() as u64,
            cfg.protocol_owner_commitment,
            cfg.fee_key_binding,
            cfg.fee_key_epoch.get(),
        )
    };
    require!(fee_key_binding != [0u8; 32], VaultError::FeeKeyBindingUnset);
    require!(
        fee_key_epoch == governed_fee_key_epoch,
        VaultError::InvalidFeeKeyEpoch
    );
    let market = &ctx.accounts.market_config;
    require!(bool::from(market.enabled), VaultError::MarketDisabled);
    require!(
        market.price_scale.get() > 0,
        VaultError::InvalidMarketParameters
    );
    let config_digest = match_config_digest(
        fee_rate_bps,
        &protocol_owner,
        &market.base_mint.to_bytes(),
        &market.quote_mint.to_bytes(),
        market.price_scale.get(),
        &fee_key_binding,
        governed_fee_key_epoch,
    )
    .map_err(|_| Error::from(VaultError::InvalidProof))?;
    let public_inputs: [[u8; 32]; 2] = [merkle_root, config_digest];

    let vk = make_vk(
        &MATCH_BATCH_N16_ALPHA_G1,
        &MATCH_BATCH_N16_BETA_G2,
        &MATCH_BATCH_N16_GAMMA_G2,
        &MATCH_BATCH_N16_DELTA_G2,
        &MATCH_BATCH_N16_IC,
    );
    verify_groth16_proof::<2>(&vk, &proof, &public_inputs)?;

    let marker = &mut ctx.accounts.marker;
    marker.payer = *ctx.accounts.payer.address();
    marker.expiry_slot = (expiry_slot).into();
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
