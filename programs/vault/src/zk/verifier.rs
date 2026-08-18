//! Thin wrapper around `groth16-solana` that normalises proof+public-input
//! encoding. All proof bytes and public inputs are big-endian 32-byte encoded.
//!
//! Proof layout (matches snarkjs -> groth16-solana convention):
//!   pi_a:  [u8; 64]   (G1 point, must be "negated" before verification)
//!   pi_b:  [u8; 128]  (G2 point)
//!   pi_c:  [u8; 64]   (G1 point)

use crate::errors::VaultError;
use anchor_lang::prelude::*;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

/// A raw Groth16 proof as it arrives from snarkjs / ark-circom.
#[derive(SchemaWrite, SchemaRead, Clone, Debug)]
pub struct Groth16Proof {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

/// Build a `Groth16Verifyingkey` at runtime from const VK bytes + runtime IC slice.
/// The on-chain VK structure borrows its IC slice, so callers must keep the IC
/// array alive for the duration of verification.
pub fn make_vk<'a>(
    alpha_g1: &'a [u8; 64],
    beta_g2: &'a [u8; 128],
    gamma_g2: &'a [u8; 128],
    delta_g2: &'a [u8; 128],
    ic: &'a [[u8; 64]],
) -> Groth16Verifyingkey<'a> {
    Groth16Verifyingkey {
        nr_pubinputs: ic.len().saturating_sub(1),
        vk_alpha_g1: *alpha_g1,
        vk_beta_g2: *beta_g2,
        vk_gamme_g2: *gamma_g2, // NB: library typo; do not fix.
        vk_delta_g2: *delta_g2,
        vk_ic: ic,
    }
}

/// Verify a Groth16 proof. Public inputs must be big-endian 32-byte encoded field
/// elements, in the same order the circom circuit declares them.
pub fn verify_groth16_proof<const NR: usize>(
    vk: &Groth16Verifyingkey<'_>,
    proof: &Groth16Proof,
    public_inputs: &[[u8; 32]; NR],
) -> Result<()> {
    let mut verifier =
        Groth16Verifier::new(&proof.pi_a, &proof.pi_b, &proof.pi_c, public_inputs, vk)
            .map_err(|_| Error::from(VaultError::InvalidProof))?;

    verifier
        .verify()
        .map_err(|_| Error::from(VaultError::InvalidProof))?;
    Ok(())
}
