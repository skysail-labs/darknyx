//! Intake-side VALID_INPUT proof verification (audit 2026-07-25, S-02).
//!
//! # Why this exists
//!
//! A client relays a `VALID_INPUT` Groth16 proof with every order. Until this
//! module, the TEE decoded those 256 bytes, stored them, and handed them to
//! `lock_note` at settle time **without ever checking them** — the design note
//! in `api/orders.rs` said so explicitly ("The matcher does NOT verify it").
//!
//! That deferral is what made the S-02 freeze possible. `verify_commitment`
//! only proves an opening is self-consistent with a commitment the client
//! signed; a client can invent an opening from nothing, sign its Poseidon6,
//! and attach 256 bytes of noise. Every intake check passes, the matcher
//! crosses the fake against a real resting order, and the settle worker fires
//! both `lock_note` transactions concurrently. The honest side's lock — a real
//! proof for a real note — **lands**. The fake side's is rejected on-chain, the
//! batch dies, and the honest user's note is pinned by an on-chain `NoteLock`
//! for up to `MAX_LOCK_TTL_SLOTS`. Cost to the attacker: nothing.
//!
//! Verifying at intake converts "honest counterparty frozen for ~30 minutes"
//! into "attacker gets a 4xx".
//!
//! # Why it reuses the on-chain verifier
//!
//! This calls `groth16-solana` with the verifying-key constants **textually
//! included from the vault source**, so:
//!
//!   * the VK is byte-identical to the one `lock_note` uses, by construction —
//!     regenerating `vk_valid_input.rs` updates both at compile time, and the
//!     two cannot drift the way the hand-mirrored `MAX_LOCK_TTL_SLOTS` can;
//!   * the proof bytes need no conversion at all. They are already in
//!     `groth16-solana` layout (that is what the client sends and what the
//!     vault consumes), so there is no ark round-trip and no opportunity to get
//!     the `pi_a` negation or the Fq2 coefficient swap wrong;
//!   * accept/reject semantics match the chain exactly, so this check cannot
//!     reject an order the vault would have honoured.
//!
//! The TEE deliberately does **not** depend on the `vault` crate (it is an
//! Anchor `cdylib` and would drag the whole framework in). Including one
//! generated constants file is the narrow version of that dependency.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

use crate::settle::Groth16ProofBytes;

/// VALID_INPUT verifying key, included verbatim from the vault's generated
/// constants so the two can never disagree.
///
/// `scripts/build-circuits.sh` regenerates the source file; this module picks
/// the change up on the next build. The file is committed (unlike
/// `verification_key.json`, which is gitignored), so a fresh checkout compiles.
/// Path is relative to this source file's directory (`crates/darknyx-tee/src`).
/// `#[path]` rather than `include!` because the generated file opens with an
/// inner `#![allow(dead_code)]`, which is only legal at the start of a real
/// module file.
#[path = "../../../programs/vault/src/zk/vk_valid_input.rs"]
mod vk;

/// Why an intake-side proof check failed. Both variants are client errors; the
/// caller maps them to a 4xx.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof bytes are not a well-formed Groth16 proof (bad curve point,
    /// non-canonical field element, wrong encoding).
    #[error("valid_input proof is malformed")]
    Malformed,
    /// Well-formed, but does not satisfy the VALID_INPUT relation for the
    /// supplied public inputs.
    #[error("valid_input proof does not verify against the declared note")]
    Invalid,
}

/// Split a 32-byte pubkey into the two 128-bit halves the circuit takes as
/// `tokenMint[2]`, each right-aligned in a 32-byte big-endian field element.
///
/// Byte-identical to `pubkey_pair_be32` in the vault's `lock_note`/`withdraw`/
/// `deposit` handlers. A 256-bit pubkey does not fit one BN254 Fr element,
/// which is why the split exists at all.
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    [lo, hi]
}

/// Verify a relayed VALID_INPUT proof exactly as `lock_note` will.
///
/// Public inputs are assembled in the order the circom `component main {
/// public [merkleRoot, noteCommitment, tokenMint] }` declares, with
/// `tokenMint[2]` expanding to two entries — four total. The note amount stays
/// a private witness, range-constrained inside the proof (N-13).
///
/// **This does not check root recency.** Callers must independently confirm
/// `merkle_root` is in the shard mirror's window
/// (`MerkleMirror::contains_root`) — a proof against a long-dead root is
/// perfectly valid, just unusable by the time settle runs.
pub fn verify_valid_input(
    proof: &Groth16ProofBytes,
    merkle_root: &[u8; 32],
    note_commitment: &[u8; 32],
    token_mint: &[u8; 32],
) -> Result<(), VerifyError> {
    let [mint_lo, mint_hi] = pubkey_pair_be32(token_mint);
    let public_inputs: [[u8; 32]; 4] = [*merkle_root, *note_commitment, mint_lo, mint_hi];

    let vk = Groth16Verifyingkey {
        nr_pubinputs: vk::VALID_INPUT_IC.len().saturating_sub(1),
        vk_alpha_g1: vk::VALID_INPUT_ALPHA_G1,
        vk_beta_g2: vk::VALID_INPUT_BETA_G2,
        vk_gamme_g2: vk::VALID_INPUT_GAMMA_G2, // library typo; mirrored from the vault
        vk_delta_g2: vk::VALID_INPUT_DELTA_G2,
        vk_ic: &vk::VALID_INPUT_IC,
    };

    let mut verifier =
        Groth16Verifier::new(&proof.pi_a, &proof.pi_b, &proof.pi_c, &public_inputs, &vk)
            .map_err(|_| VerifyError::Malformed)?;

    verifier.verify().map_err(|_| VerifyError::Invalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The included VK must describe the circuit the vault verifies against:
    /// four public inputs, so five IC points.
    #[test]
    fn included_vk_matches_the_on_chain_public_input_count() {
        assert_eq!(vk::VALID_INPUT_NR_PUBLIC_INPUTS, 4);
        assert_eq!(
            vk::VALID_INPUT_IC.len(),
            vk::VALID_INPUT_NR_PUBLIC_INPUTS + 1,
            "IC must hold one point per public input plus the constant term"
        );
    }

    /// Pins the mint split against the vault's `pubkey_pair_be32`. A silent
    /// divergence here would make every intake verification fail while the
    /// chain accepted the same proof — the worst possible direction.
    #[test]
    fn mint_split_matches_the_vault_encoding() {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let [lo, hi] = pubkey_pair_be32(&pk);

        // lo carries the LAST 16 bytes, right-aligned; top 16 bytes zero.
        assert!(lo[..16].iter().all(|&b| b == 0));
        assert_eq!(&lo[16..], &pk[16..]);
        // hi carries the FIRST 16 bytes, right-aligned.
        assert!(hi[..16].iter().all(|&b| b == 0));
        assert_eq!(&hi[16..], &pk[..16]);
        // Both halves are Fr-safe (top byte zero) by construction.
        assert_eq!(lo[0], 0);
        assert_eq!(hi[0], 0);
    }

    /// Garbage bytes must be rejected, not panic. This is the exact input an
    /// S-02 attacker supplies: a fabricated opening plus 256 bytes of noise.
    #[test]
    fn random_bytes_are_rejected_without_panicking() {
        let proof = Groth16ProofBytes {
            pi_a: [7u8; 64],
            pi_b: [9u8; 128],
            pi_c: [11u8; 64],
        };
        // `expect_err` is the assertion: reaching it means the call returned
        // rather than panicking, and that it rejected. Matching on the variant
        // would be tautological — the enum has only these two.
        verify_valid_input(&proof, &[1u8; 32], &[2u8; 32], &[3u8; 32])
            .expect_err("noise must never verify");
    }

    /// An all-zero proof (the "I forgot to prove" case) must also be rejected.
    #[test]
    fn zero_proof_is_rejected() {
        let proof = Groth16ProofBytes {
            pi_a: [0u8; 64],
            pi_b: [0u8; 128],
            pi_c: [0u8; 64],
        };
        assert!(verify_valid_input(&proof, &[0u8; 32], &[0u8; 32], &[0u8; 32]).is_err());
    }
}
