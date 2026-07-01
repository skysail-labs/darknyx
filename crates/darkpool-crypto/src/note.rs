//! UTXO note structure and commitment derivation.
//!
//! **The live construction is v2 (`inner_hash`)** — a SINGLE per-note blinding
//! that anchors both the commitment AND the nullifier (see
//! [`crate::nullifier::nullifier_v2`]), so a client can PRE-SUPPLY the nullifier
//! of a change note it has not yet received (the per-order "anchor pool"). Domain
//! tag DOMAIN_NOTE=2 is prepended to prevent second-preimage collisions with the
//! owner-commitment and nullifier Poseidon uses (DOMAIN_OWNER=1, DOMAIN_NULL=3).
//!
//! ```text
//!     C_v2(note) = Poseidon6(
//!         DOMAIN_NOTE=2,        // domain separation tag
//!         token_mint_lo_u128,   // Solana pubkey low 128 bits
//!         token_mint_hi_u128,   // Solana pubkey high 128 bits
//!         amount_u64,
//!         owner_commitment_fr,  // = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)
//!         inner_hash_fr,        // single per-note blinding (replaces nonce+blinding_r)
//!     )
//! ```
//!
//! Byte-identical across Rust [`commitment_from_fields_v2`], circom
//! (`valid_input`/`valid_spend`), on-chain `deposit`, and the TS SDK
//! `noteCommitmentV2`. The deposit + settle paths both use v2. (The pre-v2 v1
//! `Poseidon7` construction — separate `nonce`/`blinding_r` fields — has been
//! fully retired.)
//!
//! Reference: Section 23.1.2 of darkpool_protocol_spec_v3_changed.md +
//! `~/.claude/plans/agile-chasing-parnas.md`

use crate::errors::CryptoError;
use crate::field::{fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr, Fr};
use crate::poseidon::poseidon_hash;

pub const NOTE_COMMITMENT_BYTES: usize = 32;

/// A note commitment — the 32-byte on-chain representation of a note.
pub type NoteCommitment = [u8; NOTE_COMMITMENT_BYTES];

const DOMAIN_OWNER: u64 = 1;
const DOMAIN_NOTE: u64 = 2;

/// Compute the owner commitment: Poseidon3(DOMAIN_OWNER, spending_key, r_owner).
/// This is the value stored inside each note and constrained by VALID_SPEND.
pub fn owner_commitment(spending_key: &Fr, r_owner: &Fr) -> Result<[u8; 32], CryptoError> {
    let h = poseidon_hash(&[Fr::from(DOMAIN_OWNER), *spending_key, *r_owner])?;
    Ok(fr_to_be_bytes(&h))
}

/// v2 note commitment: `Poseidon6(DOMAIN_NOTE, mint_lo, mint_hi, amount,
/// owner_commitment, inner_hash)`. A single `inner_hash` carries the per-note
/// blinding (the retired v1 construction used a separate `nonce`/`blinding_r`
/// pair) while keeping the mint binding. Pairs with
/// [`crate::nullifier::nullifier_v2`].
///
/// `inner_hash` is a canonical BN254 `Fr` (32 BE bytes) — typically derived
/// client-side via [`crate::keys::derive_inner_hash`].
pub fn commitment_from_fields_v2(
    token_mint: &[u8; 32],
    amount: u64,
    owner_commitment: &[u8; 32],
    inner_hash: &[u8; 32],
) -> Result<NoteCommitment, CryptoError> {
    use crate::field::fr_from_be_bytes;

    let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
    let amount_fr = u64_to_fr(amount);
    let owner_fr = fr_from_be_bytes(owner_commitment)?;
    let inner_fr = fr_from_be_bytes(inner_hash)?;

    let inputs: [Fr; 6] = [
        Fr::from(DOMAIN_NOTE),
        mint_lo,
        mint_hi,
        amount_fr,
        owner_fr,
        inner_fr,
    ];
    let h = poseidon_hash(&inputs)?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner(seed: u8) -> [u8; 32] {
        // Fr-safe: small value in the low byte, zero top bytes.
        let mut v = [0u8; 32];
        v[31] = seed;
        v
    }

    #[test]
    fn commitment_v2_deterministic() {
        let mint = [1u8; 32];
        let owner = [2u8; 32];
        let ih = inner(7);
        let c1 = commitment_from_fields_v2(&mint, 100, &owner, &ih).unwrap();
        let c2 = commitment_from_fields_v2(&mint, 100, &owner, &ih).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_v2_distinguishes_amount_mint_owner_inner() {
        let mint = [1u8; 32];
        let owner = [2u8; 32];
        let base = commitment_from_fields_v2(&mint, 100, &owner, &inner(7)).unwrap();
        // amount
        assert_ne!(
            base,
            commitment_from_fields_v2(&mint, 101, &owner, &inner(7)).unwrap()
        );
        // mint
        let mut mint2 = mint;
        mint2[0] = 0xaa;
        assert_ne!(
            base,
            commitment_from_fields_v2(&mint2, 100, &owner, &inner(7)).unwrap()
        );
        // owner
        let mut owner2 = owner;
        owner2[31] = 3;
        assert_ne!(
            base,
            commitment_from_fields_v2(&mint, 100, &owner2, &inner(7)).unwrap()
        );
        // inner_hash
        assert_ne!(
            base,
            commitment_from_fields_v2(&mint, 100, &owner, &inner(8)).unwrap()
        );
    }
}
