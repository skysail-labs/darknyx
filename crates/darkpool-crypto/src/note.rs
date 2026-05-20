//! UTXO note structure and commitment derivation.
//!
//! Note commitment formula (must be byte-identical across Rust, circom, on-chain):
//!
//! Domain tag DOMAIN_NOTE=2 is prepended as the first Poseidon input to prevent
//! second-preimage collisions with the owner-commitment and nullifier Poseidon
//! uses (which use DOMAIN_OWNER=1 and DOMAIN_NULL=3 respectively).
//!
//! ```text
//!     C(note) = Poseidon7(
//!         DOMAIN_NOTE=2,        // domain separation tag
//!         token_mint_lo_u128,   // Solana pubkey low 128 bits
//!         token_mint_hi_u128,   // Solana pubkey high 128 bits
//!         amount_u64,
//!         owner_commitment_fr,  // = Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)
//!         nonce_fr,
//!         blinding_r_fr,
//!     )
//! ```
//!
//! Reference: Section 23.1.2 of darkpool_protocol_spec_v3_changed.md

use crate::errors::CryptoError;
use crate::field::{fr_to_be_bytes, pubkey_to_fr_pair, u64_to_fr, Fr};
use crate::poseidon::poseidon_hash;
use borsh::{BorshDeserialize, BorshSerialize};

pub const NOTE_COMMITMENT_BYTES: usize = 32;

/// A UTXO note — the client's local representation of a shielded holding.
/// Only its 32-byte commitment is stored on-chain.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Note {
    /// SPL token mint (Solana pubkey, 32 bytes).
    pub token_mint: [u8; 32],
    /// Amount in base units (lamports for SOL, 1e6 for USDC, etc.).
    pub amount: u64,
    /// Owner commitment = Poseidon(spending_key, r_owner).
    pub owner_commitment: [u8; 32],
    /// Unique per-note nonce.
    pub nonce: [u8; 32],
    /// Random blinding factor (KMAC256-derived from master seed + counter).
    pub blinding_r: [u8; 32],
}

/// A note commitment — the 32-byte on-chain representation of a note.
pub type NoteCommitment = [u8; NOTE_COMMITMENT_BYTES];

impl Note {
    /// Compute this note's on-chain commitment.
    pub fn commitment(&self) -> Result<NoteCommitment, CryptoError> {
        commitment_from_fields(
            &self.token_mint,
            self.amount,
            &self.owner_commitment,
            &self.nonce,
            &self.blinding_r,
        )
    }
}

/// Compute a note commitment directly from its field components. Useful for
/// the vault program, which does not need to hold a full `Note` struct in
/// account state.
const DOMAIN_OWNER: u64 = 1;
const DOMAIN_NOTE: u64 = 2;

/// Compute the owner commitment: Poseidon3(DOMAIN_OWNER, spending_key, r_owner).
/// This is the value stored inside each note and constrained by VALID_SPEND.
pub fn owner_commitment(spending_key: &Fr, r_owner: &Fr) -> Result<[u8; 32], CryptoError> {
    let h = poseidon_hash(&[Fr::from(DOMAIN_OWNER), *spending_key, *r_owner])?;
    Ok(fr_to_be_bytes(&h))
}

pub fn commitment_from_fields(
    token_mint: &[u8; 32],
    amount: u64,
    owner_commitment: &[u8; 32],
    nonce: &[u8; 32],
    blinding_r: &[u8; 32],
) -> Result<NoteCommitment, CryptoError> {
    use crate::field::fr_from_be_bytes;

    let [mint_lo, mint_hi] = pubkey_to_fr_pair(token_mint);
    let amount_fr = u64_to_fr(amount);
    let owner_fr = fr_from_be_bytes(owner_commitment)?;
    let nonce_fr = fr_from_be_bytes(nonce)?;
    let blinding_fr = fr_from_be_bytes(blinding_r)?;

    let inputs: [Fr; 7] = [
        Fr::from(DOMAIN_NOTE),
        mint_lo,
        mint_hi,
        amount_fr,
        owner_fr,
        nonce_fr,
        blinding_fr,
    ];
    let h = poseidon_hash(&inputs)?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_note(amount: u64) -> Note {
        Note {
            token_mint: [1u8; 32],
            amount,
            owner_commitment: [2u8; 32],
            nonce: [3u8; 32],
            blinding_r: [4u8; 32],
        }
    }

    #[test]
    fn commitment_deterministic() {
        let n = dummy_note(100);
        assert_eq!(n.commitment().unwrap(), n.commitment().unwrap());
    }

    #[test]
    fn commitment_distinguishes_amount() {
        let a = dummy_note(100);
        let b = dummy_note(101);
        assert_ne!(a.commitment().unwrap(), b.commitment().unwrap());
    }

    #[test]
    fn commitment_distinguishes_mint() {
        let mut a = dummy_note(100);
        let mut b = dummy_note(100);
        a.token_mint[0] = 0xaa;
        b.token_mint[0] = 0xbb;
        assert_ne!(a.commitment().unwrap(), b.commitment().unwrap());
    }

    #[test]
    fn commitment_distinguishes_blinding() {
        let mut a = dummy_note(100);
        let mut b = dummy_note(100);
        a.blinding_r = [5u8; 32];
        b.blinding_r = [6u8; 32];
        assert_ne!(a.commitment().unwrap(), b.commitment().unwrap());
    }
}
