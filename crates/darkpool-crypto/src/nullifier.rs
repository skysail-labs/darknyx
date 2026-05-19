//! Nullifier derivation.
//!
//! Formula (must be byte-identical across Rust, circom, on-chain):
//!
//! ```text
//!     nullifier = Poseidon2( spending_key_fr, note_commitment_fr )
//! ```
//!
//! The spending key is a BN254 field element; the note commitment is also a
//! field element. Only the note owner (who knows the spending key) can compute
//! this value.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::note::NoteCommitment;
use crate::poseidon::poseidon_hash;

pub const NULLIFIER_BYTES: usize = 32;
pub type Nullifier = [u8; NULLIFIER_BYTES];

/// Compute the nullifier for a note given the spending key.
pub fn nullifier(
    spending_key: &Fr,
    note_commitment: &NoteCommitment,
) -> Result<Nullifier, CryptoError> {
    let c_fr = fr_from_be_bytes(note_commitment)?;
    let h = poseidon_hash(&[*spending_key, c_fr])?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_deterministic() {
        let sk = Fr::from(42u64);
        let c = [9u8; 32];
        // [9u8; 32] is not necessarily in-field; use a safer commitment
        let c_safe = {
            let mut v = [0u8; 32];
            v[31] = 9;
            v
        };
        let n1 = nullifier(&sk, &c_safe).unwrap();
        let n2 = nullifier(&sk, &c_safe).unwrap();
        assert_eq!(n1, n2);
        let _ = c;
    }

    #[test]
    fn nullifier_distinguishes_spending_key() {
        let c = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        let sk_a = Fr::from(1u64);
        let sk_b = Fr::from(2u64);
        assert_ne!(nullifier(&sk_a, &c).unwrap(), nullifier(&sk_b, &c).unwrap());
    }

    #[test]
    fn nullifier_distinguishes_commitment() {
        let sk = Fr::from(7u64);
        let c1 = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        let c2 = {
            let mut v = [0u8; 32];
            v[31] = 2;
            v
        };
        assert_ne!(nullifier(&sk, &c1).unwrap(), nullifier(&sk, &c2).unwrap());
    }
}
