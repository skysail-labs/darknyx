//! Nullifier derivation.
//!
//! Formula (must be byte-identical across Rust, circom, on-chain). DOMAIN_NULL=3
//! is prepended to prevent second-preimage collisions with owner_commitment
//! (DOMAIN_OWNER=1) and note_commitment (DOMAIN_NOTE=2):
//!
//! ```text
//!     nullifier_v2 = Poseidon3( DOMAIN_NULL=3, spending_key_fr, inner_hash_fr )
//! ```
//!
//! The nullifier anchors on the note's amount-independent `inner_hash` (not its
//! commitment). Only the note owner (who knows the spending key) can compute
//! it. Pairs with
//! [`crate::note::commitment_from_fields_v2`]. (The pre-v2 v1 nullifier — anchored
//! on the note commitment — has been fully retired.)

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

pub const NULLIFIER_BYTES: usize = 32;
pub type Nullifier = [u8; NULLIFIER_BYTES];

const DOMAIN_NULL: u64 = 3;

/// v2 nullifier: `Poseidon3(DOMAIN_NULL, spending_key, inner_hash)`. Anchored on
/// the amount-independent `inner_hash` (32 BE bytes, a canonical BN254 `Fr`)
/// rather than the commitment. See the module docs.
pub fn nullifier_v2(spending_key: &Fr, inner_hash: &[u8; 32]) -> Result<Nullifier, CryptoError> {
    let inner_fr = fr_from_be_bytes(inner_hash)?;
    let h = poseidon_hash(&[Fr::from(DOMAIN_NULL), *spending_key, inner_fr])?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr_safe(seed: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[31] = seed;
        v
    }

    #[test]
    fn nullifier_v2_deterministic() {
        let sk = Fr::from(42u64);
        let ih = fr_safe(9);
        assert_eq!(
            nullifier_v2(&sk, &ih).unwrap(),
            nullifier_v2(&sk, &ih).unwrap()
        );
    }

    #[test]
    fn nullifier_v2_distinguishes_spending_key_and_inner() {
        let ih = fr_safe(1);
        assert_ne!(
            nullifier_v2(&Fr::from(1u64), &ih).unwrap(),
            nullifier_v2(&Fr::from(2u64), &ih).unwrap()
        );
        let sk = Fr::from(7u64);
        assert_ne!(
            nullifier_v2(&sk, &fr_safe(1)).unwrap(),
            nullifier_v2(&sk, &fr_safe(2)).unwrap()
        );
    }
}
