//! Deterministic inner-hash derivation for VALID_MERGE outputs.
//!
//! The output inner derives from the exact commitment slots the proof consumes,
//! not from mutable client state:
//!
//! ```text
//!   Poseidon6(DOMAIN_MERGE_INNER = 26, c0, c1, c2, c3, active_bitmap)
//! ```
//!
//! Binding to the consumed slots is what stops a merge output being re-derived
//! against a different input set. `active_bitmap` is part of the preimage, so the
//! K=2 and K=4 circuits cannot produce the same inner from the same slots.
//!
//! Pinned by `merge-inner-parity.test.ts` via `examples/merge-inner-hash`, and by
//! `merge-prover.test.ts` against the circuit itself.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

pub const DOMAIN_MERGE_INNER: u64 = 26;

/// Derive the merged output's canonical BN254 inner hash.
///
/// Commitment slots are always four-wide. Inactive slots must be zero and
/// active slots must be non-zero, exactly matching VALID_MERGE's public-output
/// convention. `active_bitmap` uses bit `i` for commitment slot `i`.
pub fn merge_output_inner_hash(
    input_commitments: &[[u8; 32]; 4],
    active_bitmap: u8,
) -> Result<[u8; 32], CryptoError> {
    if active_bitmap == 0 || active_bitmap & !0x0f != 0 {
        return Err(CryptoError::InvalidMergeInput);
    }

    let mut commitments = [Fr::from(0u64); 4];
    for (i, commitment) in input_commitments.iter().enumerate() {
        let active = active_bitmap & (1 << i) != 0;
        if active == (*commitment == [0u8; 32]) {
            return Err(CryptoError::InvalidMergeInput);
        }
        if active {
            commitments[i] = fr_from_be_bytes(commitment)?;
        }
    }

    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_MERGE_INNER),
        commitments[0],
        commitments[1],
        commitments[2],
        commitments[3],
        Fr::from(active_bitmap as u64),
    ])?;
    Ok(fr_to_be_bytes(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    #[test]
    fn deterministic_and_slot_ordered() {
        let inputs = [commitment(1), commitment(2), [0u8; 32], [0u8; 32]];
        let a = merge_output_inner_hash(&inputs, 0b0011).unwrap();
        let b = merge_output_inner_hash(&inputs, 0b0011).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            hex::encode(a),
            "1ed62782faeb9cd43f741e189ade09a0406a22f9c633cb9311b00e692c1458d5"
        );

        let reversed = [commitment(2), commitment(1), [0u8; 32], [0u8; 32]];
        assert_ne!(a, merge_output_inner_hash(&reversed, 0b0011).unwrap());
    }

    #[test]
    fn rejects_noncanonical_bitmap_and_padding() {
        let inputs = [commitment(1), commitment(2), [0u8; 32], [0u8; 32]];
        assert!(matches!(
            merge_output_inner_hash(&inputs, 0),
            Err(CryptoError::InvalidMergeInput)
        ));
        assert!(matches!(
            merge_output_inner_hash(&inputs, 0b1_0011),
            Err(CryptoError::InvalidMergeInput)
        ));
        assert!(matches!(
            merge_output_inner_hash(&inputs, 0b0001),
            Err(CryptoError::InvalidMergeInput)
        ));
    }
}
