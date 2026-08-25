//! Deterministic inner-hash derivation for VALID_MERGE outputs.
//!
//! The output inner derives from the private inners of the exact note slots the
//! proof consumes, not from public commitments or mutable client state:
//!
//! ```text
//!   Poseidon6(DOMAIN_MERGE_INNER_V2 = 34,
//!             inner0, inner1, inner2, inner3, active_bitmap)
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

pub const DOMAIN_MERGE_INNER_V2: u64 = 34;

/// Derive the merged output's canonical BN254 inner hash.
///
/// Inner slots are always four-wide. Inactive slots must be zero and
/// active slots must be non-zero, exactly matching VALID_MERGE's public-output
/// convention. `active_bitmap` uses bit `i` for commitment slot `i`.
pub fn merge_output_inner_hash(
    input_inners: &[[u8; 32]; 4],
    active_bitmap: u8,
) -> Result<[u8; 32], CryptoError> {
    if active_bitmap == 0 || active_bitmap & !0x0f != 0 {
        return Err(CryptoError::InvalidMergeInput);
    }

    let mut inners = [Fr::from(0u64); 4];
    for (i, inner) in input_inners.iter().enumerate() {
        let active = active_bitmap & (1 << i) != 0;
        if active == (*inner == [0u8; 32]) {
            return Err(CryptoError::InvalidMergeInput);
        }
        if active {
            inners[i] = fr_from_be_bytes(inner)?;
        }
    }

    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_MERGE_INNER_V2),
        inners[0],
        inners[1],
        inners[2],
        inners[3],
        Fr::from(active_bitmap as u64),
    ])?;
    Ok(fr_to_be_bytes(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    #[test]
    fn deterministic_and_slot_ordered() {
        let inputs = [scalar(1), scalar(2), [0u8; 32], [0u8; 32]];
        let a = merge_output_inner_hash(&inputs, 0b0011).unwrap();
        let b = merge_output_inner_hash(&inputs, 0b0011).unwrap();
        assert_eq!(a, b);
        let reversed = [scalar(2), scalar(1), [0u8; 32], [0u8; 32]];
        assert_ne!(a, merge_output_inner_hash(&reversed, 0b0011).unwrap());
    }

    #[test]
    fn rejects_noncanonical_bitmap_and_padding() {
        let inputs = [scalar(1), scalar(2), [0u8; 32], [0u8; 32]];
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

    #[test]
    fn matches_phase_zero_vector() {
        let inputs = [scalar(11), scalar(22), [0u8; 32], [0u8; 32]];
        assert_eq!(
            hex::encode(merge_output_inner_hash(&inputs, 0b0011).unwrap()),
            "29cc149632528880c9b9271d09833b6ee8a12b768b6f32471038f3191c1131f1"
        );
    }

    #[test]
    fn merge_lineage_requires_private_input_inners() {
        let first = [scalar(11), scalar(22), [0u8; 32], [0u8; 32]];
        let second = [scalar(11), scalar(23), [0u8; 32], [0u8; 32]];
        assert_ne!(
            merge_output_inner_hash(&first, 0b0011).unwrap(),
            merge_output_inner_hash(&second, 0b0011).unwrap()
        );
    }
}
