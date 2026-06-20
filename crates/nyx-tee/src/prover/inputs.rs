//! Snarkjs-format public-input vector assembly.
//!
//! VALID_MATCH_BATCH has exactly ONE public input: the Merkle root
//! over the per-slot leaves. The on-chain verifier
//! (`vault::verify_match_batch`) re-derives it from the recomputed
//! leaf of the match being settled and walks the inclusion path
//! committed in `BatchValidityMarker`.
//!
//! `groth16-solana` expects each public input as a 32-byte big-
//! endian field-element encoding — the same shape `bn254ToBE32`
//! produces on the TS side.

use super::leaf::{compute_batch_leaf, compute_batch_root, LeafError};
use super::witness::{u64_to_be32, MatchSlotWitness};

/// Computed leaves + root + the single-element public-input vector,
/// in the wire shape `groth16-solana` consumes.
#[derive(Debug, Clone)]
pub struct BatchPublicInputs {
    /// Per-slot leaf hashes in input order.
    pub leaves: Vec<[u8; 32]>,
    /// Merkle root over `leaves`. Equals `public_inputs_be[0]`.
    pub merkle_root: [u8; 32],
    /// snarkjs-format public inputs vector. One element for
    /// VALID_MATCH_BATCH. The on-chain verifier consumes the
    /// vector unchanged.
    pub public_inputs_be: Vec<[u8; 32]>,
}

/// Compute leaves + root + the public-input vector for a batch.
/// The caller must already have padded the batch up to the
/// circuit's N via `witness::pad_batch`.
pub fn build_batch_public_inputs(
    slots: &[MatchSlotWitness],
) -> Result<BatchPublicInputs, LeafError> {
    let n = slots.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(LeafError::InvalidBatchSize(n));
    }
    let leaves: Vec<[u8; 32]> = slots
        .iter()
        .map(compute_batch_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = compute_batch_root(&leaves)?;
    // Batch-level values (identical on every slot); read from slot 0. ORDER
    // must match the circuit `main` public list:
    // [merkle_root, fee_rate_bps, protocol_owner_commitment].
    let fee_rate_bps = slots[0].fee_rate_bps;
    let protocol_owner = slots[0].protocol_owner_commitment;
    Ok(BatchPublicInputs {
        leaves,
        merkle_root,
        public_inputs_be: vec![merkle_root, u64_to_be32(fee_rate_bps), protocol_owner],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::dummy_slot;

    #[test]
    fn public_input_vector_is_root_fee_rate_owner() {
        let mut slots = vec![dummy_slot(); 4];
        slots[0].fee_rate_bps = 30;
        let owner = {
            let mut o = [0x11u8; 32];
            o[0] = 0; // Fr-safe
            o
        };
        slots[0].protocol_owner_commitment = owner;
        let pi = build_batch_public_inputs(&slots).unwrap();
        assert_eq!(pi.leaves.len(), 4);
        // [merkle_root, fee_rate_bps, protocol_owner] — circuit `main` order.
        assert_eq!(pi.public_inputs_be.len(), 3);
        assert_eq!(pi.public_inputs_be[0], pi.merkle_root);
        let mut fee_be = [0u8; 32];
        fee_be[31] = 30;
        assert_eq!(pi.public_inputs_be[1], fee_be);
        assert_eq!(pi.public_inputs_be[2], owner);
    }

    #[test]
    fn non_power_of_two_rejected() {
        let slots = vec![dummy_slot(); 3];
        let err = build_batch_public_inputs(&slots).unwrap_err();
        assert!(matches!(err, LeafError::InvalidBatchSize(3)));
    }

    #[test]
    fn distinct_batches_produce_distinct_roots() {
        let mut a = dummy_slot();
        let mut b = dummy_slot();
        a.batch_slot = 1;
        b.batch_slot = 2;
        let pi_a = build_batch_public_inputs(&[a.clone(), a]).unwrap();
        let pi_b = build_batch_public_inputs(&[b.clone(), b]).unwrap();
        assert_ne!(pi_a.merkle_root, pi_b.merkle_root);
    }
}
