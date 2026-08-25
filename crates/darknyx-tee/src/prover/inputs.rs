//! Snarkjs-format public-input vector assembly.
//!
//! VALID_MATCH_BATCH exposes two public inputs: the batch root and a governed
//! config digest over fee/protocol values, mint halves, and price scale.
//!
//! `groth16-solana` expects each public input as a 32-byte big-
//! endian field-element encoding — the same shape `bn254ToBE32`
//! produces on the TS side.

use super::leaf::{build_batch_merkle_paths, compute_batch_leaf, BatchMerklePaths, LeafError};
use super::witness::MatchSlotWitness;
use darkpool_crypto::match_config_digest;

/// Computed leaves + root + the two-element public-input vector,
/// in the wire shape `groth16-solana` consumes.
#[derive(Debug, Clone)]
pub struct BatchPublicInputs {
    /// Per-slot leaf hashes in input order.
    pub leaves: Vec<[u8; 32]>,
    /// Merkle root over `leaves`. Equals `public_inputs_be[0]`.
    pub merkle_root: [u8; 32],
    /// Poseidon8 digest of the authoritative protocol + market preimage.
    pub config_digest: [u8; 32],
    /// The same single tree build retained as all fixed-width settlement paths.
    /// Consumers must not hash the levels again per match.
    pub merkle_paths: BatchMerklePaths,
    /// snarkjs-format public input vector in circuit order.
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
    let merkle_paths = build_batch_merkle_paths(&leaves)?;
    let merkle_root = merkle_paths.root();
    // Batch-level values (identical on every ACTIVE slot); read from slot 0.
    // Reject drift before the expensive witness/prove path. ORDER
    // must match the config-digest preimage order.
    let fee_rate_bps = slots[0].fee_rate_bps;
    let protocol_owner = slots[0].protocol_owner_commitment;
    let base_mint = slots[0].base_mint;
    let quote_mint = slots[0].quote_mint;
    let price_scale = slots[0].price_scale;
    let fee_key_binding = slots[0].fee_key_binding;
    let fee_key_epoch = slots[0].fee_key_epoch;
    for (idx, slot) in slots.iter().enumerate().filter(|(_, slot)| slot.is_active) {
        if slot.fee_rate_bps != fee_rate_bps
            || slot.protocol_owner_commitment != protocol_owner
            || slot.base_mint != base_mint
            || slot.quote_mint != quote_mint
            || slot.price_scale != price_scale
            || slot.fee_key_binding != fee_key_binding
            || slot.fee_key_epoch != fee_key_epoch
        {
            return Err(LeafError::MixedBatchConfig { idx });
        }
    }
    let config_digest = match_config_digest(
        fee_rate_bps,
        &protocol_owner,
        &base_mint,
        &quote_mint,
        price_scale,
        &fee_key_binding,
        fee_key_epoch,
    )?;
    Ok(BatchPublicInputs {
        leaves,
        merkle_root,
        config_digest,
        merkle_paths,
        public_inputs_be: vec![merkle_root, config_digest],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::dummy_slot;

    #[test]
    fn public_input_vector_binds_market_config() {
        let mut slots = vec![dummy_slot(); 4];
        slots[0].fee_rate_bps = 30;
        slots[0].price_scale = 100_000_000;
        slots[0].base_mint = [0x22; 32];
        slots[0].quote_mint = [0x33; 32];
        let owner = {
            let mut o = [0x11u8; 32];
            o[0] = 0; // Fr-safe
            o
        };
        slots[0].protocol_owner_commitment = owner;
        slots[0].fee_key_binding = [0x04; 32];
        slots[0].fee_key_binding[0] = 0;
        slots[0].fee_key_epoch = 7;
        let pi = build_batch_public_inputs(&slots).unwrap();
        assert_eq!(pi.leaves.len(), 4);
        assert_eq!(pi.merkle_paths.root(), pi.merkle_root);
        assert_eq!(pi.merkle_paths.internal_hash_count(), 3);
        assert_eq!(pi.public_inputs_be.len(), 2);
        assert_eq!(pi.public_inputs_be[0], pi.merkle_root);
        assert_eq!(pi.public_inputs_be[1], pi.config_digest);
        assert_eq!(
            pi.config_digest,
            match_config_digest(
                30,
                &owner,
                &[0x22; 32],
                &[0x33; 32],
                100_000_000,
                &slots[0].fee_key_binding,
                7,
            )
            .unwrap()
        );
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
