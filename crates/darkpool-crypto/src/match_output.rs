//! Canonical inner-hash derivation for VALID_MATCH_BATCH v3 outputs.
//!
//! User outputs derive from the consumed input's opening; protocol fee outputs
//! derive from a governed epoch key plus the consumed input's proof-bound use
//! tag. This removes prover-selected randomness without making fee-note lineage
//! testable from public commitments.
//!
//! The derivation is load-bearing for spendability, not just for uniqueness: an
//! owner re-derives these inners from their own consumed input in order to spend
//! the outputs later. A divergence produces notes nobody can reconstruct, and it
//! fails as a parity assertion rather than at runtime here.
//!
//! Mirrored by `packages/sdk/tests/helpers/e2e-helpers.ts::deriveInner` and pinned
//! by `match-output-parity.test.ts` and `inner-hash-parity.test.ts`.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::note_use::NoteUseTag;
use crate::poseidon::poseidon_hash;

pub const DOMAIN_MATCH_OUTPUT_INNER: u64 = 24;
pub const DOMAIN_FEE_KEY_BINDING: u64 = 35;
pub const DOMAIN_FEE_INNER_V2: u64 = 36;

pub fn match_output_inner_hash(input_inner: &[u8; 32], role: u8) -> Result<[u8; 32], CryptoError> {
    let input = fr_from_be_bytes(input_inner)?;
    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_MATCH_OUTPUT_INNER),
        input,
        Fr::from(role as u64),
    ])?;
    Ok(fr_to_be_bytes(&hash))
}

pub fn fee_key_binding(fee_epoch_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let key = fr_from_be_bytes(fee_epoch_key)?;
    let hash = poseidon_hash(&[Fr::from(DOMAIN_FEE_KEY_BINDING), key])?;
    Ok(fr_to_be_bytes(&hash))
}

pub fn match_fee_inner_hash(
    fee_epoch_key: &[u8; 32],
    input_use_tag: &NoteUseTag,
    role: u8,
) -> Result<[u8; 32], CryptoError> {
    let key = fr_from_be_bytes(fee_epoch_key)?;
    let input = fr_from_be_bytes(input_use_tag.as_bytes())?;
    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_FEE_INNER_V2),
        key,
        input,
        Fr::from(role as u64),
    ])?;
    Ok(fr_to_be_bytes(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = n;
        value
    }

    #[test]
    fn derivations_are_deterministic_and_domain_separated() {
        let input = scalar(7);
        let output = match_output_inner_hash(&input, 0xC1).unwrap();
        let tag = NoteUseTag::from_bytes(input).unwrap();
        let fee = match_fee_inner_hash(&scalar(9), &tag, 0xC1).unwrap();
        assert_eq!(
            hex::encode(output),
            "13e02ab830905bd6a94bbf1c9c1d231150db9ee480d9cd2b596a1fc425c6dde0"
        );
        assert_eq!(output, match_output_inner_hash(&input, 0xC1).unwrap());
        assert_ne!(output, fee);
        assert_ne!(output, match_output_inner_hash(&input, 0xD1).unwrap());
    }

    #[test]
    fn cs08_distinct_consumed_inputs_cannot_reuse_fee_inner_across_pages_or_reboots() {
        assert_ne!(
            match_fee_inner_hash(
                &scalar(9),
                &NoteUseTag::from_bytes(scalar(1)).unwrap(),
                0xFB
            )
            .unwrap(),
            match_fee_inner_hash(
                &scalar(9),
                &NoteUseTag::from_bytes(scalar(2)).unwrap(),
                0xFB
            )
            .unwrap()
        );
    }

    #[test]
    fn fee_v2_matches_phase_zero_vectors() {
        let key = scalar_u64(4004);
        assert_eq!(
            hex::encode(fee_key_binding(&key).unwrap()),
            "0dea674cc22c4550b60604faaa62edd0ce4fe22ca4b38ebe24506cc9795faa19"
        );
        let tag = NoteUseTag::from_bytes(scalar_u64(5005)).unwrap();
        assert_eq!(
            hex::encode(match_fee_inner_hash(&key, &tag, 2).unwrap()),
            "25b0e3d61c48456c00303a06d9dcea509389561a8e9f379cb694fec042a769e4"
        );
    }

    #[test]
    fn fee_inner_requires_the_epoch_secret_not_only_public_chain_data() {
        let public_use_tag = NoteUseTag::from_bytes(scalar_u64(5005)).unwrap();
        let first = match_fee_inner_hash(&scalar_u64(4004), &public_use_tag, 2).unwrap();
        let second = match_fee_inner_hash(&scalar_u64(4005), &public_use_tag, 2).unwrap();
        assert_ne!(first, second);
        assert_ne!(
            fee_key_binding(&scalar_u64(4004)).unwrap(),
            fee_key_binding(&scalar_u64(4005)).unwrap()
        );
    }

    fn scalar_u64(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
}
