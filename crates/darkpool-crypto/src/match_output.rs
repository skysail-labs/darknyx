//! Canonical inner-hash derivation for VALID_MATCH_BATCH v3 outputs.
//!
//! User outputs derive from the consumed input opening; protocol fee outputs
//! derive from the consumed input commitment. This removes prover-selected
//! output randomness and makes every fee note unique to the value it consumes.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

pub const DOMAIN_MATCH_OUTPUT_INNER: u64 = 24;
pub const DOMAIN_MATCH_FEE_INNER: u64 = 25;

pub fn match_output_inner_hash(input_inner: &[u8; 32], role: u8) -> Result<[u8; 32], CryptoError> {
    let input = fr_from_be_bytes(input_inner)?;
    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_MATCH_OUTPUT_INNER),
        input,
        Fr::from(role as u64),
    ])?;
    Ok(fr_to_be_bytes(&hash))
}

pub fn match_fee_inner_hash(
    input_commitment: &[u8; 32],
    role: u8,
) -> Result<[u8; 32], CryptoError> {
    let input = fr_from_be_bytes(input_commitment)?;
    let hash = poseidon_hash(&[
        Fr::from(DOMAIN_MATCH_FEE_INNER),
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
        let fee = match_fee_inner_hash(&input, 0xC1).unwrap();
        assert_eq!(
            hex::encode(output),
            "13e02ab830905bd6a94bbf1c9c1d231150db9ee480d9cd2b596a1fc425c6dde0"
        );
        assert_eq!(
            hex::encode(fee),
            "18b28713db5e2e0ebd3a8382ca32d363811d5d2bf4244e916330204be6484c74"
        );
        assert_eq!(output, match_output_inner_hash(&input, 0xC1).unwrap());
        assert_ne!(output, fee);
        assert_ne!(output, match_output_inner_hash(&input, 0xD1).unwrap());
    }

    #[test]
    fn cs08_distinct_consumed_inputs_cannot_reuse_fee_inner_across_pages_or_reboots() {
        assert_ne!(
            match_fee_inner_hash(&scalar(1), 0xFB).unwrap(),
            match_fee_inner_hash(&scalar(2), 0xFB).unwrap()
        );
    }
}
