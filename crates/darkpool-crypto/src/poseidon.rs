//! Poseidon hashing over BN254.
//!
//! We delegate to `light-poseidon` which is byte-compatible with:
//! - the on-chain `sol_poseidon` syscall (same parameter set, same endianness)
//! - circomlib's `poseidon.circom` (same round constants & MDS, modulo endianness
//!   conversions handled by snarkjs when producing witness inputs)
//!
//! The on-chain verifier (vault program) will call `solana_poseidon::hashv`
//! directly. This crate exposes an equivalent API so that off-chain computation
//! produces the same result.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr, FR_BYTES};
#[cfg(not(target_os = "solana"))]
use light_poseidon::{Poseidon, PoseidonBytesHasher};
#[cfg(target_os = "solana")]
use solana_poseidon::{hashv, Endianness, Parameters};

/// Hash a sequence of BN254 field elements and return the resulting field element.
///
/// Supported arities: 1..=12 (light-poseidon / BN254 Poseidon spec).
pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, CryptoError> {
    let bytes = poseidon_hash_bytes(&inputs.iter().map(fr_to_be_bytes).collect::<Vec<_>>())?;
    fr_from_be_bytes(&bytes)
}

/// Hash a sequence of 32-byte big-endian field encodings and return 32 big-endian bytes.
/// This is the canonical low-level form used across all three environments.
pub fn poseidon_hash_bytes(inputs: &[[u8; FR_BYTES]]) -> Result<[u8; FR_BYTES], CryptoError> {
    #[cfg(target_os = "solana")]
    {
        let input_refs: Vec<&[u8]> = inputs.iter().map(|b| b.as_slice()).collect();
        let out = hashv(Parameters::Bn254X5, Endianness::BigEndian, &input_refs)
            .map_err(|e| CryptoError::Poseidon(format!("hash syscall: {:?}", e)))?;
        return Ok(out.to_bytes());
    }

    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).map_err(|e| {
            CryptoError::Poseidon(format!("init (arity {}): {:?}", inputs.len(), e))
        })?;
        let input_refs: Vec<&[u8]> = inputs.iter().map(|b| b.as_slice()).collect();
        let out = hasher
            .hash_bytes_be(&input_refs)
            .map_err(|e| CryptoError::Poseidon(format!("hash: {:?}", e)))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn poseidon_1_deterministic() {
        let a = Fr::from(1u64);
        let h1 = poseidon_hash(&[a]).unwrap();
        let h2 = poseidon_hash(&[a]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_2_distinguishes_inputs() {
        let h_ab = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
        let h_ba = poseidon_hash(&[Fr::from(2u64), Fr::from(1u64)]).unwrap();
        assert_ne!(h_ab, h_ba, "order must matter");
    }

    #[test]
    fn poseidon_zero_not_zero() {
        let h = poseidon_hash(&[Fr::zero()]).unwrap();
        assert_ne!(h, Fr::zero(), "hash of zero must not be zero");
    }

    #[test]
    fn poseidon_6_arity_matches_note_commitment_use() {
        // Note commitment uses arity 6 in the circuit (tokenMint[lo], tokenMint[hi],
        // amount, ownerCommitment, nonce, blindingR). Make sure we can do arity 6.
        let inputs = (0..6).map(|i| Fr::from((i + 1) as u64)).collect::<Vec<_>>();
        let h = poseidon_hash(&inputs).unwrap();
        assert_ne!(h, Fr::zero());
    }
}
