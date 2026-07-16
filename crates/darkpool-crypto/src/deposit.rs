//! Recoverable inner-hash derivation for proof-gated deposits.
//!
//! `Poseidon3(27, owner_commitment, recovery_nonce)` keeps the wallet-wide
//! owner private while allowing a seed-recovered wallet to rebuild the note
//! opening from the public pseudorandom nonce recorded in the deposit ix.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

pub const DOMAIN_DEPOSIT_INNER: u64 = 27;

pub fn deposit_inner_hash(
    owner_commitment: &[u8; 32],
    recovery_nonce: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let owner = fr_from_be_bytes(owner_commitment)?;
    let nonce = fr_from_be_bytes(recovery_nonce)?;
    let hash = poseidon_hash(&[Fr::from(DOMAIN_DEPOSIT_INNER), owner, nonce])?;
    Ok(fr_to_be_bytes(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    #[test]
    fn deterministic_and_domain_separated() {
        let inner = deposit_inner_hash(&scalar(7), &scalar(9)).unwrap();
        assert_eq!(inner, deposit_inner_hash(&scalar(7), &scalar(9)).unwrap());
        assert_ne!(inner, deposit_inner_hash(&scalar(7), &scalar(10)).unwrap());
        assert_ne!(inner, deposit_inner_hash(&scalar(8), &scalar(9)).unwrap());
    }

    #[test]
    fn rejects_non_field_inputs() {
        assert!(deposit_inner_hash(&[0xff; 32], &scalar(1)).is_err());
        assert!(deposit_inner_hash(&scalar(1), &[0xff; 32]).is_err());
    }
}
