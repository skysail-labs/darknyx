//! Price commitment — `Poseidon3(DOMAIN_PRICE = 5, clearing_price, batch_slot)`.
//!
//! **Vestigial.** This binding belonged to the VALID_PRICE circuit, which was
//! retired: clearing-price binding is now carried inside VALID_MATCH_BATCH, and
//! `circuits/valid_price/` no longer exists. Nothing in the workspace calls
//! `price_commitment` — see `programs/vault/src/instructions/settlement_shared.rs`
//! for the note recording that `verify_valid_price` was subsumed by the batched
//! proof, and `circuits/templates/match_batch.circom` for where the binding lives
//! now.
//!
//! Retained only so a caller pinned to the old formula keeps compiling.
//! `packages/sdk/src/zk/price-commitment.ts` mirrors it and is equally unused.
//! Removing both is a code change, not a documentation one.

use crate::errors::CryptoError;
use crate::field::{fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

const DOMAIN_PRICE: u64 = 5;

/// Compute price_commitment = Poseidon3(DOMAIN_PRICE=5, clearing_price, batch_slot).
pub fn price_commitment(clearing_price: u64, batch_slot: u64) -> Result<[u8; 32], CryptoError> {
    let h = poseidon_hash(&[
        Fr::from(DOMAIN_PRICE),
        Fr::from(clearing_price),
        Fr::from(batch_slot),
    ])?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_commitment_deterministic() {
        let a = price_commitment(100, 42).unwrap();
        let b = price_commitment(100, 42).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn price_commitment_distinguishes_price() {
        let a = price_commitment(100, 42).unwrap();
        let b = price_commitment(101, 42).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn price_commitment_distinguishes_slot() {
        let a = price_commitment(100, 42).unwrap();
        let b = price_commitment(100, 43).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn price_commitment_zero_price_allowed() {
        let r = price_commitment(0, 0);
        assert!(r.is_ok());
    }
}
