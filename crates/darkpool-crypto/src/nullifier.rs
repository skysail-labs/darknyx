//! Nullifier derivation.
//!
//! Formula (must be byte-identical across Rust, circom, on-chain):
//!
//! DOMAIN_NULL=3 is prepended to prevent second-preimage collisions with
//! owner_commitment (DOMAIN_OWNER=1) and note_commitment (DOMAIN_NOTE=2).
//!
//! ```text
//!     nullifier = Poseidon3( DOMAIN_NULL=3, spending_key_fr, note_commitment_fr )
//! ```
//!
//! Only the note owner (who knows the spending key) can compute this value.
//!
//! ## v2 (inner_hash) nullifier
//!
//! The v2 nullifier anchors on the note's `inner_hash` instead of its
//! commitment:
//!
//! ```text
//!     nullifier_v2 = Poseidon3( DOMAIN_NULL=3, spending_key_fr, inner_hash_fr )
//! ```
//!
//! Because `inner_hash` is amount-independent (unlike the commitment, which
//! contains the amount), the owner can compute this nullifier BEFORE the note's
//! amount is known — which is what lets a client pre-supply the nullifiers of
//! change notes it has not yet received (the per-order anchor pool). The
//! spending-key dependency is unchanged: only the owner can compute it. Pairs
//! with [`crate::note::commitment_from_fields_v2`].

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::note::NoteCommitment;
use crate::poseidon::poseidon_hash;

pub const NULLIFIER_BYTES: usize = 32;
pub type Nullifier = [u8; NULLIFIER_BYTES];

const DOMAIN_NULL: u64 = 3;

/// Compute the nullifier for a note given the spending key.
pub fn nullifier(
    spending_key: &Fr,
    note_commitment: &NoteCommitment,
) -> Result<Nullifier, CryptoError> {
    let c_fr = fr_from_be_bytes(note_commitment)?;
    let h = poseidon_hash(&[Fr::from(DOMAIN_NULL), *spending_key, c_fr])?;
    Ok(fr_to_be_bytes(&h))
}

/// v2 nullifier: `Poseidon3(DOMAIN_NULL, spending_key, inner_hash)`. Anchored on
/// the amount-independent `inner_hash` (32 BE bytes, a canonical BN254 `Fr`)
/// rather than the commitment, so it can be precomputed before the note amount
/// is known. See the module docs.
pub fn nullifier_v2(spending_key: &Fr, inner_hash: &[u8; 32]) -> Result<Nullifier, CryptoError> {
    let inner_fr = fr_from_be_bytes(inner_hash)?;
    let h = poseidon_hash(&[Fr::from(DOMAIN_NULL), *spending_key, inner_fr])?;
    Ok(fr_to_be_bytes(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_deterministic() {
        let sk = Fr::from(42u64);
        let c = [9u8; 32];
        // [9u8; 32] is not necessarily in-field; use a safer commitment
        let c_safe = {
            let mut v = [0u8; 32];
            v[31] = 9;
            v
        };
        let n1 = nullifier(&sk, &c_safe).unwrap();
        let n2 = nullifier(&sk, &c_safe).unwrap();
        assert_eq!(n1, n2);
        let _ = c;
    }

    #[test]
    fn nullifier_distinguishes_spending_key() {
        let c = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        let sk_a = Fr::from(1u64);
        let sk_b = Fr::from(2u64);
        assert_ne!(nullifier(&sk_a, &c).unwrap(), nullifier(&sk_b, &c).unwrap());
    }

    #[test]
    fn nullifier_distinguishes_commitment() {
        let sk = Fr::from(7u64);
        let c1 = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        let c2 = {
            let mut v = [0u8; 32];
            v[31] = 2;
            v
        };
        assert_ne!(nullifier(&sk, &c1).unwrap(), nullifier(&sk, &c2).unwrap());
    }

    // ── v2 (inner_hash) nullifier ─────────────────────────────────────────

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
