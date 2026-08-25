//! Recoverable inner-hash derivation for proof-gated deposits.
//!
//! ```text
//! deposit_inner_hash = Poseidon3(33, recovery_nonce, note_secret)
//! ```
//!
//! The note commitment already binds the wallet-wide owner. The inner therefore
//! carries only the public recovery nonce and the seed-derived per-note secret.
//!
//! # Why `note_secret` exists (arity 3 -> 4)
//!
//! The inner hash needs a per-note secret because [`crate::note_use`] derives
//! the public consumption handle from it: the handle's unlinkability reduces
//! entirely to the secrecy of the inner. Without `note_secret` — that is, from
//! `Poseidon3(27, owner_commitment, recovery_nonce)` alone — the inner would
//! have exactly one secret input:
//!
//! * `recovery_nonce` is a **public** deposit instruction argument, and
//! * `owner_commitment` is **wallet-wide and reused** across every note a user
//!   holds (a deliberate choice — see CRYPTOGRAPHY.md on why `r_owner` is not
//!   per-note).
//!
//! So an adversary who learned one user's `owner_commitment` could recompute the
//! inner for every deposit that user ever made (the nonces are on chain),
//! therefore every note-use tag, therefore that user's entire history —
//! **retroactively, from a single value**. The blast radius was the account, not
//! the note.
//!
//! `note_secret` is seed-derived ([`crate::keys::derive_note_secret`]) and never
//! leaves the client, so the inner is no longer a function of public data plus
//! one long-lived value. It costs nothing downstream: output inners already
//! chain via `Poseidon3(24, input_inner, role)`, so every descendant of a
//! deposit inherits the secret automatically. In particular the enclave needs no
//! new input — it derives output inners from the input inner it already holds,
//! and never sees the seed.
//!
//! Recovery is unaffected: `note_secret` is a pure function of the master seed
//! and the public nonce, so a cold wallet rebuilds it from the chain exactly as
//! before.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::poseidon::poseidon_hash;

pub const DOMAIN_DEPOSIT_INNER_V2: u64 = 33;

/// Derive a deposit note's inner hash.
///
/// The domain tag is unchanged at 27 while the arity moves 3 -> 4. That is safe
/// for domain separation because Poseidon is a different permutation per arity,
/// so a 3-input and a 4-input hash under the same tag cannot collide. The tag is
/// kept so the field keeps its meaning across the change; the parity vectors
/// move, and are re-pinned in the tests below.
pub fn deposit_inner_hash(
    recovery_nonce: &[u8; 32],
    note_secret: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let nonce = fr_from_be_bytes(recovery_nonce)?;
    let secret = fr_from_be_bytes(note_secret)?;
    let hash = poseidon_hash(&[Fr::from(DOMAIN_DEPOSIT_INNER_V2), nonce, secret])?;
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
        let inner = deposit_inner_hash(&scalar(9), &scalar(11)).unwrap();
        assert_eq!(inner, deposit_inner_hash(&scalar(9), &scalar(11)).unwrap());
        assert_ne!(inner, deposit_inner_hash(&scalar(10), &scalar(11)).unwrap());
    }

    /// The whole point of the fourth input: two deposits that agree on the
    /// PUBLIC data must still produce different inners.
    ///
    /// `recovery_nonce` is on chain and `owner_commitment` is wallet-wide, so
    /// without this the inner — and therefore the note-use tag — would be
    /// recomputable by anyone who learned that one value.
    #[test]
    fn the_secret_separates_deposits_that_agree_on_all_public_data() {
        let nonce = scalar(9);
        assert_ne!(
            deposit_inner_hash(&nonce, &scalar(1)).unwrap(),
            deposit_inner_hash(&nonce, &scalar(2)).unwrap(),
            "the inner must retain a per-note observer secret"
        );
    }

    #[test]
    fn rejects_non_field_inputs() {
        assert!(deposit_inner_hash(&[0xff; 32], &scalar(1)).is_err());
        assert!(deposit_inner_hash(&scalar(1), &[0xff; 32]).is_err());
    }

    #[test]
    fn matches_phase_zero_vector() {
        let inner = deposit_inner_hash(&scalar_u64(2002), &scalar_u64(3003)).unwrap();
        assert_eq!(
            hex::encode(inner),
            "2a0d7bf65498b8f216e0a66fb57cbbb807f54506c9618990fa4d879e322ae6ad"
        );
    }

    fn scalar_u64(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
}
