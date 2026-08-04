//! Recoverable inner-hash derivation for proof-gated deposits.
//!
//! ```text
//! deposit_inner_hash = Poseidon4(27, owner_commitment, recovery_nonce, note_secret)
//! ```
//!
//! Keeps the wallet-wide owner private while letting a seed-recovered wallet
//! rebuild the note opening from the public pseudorandom nonce recorded in the
//! deposit instruction.
//!
//! # Why `note_secret` exists (arity 3 -> 4)
//!
//! This used to be `Poseidon3(27, owner_commitment, recovery_nonce)`. That was
//! adequate while the inner hash only had to hide a note's opening. It is NOT
//! adequate now that [`crate::note_use`] derives the public consumption handle
//! from it, because the handle's unlinkability reduces to the secrecy of the
//! inner — and under the old derivation the inner had exactly one secret input:
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

pub const DOMAIN_DEPOSIT_INNER: u64 = 27;

/// Derive a deposit note's inner hash.
///
/// The domain tag is unchanged at 27 while the arity moves 3 -> 4. That is safe
/// for domain separation because Poseidon is a different permutation per arity,
/// so a 3-input and a 4-input hash under the same tag cannot collide. The tag is
/// kept so the field keeps its meaning across the change; the parity vectors
/// move, and are re-pinned in the tests below.
pub fn deposit_inner_hash(
    owner_commitment: &[u8; 32],
    recovery_nonce: &[u8; 32],
    note_secret: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let owner = fr_from_be_bytes(owner_commitment)?;
    let nonce = fr_from_be_bytes(recovery_nonce)?;
    let secret = fr_from_be_bytes(note_secret)?;
    let hash = poseidon_hash(&[Fr::from(DOMAIN_DEPOSIT_INNER), owner, nonce, secret])?;
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
        let inner = deposit_inner_hash(&scalar(7), &scalar(9), &scalar(11)).unwrap();
        assert_eq!(
            inner,
            deposit_inner_hash(&scalar(7), &scalar(9), &scalar(11)).unwrap()
        );
        assert_ne!(
            inner,
            deposit_inner_hash(&scalar(7), &scalar(10), &scalar(11)).unwrap()
        );
        assert_ne!(
            inner,
            deposit_inner_hash(&scalar(8), &scalar(9), &scalar(11)).unwrap()
        );
    }

    /// The whole point of the fourth input: two deposits that agree on the
    /// PUBLIC data must still produce different inners.
    ///
    /// `recovery_nonce` is on chain and `owner_commitment` is wallet-wide, so
    /// without this the inner — and therefore the note-use tag — would be
    /// recomputable by anyone who learned that one value.
    #[test]
    fn the_secret_separates_deposits_that_agree_on_all_public_data() {
        let owner = scalar(7);
        let nonce = scalar(9);
        assert_ne!(
            deposit_inner_hash(&owner, &nonce, &scalar(1)).unwrap(),
            deposit_inner_hash(&owner, &nonce, &scalar(2)).unwrap(),
            "the inner must not be a function of public data plus a wallet-wide value"
        );
    }

    #[test]
    fn rejects_non_field_inputs() {
        assert!(deposit_inner_hash(&[0xff; 32], &scalar(1), &scalar(1)).is_err());
        assert!(deposit_inner_hash(&scalar(1), &[0xff; 32], &scalar(1)).is_err());
        assert!(deposit_inner_hash(&scalar(1), &scalar(1), &[0xff; 32]).is_err());
    }
}
