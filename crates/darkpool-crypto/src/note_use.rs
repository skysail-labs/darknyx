//! The public note-consumption handle.
//!
//! # What this replaces, and why
//!
//! `note_commitment` used to play two roles: the Merkle-leaf identity of a note,
//! AND the public handle every consumption path keyed on — the `NoteLock` and
//! `ConsumedNoteEntry` PDA seeds, the `lock_note` / `withdraw` / `merge`
//! instruction arguments, and the consumed slots of the settle payload.
//!
//! Because the same 32 bytes appeared at deposit, at lock, at settle and at
//! withdraw, a chain observer reconstructed a note's entire lineage by
//! string-matching. Unlike a classic shielded pool, no spend published an
//! unlinkable nullifier: `withdraw` published the commitment *and* the
//! nullifier, and the settle's consume guard was commitment-keyed. So the
//! deposit -> trade -> withdrawal chain was fully traceable, rooted at a public
//! depositor with a public gross amount.
//!
//! The commitment now appears exactly ONCE in a note's life — when it is created
//! as a Merkle leaf. Everything downstream references this tag instead.
//!
//! # Why the commitment is an input, and not just the inner hash
//!
//! ```text
//! note_use_tag = Poseidon3(29, note_commitment, inner_hash)
//! ```
//!
//! An earlier draft used `Poseidon2(29, inner_hash)`. That is **unsound**, and
//! the reason is worth keeping here because it is not obvious.
//!
//! The commitment is what binds a note's fields together:
//! `C = Poseidon6(2, mint_lo, mint_hi, amount, owner_commitment, inner_hash)`.
//! In `VALID_MATCH_BATCH` the input commitment is a *private* witness
//! constrained by `is_active * (note_a_commitment - hashA.out) === 0`, and it
//! reaches the chain only through the batch leaf. So the published commitment is
//! the sole anchor tying `a_amount` / `a_owner_commit` / mint to the note that
//! was actually locked.
//!
//! Key the handle on `inner_hash` alone and `a_amount` becomes a free witness: a
//! prover supplies the real inner (so the lock PDA exists) with an inflated
//! amount, every constraint is satisfied, conservation is checked against the
//! inflated figure, and the outputs mint value. That is exactly the hole
//! `lock_note.rs` records `VALID_INPUT` as having closed, reopened one layer
//! down at settle instead of at lock.
//!
//! Feeding the commitment in restores the binding: change any field and `C`
//! changes, so the tag changes, so the lock PDA does not exist.
//!
//! # Why it is unlinkable
//!
//! An observer holds `note_commitment` — it is a public Merkle leaf. They do not
//! hold `inner_hash`, which is private to the owner and the enclave. Preimage
//! resistance does the rest.
//!
//! The strength of that therefore reduces to the secrecy of `inner_hash`. For a
//! deposit note the inner is `Poseidon3(33, recovery_nonce, note_secret)` — see
//! [`crate::deposit`] for why the secret input exists and what breaks without
//! it.

use crate::errors::CryptoError;
use crate::field::{fr_from_be_bytes, fr_to_be_bytes, Fr};
use crate::note::NoteCommitment;
use crate::poseidon::poseidon_hash;

/// Domain tag for the note-use handle.
///
/// Domain numbers are never reused, including retired assignments. The
/// authoritative lifecycle and consumer list lives in
/// `docs/privacy-architecture/domain-registry.json`.
pub const DOMAIN_NOTE_USE: u64 = 29;

/// Circuit-derived public consumption handle. It is intentionally not
/// interchangeable with [`NoteCommitment`] even though both serialize as 32
/// bytes.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoteUseTag([u8; 32]);

impl NoteUseTag {
    /// Check and wrap raw wire bytes at an instruction/API boundary.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        fr_from_be_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Derive the public consumption handle for a note.
///
/// Both inputs must be BN254 field elements. `note_commitment` is a Poseidon
/// output and `inner_hash` is either a Poseidon output or a deposit-derived
/// inner, so both are Fr-safe by construction; a non-canonical value here means
/// a caller built one by hand and is a bug worth surfacing rather than reducing.
pub fn note_use_tag(
    note_commitment: &NoteCommitment,
    inner_hash: &[u8; 32],
) -> Result<NoteUseTag, CryptoError> {
    let commitment = fr_from_be_bytes(note_commitment.as_bytes())?;
    let inner = fr_from_be_bytes(inner_hash)?;
    let hash = poseidon_hash(&[Fr::from(DOMAIN_NOTE_USE), commitment, inner])?;
    Ok(NoteUseTag(fr_to_be_bytes(&hash)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::commitment_from_fields_v2;

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    #[test]
    fn deterministic_and_domain_separated() {
        let c7 = NoteCommitment::from_bytes(scalar(7)).unwrap();
        let c8 = NoteCommitment::from_bytes(scalar(8)).unwrap();
        let tag = note_use_tag(&c7, &scalar(9)).unwrap();
        assert_eq!(tag, note_use_tag(&c7, &scalar(9)).unwrap());
        assert_ne!(tag, note_use_tag(&c7, &scalar(10)).unwrap());
        assert_ne!(tag, note_use_tag(&c8, &scalar(9)).unwrap());
    }

    /// The two inputs must not be interchangeable — a tag that ignored argument
    /// order would collide across unrelated notes.
    #[test]
    fn argument_order_matters() {
        let c7 = NoteCommitment::from_bytes(scalar(7)).unwrap();
        let c9 = NoteCommitment::from_bytes(scalar(9)).unwrap();
        assert_ne!(
            note_use_tag(&c7, &scalar(9)).unwrap(),
            note_use_tag(&c9, &scalar(7)).unwrap()
        );
    }

    /// THE property the whole construction exists for: the tag binds every field
    /// of the note, not just its inner hash.
    ///
    /// Perturb amount, mint, owner and inner one at a time. Each must move the
    /// tag. A tag derived from `inner_hash` alone passes the inner case and
    /// FAILS the other three — which is precisely the value-inflation hole:
    /// the settle could then claim any amount against a real lock.
    #[test]
    fn the_tag_binds_every_field_of_the_note() {
        let mint = scalar(0x11);
        let owner = scalar(0x22);
        let inner = scalar(0x33);
        let amount = 1_000u64;

        let base_c = commitment_from_fields_v2(&mint, amount, &owner, &inner).unwrap();
        let base = note_use_tag(&base_c, &inner).unwrap();

        // Amount — the substitution attack from review: same inner, bigger value.
        let inflated_c = commitment_from_fields_v2(&mint, 10_000, &owner, &inner).unwrap();
        assert_ne!(
            base,
            note_use_tag(&inflated_c, &inner).unwrap(),
            "an inflated amount must not reuse the tag of a real lock"
        );

        // Owner — otherwise one user could spend against another's lock.
        let other_owner_c =
            commitment_from_fields_v2(&mint, amount, &scalar(0x23), &inner).unwrap();
        assert_ne!(base, note_use_tag(&other_owner_c, &inner).unwrap());

        // Mint — otherwise a quote note could be consumed as a base note.
        let other_mint_c =
            commitment_from_fields_v2(&scalar(0x12), amount, &owner, &inner).unwrap();
        assert_ne!(base, note_use_tag(&other_mint_c, &inner).unwrap());

        // Inner — distinct notes of identical value stay distinct.
        let other_inner = scalar(0x34);
        let other_inner_c = commitment_from_fields_v2(&mint, amount, &owner, &other_inner).unwrap();
        assert_ne!(base, note_use_tag(&other_inner_c, &other_inner).unwrap());
    }

    /// Unlinkability, stated as a test: the commitment alone is not enough.
    ///
    /// An observer has the leaf. If the tag were computable from it, the whole
    /// change would be decorative. This asserts the secret input is
    /// load-bearing by showing one commitment yields different tags under
    /// different inners.
    #[test]
    fn the_commitment_alone_does_not_determine_the_tag() {
        let c = NoteCommitment::from_bytes(scalar(0x55)).unwrap();
        assert_ne!(
            note_use_tag(&c, &scalar(1)).unwrap(),
            note_use_tag(&c, &scalar(2)).unwrap(),
            "the tag must depend on the private inner, not only on the public leaf"
        );
    }

    #[test]
    fn rejects_non_field_inputs() {
        assert!(NoteCommitment::from_bytes([0xff; 32]).is_err());
        let c = NoteCommitment::from_bytes(scalar(1)).unwrap();
        assert!(note_use_tag(&c, &[0xff; 32]).is_err());
        assert!(NoteUseTag::from_bytes([0xff; 32]).is_err());
    }
}
