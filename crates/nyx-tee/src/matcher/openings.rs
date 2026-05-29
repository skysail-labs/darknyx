//! In-enclave input-note opening store.
//!
//! The VALID_MATCH_BATCH circuit opens each input note — it
//! re-derives `note_a_commitment` from the note's full opening
//! (`amount`, `owner_commitment`, `nonce`, `blinding`) and asserts
//! equality (`circuits/templates/match_batch.circom`, `hashA`). So
//! the in-TEE prover needs those secret fields, which the
//! `MatchPair` (commitments only) does not carry. They arrive with
//! the order ([`crate::api::orders`]), get verified against the
//! already-signed `note_commitment`, and live here — in enclave
//! memory only, keyed by `order_id` — until the settle worker
//! consumes them.
//!
//! Why this is safe to accept over the wire: the trading key signs
//! `note_commitment` (via `OrderCanonical`). We then check
//! `commitment_from_fields(opening) == note_commitment`. Poseidon is
//! collision-resistant, so a caller cannot substitute a different
//! opening that still hashes to the signed commitment — the opening
//! is cryptographically pinned to the signature WITHOUT having to
//! expand the canonical order encoding (and therefore without a
//! cross-language signing-contract change — CLAUDE.md §6).
//!
//! The `nullifier` is the exception: `nullifier =
//! Poseidon3(DOMAIN_NULL, spending_key, commitment)` needs the
//! user's spending key, which must NEVER enter the TEE. The user
//! precomputes it client-side and submits it; the matcher cannot
//! verify it (it lacks the spending key). A wrong nullifier is
//! self-harm only — on-chain replay protection keys the
//! `ConsumedNoteEntry` PDA off the note commitment, not the
//! nullifier, so a bad value cannot let anyone ELSE double-spend.
//!
//! Spending keys, viewing keys, and blinding-derivation seeds never
//! appear here — only the per-note opening fields the circuit
//! consumes as private witnesses.

use std::collections::HashMap;

use darkpool_crypto::note::commitment_from_fields;

/// The full opening of one input note — everything the
/// VALID_MATCH_BATCH circuit needs to re-derive its commitment, plus
/// the user-supplied nullifier the settle payload carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteOpening {
    /// SPL mint of the collateral note (quote mint for a bid, base
    /// mint for an ask). Split into an Fr pair at hash time.
    pub token_mint: [u8; 32],
    /// Committed note value. MUST equal the matcher's `note_amount`
    /// for the conservation constraint to hold — enforced by
    /// [`Self::verify_commitment`] (the commitment binds the amount).
    pub amount: u64,
    /// `Poseidon3(DOMAIN_OWNER=1, spending_key, r_owner)`. Distinct
    /// from the wallet `user_commitment`.
    pub owner_commitment: [u8; 32],
    /// Per-note nonce.
    pub nonce: [u8; 32],
    /// Per-note blinding factor `r`.
    pub blinding: [u8; 32],
    /// `Poseidon3(DOMAIN_NULL=3, spending_key, note_commitment)`,
    /// precomputed by the user. Opaque to the matcher.
    pub nullifier: [u8; 32],
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum OpeningError {
    /// The opening does not hash to the claimed (signed) commitment.
    #[error("opening does not match note_commitment (expected {expected}, computed {got})")]
    CommitmentMismatch { expected: String, got: String },
    /// A field wasn't a valid BN254 Fr element (top byte too large),
    /// so Poseidon couldn't hash it.
    #[error("opening field not Fr-safe: {0}")]
    NotFrSafe(String),
}

impl NoteOpening {
    /// Re-derive this note's commitment from its opening fields,
    /// using the exact same `darkpool_crypto::note::commitment_from_fields`
    /// the deposit path + the on-chain verifier + the TS SDK agree
    /// on. Errors if any field isn't a valid BN254 Fr element.
    pub fn commitment(&self) -> Result<[u8; 32], OpeningError> {
        commitment_from_fields(
            &self.token_mint,
            self.amount,
            &self.owner_commitment,
            &self.nonce,
            &self.blinding,
        )
        .map_err(|e| OpeningError::NotFrSafe(e.to_string()))
    }

    /// Re-derive the note commitment from this opening and assert it
    /// equals `expected` (the trading-key-signed `note_commitment`).
    ///
    /// This is the byte-equality anchor: a passing check guarantees
    /// the prover will reconstruct the same commitment the circuit's
    /// `hashA`/`hashB` constraint expects.
    pub fn verify_commitment(&self, expected: &[u8; 32]) -> Result<(), OpeningError> {
        let got = self.commitment()?;
        if &got != expected {
            return Err(OpeningError::CommitmentMismatch {
                expected: hex::encode(expected),
                got: hex::encode(got),
            });
        }
        Ok(())
    }
}

/// Per-order opening table. One entry per live order, keyed by the
/// 16-byte `order_id`. Inserted at intake (after the opening
/// verifies), read by the settle assembler (4g.7b), and removed on
/// cancel / expiry / settle so the table tracks the live book.
#[derive(Default, Debug)]
pub struct OpeningStore {
    map: HashMap<[u8; 16], NoteOpening>,
}

impl OpeningStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an order's verified opening. Overwrites any prior entry
    /// for the same `order_id` (the book rejects duplicate live ids,
    /// so in practice this only fires on a re-lock rotation that
    /// reuses the id with a fresh change-note opening).
    pub fn insert(&mut self, order_id: [u8; 16], opening: NoteOpening) {
        self.map.insert(order_id, opening);
    }

    /// Fetch a clone of the opening for `order_id` (the assembler
    /// needs an owned copy it can move into a witness without holding
    /// the matcher lock across the proof).
    pub fn get(&self, order_id: &[u8; 16]) -> Option<NoteOpening> {
        self.map.get(order_id).cloned()
    }

    /// Drop an order's opening — on cancel, expiry, or after settle.
    /// Returns the removed opening, if any.
    pub fn remove(&mut self, order_id: &[u8; 16]) -> Option<NoteOpening> {
        self.map.remove(order_id)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_crypto::note::commitment_from_fields;

    // A deterministic, Fr-safe opening. `commitment_from_fields`
    // rejects non-Fr-safe field elements, so the owner/nonce/blinding
    // keep their top byte zeroed.
    fn sample_opening(amount: u64) -> NoteOpening {
        let mut owner = [0u8; 32];
        owner[31] = 0x11;
        let mut nonce = [0u8; 32];
        nonce[31] = 0x22;
        let mut blinding = [0u8; 32];
        blinding[31] = 0x33;
        let mut mint = [0u8; 32];
        mint[0] = 1;
        mint[31] = 0x9e;
        NoteOpening {
            token_mint: mint,
            amount,
            owner_commitment: owner,
            nonce,
            blinding,
            nullifier: [0xAB; 32],
        }
    }

    #[test]
    fn verify_commitment_accepts_matching_opening() {
        let o = sample_opening(1_000);
        // Compute the canonical commitment the same way the deposit
        // path / on-chain verifier would.
        let commitment = commitment_from_fields(
            &o.token_mint,
            o.amount,
            &o.owner_commitment,
            &o.nonce,
            &o.blinding,
        )
        .unwrap();
        assert!(o.verify_commitment(&commitment).is_ok());
    }

    #[test]
    fn verify_commitment_rejects_wrong_amount() {
        let o = sample_opening(1_000);
        let commitment = commitment_from_fields(
            &o.token_mint,
            o.amount,
            &o.owner_commitment,
            &o.nonce,
            &o.blinding,
        )
        .unwrap();
        // An opening that claims a different amount must not verify
        // against the same commitment — this is the check that pins
        // a_amount == note_amount.
        let mut tampered = o.clone();
        tampered.amount = 1_001;
        let err = tampered.verify_commitment(&commitment).unwrap_err();
        assert!(matches!(err, OpeningError::CommitmentMismatch { .. }));
    }

    #[test]
    fn verify_commitment_rejects_wrong_blinding() {
        let o = sample_opening(1_000);
        let commitment = commitment_from_fields(
            &o.token_mint,
            o.amount,
            &o.owner_commitment,
            &o.nonce,
            &o.blinding,
        )
        .unwrap();
        let mut tampered = o.clone();
        tampered.blinding[31] = 0x34;
        assert!(tampered.verify_commitment(&commitment).is_err());
    }

    #[test]
    fn verify_commitment_surfaces_non_fr_safe_field() {
        let mut o = sample_opening(1_000);
        // Top byte 0xFF makes the value exceed the BN254 modulus →
        // commitment_from_fields fails before any comparison.
        o.owner_commitment = [0xFF; 32];
        let err = o.verify_commitment(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, OpeningError::NotFrSafe(_)));
    }

    #[test]
    fn store_insert_get_remove() {
        let mut store = OpeningStore::new();
        assert!(store.is_empty());
        let id = [7u8; 16];
        let o = sample_opening(500);
        store.insert(id, o.clone());
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&id), Some(o.clone()));
        assert_eq!(store.get(&[9u8; 16]), None);
        assert_eq!(store.remove(&id), Some(o));
        assert!(store.is_empty());
    }
}
