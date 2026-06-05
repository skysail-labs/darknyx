//! In-enclave input-note opening store.
//!
//! The VALID_MATCH_BATCH circuit opens each input note — it
//! re-derives `note_a_commitment` from the note's full opening
//! (`amount`, `owner_commitment`, `inner_hash`) and asserts
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
//! Poseidon3(DOMAIN_NULL, spending_key, inner_hash)` needs the
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

use darkpool_crypto::note::commitment_from_fields_v2;
pub use darkpool_matcher::order_canonical::Anchor;

use crate::settle::lock_note::Groth16ProofBytes;

/// Per-order pool of pre-supplied continuation anchors. The client
/// submits a fixed [`darkpool_matcher::order_canonical::ANCHOR_POOL_SIZE`]
/// pool with each order; the settle assembler consumes one anchor per
/// partial-fill change note (monotonic, single-use), so the residual's
/// change note carries a client-known `inner_hash` + a pre-computed
/// `nullifier` — which is what lets the matcher re-match the residual
/// without a per-fill roundtrip (Phase 6). Keyed by `order_id` (NOT the
/// collateral commitment, which rotates on each continuation).
#[derive(Clone, Debug, Default)]
pub struct AnchorPool {
    anchors: Vec<Anchor>,
    /// Index of the next unconsumed anchor (monotonic; single-use).
    next_index: usize,
    /// Set when the pool is exhausted and the matcher is awaiting a
    /// WebSocket top-up (Phase 7). A paused order is skipped by the tick.
    pub paused: bool,
    /// Highest `topup_nonce` accepted so far (Phase 7 replay protection).
    /// A top-up must carry a strictly greater nonce. 0 = none yet.
    pub last_topup_nonce: u64,
}

impl AnchorPool {
    pub fn new(anchors: Vec<Anchor>) -> Self {
        Self {
            anchors,
            next_index: 0,
            paused: false,
            last_topup_nonce: 0,
        }
    }

    /// Consume the next unconsumed anchor, advancing the cursor. Returns
    /// `(index, anchor)` so the caller can report the consumed slot in a
    /// fill memo; `None` (and the caller should pause) when exhausted.
    pub fn consume_next(&mut self) -> Option<(usize, Anchor)> {
        let idx = self.next_index;
        let a = self.anchors.get(idx).copied()?;
        self.next_index += 1;
        Some((idx, a))
    }

    /// Append more anchors (a WebSocket top-up). Clears `paused`.
    pub fn append(&mut self, more: impl IntoIterator<Item = Anchor>) {
        self.anchors.extend(more);
        self.paused = false;
    }

    /// Number of anchors not yet consumed.
    pub fn remaining(&self) -> usize {
        self.anchors.len().saturating_sub(self.next_index)
    }
}

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
    /// v2: the note's single `inner_hash` (replaces the old nonce +
    /// blinding pair). Anchors both the commitment and the nullifier.
    pub inner_hash: [u8; 32],
    /// `Poseidon3(DOMAIN_NULL=3, spending_key, inner_hash)`,
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
        commitment_from_fields_v2(
            &self.token_mint,
            self.amount,
            &self.owner_commitment,
            &self.inner_hash,
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

/// Everything the settle pipeline needs for one input note, captured
/// at order intake. Bundles the crypto opening (for the proof
/// witness) with the lock-side inputs the TEE relays into `lock_note`
/// (Tx A) — the per-note VALID_INPUT proof + the merkle root it was
/// generated against. The TEE cannot generate that proof (it needs
/// the user's spending key + merkle witness), so the client supplies
/// it; the on-chain `lock_note` verifies it against the vault's
/// 64-root ring buffer, so it stays valid as long as settle lands
/// within 64 tree updates of submission.
#[derive(Clone, Debug)]
pub struct OrderOpening {
    /// The crypto opening (verified against the signed commitment).
    pub opening: NoteOpening,
    /// The order this note collateralises (payload `order_id_*`).
    pub order_id: [u8; 16],
    /// Lock TTL the matcher relays into `lock_note`.
    pub expiry_slot: u64,
    /// Merkle root the VALID_INPUT proof was generated against — must
    /// still be in the vault's root history at lock time.
    pub merkle_root: [u8; 32],
    /// The client-generated VALID_INPUT Groth16 proof for `lock_note`.
    pub valid_input_proof: Groth16ProofBytes,
}

/// Per-order settle-input table. One entry per live order, keyed by
/// its collateral `note_commitment` — the matcher's `MatchPair`
/// carries `note_buyer` / `note_seller` (commitments, not order ids),
/// so keying by commitment lets the settle assembler resolve both
/// sides of a match directly. Inserted at intake (after the opening
/// verifies), read by the assembler (4g.7d), removed on cancel /
/// expiry / settle so the table tracks the live book.
#[derive(Default, Debug)]
pub struct OpeningStore {
    map: HashMap<[u8; 32], OrderOpening>,
    /// Per-order anchor pools, keyed by `order_id` (stable across the
    /// collateral-note rotation a continuation performs). Inserted at
    /// intake; consumed by the assembler on each partial fill; evicted
    /// when the order leaves the book.
    anchor_pools: HashMap<[u8; 16], AnchorPool>,
}

impl OpeningStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an order's anchor pool, keyed by `order_id`.
    pub fn insert_anchor_pool(&mut self, order_id: [u8; 16], pool: AnchorPool) {
        self.anchor_pools.insert(order_id, pool);
    }

    /// Mutable access to an order's anchor pool (for the assembler to
    /// `consume_next`, or the WS handler to `append`).
    pub fn anchor_pool_mut(&mut self, order_id: &[u8; 16]) -> Option<&mut AnchorPool> {
        self.anchor_pools.get_mut(order_id)
    }

    /// Read-only access to an order's anchor pool.
    pub fn anchor_pool(&self, order_id: &[u8; 16]) -> Option<&AnchorPool> {
        self.anchor_pools.get(order_id)
    }

    /// Drop an order's anchor pool — on full fill / cancel / expiry.
    pub fn remove_anchor_pool(&mut self, order_id: &[u8; 16]) -> Option<AnchorPool> {
        self.anchor_pools.remove(order_id)
    }

    /// Record an order's settle inputs, keyed by collateral note
    /// commitment. Overwrites any prior entry for the same commitment
    /// (a re-lock rotation reuses the slot with a fresh opening).
    pub fn insert(&mut self, note_commitment: [u8; 32], record: OrderOpening) {
        self.map.insert(note_commitment, record);
    }

    /// Fetch a clone of the record for a collateral note commitment
    /// (the assembler needs an owned copy it can use without holding
    /// the matcher lock across the proof).
    pub fn get(&self, note_commitment: &[u8; 32]) -> Option<OrderOpening> {
        self.map.get(note_commitment).cloned()
    }

    /// Drop a note's record — on cancel, expiry, or after settle.
    /// Returns the removed record, if any.
    pub fn remove(&mut self, note_commitment: &[u8; 32]) -> Option<OrderOpening> {
        self.map.remove(note_commitment)
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
    use darkpool_crypto::note::commitment_from_fields_v2;

    // A deterministic, Fr-safe opening. `commitment_from_fields_v2`
    // rejects non-Fr-safe field elements, so the owner/inner_hash
    // keep their top byte zeroed.
    fn sample_opening(amount: u64) -> NoteOpening {
        let mut owner = [0u8; 32];
        owner[31] = 0x11;
        let mut inner_hash = [0u8; 32];
        inner_hash[31] = 0x22;
        let mut mint = [0u8; 32];
        mint[0] = 1;
        mint[31] = 0x9e;
        NoteOpening {
            token_mint: mint,
            amount,
            owner_commitment: owner,
            inner_hash,
            nullifier: [0xAB; 32],
        }
    }

    #[test]
    fn verify_commitment_accepts_matching_opening() {
        let o = sample_opening(1_000);
        // Compute the canonical commitment the same way the deposit
        // path / on-chain verifier would.
        let commitment =
            commitment_from_fields_v2(&o.token_mint, o.amount, &o.owner_commitment, &o.inner_hash)
                .unwrap();
        assert!(o.verify_commitment(&commitment).is_ok());
    }

    #[test]
    fn verify_commitment_rejects_wrong_amount() {
        let o = sample_opening(1_000);
        let commitment =
            commitment_from_fields_v2(&o.token_mint, o.amount, &o.owner_commitment, &o.inner_hash)
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
    fn verify_commitment_rejects_wrong_inner_hash() {
        let o = sample_opening(1_000);
        let commitment =
            commitment_from_fields_v2(&o.token_mint, o.amount, &o.owner_commitment, &o.inner_hash)
                .unwrap();
        let mut tampered = o.clone();
        tampered.inner_hash[31] = 0x34;
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

    fn sample_record(amount: u64) -> OrderOpening {
        OrderOpening {
            opening: sample_opening(amount),
            order_id: [7u8; 16],
            expiry_slot: 1_000_000,
            merkle_root: [0xDD; 32],
            valid_input_proof: Groth16ProofBytes {
                pi_a: [1u8; 64],
                pi_b: [2u8; 128],
                pi_c: [3u8; 64],
            },
        }
    }

    #[test]
    fn anchor_pool_consume_is_monotonic_and_single_use() {
        let anchors: Vec<Anchor> = (0..3)
            .map(|i| Anchor {
                inner_hash: [i as u8; 32],
                nullifier: [(i + 100) as u8; 32],
            })
            .collect();
        let mut pool = AnchorPool::new(anchors.clone());
        assert_eq!(pool.remaining(), 3);
        assert_eq!(pool.consume_next(), Some((0, anchors[0])));
        assert_eq!(pool.consume_next(), Some((1, anchors[1])));
        assert_eq!(pool.remaining(), 1);
        assert_eq!(pool.consume_next(), Some((2, anchors[2])));
        // Exhausted → None (caller pauses the order).
        assert_eq!(pool.consume_next(), None);
        assert_eq!(pool.remaining(), 0);
        // A top-up replenishes + unpauses.
        pool.paused = true;
        pool.append([Anchor {
            inner_hash: [9u8; 32],
            nullifier: [9u8; 32],
        }]);
        assert!(!pool.paused);
        assert_eq!(pool.remaining(), 1);
        assert!(pool.consume_next().is_some());
    }

    #[test]
    fn store_anchor_pool_insert_consume_evict() {
        let mut store = OpeningStore::new();
        let oid = [0x42u8; 16];
        store.insert_anchor_pool(
            oid,
            AnchorPool::new(vec![Anchor {
                inner_hash: [1u8; 32],
                nullifier: [2u8; 32],
            }]),
        );
        assert!(store.anchor_pool(&oid).is_some());
        assert!(store
            .anchor_pool_mut(&oid)
            .unwrap()
            .consume_next()
            .is_some());
        assert!(store.remove_anchor_pool(&oid).is_some());
        assert!(store.anchor_pool(&oid).is_none());
    }

    #[test]
    fn store_insert_get_remove() {
        let mut store = OpeningStore::new();
        assert!(store.is_empty());
        let rec = sample_record(500);
        // Keyed by the collateral note commitment.
        let key = rec.opening.commitment().unwrap();
        store.insert(key, rec.clone());
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&key).map(|r| r.order_id), Some(rec.order_id));
        assert!(store.get(&[9u8; 32]).is_none());
        assert!(store.remove(&key).is_some());
        assert!(store.is_empty());
    }
}
