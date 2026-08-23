//! `MatchResultPayload` + `canonical_payload_hash` — the third leg
//! of a CLAUDE.md §7 byte-equality contract.
//!
//! This Rust port MUST produce, for any payload:
//!   - the SAME 552-byte Borsh serialization as the on-chain
//!     `vault::instructions::settlement_shared::MatchResultPayload`
//!     (AnchorSerialize) and the SDK's
//!     `settle-builder.ts::serializePayload`;
//!   - the SAME 32-byte canonical hash as the on-chain
//!     `canonical_payload_hash` and the SDK's
//!     `canonicalPayloadHash`.
//!
//! A drift in EITHER means the TEE's settle signature won't verify
//! on-chain and every settlement fails. The fixed-vector test
//! below pins the hash byte-for-byte against the on-chain
//! `canonical_payload_hash_fixed_vector` unit test.
//!
//! ## Amount-privacy
//!
//! The seven plaintext amount fields (`base_amount`, `quote_amount`,
//! `buyer/seller_change_amt`, `buyer/seller_fee_amt`, `clearing_price`) were
//! dropped from the payload — they're proven in-circuit + bound by the note
//! commitments, and putting them in the (public, on-chain) settle ix leaked
//! every trade size. The domain tag bumped `v6`→`v7`. Output recovery then
//! appended the 128-byte `fill_recovery` field and bumped
//! `v7`→`v8` (424→552 bytes). Settlement payload v9 removed the two
//! vestigial nullifiers, shrinking the wire shape to 488 bytes. Recovery v3
//! repacks those same 128 bytes with two u64s per side. The clean Darknyx
//! namespace cutover kept the 488-byte layout but bumped the signature domain
//! to v10. Note-use tags then replaced the two consumed commitments and added
//! two relock tags, yielding the 552-byte v11 layout.
//!
//! ## Two distinct field orderings (do not conflate)
//!
//! - **Borsh serialize** (the ix data): declaration order, with the two
//!   fee-note fields `note_fee_base_commitment` + `note_fee_quote_commitment`
//!   right after `order_id_b`.
//! - **Canonical hash**: the same hand-ordered concatenation, domain-tagged
//!   `b"darknyx-match-v11"`.
//!
//! Both orderings are reproduced verbatim below from the on-chain
//! source + the SDK.

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// Domain tag for the canonical hash. **Do not change** — on-chain
/// verification rejects any hash computed with a different tag. Bumped
/// `v6`→`v7` when amount-privacy dropped the seven plaintext amounts;
/// `v7`→`v8` when output recovery appended the 128-byte `fill_recovery` field;
/// `v8`→`v9` when the two unused nullifiers left the settle payload; and
/// `v9`→`v10` for the clean Darknyx namespace cutover; and `v10`→`v11` when the
/// consumed commitments became note-use TAGS and the two relock tags were
/// appended (488 → 552 bytes).
pub const CANONICAL_DOMAIN: &[u8] = b"darknyx-match-v11";

/// Settle payload. Field order is the on-chain struct's declaration order —
/// `#[derive(BorshSerialize)]` then produces byte-identical output to
/// AnchorSerialize + the SDK's `serializePayload`.
// `BorshDeserialize` is the exact inverse of `BorshSerialize` — same
// byte layout, so the §6 byte-equality contract is untouched. It's
// needed by `crate::merkle::events` to recover settle leaf values from
// a `tee_forced_settle_batched` instruction's data during sync.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct MatchResultPayload {
    pub match_id: [u8; 16],
    /// CONSUMED inputs, as note-use tags. These seed the `NoteLock` and
    /// `ConsumedNoteEntry` PDAs; republishing the commitments here would relink
    /// both inputs to their Merkle leaves.
    pub note_a_use_tag: [u8; 32],
    pub note_b_use_tag: [u8; 32],
    /// OUTPUTS stay commitments — they are appended as new leaves.
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    /// Tags for the change notes this settle creates and immediately re-locks.
    /// Needed ALONGSIDE `note_e/f_commitment`: the commitment is the leaf value,
    /// the tag is the `NoteLock` seed, and neither derives from the other
    /// without the private inner hash. `[0u8; 32]` when that side has no change.
    pub note_e_use_tag: [u8; 32],
    pub note_f_use_tag: [u8; 32],
    pub batch_slot: u64,
    /// Recovery v3: the per-fill X25519-ECIES bundle
    /// `ephemeral_pubkey(32) ‖ buyer_enc(44) ‖ seller_enc(44) ‖ "DNYXREC3"`
    /// (see `crate::settle::fill_recovery::FillCiphertext::to_payload_bytes`).
    /// Each side encrypts `(trade, change)`; all-zero only when neither order
    /// supplies a viewing key.
    pub fill_recovery: [u8; 128],
}

impl MatchResultPayload {
    /// Total Borsh-encoded width: 16 + 6×32 + 2×16 +
    /// 2×32 (base+quote fee notes) + 16 + 8 + 16 + 8 + 2×32 (relock tags)
    /// + 8 + 128 (fill_recovery) = 552 bytes.
    ///
    /// Was 488. The +64 is the two relock tags; it eats into Tx D's headroom
    /// against the 1232-byte cap, which `tx_d_stays_within_the_size_budget`
    /// asserts rather than leaving to chance.
    pub const WIRE_LEN: usize = 552;

    /// Borsh serialization — the bytes that go into the
    /// `tee_forced_settle_batched` ix data. Byte-identical to the
    /// SDK's `serializePayload` and the on-chain AnchorSerialize.
    pub fn serialize(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialize of fixed-shape payload cannot fail")
    }

    /// Canonical 32-byte SHA-256 hash — the message the TEE's
    /// Ed25519 key signs. Field order is the hand-ordered sequence
    /// from `canonical_payload_hash` (NOT the Borsh/struct order): the
    /// two fee-note fields sit right after `note_f_commitment`.
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CANONICAL_DOMAIN);
        h.update(self.match_id);
        h.update(self.note_a_use_tag);
        h.update(self.note_b_use_tag);
        h.update(self.note_c_commitment);
        h.update(self.note_d_commitment);
        h.update(self.note_e_commitment);
        h.update(self.note_f_commitment);
        h.update(self.note_fee_base_commitment); // <- moved up vs Borsh order
        h.update(self.note_fee_quote_commitment);
        h.update(self.order_id_a);
        h.update(self.order_id_b);
        h.update(self.buyer_relock_order_id);
        h.update(self.buyer_relock_expiry.to_le_bytes());
        h.update(self.seller_relock_order_id);
        h.update(self.seller_relock_expiry.to_le_bytes());
        h.update(self.note_e_use_tag);
        h.update(self.note_f_use_tag);
        h.update(self.batch_slot.to_le_bytes());
        h.update(self.fill_recovery); // v8: encrypted output-recovery bundle
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact fixture from the on-chain
    /// `canonical_payload_hash_fixed_vector` unit test in
    /// programs/vault/src/instructions/settlement_shared.rs.
    fn fixed_vector_payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_use_tag: [0xA1; 32],
            note_b_use_tag: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0xE1; 32],
            note_f_commitment: [0xF1; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: [0xEA; 32],
            note_f_use_tag: [0xFA; 32],
            batch_slot: 0,
            fill_recovery: [0; 128],
        }
    }

    /// THE load-bearing test. Must equal the on-chain
    /// `expected` array byte-for-byte. If this drifts, the TEE
    /// signature won't verify on-chain and every settle fails.
    #[test]
    fn canonical_hash_matches_onchain_fixed_vector() {
        let expected: [u8; 32] = [
            0xC7, 0xFF, 0x67, 0xAC, 0xDA, 0x24, 0x5D, 0x16, 0x4C, 0x12, 0x48, 0xDC, 0x51, 0xDC,
            0x2D, 0x97, 0x05, 0x2C, 0x3A, 0xBE, 0x76, 0x96, 0x41, 0x3D, 0x54, 0xE6, 0x53, 0x6E,
            0xD0, 0x15, 0x6D, 0x45,
        ];
        let got = fixed_vector_payload().canonical_hash();
        assert_eq!(
            got, expected,
            "canonical_payload_hash drifted from on-chain — got {got:02X?}"
        );
    }

    #[test]
    fn borsh_serialization_is_552_bytes() {
        let bytes = fixed_vector_payload().serialize();
        assert_eq!(bytes.len(), MatchResultPayload::WIRE_LEN);
        assert_eq!(bytes.len(), 552);
        // The appended fill_recovery field still occupies the LAST 128 bytes;
        // the two relock tags sit ahead of batch_slot, so the offset moved by
        // exactly 64. Three independent decoders read this layout by offset
        // (the SDK's chain-history, the indexer, and merkle::events), so the
        // shift has to be asserted here rather than discovered downstream.
        assert_eq!(&bytes[424..552], &[0u8; 128]);
    }

    #[test]
    fn borsh_field_order_matches_struct_declaration() {
        // Spot-check the first few fields' byte offsets: match_id
        // (16) then note_a (32) — Borsh has no length prefixes for
        // fixed arrays, so they sit back-to-back.
        let bytes = fixed_vector_payload().serialize();
        assert_eq!(&bytes[0..16], &[0x11; 16]); // match_id
        assert_eq!(&bytes[16..48], &[0xA1; 32]); // note_a
        assert_eq!(&bytes[48..80], &[0xB1; 32]); // note_b
                                                 // Amount-privacy: the amount block is gone, so the two fee-note
                                                 // commitments now sit right after order_id_b at offset
                                                 // 16 + 6*32 + 2*16 = 240 (both [0;32] in the fixture).
        assert_eq!(&bytes[240..272], &[0u8; 32]); // note_fee_base_commitment
        assert_eq!(&bytes[272..304], &[0u8; 32]); // note_fee_quote_commitment
    }

    #[test]
    fn note_fee_commitments_differ_between_borsh_and_hash() {
        // Regression guard for the easiest mistake: the two fee-note
        // fields are at Borsh positions 18-19 (after seller_fee_amt) but
        // hashed at positions 8-9 (after note_f). Perturb each and
        // confirm both the serialize bytes AND the hash change.
        let base = fixed_vector_payload();
        let mut a = fixed_vector_payload();
        a.note_fee_base_commitment = [0x77; 32];
        assert_ne!(a.canonical_hash(), base.canonical_hash());
        assert_ne!(a.serialize(), base.serialize());

        let mut b = fixed_vector_payload();
        b.note_fee_quote_commitment = [0x88; 32];
        assert_ne!(b.canonical_hash(), base.canonical_hash());
        assert_ne!(b.serialize(), base.serialize());
        // base vs quote must not collide (distinct hash positions).
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn each_field_affects_the_hash() {
        let base = fixed_vector_payload().canonical_hash();
        macro_rules! perturb {
            ($field:ident = $val:expr) => {{
                let mut p = fixed_vector_payload();
                p.$field = $val;
                assert_ne!(
                    p.canonical_hash(),
                    base,
                    "field {} did not affect the hash",
                    stringify!($field)
                );
            }};
        }
        perturb!(match_id = [0x12; 16]);
        perturb!(note_a_use_tag = [0xA2; 32]);
        perturb!(order_id_b = [0x03; 16]);
        perturb!(note_fee_base_commitment = [0x77; 32]);
        perturb!(batch_slot = 1);
        perturb!(buyer_relock_expiry = 1);
        perturb!(fill_recovery = [0x99; 128]);
    }
}
