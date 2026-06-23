//! `MatchResultPayload` + `canonical_payload_hash` — the third leg
//! of a CLAUDE.md §6 byte-equality contract.
//!
//! This Rust port MUST produce, for any payload:
//!   - the SAME 424-byte Borsh serialization as the on-chain
//!     `vault::instructions::tee_forced_settle::MatchResultPayload`
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
//! ## Amount-privacy (P3b)
//!
//! The seven plaintext amount fields (`base_amount`, `quote_amount`,
//! `buyer/seller_change_amt`, `buyer/seller_fee_amt`, `clearing_price`) were
//! dropped from the payload — they're proven in-circuit + bound by the note
//! commitments, and putting them in the (public, on-chain) settle ix leaked
//! every trade size. The domain tag bumped `v6`→`v7`.
//!
//! ## Two distinct field orderings (do not conflate)
//!
//! - **Borsh serialize** (the ix data): declaration order, with the two
//!   fee-note fields `note_fee_base_commitment` + `note_fee_quote_commitment`
//!   right after `order_id_b`.
//! - **Canonical hash**: the same hand-ordered concatenation, domain-tagged
//!   `b"nyx-match-v7"`.
//!
//! Both orderings are reproduced verbatim below from the on-chain
//! source + the SDK.

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// Domain tag for the canonical hash. **Do not change** — on-chain
/// verification rejects any hash computed with a different tag. Bumped
/// `v6`→`v7` when amount-privacy (P3b) dropped the seven plaintext amounts;
/// `v7`→`v8` when change-amount recovery (Proposal B) appended the 128-byte
/// `fill_recovery` field (the on-chain encrypted change_amount backstop).
pub const CANONICAL_DOMAIN: &[u8] = b"nyx-match-v8";

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
    pub note_a_commitment: [u8; 32],
    pub note_b_commitment: [u8; 32],
    pub note_c_commitment: [u8; 32],
    pub note_d_commitment: [u8; 32],
    pub note_e_commitment: [u8; 32],
    pub note_f_commitment: [u8; 32],
    pub nullifier_a: [u8; 32],
    pub nullifier_b: [u8; 32],
    pub order_id_a: [u8; 16],
    pub order_id_b: [u8; 16],
    pub note_fee_base_commitment: [u8; 32],
    pub note_fee_quote_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub batch_slot: u64,
    /// Change-amount recovery (Proposal B): the per-fill X25519-ECIES bundle
    /// `ephemeral_pubkey(32) ‖ buyer_enc(36) ‖ seller_enc(36) ‖ zero_pad(24)`
    /// (see `crate::settle::fill_recovery::FillCiphertext::to_payload_bytes`).
    /// All-zero when the fill has no recoverable change. 128 (not 104) because
    /// Anchor's borsh 0.10 only serializes `[u8; N]` for `N ≤ 32` then 64/128.
    pub fill_recovery: [u8; 128],
}

impl MatchResultPayload {
    /// Total Borsh-encoded width: 16 + 6×32 + 2×32 + 2×16 +
    /// 2×32 (base+quote fee notes) + 16 + 8 + 16 + 8 + 8 + 128
    /// (fill_recovery) = 552 bytes.
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
        h.update(self.note_a_commitment);
        h.update(self.note_b_commitment);
        h.update(self.note_c_commitment);
        h.update(self.note_d_commitment);
        h.update(self.note_e_commitment);
        h.update(self.note_f_commitment);
        h.update(self.note_fee_base_commitment); // <- moved up vs Borsh order
        h.update(self.note_fee_quote_commitment);
        h.update(self.nullifier_a);
        h.update(self.nullifier_b);
        h.update(self.order_id_a);
        h.update(self.order_id_b);
        h.update(self.buyer_relock_order_id);
        h.update(self.buyer_relock_expiry.to_le_bytes());
        h.update(self.seller_relock_order_id);
        h.update(self.seller_relock_expiry.to_le_bytes());
        h.update(self.batch_slot.to_le_bytes());
        h.update(self.fill_recovery); // v8: change-amount recovery bundle
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact fixture from the on-chain
    /// `canonical_payload_hash_fixed_vector` unit test in
    /// programs/vault/src/instructions/tee_forced_settle.rs.
    fn fixed_vector_payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_commitment: [0xA1; 32],
            note_b_commitment: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            nullifier_a: [0xEA; 32],
            nullifier_b: [0xEB; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
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
            0x32, 0x4C, 0xA2, 0x82, 0x93, 0x52, 0x9A, 0xDA, 0x1D, 0x68, 0x34, 0xC1, 0x63, 0x43,
            0xE2, 0xA0, 0x59, 0x3E, 0x0A, 0x50, 0xBB, 0x2D, 0x7B, 0x9D, 0x63, 0xFB, 0xDE, 0xF1,
            0x2F, 0xBC, 0x26, 0x88,
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
        // The appended fill_recovery field occupies the last 128 bytes.
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
                                                 // Amount-privacy (P3b): the amount block is gone, so the two fee-note
                                                 // commitments now sit right after order_id_b at offset
                                                 // 16 + 6*32 + 2*32 + 2*16 = 304 (both [0;32] in the fixture).
        assert_eq!(&bytes[304..336], &[0u8; 32]); // note_fee_base_commitment
        assert_eq!(&bytes[336..368], &[0u8; 32]); // note_fee_quote_commitment
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
        perturb!(note_a_commitment = [0xA2; 32]);
        perturb!(nullifier_a = [0xE0; 32]);
        perturb!(order_id_b = [0x03; 16]);
        perturb!(note_fee_base_commitment = [0x77; 32]);
        perturb!(batch_slot = 1);
        perturb!(buyer_relock_expiry = 1);
        perturb!(fill_recovery = [0x99; 128]);
    }
}
