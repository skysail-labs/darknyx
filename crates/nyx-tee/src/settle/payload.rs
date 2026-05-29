//! `MatchResultPayload` + `canonical_payload_hash` — the third leg
//! of a CLAUDE.md §6 byte-equality contract.
//!
//! This Rust port MUST produce, for any payload:
//!   - the SAME 448-byte Borsh serialization as the on-chain
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
//! ## Two distinct field orderings (do not conflate)
//!
//! - **Borsh serialize** (the ix data): declaration order, with
//!   `note_fee_commitment` AFTER `seller_fee_amt` (position 18).
//! - **Canonical hash**: a hand-ordered concatenation that places
//!   `note_fee_commitment` right after `note_f_commitment`
//!   (position 8), before the nullifiers. Domain-tagged
//!   `b"nyx-match-v5"`.
//!
//! Both orderings are reproduced verbatim below from the on-chain
//! source + the SDK.

use borsh::BorshSerialize;
use sha2::{Digest, Sha256};

/// Domain tag for the canonical hash. **Do not change** — on-chain
/// verification rejects any hash computed with a different tag.
pub const CANONICAL_DOMAIN: &[u8] = b"nyx-match-v5";

/// 24-field settle payload. Field order is the on-chain struct's
/// declaration order — `#[derive(BorshSerialize)]` then produces
/// byte-identical output to AnchorSerialize + the SDK's
/// `serializePayload`.
#[derive(Clone, Debug, BorshSerialize)]
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
    pub base_amount: u64,
    pub quote_amount: u64,
    pub buyer_change_amt: u64,
    pub seller_change_amt: u64,
    pub buyer_fee_amt: u64,
    pub seller_fee_amt: u64,
    pub note_fee_commitment: [u8; 32],
    pub buyer_relock_order_id: [u8; 16],
    pub buyer_relock_expiry: u64,
    pub seller_relock_order_id: [u8; 16],
    pub seller_relock_expiry: u64,
    pub clearing_price: u64,
    pub batch_slot: u64,
}

impl MatchResultPayload {
    /// Total Borsh-encoded width: 16 + 6×32 + 2×32 + 2×16 + 6×8 +
    /// 32 + 16 + 8 + 16 + 8 + 8 + 8 = 448 bytes.
    pub const WIRE_LEN: usize = 448;

    /// Borsh serialization — the bytes that go into the
    /// `tee_forced_settle_batched` ix data. Byte-identical to the
    /// SDK's `serializePayload` and the on-chain AnchorSerialize.
    pub fn serialize(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialize of fixed-shape payload cannot fail")
    }

    /// Canonical 32-byte SHA-256 hash — the message the TEE's
    /// Ed25519 key signs. Field order is the hand-ordered sequence
    /// from `canonical_payload_hash` (NOT the Borsh/struct order):
    /// `note_fee_commitment` sits right after `note_f_commitment`.
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
        h.update(self.note_fee_commitment); // <- moved up vs Borsh order
        h.update(self.nullifier_a);
        h.update(self.nullifier_b);
        h.update(self.order_id_a);
        h.update(self.order_id_b);
        h.update(self.base_amount.to_le_bytes());
        h.update(self.quote_amount.to_le_bytes());
        h.update(self.buyer_change_amt.to_le_bytes());
        h.update(self.seller_change_amt.to_le_bytes());
        h.update(self.buyer_fee_amt.to_le_bytes());
        h.update(self.seller_fee_amt.to_le_bytes());
        h.update(self.buyer_relock_order_id);
        h.update(self.buyer_relock_expiry.to_le_bytes());
        h.update(self.seller_relock_order_id);
        h.update(self.seller_relock_expiry.to_le_bytes());
        h.update(self.clearing_price.to_le_bytes());
        h.update(self.batch_slot.to_le_bytes());
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
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            clearing_price: 0,
            batch_slot: 0,
        }
    }

    /// THE load-bearing test. Must equal the on-chain
    /// `expected` array byte-for-byte. If this drifts, the TEE
    /// signature won't verify on-chain and every settle fails.
    #[test]
    fn canonical_hash_matches_onchain_fixed_vector() {
        let expected: [u8; 32] = [
            0x03, 0x88, 0xE8, 0x01, 0x83, 0x01, 0x59, 0x29, 0x83, 0xB8, 0x6C, 0xBC, 0x2F, 0xB7,
            0x96, 0x76, 0x57, 0x6C, 0x04, 0xC1, 0xA4, 0xB8, 0xAD, 0x79, 0x26, 0x15, 0xCA, 0x63,
            0xFC, 0xE7, 0x1F, 0x92,
        ];
        let got = fixed_vector_payload().canonical_hash();
        assert_eq!(
            got, expected,
            "canonical_payload_hash drifted from on-chain — got {got:02X?}"
        );
    }

    #[test]
    fn borsh_serialization_is_448_bytes() {
        let bytes = fixed_vector_payload().serialize();
        assert_eq!(bytes.len(), MatchResultPayload::WIRE_LEN);
        assert_eq!(bytes.len(), 448);
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
                                                 // base_amount is at offset 16 + 6*32 + 2*32 + 2*16 = 16+192+64+32 = 304.
        assert_eq!(&bytes[304..312], &100u64.to_le_bytes());
        // quote_amount immediately after.
        assert_eq!(&bytes[312..320], &5_000u64.to_le_bytes());
    }

    #[test]
    fn note_fee_commitment_position_differs_between_borsh_and_hash() {
        // Regression guard for the easiest mistake: note_fee_commitment
        // is at Borsh position 18 (after seller_fee_amt) but hashed
        // at position 8 (after note_f). Build two payloads that
        // differ ONLY in note_fee_commitment and confirm both the
        // serialize bytes AND the hash change — and that moving the
        // value to a different field doesn't accidentally collide.
        let mut a = fixed_vector_payload();
        a.note_fee_commitment = [0x77; 32];
        let base = fixed_vector_payload();
        assert_ne!(a.canonical_hash(), base.canonical_hash());
        assert_ne!(a.serialize(), base.serialize());
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
        perturb!(base_amount = 101);
        perturb!(quote_amount = 5_001);
        perturb!(clearing_price = 1);
        perturb!(batch_slot = 1);
        perturb!(buyer_relock_expiry = 1);
    }
}
