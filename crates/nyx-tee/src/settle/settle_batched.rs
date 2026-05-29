//! `tee_forced_settle_batched` instruction builder (Tx D).
//!
//! The atomic settle. Consumes both input notes, creates change
//! notes, transfers value, and emits `TradeSettled`. Verified by an
//! Ed25519 precompile ix (the TEE signature, built separately by
//! [`super::ed25519::build_ed25519_verify_ix`]) that MUST precede
//! this ix in the same transaction.
//!
//! On-chain reference:
//! `programs/vault/src/instructions/tee_forced_settle_batched.rs`.
//! Account order + ix-data layout mirror the SDK's
//! `settle-builder.ts::buildSettleBatchedIx`.
//!
//! Args (after the 8-byte discriminator):
//!   - `payload: MatchResultPayload`  — 448-byte Borsh ([`super::payload`])
//!   - `match_index: u8`              — position in the batch (0..15)
//!   - `merkle_proof: [[u8;32]; 4]`   — 128 contiguous bytes, the
//!     depth-4 inclusion path (leaf-level sibling first)
//!
//! ix data total = 8 + 448 + 1 + 128 = 585 bytes.
//!
//! `merkle_root` is NOT in the ix data — it only derives the
//! `batch_validity_marker` PDA address. The handler recomputes the
//! root from (leaf, merkle_proof, match_index) and asserts the
//! marker PDA sits at `[b"batch_validity", recomputed_root]`.

use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use super::payload::MatchResultPayload;
use super::vault::{
    batch_validity_marker_pda, consumed_note_pda, note_lock_pda, nullifier_pda, vault_config_pda,
    vault_program_id, SYSTEM_PROGRAM_ID,
};

/// Solana instructions sysvar id (`Sysvar1nstructions1111111111111111111111111`).
/// The settle handler reads this to find the Ed25519 precompile ix.
pub const INSTRUCTIONS_SYSVAR_ID: Address = Address::new_from_array([
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66, 0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
    0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5, 0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
]);

/// Anchor discriminator for `tee_forced_settle_batched`.
pub static SETTLE_BATCHED_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let h = Sha256::digest(b"global:tee_forced_settle_batched");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

/// Build the `tee_forced_settle_batched` instruction.
///
/// `tee_authority` is the TEE pubkey (signer + writable). The
/// caller MUST prepend an Ed25519 precompile ix signing
/// `payload.canonical_hash()` with the same key.
pub fn build_settle_batched_ix(
    tee_authority: &Address,
    payload: &MatchResultPayload,
    match_index: u8,
    merkle_proof: &[[u8; 32]; 4],
    merkle_root: &[u8; 32],
) -> Instruction {
    // Depth-4 batch tree → 16 leaves, so match_index ∈ [0, 15]. The
    // assembler only ever passes `idx < N=16`; assert it so an
    // out-of-range index surfaces in tests rather than as an opaque
    // on-chain root mismatch.
    debug_assert!(
        match_index < 16,
        "match_index {match_index} out of range for a depth-4 batch (0..15)"
    );
    let program_id = vault_program_id();
    let (vault_config, _) = vault_config_pda();
    let (lock_a, _) = note_lock_pda(&payload.note_a_commitment);
    let (lock_b, _) = note_lock_pda(&payload.note_b_commitment);
    let (consumed_a, _) = consumed_note_pda(&payload.note_a_commitment);
    let (consumed_b, _) = consumed_note_pda(&payload.note_b_commitment);
    let (null_a, _) = nullifier_pda(&payload.nullifier_a);
    let (null_b, _) = nullifier_pda(&payload.nullifier_b);
    let (lock_e, _) = note_lock_pda(&payload.note_e_commitment);
    let (lock_f, _) = note_lock_pda(&payload.note_f_commitment);
    let (marker, _) = batch_validity_marker_pda(merkle_root);

    // Account order MUST match TeeForcedSettleBatched<'info>.
    let accounts = vec![
        AccountMeta::new(*tee_authority, true), // 0 tee_authority (signer, mut)
        AccountMeta::new(vault_config, false),  // 1 vault_config (mut)
        AccountMeta::new(lock_a, false),        // 2 note_lock_a (mut, close)
        AccountMeta::new(lock_b, false),        // 3 note_lock_b (mut, close)
        AccountMeta::new(consumed_a, false),    // 4 consumed_a (init)
        AccountMeta::new(consumed_b, false),    // 5 consumed_b (init)
        AccountMeta::new(null_a, false),        // 6 nullifier_a_entry (init)
        AccountMeta::new(null_b, false),        // 7 nullifier_b_entry (init)
        AccountMeta::new(lock_e, false),        // 8 note_lock_e (mut, unchecked)
        AccountMeta::new(lock_f, false),        // 9 note_lock_f (mut, unchecked)
        AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false), // 10
        AccountMeta::new(marker, false),        // 11 batch_validity_marker (mut)
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false), // 12
    ];

    // ix data: disc || Borsh(payload) || match_index || 4×32 siblings.
    let mut data = Vec::with_capacity(8 + MatchResultPayload::WIRE_LEN + 1 + 128);
    data.extend_from_slice(&*SETTLE_BATCHED_DISCRIMINATOR);
    data.extend_from_slice(&payload.serialize());
    data.push(match_index);
    for sib in merkle_proof {
        data.extend_from_slice(sib);
    }

    Instruction {
        program_id,
        accounts,
        data,
    }
}

/// The five per-batch PDAs that go into the per-batch ALT (Tx C):
/// `note_lock_a/b/e/f` + `batch_validity_marker`. These are exactly
/// the writable, match-derivable accounts that Tx D references but
/// that vary per batch — hoisting them into the ALT is what keeps
/// the settle tx under the 1232-byte cap.
pub fn per_batch_alt_addresses(
    payload: &MatchResultPayload,
    merkle_root: &[u8; 32],
) -> Vec<Address> {
    vec![
        note_lock_pda(&payload.note_a_commitment).0,
        note_lock_pda(&payload.note_b_commitment).0,
        note_lock_pda(&payload.note_e_commitment).0,
        note_lock_pda(&payload.note_f_commitment).0,
        batch_validity_marker_pda(merkle_root).0,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_payload() -> MatchResultPayload {
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

    fn dummy_tee() -> Address {
        bs58::encode([0xEEu8; 32]).into_string().parse().unwrap()
    }

    fn proof() -> [[u8; 32]; 4] {
        [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]]
    }

    #[test]
    fn discriminator_pins() {
        // sha256("global:tee_forced_settle_batched")[..8].
        let expected = "fb19443ebfe1b0fd";
        let got = hex::encode(*SETTLE_BATCHED_DISCRIMINATOR);
        assert_eq!(got, expected, "settle_batched discriminator drifted");
    }

    #[test]
    fn instructions_sysvar_id_is_canonical() {
        assert_eq!(
            INSTRUCTIONS_SYSVAR_ID.to_string(),
            "Sysvar1nstructions1111111111111111111111111"
        );
    }

    #[test]
    fn ix_data_total_length() {
        let ix = build_settle_batched_ix(&dummy_tee(), &dummy_payload(), 3, &proof(), &[0xAB; 32]);
        // 8 disc + 448 payload + 1 match_index + 128 siblings = 585.
        assert_eq!(ix.data.len(), 8 + 448 + 1 + 128);
        assert_eq!(ix.data.len(), 585);
    }

    #[test]
    fn ix_data_layout() {
        let ix = build_settle_batched_ix(&dummy_tee(), &dummy_payload(), 7, &proof(), &[0xAB; 32]);
        assert_eq!(&ix.data[..8], &*SETTLE_BATCHED_DISCRIMINATOR);
        // payload occupies [8, 456); match_index at 456; siblings [457, 585).
        assert_eq!(ix.data[456], 7); // match_index
        assert_eq!(&ix.data[457..489], &[0x01; 32]); // sibling 0
        assert_eq!(&ix.data[489..521], &[0x02; 32]); // sibling 1
        assert_eq!(&ix.data[521..553], &[0x03; 32]);
        assert_eq!(&ix.data[553..585], &[0x04; 32]);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        let tee = dummy_tee();
        let ix = build_settle_batched_ix(&tee, &dummy_payload(), 0, &proof(), &[0xAB; 32]);
        assert_eq!(ix.accounts.len(), 13);

        // [0] tee_authority signer + writable.
        assert_eq!(ix.accounts[0].pubkey, tee);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // [10] instructions sysvar: readonly.
        assert_eq!(ix.accounts[10].pubkey, INSTRUCTIONS_SYSVAR_ID);
        assert!(!ix.accounts[10].is_writable);

        // [12] system program: readonly.
        assert_eq!(ix.accounts[12].pubkey, SYSTEM_PROGRAM_ID);
        assert!(!ix.accounts[12].is_writable);

        // Marker [11] matches the PDA for the given root.
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[11].pubkey, marker);
        assert!(ix.accounts[11].is_writable);
    }

    #[test]
    fn exact_fill_dedups_note_lock_e_and_f() {
        // When both change amounts are zero, note_e/f commitments are
        // [0;32], so note_lock_e and note_lock_f derive to the SAME
        // PDA. The legacy tx encoder dedups these to one key (saving
        // 32 bytes) — we surface the equality here so the
        // 1232-byte budget analysis in CLAUDE.md §5 holds.
        let ix = build_settle_batched_ix(&dummy_tee(), &dummy_payload(), 0, &proof(), &[0xAB; 32]);
        assert_eq!(ix.accounts[8].pubkey, ix.accounts[9].pubkey);
    }

    #[test]
    fn per_batch_alt_has_five_addresses() {
        let addrs = per_batch_alt_addresses(&dummy_payload(), &[0xAB; 32]);
        assert_eq!(addrs.len(), 5);
        // Marker is last; matches the standalone PDA.
        assert_eq!(addrs[4], batch_validity_marker_pda(&[0xAB; 32]).0);
    }
}
