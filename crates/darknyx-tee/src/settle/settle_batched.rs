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
//!   - `tree_id: u8`                  — which `merkle_tree` shard the
//!     output notes append to (post-sharding; first arg)
//!   - `payload: MatchResultPayload`  — 552-byte Borsh ([`super::payload`])
//!   - `match_index: u8`              — position in the batch (0..15)
//!   - `merkle_proof: [[u8;32]; 4]`   — 128 contiguous bytes, the
//!     depth-4 inclusion path (leaf-level sibling first)
//!
//! ix data total = 8 + 1 + 552 + 1 + 128 = 690 bytes.
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
    batch_validity_marker_pda, consumed_note_pda, merkle_tree_pda, note_lock_pda, vault_config_pda,
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
/// `tee_authority` is the TEE pubkey (signer + writable) — the shard's
/// fee-payer key. `tree_id` selects the `merkle_tree` shard the output notes
/// append to; settles to different shards write distinct accounts (and a
/// distinct fee-payer) → the leader can co-include + parallelize them. The
/// caller MUST prepend an Ed25519 precompile ix signing
/// `payload.canonical_hash()` with the same key.
pub fn build_settle_batched_ix(
    tee_authority: &Address,
    tree_id: u8,
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
    let (merkle_tree, _) = merkle_tree_pda(tree_id);
    let (lock_a, _) = note_lock_pda(&payload.note_a_use_tag);
    let (lock_b, _) = note_lock_pda(&payload.note_b_use_tag);
    let (consumed_a, _) = consumed_note_pda(&payload.note_a_use_tag);
    let (consumed_b, _) = consumed_note_pda(&payload.note_b_use_tag);
    // Change-note leaves stay commitments, but their re-lock PDAs are keyed by
    // the circuit-bound use tags. Both fields are `[u8; 32]`, so accidentally
    // using the commitment compiles and only fails on chain when the vault
    // re-derives `[NoteLock::SEED, note_{e,f}_use_tag]`.
    let (lock_e, _) = note_lock_pda(&payload.note_e_use_tag);
    let (lock_f, _) = note_lock_pda(&payload.note_f_use_tag);
    let (marker, _) = batch_validity_marker_pda(merkle_root);

    // Account order MUST match TeeForcedSettleBatched<'info>. Post-sharding:
    // vault_config is READ-ONLY (key/owner/zsr source) and the writable tree
    // state moved to `merkle_tree` (slot 2). The two per-match nullifier_entry
    // accounts were REMOVED (the tag-keyed consumed_a/b are now the sole
    // consume-once guard — see the vault handler). The vestigial nullifier
    // fields left the v9 payload entirely.
    let accounts = vec![
        AccountMeta::new(*tee_authority, true), // 0 tee_authority (signer, mut)
        AccountMeta::new_readonly(vault_config, false), // 1 vault_config (readonly)
        AccountMeta::new(merkle_tree, false),   // 2 merkle_tree[tree_id] (mut)
        AccountMeta::new(lock_a, false),        // 3 note_lock_a (mut, close)
        AccountMeta::new(lock_b, false),        // 4 note_lock_b (mut, close)
        AccountMeta::new(consumed_a, false),    // 5 consumed_a (init)
        AccountMeta::new(consumed_b, false),    // 6 consumed_b (init)
        if payload.buyer_relock_order_id != [0u8; 16] {
            AccountMeta::new(lock_e, false) // 7 note_lock_e (conditional relock write)
        } else {
            AccountMeta::new_readonly(lock_e, false)
        },
        if payload.seller_relock_order_id != [0u8; 16] {
            AccountMeta::new(lock_f, false) // 8 note_lock_f (conditional relock write)
        } else {
            AccountMeta::new_readonly(lock_f, false)
        },
        AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false), // 9
        AccountMeta::new_readonly(marker, false), // 10 batch_validity_marker (readonly)
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false), // 11
    ];

    // ix data: disc || tree_id || Borsh(payload) || match_index || 4×32 siblings.
    let mut data = Vec::with_capacity(8 + 1 + MatchResultPayload::WIRE_LEN + 1 + 128);
    data.extend_from_slice(&*SETTLE_BATCHED_DISCRIMINATOR);
    data.push(tree_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_use_tag: [0xA1; 32],
            note_b_use_tag: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: [0u8; 32],
            note_f_use_tag: [0u8; 32],
            batch_slot: 0,
            fill_recovery: [0u8; 128],
        }
    }

    fn dummy_addr(byte: u8) -> Address {
        bs58::encode([byte; 32]).into_string().parse().unwrap()
    }

    fn dummy_tee() -> Address {
        dummy_addr(0xEE)
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
        let ix =
            build_settle_batched_ix(&dummy_tee(), 0, &dummy_payload(), 3, &proof(), &[0xAB; 32]);
        // 8 disc + 1 tree_id + 552 payload (v11 added the two relock tags)
        // + 1 match_index + 128 siblings = 690.
        assert_eq!(ix.data.len(), 8 + 1 + 552 + 1 + 128);
        assert_eq!(ix.data.len(), 690);
    }

    #[test]
    fn ix_data_layout() {
        let ix =
            build_settle_batched_ix(&dummy_tee(), 5, &dummy_payload(), 7, &proof(), &[0xAB; 32]);
        assert_eq!(&ix.data[..8], &*SETTLE_BATCHED_DISCRIMINATOR);
        // tree_id at 8; payload occupies [9, 561); match_index at 561;
        // siblings [562, 690). Every offset past the payload moved by exactly
        // 64 — the same shift the SDK, indexer and merkle::events decoders take.
        assert_eq!(ix.data[8], 5); // tree_id
        assert_eq!(ix.data[561], 7); // match_index
        assert_eq!(&ix.data[562..594], &[0x01; 32]); // sibling 0
        assert_eq!(&ix.data[594..626], &[0x02; 32]); // sibling 1
        assert_eq!(&ix.data[626..658], &[0x03; 32]);
        assert_eq!(&ix.data[658..690], &[0x04; 32]);
    }

    #[test]
    fn account_layout_matches_anchor_struct() {
        let tee = dummy_tee();
        let ix = build_settle_batched_ix(&tee, 3, &dummy_payload(), 0, &proof(), &[0xAB; 32]);
        assert_eq!(ix.accounts.len(), 12);

        // [0] tee_authority signer + writable.
        assert_eq!(ix.accounts[0].pubkey, tee);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // [1] vault_config is now READ-ONLY (state moved to merkle_tree).
        assert_eq!(ix.accounts[1].pubkey, vault_config_pda().0);
        assert!(!ix.accounts[1].is_writable);

        // [2] merkle_tree[tree_id] writable — the sharded output target.
        assert_eq!(ix.accounts[2].pubkey, merkle_tree_pda(3).0);
        assert!(ix.accounts[2].is_writable);

        // [9] instructions sysvar: readonly.
        assert_eq!(ix.accounts[9].pubkey, INSTRUCTIONS_SYSVAR_ID);
        assert!(!ix.accounts[9].is_writable);

        // [11] system program: readonly.
        assert_eq!(ix.accounts[11].pubkey, SYSTEM_PROGRAM_ID);
        assert!(!ix.accounts[11].is_writable);

        // Marker [10] matches the PDA for the given root.
        let (marker, _) = batch_validity_marker_pda(&[0xAB; 32]);
        assert_eq!(ix.accounts[10].pubkey, marker);
        assert!(!ix.accounts[10].is_writable);
        // Exact-fill dummy relock destinations are also read-only; otherwise
        // their shared zero-commitment PDA would serialize distinct-shard Tx Ds.
        assert!(!ix.accounts[7].is_writable);
        assert!(!ix.accounts[8].is_writable);
    }

    #[test]
    fn exact_fill_dedups_note_lock_e_and_f() {
        // When both change amounts are zero, note_e/f commitments are
        // [0;32], so note_lock_e and note_lock_f derive to the SAME
        // PDA. The legacy tx encoder dedups these to one key (saving
        // 32 bytes) — we surface the equality here so the
        // 1232-byte budget analysis in CLAUDE.md §6 holds.
        let ix =
            build_settle_batched_ix(&dummy_tee(), 0, &dummy_payload(), 0, &proof(), &[0xAB; 32]);
        // note_lock_e [7] and note_lock_f [8] collide for an exact fill.
        assert_eq!(ix.accounts[7].pubkey, ix.accounts[8].pubkey);
        assert!(!ix.accounts[7].is_writable);
        assert!(!ix.accounts[8].is_writable);
    }

    #[test]
    fn change_relock_accounts_use_tags_not_commitments() {
        let mut p = dummy_payload();
        p.note_e_commitment = [0xE1; 32];
        p.note_f_commitment = [0xF1; 32];
        p.note_e_use_tag = [0xE2; 32];
        p.note_f_use_tag = [0xF2; 32];
        p.buyer_relock_order_id = [0x31; 16];
        p.seller_relock_order_id = [0x32; 16];

        let ix = build_settle_batched_ix(&dummy_tee(), 0, &p, 0, &proof(), &[0xAB; 32]);
        assert_eq!(ix.accounts[7].pubkey, note_lock_pda(&p.note_e_use_tag).0);
        assert_eq!(ix.accounts[8].pubkey, note_lock_pda(&p.note_f_use_tag).0);
        assert_ne!(ix.accounts[7].pubkey, note_lock_pda(&p.note_e_commitment).0);
        assert_ne!(ix.accounts[8].pubkey, note_lock_pda(&p.note_f_commitment).0);
        assert!(ix.accounts[7].is_writable);
        assert!(ix.accounts[8].is_writable);
    }

    #[test]
    fn distinct_shard_settles_share_no_writable_accounts() {
        let p0 = dummy_payload();
        let mut p1 = dummy_payload();
        p1.note_a_use_tag = [0xA2; 32];
        p1.note_b_use_tag = [0xB2; 32];
        p1.note_c_commitment = [0xC2; 32];
        p1.note_d_commitment = [0xD2; 32];
        let ix0 = build_settle_batched_ix(&dummy_addr(0xE0), 0, &p0, 0, &proof(), &[0xAB; 32]);
        let ix1 = build_settle_batched_ix(&dummy_addr(0xE1), 1, &p1, 1, &proof(), &[0xAB; 32]);
        let writable0: Vec<_> = ix0
            .accounts
            .iter()
            .filter(|meta| meta.is_writable)
            .map(|meta| meta.pubkey)
            .chain(std::iter::once(ix0.accounts[0].pubkey)) // transaction fee payer
            .collect();
        let writable1: Vec<_> = ix1
            .accounts
            .iter()
            .filter(|meta| meta.is_writable)
            .map(|meta| meta.pubkey)
            .chain(std::iter::once(ix1.accounts[0].pubkey))
            .collect();
        let shared: Vec<_> = writable0
            .iter()
            .filter(|key| writable1.contains(key))
            .collect();
        assert!(
            shared.is_empty(),
            "shared writable Tx D accounts: {shared:?}"
        );
    }
}
