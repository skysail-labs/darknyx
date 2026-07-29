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
//!   - `payload: MatchResultPayload`  — 488-byte Borsh ([`super::payload`])
//!   - `match_index: u8`              — position in the batch (0..15)
//!   - `merkle_proof: [[u8;32]; 4]`   — 128 contiguous bytes, the
//!     depth-4 inclusion path (leaf-level sibling first)
//!
//! ix data total = 8 + 1 + 488 + 1 + 128 = 626 bytes.
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
    let (lock_a, _) = note_lock_pda(&payload.note_a_commitment);
    let (lock_b, _) = note_lock_pda(&payload.note_b_commitment);
    let (consumed_a, _) = consumed_note_pda(&payload.note_a_commitment);
    let (consumed_b, _) = consumed_note_pda(&payload.note_b_commitment);
    let (lock_e, _) = note_lock_pda(&payload.note_e_commitment);
    let (lock_f, _) = note_lock_pda(&payload.note_f_commitment);
    let (marker, _) = batch_validity_marker_pda(merkle_root);

    // Account order MUST match TeeForcedSettleBatched<'info>. Post-sharding:
    // vault_config is READ-ONLY (key/owner/zsr source) and the writable tree
    // state moved to `merkle_tree` (slot 2). The two per-match nullifier_entry
    // accounts were REMOVED (the commitment-keyed consumed_a/b are now the sole
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

/// The per-batch PDAs that go into the per-batch ALT (Tx C): the writable,
/// match-derivable accounts a settle Tx D references but that vary per batch —
/// `note_lock_{a,b,e,f}`, the `consumed_note` entries for both inputs, and
/// `batch_validity_marker`. Hoisting ALL of them (not just the locks) keeps the
/// settle tx well under the 1232-byte cap: the consumed PDAs were previously
/// inline, which left the change-note / sharded tx riding the edge. (The two
/// `nullifier_entry` PDAs were dropped along with their vault accounts.)
pub fn per_batch_alt_addresses(
    payload: &MatchResultPayload,
    merkle_root: &[u8; 32],
) -> Vec<Address> {
    vec![
        note_lock_pda(&payload.note_a_commitment).0,
        note_lock_pda(&payload.note_b_commitment).0,
        note_lock_pda(&payload.note_e_commitment).0,
        note_lock_pda(&payload.note_f_commitment).0,
        consumed_note_pda(&payload.note_a_commitment).0,
        consumed_note_pda(&payload.note_b_commitment).0,
        batch_validity_marker_pda(merkle_root).0,
    ]
}

/// The full set of derivable PDAs a MULTI-match batch's ALT must hold:
/// the union of every match's `note_lock_{a,b,e,f}` (each match's Tx D
/// references its OWN locks) plus the single shared `batch_validity_marker`
/// (one per batch, keyed by the batch root). Deduped — exact-fill matches
/// collide on the all-zero `note_lock_e/f` PDA, and the marker is shared.
/// NOTE this dedup means it is NOT identical to [`per_batch_alt_addresses`]
/// even for a single match: an exact-fill payload yields 4 entries here (the
/// `note_lock_e`/`note_lock_f` collision is collapsed) vs the 5
/// (with a duplicate) that `per_batch_alt_addresses` always returns — so
/// callers must not assume the two are interchangeable. Building the ALT
/// from only `matches[0]` would leave matches 1..N's locks inline and push
/// their settle tx over the 1232-byte cap.
pub fn batch_alt_addresses<'a>(
    payloads: impl IntoIterator<Item = &'a MatchResultPayload>,
    merkle_root: &[u8; 32],
) -> Vec<Address> {
    let mut out: Vec<Address> = Vec::new();
    let mut push = |a: Address| {
        if !out.contains(&a) {
            out.push(a);
        }
    };
    for p in payloads {
        push(note_lock_pda(&p.note_a_commitment).0);
        push(note_lock_pda(&p.note_b_commitment).0);
        push(note_lock_pda(&p.note_e_commitment).0);
        push(note_lock_pda(&p.note_f_commitment).0);
        // consumed-note entries for both inputs — Tx D inits these, and
        // ALT-referencing them (vs inline) is what gives the change-note /
        // sharded settle tx its headroom under the 1232-byte cap. (The
        // nullifier entries that used to live here were dropped.)
        push(consumed_note_pda(&p.note_a_commitment).0);
        push(consumed_note_pda(&p.note_b_commitment).0);
    }
    push(batch_validity_marker_pda(merkle_root).0);
    out
}

/// The addresses the STATIC settle ALT must hold — the per-settle
/// constant, non-signer accounts (`vault_config`, the instructions
/// sysvar, the system program) PLUS the K `merkle_tree` shard accounts
/// (`num_trees` of them). Created once at devnet-setup and stacked
/// UNDER the per-batch ALT (see `pipeline.rs` + `worker.rs::static_alt`).
/// Hoisting these is what keeps the settle v0 tx under Solana's 1232-byte
/// cap — each shard's settle references its `merkle_tree[j]` from the ALT
/// (1 index byte) instead of inline (32 bytes).
pub fn static_alt_addresses(num_trees: u8) -> Vec<Address> {
    let mut out = vec![
        vault_config_pda().0,
        INSTRUCTIONS_SYSVAR_ID,
        SYSTEM_PROGRAM_ID,
    ];
    for tree_id in 0..num_trees.max(1) {
        out.push(merkle_tree_pda(tree_id).0);
    }
    out
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
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
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
    fn batch_alt_addresses_unions_all_matches_and_one_marker() {
        let root = [0xAB; 32];

        // Single match: note_lock_a, note_lock_b, (note_lock_e==f deduped to 1),
        // consumed_a, consumed_b, marker = 6 distinct. The retired
        // nullifier-keyed accounts are not part of settlement.
        let p0 = dummy_payload();
        let single = batch_alt_addresses([&p0], &root);
        assert_eq!(single.len(), 6);
        assert!(single.contains(&note_lock_pda(&p0.note_a_commitment).0));
        assert!(single.contains(&consumed_note_pda(&p0.note_a_commitment).0));
        assert!(single.contains(&batch_validity_marker_pda(&root).0));

        // Two DISTINCT matches (distinct notes): each adds its a/b locks +
        // consumed; the all-zero note_lock_e/f and the marker stay shared
        // across the batch.
        let mut p1 = dummy_payload();
        p1.note_a_commitment = [0xA2; 32];
        p1.note_b_commitment = [0xB2; 32];
        let multi = batch_alt_addresses([&p0, &p1], &root);
        // p0: a,b locks + consumed_a,b + (e/f shared 1) = 5
        // p1: a,b locks + consumed_a,b = 4 (e/f shared) → 9 + marker = 10.
        assert_eq!(multi.len(), 10);
        assert!(multi.contains(&note_lock_pda(&p1.note_a_commitment).0));
        assert!(multi.contains(&consumed_note_pda(&p1.note_a_commitment).0));
        // Exactly one marker.
        let marker = batch_validity_marker_pda(&root).0;
        assert_eq!(multi.iter().filter(|a| **a == marker).count(), 1);
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
        // 8 disc + 1 tree_id + 488 payload (v9 removed two nullifiers)
        // + 1 match_index + 128 siblings = 626.
        assert_eq!(ix.data.len(), 8 + 1 + 488 + 1 + 128);
        assert_eq!(ix.data.len(), 626);
    }

    #[test]
    fn ix_data_layout() {
        let ix =
            build_settle_batched_ix(&dummy_tee(), 5, &dummy_payload(), 7, &proof(), &[0xAB; 32]);
        assert_eq!(&ix.data[..8], &*SETTLE_BATCHED_DISCRIMINATOR);
        // tree_id at 8; payload occupies [9, 497); match_index at 497;
        // siblings [498, 626).
        assert_eq!(ix.data[8], 5); // tree_id
        assert_eq!(ix.data[497], 7); // match_index
        assert_eq!(&ix.data[498..530], &[0x01; 32]); // sibling 0
        assert_eq!(&ix.data[530..562], &[0x02; 32]); // sibling 1
        assert_eq!(&ix.data[562..594], &[0x03; 32]);
        assert_eq!(&ix.data[594..626], &[0x04; 32]);
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
        // 1232-byte budget analysis in CLAUDE.md §5 holds.
        let ix =
            build_settle_batched_ix(&dummy_tee(), 0, &dummy_payload(), 0, &proof(), &[0xAB; 32]);
        // note_lock_e [7] and note_lock_f [8] collide for an exact fill.
        assert_eq!(ix.accounts[7].pubkey, ix.accounts[8].pubkey);
        assert!(!ix.accounts[7].is_writable);
        assert!(!ix.accounts[8].is_writable);
    }

    #[test]
    fn distinct_shard_settles_share_no_writable_accounts() {
        let p0 = dummy_payload();
        let mut p1 = dummy_payload();
        p1.note_a_commitment = [0xA2; 32];
        p1.note_b_commitment = [0xB2; 32];
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

    #[test]
    fn per_batch_alt_has_seven_addresses() {
        let addrs = per_batch_alt_addresses(&dummy_payload(), &[0xAB; 32]);
        // 4 locks (a,b,e,f — e/f duplicated for an exact fill, not deduped here)
        // + 2 consumed + marker = 7.
        assert_eq!(addrs.len(), 7);
        // Marker is last; matches the standalone PDA.
        assert_eq!(addrs[6], batch_validity_marker_pda(&[0xAB; 32]).0);
    }
}
