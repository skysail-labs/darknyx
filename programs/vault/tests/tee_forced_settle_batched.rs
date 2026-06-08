//! v3.5 — integration tests for `vault::tee_forced_settle_batched` +
//! `vault::close_batch_validity_marker`.
//!
//! The TS-side devnet tests always land exactly ONE real settle per
//! batch (the prover pads to N=16 with dummy slots), so they can't
//! catch the "marker closed after the first match in a multi-match
//! batch" class of regression — match 0 always works there.
//! This file exists to cover that gap with a litesvm test that
//! seats TWO real matches at slots 0 and 1, both settling against
//! the SAME `BatchValidityMarker`.

mod settle_harness;

use settle_harness::*;
use solana_signer::Signer;

// ---------------------------------------------------------------------------
// Regression: multiple matches share one marker.
//
// Pre-fix `tee_forced_settle_batched` unconditionally drained the marker's
// lamports + zeroed its data at the end of every match. That closed the PDA
// after match 0 and tripped the existence/expiry assertion when match 1
// tried to settle against the same merkle_root. The fix removes that
// close from the per-match handler; reclaiming the marker's rent is now
// the job of `close_batch_validity_marker` (separately exercised below).
// ---------------------------------------------------------------------------

#[test]
fn test_two_matches_share_one_marker() {
    let mut h = Harness::setup();

    // ── Match 0 — exact-fill, no change ──────────────────────────
    // Notes a..f all get Poseidon-hashed inside `compute_match_leaf`,
    // so every commitment must be a valid BN254 Fr (top byte == 0x00).
    // `fr_safe` enforces that; nullifiers stay raw (only PDA-seeded,
    // not Poseidon-hashed).
    let note_a0 = fr_safe(0xA0, 0x01);
    let note_b0 = fr_safe(0xB0, 0x01);
    let oid_a0 = [0x10u8; 16];
    let oid_b0 = [0x11u8; 16];
    seed_note_lock(&mut h, &note_a0, &oid_a0, 1_000_000, 5_000); // quote
    seed_note_lock(&mut h, &note_b0, &oid_b0, 1_000_000, 100); // base
    let p0 = MatchResultPayload::exact_fill(
        [0xE0u8; 16],
        note_a0,
        note_b0,
        fr_safe(0xC0, 0x01),
        fr_safe(0xD0, 0x01),
        [0xF0u8; 32],
        [0xF1u8; 32],
        oid_a0,
        oid_b0,
        100,
        5_000,
    );

    // ── Match 1 — exact-fill, no change, distinct everything ─────
    let note_a1 = fr_safe(0xA0, 0x02);
    let note_b1 = fr_safe(0xB0, 0x02);
    let oid_a1 = [0x20u8; 16];
    let oid_b1 = [0x21u8; 16];
    seed_note_lock(&mut h, &note_a1, &oid_a1, 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b1, &oid_b1, 1_000_000, 100);
    let p1 = MatchResultPayload::exact_fill(
        [0xE1u8; 16],
        note_a1,
        note_b1,
        fr_safe(0xC1, 0x02),
        fr_safe(0xD1, 0x02),
        [0xF2u8; 32],
        [0xF3u8; 32],
        oid_a1,
        oid_b1,
        100,
        5_000,
    );

    // Both matches sit on the same market, so `compute_match_leaf`
    // sees the same (quote_mint, base_mint) pair for both.
    let mint = read_note_lock_mint(&h, &note_a0);
    let leaf0 = compute_match_leaf_for(&p0, &mint, &mint);
    let leaf1 = compute_match_leaf_for(&p1, &mint, &mint);

    // Build the 16-leaf tree: [leaf0, leaf1, 0, 0, …, 0].
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf0;
    leaves[1] = leaf1;
    let (merkle_root, proof0) = build_merkle_root_and_path_n16(&leaves, 0);
    let (_, proof1) = build_merkle_root_and_path_n16(&leaves, 1);

    // ONE marker covering both matches — emulates what
    // `verify_match_batch` would have written upstream.
    seed_batch_validity_marker(&mut h, &merkle_root, u64::MAX / 2);
    assert!(batch_validity_marker_exists(&h, &merkle_root));

    let before = vault_leaf_count(&h);

    // Match 0 → success (was always fine, even pre-fix).
    let tx0 = build_settle_batched_tx(&h, &p0, 0, &proof0, &merkle_root);
    let meta0 = h.svm.send_transaction(tx0).expect("match 0 settles");
    // CU profiling + regression guard for nyx-tee's SETTLE_COMPUTE_UNIT_LIMIT
    // (250_000 in crates/nyx-tee/src/settle/pipeline.rs). NOTE: this path
    // appends only note_c + note_d (2 leaves, ~99k CU); a production settle adds
    // a buyer change note + base/quote fee notes → up to 5 leaves (~162k CU on
    // devnet, ~21k/extra-leaf). The 140k sentinel below catches a per-op
    // regression on the 2-leaf path *before* the extrapolated 5-leaf worst case
    // would breach the 250k limit.
    eprintln!(
        "CU_PROFILE tee_forced_settle_batched(2-leaf) consumed={}",
        meta0.compute_units_consumed
    );
    assert!(
        meta0.compute_units_consumed < 140_000,
        "settle(2-leaf) CU {} regressed — extrapolated 5-leaf worst case risks \
         breaching nyx-tee SETTLE_COMPUTE_UNIT_LIMIT (250_000); re-measure",
        meta0.compute_units_consumed
    );

    // The regression assertion: match 1 must succeed too. Pre-fix
    // this trip would fail with `BatchValidityMarkerExpired`
    // because match 0's handler had drained the marker's lamports
    // and zeroed its expiry_slot bytes.
    assert!(
        batch_validity_marker_exists(&h, &merkle_root),
        "marker must remain present after match 0 — closing it here \
         bricks every subsequent match in the batch",
    );
    let tx1 = build_settle_batched_tx(&h, &p1, 1, &proof1, &merkle_root);
    h.svm
        .send_transaction(tx1)
        .expect("match 1 settles against the shared marker");

    // Both matches appended their (note_c, note_d) pair → 4 leaves.
    assert_eq!(vault_leaf_count(&h), before + 4);
    assert!(consumed_note_exists(&h, &note_a0));
    assert!(consumed_note_exists(&h, &note_b0));
    assert!(consumed_note_exists(&h, &note_a1));
    assert!(consumed_note_exists(&h, &note_b1));
    assert!(!note_lock_exists(&h, &note_a0));
    assert!(!note_lock_exists(&h, &note_b1));

    // The marker must still be sitting there — the per-match handler
    // deliberately doesn't close it. Cleanup happens via a separate
    // `close_batch_validity_marker` ix (next test).
    assert!(
        batch_validity_marker_exists(&h, &merkle_root),
        "marker must outlive every per-match settle in the batch",
    );
}

// ---------------------------------------------------------------------------
// Regression: a relocked CONTINUATION note is consumable across a SECOND
// batch (the cross-batch re-match path).
//
// Two bugs made cross-batch re-match fail and were only caught on a live CVM.
// This pins the VAULT-side one:
//
//   `create_relock_pda` once wrote every NoteLock field EXCEPT `token_mint`,
//   so a relocked note's lock carried `token_mint = Pubkey::default()`. The
//   next batch that consumed it fed that zero mint into `compute_match_leaf`
//   (token_mint is hashed into the leaf), producing a leaf that no longer
//   walked up to the marker root → InvalidBatchBinding (6022). `lock_note`
//   always set token_mint; the re-lock IS a lock and must match in every
//   field the settle reads back.
//
// (The sibling TEE-side bug — re-issuing `lock_note` on the already-relocked
// note → "Allocate: account already in use" — is guarded by
// `submit_lock_note_pair_skips_relocked_side` in nyx-tee.)
//
// Batch 0's buyer partially fills + re-locks note_e; batch 1 consumes note_e.
// Batch 1's marker is seeded from the TRUE mint (`h.test_mint`), NOT the
// lock's, so a zero-mint re-lock makes the on-chain leaf diverge from the
// marker (settle fails → this test fails) instead of silently agreeing.
// ---------------------------------------------------------------------------

#[test]
fn test_relocked_note_consumable_across_second_batch() {
    let mut h = Harness::setup();
    let far_future = u64::MAX / 2;

    // ── Batch 0: buyer partially fills, mints + re-locks note_e ──
    let note_a0 = fr_safe(0xA0, 0x11);
    let note_b0 = fr_safe(0xB0, 0x11);
    let note_e = fr_safe(0xE5, 0x11); // the buyer's continuation note
    let oid_a0 = [0x10u8; 16];
    let oid_b0 = [0x11u8; 16];
    let oid_relock = [0x30u8; 16]; // the order note_e continues under
                                   // quote_in (lock_a) = quote_amount(5000) + buyer_change(1000) = 6000.
    seed_note_lock(&mut h, &note_a0, &oid_a0, far_future, 6_000);
    seed_note_lock(&mut h, &note_b0, &oid_b0, far_future, 100);

    let mut p0 = MatchResultPayload::exact_fill(
        [0xE0u8; 16],
        note_a0,
        note_b0,
        fr_safe(0xC0, 0x11),
        fr_safe(0xD0, 0x11),
        [0xF0u8; 32],
        [0xF1u8; 32],
        oid_a0,
        oid_b0,
        100,
        5_000,
    );
    p0.note_e_commitment = note_e;
    p0.buyer_change_amt = 1_000;
    p0.buyer_relock_order_id = oid_relock;
    p0.buyer_relock_expiry = far_future;

    let tx0 = seed_marker_and_build_settle_batched_tx(&mut h, &p0);
    h.svm
        .send_transaction(tx0)
        .expect("batch 0 settles + re-locks note_e");

    // THE FIX: the re-lock must exist AND carry the note's real mint. Pre-fix
    // this was Pubkey::default() and the assertion (and batch 1) would fail.
    assert!(note_lock_exists(&h, &note_e), "note_e re-lock must exist");
    assert_eq!(
        read_note_lock_mint(&h, &note_e),
        h.test_mint,
        "re-lock must populate token_mint — a zero mint here breaks the next \
         batch's leaf↔marker binding",
    );

    // ── Batch 1: consume note_e (the relocked note) as the buyer input ──
    // note_e is ALREADY locked by the re-lock (order_id = oid_relock, amount
    // = 1000); do NOT re-seed its lock — only the fresh seller side.
    let note_b1 = fr_safe(0xB1, 0x22);
    let oid_b1 = [0x21u8; 16];
    seed_note_lock(&mut h, &note_b1, &oid_b1, far_future, 100);

    // Exact-fill: quote_in = note_e's locked 1000. order_id_a MUST equal the
    // re-lock's order_id (oid_relock) — the continuation keeps the same order.
    let p1 = MatchResultPayload::exact_fill(
        [0xE1u8; 16],
        note_e,
        note_b1,
        fr_safe(0xC1, 0x22),
        fr_safe(0xD1, 0x22),
        [0xF4u8; 32],
        [0xF5u8; 32],
        oid_relock,
        oid_b1,
        100,
        1_000,
    );

    // Seed the marker from the TRUE mint: a zero-mint re-lock then makes the
    // on-chain leaf (computed from note_e's NoteLock.token_mint) diverge from
    // this marker root → InvalidBatchBinding.
    let leaf1 = compute_match_leaf_for(&p1, &h.test_mint, &h.test_mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf1;
    let (root1, proof1) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(&mut h, &root1, far_future);

    let before = vault_leaf_count(&h);
    let tx1 = build_settle_batched_tx(&h, &p1, 0, &proof1, &root1);
    h.svm.send_transaction(tx1).expect(
        "relocked note_e settles in batch 1 (binding holds iff the re-lock's token_mint is right)",
    );

    // note_e consumed, its re-lock closed, the two output leaves appended.
    assert!(
        consumed_note_exists(&h, &note_e),
        "note_e consumed in batch 1"
    );
    assert!(
        !note_lock_exists(&h, &note_e),
        "note_e re-lock closed on consume"
    );
    assert_eq!(
        vault_leaf_count(&h),
        before + 2,
        "note_c1 + note_d1 appended by batch 1"
    );
}

// ---------------------------------------------------------------------------
// `close_batch_validity_marker` — fast-path: marker.payer closes it
// immediately, no expiry wait. Rent is refunded to the payer.
// ---------------------------------------------------------------------------

#[test]
fn test_close_marker_by_payer_refunds_rent() {
    let mut h = Harness::setup();

    // Synthesise a marker against an arbitrary root. We don't need
    // any settles for the close path — only marker + payer state.
    let merkle_root = [0xCDu8; 32];
    seed_batch_validity_marker(&mut h, &merkle_root, u64::MAX / 2);
    assert!(batch_validity_marker_exists(&h, &merkle_root));

    // Snapshot the payer's lamports before the close so we can
    // verify the refund actually lands.
    let payer = h.tee.pubkey();
    let before = h.svm.get_account(&payer).map(|a| a.lamports).unwrap_or(0);

    let close_ix = build_close_batch_validity_marker_ix(&h, &merkle_root, &payer, &payer);
    let tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(&[close_ix], Some(&payer)),
        h.svm.latest_blockhash(),
    );
    let close_meta = h.svm.send_transaction(tx).expect("close by payer");
    // Regression guard for nyx-tee's CLOSE_COMPUTE_UNIT_LIMIT (15_000).
    eprintln!(
        "CU_PROFILE close_batch_validity_marker consumed={}",
        close_meta.compute_units_consumed
    );
    assert!(
        close_meta.compute_units_consumed < 15_000,
        "close_batch_validity_marker CU {} exceeds nyx-tee CLOSE_COMPUTE_UNIT_LIMIT",
        close_meta.compute_units_consumed
    );

    // Marker bytes must be wiped + rent refunded to the payer.
    assert!(
        !batch_validity_marker_exists(&h, &merkle_root),
        "close_batch_validity_marker should zero the PDA and drain its lamports",
    );
    let after = h.svm.get_account(&payer).map(|a| a.lamports).unwrap_or(0);
    assert!(
        after > before,
        "payer should have received the marker's rent refund (before={before}, after={after})",
    );
}

// ---------------------------------------------------------------------------
// `close_batch_validity_marker` — pre-expiry close by a NON-payer signer
// must fail with `BatchValidityMarkerNotExpired`. The expiry-GC path is
// only available once `clock.slot > marker.expiry_slot`.
// ---------------------------------------------------------------------------

#[test]
fn test_close_marker_by_third_party_pre_expiry_rejects() {
    use solana_keypair::Keypair;

    let mut h = Harness::setup();
    let merkle_root = [0xEFu8; 32];
    // Far-future expiry — the third-party path should be blocked.
    seed_batch_validity_marker(&mut h, &merkle_root, u64::MAX / 2);
    let sweeper = Keypair::new();
    h.svm
        .airdrop(&sweeper.pubkey(), 100_000_000)
        .expect("airdrop sweeper");

    let payer = h.tee.pubkey();
    let close_ix =
        build_close_batch_validity_marker_ix(&h, &merkle_root, &sweeper.pubkey(), &payer);
    let tx = solana_transaction::Transaction::new(
        &[&sweeper],
        solana_message::Message::new(&[close_ix], Some(&sweeper.pubkey())),
        h.svm.latest_blockhash(),
    );
    let res = h.svm.send_transaction(tx);
    assert!(res.is_err(), "third-party close pre-expiry must fail");
    // Marker must still be intact after the rejected attempt.
    assert!(batch_validity_marker_exists(&h, &merkle_root));
}
