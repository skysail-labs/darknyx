//! v3 — integration tests for `vault::tee_forced_settle_batched` +
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

use anchor_lang::prelude::Clock;
use settle_harness::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

/// Build one exact-fill, single-match "batch" keyed off a `tag` byte: seed its
/// two input locks + the single-match `BatchValidityMarker`, and return
/// `(payload, proof, root)` so the caller can settle it to any shard, signed by
/// any key. Shared by the multi-shard / multi-key / per-shard-reset tests.
fn seed_single_match(h: &mut Harness, tag: u8) -> (MatchResultPayload, [[u8; 32]; 4], [u8; 32]) {
    let note_a = fr_safe(0xA0, tag);
    let note_b = fr_safe(0xB0, tag);
    let oid_a = [0x10u8 ^ tag; 16];
    let oid_b = [0x11u8 ^ tag; 16];
    seed_note_lock(h, &note_a, &oid_a, 1_000_000, 5_000); // quote
    seed_note_lock(h, &note_b, &oid_b, 1_000_000, 100); // base
    let p = MatchResultPayload::exact_fill(
        [0xE0u8 ^ tag; 16],
        note_a,
        note_b,
        fr_safe(0xC0, tag),
        fr_safe(0xD0, tag),
        oid_a,
        oid_b,
        100,
        5_000,
    );
    let mint = read_note_lock_mint(h, &note_a);
    let leaf = compute_match_leaf_for(&p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(h, &root, u64::MAX / 2);
    (p, proof, root)
}

// CS-09 boundary: release_lock is valid at E, therefore settle must already be
// invalid at E. Exercise both input sides and assert rejection occurs before
// any consume guard, tree append, lock close, or marker mutation.
#[test]
fn settle_rejects_at_or_after_either_input_lock_expiry() {
    for (tag, expire_a, past_boundary) in [(0x31, true, false), (0x32, false, true)] {
        let mut h = Harness::setup();
        if past_boundary {
            h.svm.warp_to_slot(10);
        }
        let (p, proof, root) = seed_single_match(&mut h, tag);
        let now = h.svm.get_sysvar::<Clock>().slot;
        let expiry = if past_boundary {
            now.saturating_sub(1)
        } else {
            now
        };
        if expire_a {
            seed_note_lock(&mut h, &p.note_a_commitment, &p.order_id_a, expiry, 0);
        } else {
            seed_note_lock(&mut h, &p.note_b_commitment, &p.order_id_b, expiry, 0);
        }

        let before = tree_leaf_count(&h, 0);
        let tx = build_settle_batched_tx(&h, 0, &p, 0, &proof, &root);
        let result = h.svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "settle must reject {} lock at slot {now} with expiry {expiry}",
            if expire_a { "A" } else { "B" }
        );
        assert_eq!(tree_leaf_count(&h, 0), before);
        assert!(!consumed_note_exists(&h, &p.note_a_commitment));
        assert!(!consumed_note_exists(&h, &p.note_b_commitment));
        assert!(note_lock_exists(&h, &p.note_a_commitment));
        assert!(note_lock_exists(&h, &p.note_b_commitment));
        assert!(batch_validity_marker_exists(&h, &root));
    }
}

// ===========================================================================
// Regression — withdraw→settle double-spend is CLOSED (the consume-guard fix).
//
// Before the fix a withdrawn note left NO commitment-keyed consume guard:
// `withdraw` only inited `NullifierEntry[nullifier]` + *read* (never wrote)
// `ConsumedNoteEntry[commitment]`, while settle consumes a note by its
// COMMITMENT (`consumed_a`). A TEE-chosen nullifier used to ride the settle
// payload and could avoid colliding with the withdraw's real one, so the same
// note paid out twice. (A litesvm PoC confirmed this reproduces on the pre-fix
// code before the fix landed.)
//
// The fix: `withdraw` now ALSO inits `ConsumedNoteEntry[commitment]`, making
// the commitment-keyed entry the single trustless consume-once guard shared by
// both paths. This test runs a REAL end-to-end withdraw (real SPL mint +
// deposit + snarkjs VALID_SPEND proof) and asserts a subsequent settle of the
// same note now REVERTS on the `consumed_a` init collision.
// ===========================================================================
#[test]
fn withdraw_then_settle_double_spend_is_blocked() {
    let mut h = Harness::setup();

    // ── Deposit note X into a fresh shard (leaf 0) with a real SPL mint ──
    let mint = create_spl_mint(&mut h, 6);
    let depositor = Keypair::new();
    h.svm
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop depositor");
    let secret = NoteSecret::from_seeds(0x41, 0x42, 0x43);
    let note = deposit_note(&mut h, &depositor, 0, secret, &mint, 1_234_567);

    // ── Withdraw X with a real VALID_SPEND proof. Tokens leave the vault. ──
    let dest = create_spl_token_account(&mut h, &mint, &depositor.pubkey(), 0);
    let wtx = build_withdraw_tx(&h, &note, &depositor, &dest);
    h.svm
        .send_transaction(wtx)
        .expect("withdraw of X must succeed");

    // THE FIX: withdraw wrote the commitment-keyed consume guard for X.
    assert!(
        consumed_note_exists(&h, &note.commitment),
        "withdraw must init ConsumedNoteEntry[X] (the shared consume-once guard)",
    );

    // ── A malicious matcher now tries to settle a batch CONSUMING withdrawn X ──
    // (Seed a NoteLock for X — the attacker locks the already-withdrawn note —
    // plus a counterparty note.)
    let note_b = fr_safe(0xB0, 0x01);
    let oid_a = [0x10u8; 16];
    let oid_b = [0x11u8; 16];
    seed_note_lock(&mut h, &note.commitment, &oid_a, 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &oid_b, 1_000_000, 100);
    let p = MatchResultPayload::exact_fill(
        [0xE0u8; 16],
        note.commitment,
        note_b,
        fr_safe(0xC0, 0x01),
        fr_safe(0xD0, 0x01),
        oid_a,
        oid_b,
        100,
        5_000,
    );
    let m = read_note_lock_mint(&h, &note.commitment);
    let leaf = compute_match_leaf_for(&p, &m, &m);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(&mut h, &root, u64::MAX / 2);

    let stx = build_settle_batched_tx(&h, 0, &p, 0, &proof, &root);
    let res = h.svm.send_transaction(stx);

    // POST-FIX: the settle REVERTS — `consumed_a` init collides with the entry
    // withdraw wrote, so the already-withdrawn note cannot be consumed again.
    assert!(
        res.is_err(),
        "withdraw→settle double-spend must be blocked (settle's consumed_a init \
         collides with the withdraw's ConsumedNoteEntry[X]); got Ok",
    );
}

// ===========================================================================
// Regression — settle→withdraw double-spend is CLOSED.
//
// The mirror direction: a note consumed by a settle (which inits
// `ConsumedNoteEntry[X]`) can no longer be withdrawn. Post-fix withdraw's own
// `consumed_note` init collides on that PDA (pre-fix it was the manual Layer-3
// check; the guarantee is unchanged, but the guard is now a single `init`).
// ===========================================================================
#[test]
fn settle_then_withdraw_double_spend_is_blocked() {
    let mut h = Harness::setup();

    // Deposit note X (real mint) so it's a spendable leaf with a real proof.
    let mint = create_spl_mint(&mut h, 6);
    let depositor = Keypair::new();
    h.svm
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop depositor");
    let secret = NoteSecret::from_seeds(0x51, 0x52, 0x53);
    let note = deposit_note(&mut h, &depositor, 0, secret, &mint, 2_222_222);

    // ── Settle a batch that consumes X first ──
    let note_b = fr_safe(0xB0, 0x02);
    let oid_a = [0x20u8; 16];
    let oid_b = [0x21u8; 16];
    seed_note_lock(&mut h, &note.commitment, &oid_a, 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &oid_b, 1_000_000, 100);
    let p = MatchResultPayload::exact_fill(
        [0xE0u8; 16],
        note.commitment,
        note_b,
        fr_safe(0xC0, 0x02),
        fr_safe(0xD0, 0x02),
        oid_a,
        oid_b,
        100,
        5_000,
    );
    let m = read_note_lock_mint(&h, &note.commitment);
    let leaf = compute_match_leaf_for(&p, &m, &m);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(&mut h, &root, u64::MAX / 2);
    h.svm
        .send_transaction(build_settle_batched_tx(&h, 0, &p, 0, &proof, &root))
        .expect("settle consuming X succeeds");
    assert!(consumed_note_exists(&h, &note.commitment));

    // FREEZE-VECTOR CHECK: the settle wrote NO NullifierEntry — so a compromised
    // TEE can no longer pre-claim a victim's future withdraw nullifier via the
    // settle path. Payload v9 cannot carry an alternate nullifier at all.
    assert!(
        !nullifier_exists(&h, &note.nullifier),
        "settle must not write a NullifierEntry (freeze vector removed)",
    );

    // ── Now withdrawing the already-consumed X must REVERT ──
    let dest = create_spl_token_account(&mut h, &mint, &depositor.pubkey(), 0);
    let wtx = build_withdraw_tx(&h, &note, &depositor, &dest);
    assert!(
        h.svm.send_transaction(wtx).is_err(),
        "withdraw of an already-settle-consumed note must be blocked",
    );
}

// ---------------------------------------------------------------------------
// F-08 regression: the settle handler reads `batch_validity_marker` raw (it's an
// UncheckedAccount), so it must validate the Anchor discriminator — not just the
// owner + length + PDA address. Tamper only the discriminator byte (everything
// else stays valid) and assert the settle is rejected.
// ---------------------------------------------------------------------------
#[test]
fn settle_rejects_marker_with_tampered_discriminator() {
    let mut h = Harness::setup();
    let (p, proof, root) = seed_single_match(&mut h, 0x44);

    // Corrupt byte 0 of the marker's 8-byte discriminator; leave payer/expiry/
    // owner/length/PDA-address intact.
    let (marker_pda, _) = batch_validity_marker_pda(&h, &root);
    let mut acct = h.svm.get_account(&marker_pda).expect("marker seeded");
    acct.data[0] ^= 0xFF;
    h.svm.set_account(marker_pda, acct).unwrap();

    let tx = build_settle_batched_tx(&h, 0, &p, 0, &proof, &root);
    assert!(
        h.svm.send_transaction(tx).is_err(),
        "settle must reject a marker whose Anchor discriminator was tampered",
    );
    assert!(
        !consumed_note_exists(&h, &p.note_a_commitment),
        "the rejected settle must not have consumed its input note",
    );
}

// ---------------------------------------------------------------------------
// CU profiling — TRUE WORST CASE: a single settle that appends all SIX output
// leaves (note_c, note_d, buyer change note_e, seller change note_f, base-fee
// note, quote-fee note) AND creates BOTH continuation re-lock PDAs (buyer +
// seller change). This is the absolute upper bound the on-chain settle pays,
// and the figure nyx-tee's SETTLE_COMPUTE_UNIT_LIMIT must cover. Pairs with
// `test_two_matches_share_one_marker`'s 2-leaf print so we bracket the range.
// ---------------------------------------------------------------------------
#[test]
fn cu_profile_worst_case_settle() {
    let mut h = Harness::setup();
    // Fee notes require a set protocol owner (handler `require!(protocol_owner_set)`).
    set_vault_fee_config(&mut h, fr_safe(0x9A, 0x01), 30);

    let note_a = fr_safe(0xA0, 0x77);
    let note_b = fr_safe(0xB0, 0x77);
    let oid_a = [0x10u8; 16];
    let oid_b = [0x11u8; 16];
    seed_note_lock(&mut h, &note_a, &oid_a, u64::MAX / 2, 6_000); // quote
    seed_note_lock(&mut h, &note_b, &oid_b, u64::MAX / 2, 200); // base

    // All six output commitments non-zero → all six leaves append.
    let mut p = MatchResultPayload::exact_fill(
        [0xE0u8; 16],
        note_a,
        note_b,
        fr_safe(0xC0, 0x77),
        fr_safe(0xD0, 0x77),
        oid_a,
        oid_b,
        100,
        5_000,
    );
    p.note_e_commitment = fr_safe(0xE5, 0x77);
    p.note_f_commitment = fr_safe(0xF5, 0x77);
    p.note_fee_base_commitment = fr_safe(0xFB, 0x77);
    p.note_fee_quote_commitment = fr_safe(0xFC, 0x77);
    // BOTH continuation re-locks fire too — note_lock_e/f are freshly init'd by
    // `create_relock_pda` (we never seed them), so this also pays the two
    // system-CPI account creations the production worst case incurs.
    // Re-lock expiries must sit within `MAX_LOCK_TTL_SLOTS` (=4_500) of the
    // current slot (litesvm genesis = slot 0) — `create_relock_pda` now caps
    // them (C-02), same as `lock_note`.
    p.buyer_relock_order_id = [0x31u8; 16];
    p.buyer_relock_expiry = 4_000;
    p.seller_relock_order_id = [0x32u8; 16];
    p.seller_relock_expiry = 4_000;

    let mint = read_note_lock_mint(&h, &note_a);
    let leaf = compute_match_leaf_for(&p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(&mut h, &root, u64::MAX / 2);

    let before = vault_leaf_count(&h);
    let tx = build_settle_batched_tx(&h, 0, &p, 0, &proof, &root);
    let meta = h
        .svm
        .send_transaction(tx)
        .expect("worst-case settle succeeds");
    eprintln!(
        "CU_PROFILE tee_forced_settle_batched(6-leaf+2-relock) consumed={}",
        meta.compute_units_consumed
    );
    // This is the figure nyx-tee's SETTLE_COMPUTE_UNIT_LIMIT must cover
    // (crates/nyx-tee/src/settle/pipeline.rs). Post-CU-1 the worst case is far
    // below the old ~165k; the sentinel guards a regression that would erode
    // the headroom a lowered limit relies on.
    assert!(
        meta.compute_units_consumed < 110_000,
        "settle worst-case CU {} regressed; re-measure + re-check nyx-tee \
         SETTLE_COMPUTE_UNIT_LIMIT margin",
        meta.compute_units_consumed
    );
    // All six leaves landed.
    assert_eq!(vault_leaf_count(&h), before + 6);
    // Both continuation re-locks were created.
    assert!(note_lock_exists(&h, &p.note_e_commitment));
    assert!(note_lock_exists(&h, &p.note_f_commitment));
}

// ---------------------------------------------------------------------------
// C-02 regression: `create_relock_pda` must cap a continuation re-lock's expiry
// at `current_slot + MAX_LOCK_TTL_SLOTS`, exactly as `lock_note` caps a fresh
// lock. Before the fix the re-lock path set `expiry_slot` unchecked, so a
// malicious TEE could stamp an arbitrarily distant expiry — and because
// `withdraw` rejects while ANY NoteLock exists (even an expired one), that
// freezes the note indefinitely (censorship). This mirrors the passing
// worst-case settle above; the ONLY change is the buyer re-lock expiry is set
// beyond the cap, so the whole settle must revert atomically.
// ---------------------------------------------------------------------------
#[test]
fn settle_rejects_relock_expiry_beyond_ttl_cap() {
    let mut h = Harness::setup();
    set_vault_fee_config(&mut h, fr_safe(0x9A, 0x02), 30);

    let note_a = fr_safe(0xA0, 0x78);
    let note_b = fr_safe(0xB0, 0x78);
    let oid_a = [0x12u8; 16];
    let oid_b = [0x13u8; 16];
    seed_note_lock(&mut h, &note_a, &oid_a, u64::MAX / 2, 6_000); // quote
    seed_note_lock(&mut h, &note_b, &oid_b, u64::MAX / 2, 200); // base

    let mut p = MatchResultPayload::exact_fill(
        [0xE2u8; 16],
        note_a,
        note_b,
        fr_safe(0xC0, 0x78),
        fr_safe(0xD0, 0x78),
        oid_a,
        oid_b,
        100,
        5_000,
    );
    p.note_e_commitment = fr_safe(0xE5, 0x78);
    p.note_f_commitment = fr_safe(0xF5, 0x78);
    p.note_fee_base_commitment = fr_safe(0xFB, 0x78);
    p.note_fee_quote_commitment = fr_safe(0xFC, 0x78);
    p.buyer_relock_order_id = [0x33u8; 16];
    p.seller_relock_order_id = [0x34u8; 16];
    // Seller re-lock is within cap; buyer re-lock is OVER the cap (genesis slot
    // 0, cap = MAX_LOCK_TTL_SLOTS = 4_500). The over-cap buyer re-lock is the
    // sole reason the settle must fail.
    p.seller_relock_expiry = 4_000;
    p.buyer_relock_expiry = u64::MAX / 2;

    let mint = read_note_lock_mint(&h, &note_a);
    let leaf = compute_match_leaf_for(&p, &mint, &mint);
    let mut leaves = [[0u8; 32]; 16];
    leaves[0] = leaf;
    let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
    seed_batch_validity_marker(&mut h, &root, u64::MAX / 2);

    let tx = build_settle_batched_tx(&h, 0, &p, 0, &proof, &root);
    assert!(
        h.svm.send_transaction(tx).is_err(),
        "settle must reject a continuation re-lock whose expiry exceeds MAX_LOCK_TTL_SLOTS",
    );
    // Atomic revert: the input note must stay unconsumed and NEITHER re-lock
    // (over-cap buyer, within-cap seller) may have been created.
    assert!(
        !consumed_note_exists(&h, &p.note_a_commitment),
        "rejected settle must not consume its input note",
    );
    assert!(
        !note_lock_exists(&h, &p.note_e_commitment),
        "rejected settle must not create the over-cap buyer re-lock",
    );
    assert!(
        !note_lock_exists(&h, &p.note_f_commitment),
        "rejected settle must roll back the within-cap seller re-lock too (atomicity)",
    );
}

// NOTE: the on-chain fee-FLOOR + conservation regression test that lived here
// was removed with P3a — both checks moved IN-CIRCUIT (amount-privacy), so the
// settle handler no longer reads plaintext amounts to enforce them. The floor's
// enforcement is now covered by the circuit negative tests in
// `packages/sdk/tests/match-batch-prototype.test.ts` (charging exactly the
// floor proves at rate=30; under-charging is unprovable).

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
    // `fr_safe` enforces that.
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
    let mut p1 = MatchResultPayload::exact_fill(
        [0xE1u8; 16],
        note_a1,
        note_b1,
        fr_safe(0xC1, 0x02),
        fr_safe(0xD1, 0x02),
        oid_a1,
        oid_b1,
        100,
        5_000,
    );
    // C-08: match 1 settles at match_index 1, and the handler now asserts
    // `payload.batch_slot == match_index`. Set it (+ it flows into leaf1 below so
    // the marker root binds the slot-1 leaf built with batch_slot=1).
    p1.batch_slot = 1;

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

    // Match 0 → success (was always fine, even pre-fix). Both matches settle to
    // shard 0 here — the shared-marker invariant is tree-independent.
    let tx0 = build_settle_batched_tx(&h, 0, &p0, 0, &proof0, &merkle_root);
    let meta0 = h.svm.send_transaction(tx0).expect("match 0 settles");
    // CU profiling for the 2-leaf (note_c + note_d only) path. Since CU-1
    // (the multi-leaf batch-append in merkle.rs), leaf count barely moves the
    // needle — the dominant cost is the fixed per-settle overhead (Ed25519
    // verify + canonical-hash recompute + marker check + the consumed/nullifier
    // PDA inits), and `append_leaves` shares the Merkle path across all output
    // leaves. The true worst case (6 leaves) is guarded directly by
    // `cu_profile_six_leaf_settle` below — no extrapolation needed. Baselines
    // (litesvm, pre/post CU-1): 2-leaf 93,112 → 77,135; 6-leaf 165,355 → 80,230.
    eprintln!(
        "CU_PROFILE tee_forced_settle_batched(2-leaf) consumed={}",
        meta0.compute_units_consumed
    );
    assert!(
        meta0.compute_units_consumed < 90_000,
        "settle(2-leaf) CU {} regressed past the post-CU-1 baseline (~77k); re-measure",
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
    let tx1 = build_settle_batched_tx(&h, 0, &p1, 1, &proof1, &merkle_root);
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
        oid_a0,
        oid_b0,
        100,
        5_000,
    );
    p0.note_e_commitment = note_e;
    p0.buyer_relock_order_id = oid_relock;
    // Within `MAX_LOCK_TTL_SLOTS` of genesis slot 0 — the re-lock path now caps
    // this (C-02). The input-lock + marker seeds above stay far-future (they're
    // written directly, bypassing the cap).
    p0.buyer_relock_expiry = 4_000;

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
    let tx1 = build_settle_batched_tx(&h, 0, &p1, 0, &proof1, &root1);
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
// `close_batch_validity_marker` — the payer has no early-close privilege.
// At E the marker is no longer usable for settle and may be reclaimed.
// ---------------------------------------------------------------------------

#[test]
fn test_close_marker_by_payer_requires_expiry_and_refunds_rent() {
    let mut h = Harness::setup();

    // Synthesise a marker against an arbitrary root. We don't need
    // any settles for the close path — only marker + payer state.
    let merkle_root = [0xCDu8; 32];
    let expiry = h.svm.get_sysvar::<Clock>().slot + 10;
    seed_batch_validity_marker(&mut h, &merkle_root, expiry);
    assert!(batch_validity_marker_exists(&h, &merkle_root));

    // Snapshot the payer's lamports before the close so we can
    // verify the refund actually lands.
    let payer = h.tee.pubkey();
    let before = h.svm.get_account(&payer).map(|a| a.lamports).unwrap_or(0);

    let close_ix = build_close_batch_validity_marker_ix(&h, &merkle_root, &payer, &payer);
    let early_tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(std::slice::from_ref(&close_ix), Some(&payer)),
        h.svm.latest_blockhash(),
    );
    assert!(
        h.svm.send_transaction(early_tx).is_err(),
        "marker payer must not close before expiry"
    );
    assert!(batch_validity_marker_exists(&h, &merkle_root));

    h.svm.warp_to_slot(expiry);
    // The early and boundary messages are otherwise byte-identical. Rotate the
    // litesvm blockhash so the boundary attempt is not rejected as a replay.
    h.svm.expire_blockhash();
    let tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(&[close_ix], Some(&payer)),
        h.svm.latest_blockhash(),
    );
    let close_meta = h.svm.send_transaction(tx).expect("close by payer");
    // Regression guard for nyx-tee's CLOSE_COMPUTE_UNIT_LIMIT (5_000).
    eprintln!(
        "CU_PROFILE close_batch_validity_marker consumed={}",
        close_meta.compute_units_consumed
    );
    assert!(
        close_meta.compute_units_consumed < 5_000,
        "close_batch_validity_marker CU {} exceeds nyx-tee CLOSE_COMPUTE_UNIT_LIMIT (5_000)",
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
// `close_batch_validity_marker` — a non-payer follows the same boundary:
// reject before E, permit at E, and refund the marker payer.
// ---------------------------------------------------------------------------

#[test]
fn test_close_marker_by_third_party_requires_expiry_and_refunds_payer() {
    let mut h = Harness::setup();
    let merkle_root = [0xEFu8; 32];
    let expiry = h.svm.get_sysvar::<Clock>().slot + 10;
    seed_batch_validity_marker(&mut h, &merkle_root, expiry);
    let sweeper = Keypair::new();
    h.svm
        .airdrop(&sweeper.pubkey(), 100_000_000)
        .expect("airdrop sweeper");

    let payer = h.tee.pubkey();
    let close_ix =
        build_close_batch_validity_marker_ix(&h, &merkle_root, &sweeper.pubkey(), &payer);
    let early_tx = solana_transaction::Transaction::new(
        &[&sweeper],
        solana_message::Message::new(std::slice::from_ref(&close_ix), Some(&sweeper.pubkey())),
        h.svm.latest_blockhash(),
    );
    let res = h.svm.send_transaction(early_tx);
    assert!(res.is_err(), "third-party close pre-expiry must fail");
    assert!(batch_validity_marker_exists(&h, &merkle_root));

    let before = h.svm.get_account(&payer).map(|a| a.lamports).unwrap_or(0);
    h.svm.warp_to_slot(expiry);
    h.svm.expire_blockhash();
    let tx = solana_transaction::Transaction::new(
        &[&sweeper],
        solana_message::Message::new(&[close_ix], Some(&sweeper.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect("third-party close at expiry");
    assert!(!batch_validity_marker_exists(&h, &merkle_root));
    let after = h.svm.get_account(&payer).map(|a| a.lamports).unwrap_or(0);
    assert!(after > before, "marker rent must return to recorded payer");
}

// ---------------------------------------------------------------------------
// Tree-sharding: two settles routed to DISTINCT shards advance each shard's
// `leaf_count` independently — the whole point of splitting the single
// Merkle-tree account into K. The output appends touch only `merkle_tree[id]`,
// so settle-to-shard-0 and settle-to-shard-1 share no writable tree account
// (the lever that lets the leader co-include them). Each is its own
// single-match batch with its own marker (distinct merkle roots).
// ---------------------------------------------------------------------------

#[test]
fn test_settles_to_distinct_shards_advance_independently() {
    let mut h = Harness::setup();

    // Both shards start empty.
    assert_eq!(tree_leaf_count(&h, 0), 0);
    assert_eq!(tree_leaf_count(&h, 1), 0);

    // Helper: build one exact-fill match keyed off a `tag` byte, seed its
    // locks + a single-match marker, and return a tx settling it to `tree_id`.
    let build_one = |h: &mut Harness, tag: u8, tree_id: u8| {
        let note_a = fr_safe(0xA0, tag);
        let note_b = fr_safe(0xB0, tag);
        let oid_a = [0x10u8 ^ tag; 16];
        let oid_b = [0x11u8 ^ tag; 16];
        seed_note_lock(h, &note_a, &oid_a, 1_000_000, 5_000); // quote
        seed_note_lock(h, &note_b, &oid_b, 1_000_000, 100); // base
        let p = MatchResultPayload::exact_fill(
            [0xE0u8 ^ tag; 16],
            note_a,
            note_b,
            fr_safe(0xC0, tag),
            fr_safe(0xD0, tag),
            oid_a,
            oid_b,
            100,
            5_000,
        );
        let mint = read_note_lock_mint(h, &note_a);
        let leaf = compute_match_leaf_for(&p, &mint, &mint);
        let mut leaves = [[0u8; 32]; 16];
        leaves[0] = leaf;
        let (root, proof) = build_merkle_root_and_path_n16(&leaves, 0);
        seed_batch_validity_marker(h, &root, u64::MAX / 2);
        build_settle_batched_tx(h, tree_id, &p, 0, &proof, &root)
    };

    // Match 0 → shard 0; match 1 → shard 1.
    let tx0 = build_one(&mut h, 0x01, 0);
    h.svm.send_transaction(tx0).expect("settle to shard 0");
    let tx1 = build_one(&mut h, 0x02, 1);
    h.svm.send_transaction(tx1).expect("settle to shard 1");

    // Each shard appended exactly its own (note_c, note_d) pair — and the two
    // are wholly independent: shard 0's count didn't pick up shard 1's leaves.
    assert_eq!(
        tree_leaf_count(&h, 0),
        2,
        "shard 0 holds only its own 2 output leaves"
    );
    assert_eq!(
        tree_leaf_count(&h, 1),
        2,
        "shard 1 holds only its own 2 output leaves"
    );
}

// ---------------------------------------------------------------------------
// Multi-key authorized set: a settle signed by ANY of the registered
// `tee_pubkeys` (here `tee_pubkeys[1]`) succeeds; one signed by a key NOT in
// the set is rejected `Unauthorized`. This is the on-chain half of the K
// fee-payer lever — each shard's settle is paid + signed by a distinct dstack
// key, and the vault must accept the whole registered set, not just key 0.
// ---------------------------------------------------------------------------

#[test]
fn test_settle_signed_by_registered_key_succeeds_unregistered_fails() {
    let mut h = Harness::setup();

    // Register a SECOND authorized key alongside the default `h.tee`.
    let second = Keypair::new();
    h.svm
        .airdrop(&second.pubkey(), 10_000_000_000)
        .expect("airdrop second key");
    let set_ix = build_set_tee_pubkeys_ix(&h, &[h.tee.pubkey(), second.pubkey()]);
    let set_tx = solana_transaction::Transaction::new(
        &[&h.admin],
        solana_message::Message::new(&[set_ix], Some(&h.admin.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(set_tx)
        .expect("register the 2-key authorized set");

    // A settle signed by `tee_pubkeys[1]` (the second registered key) settles.
    let (p_ok, proof_ok, root_ok) = seed_single_match(&mut h, 0x11);
    let tx_ok = build_settle_batched_tx_signed_by(&h, &second, 0, &p_ok, 0, &proof_ok, &root_ok);
    h.svm
        .send_transaction(tx_ok)
        .expect("settle signed by a registered key must succeed");
    assert!(consumed_note_exists(&h, &p_ok.note_a_commitment));

    // A settle signed by an UNREGISTERED key is rejected (`is_authorized_tee`
    // fails before any state mutation).
    let impostor = Keypair::new();
    h.svm
        .airdrop(&impostor.pubkey(), 10_000_000_000)
        .expect("airdrop impostor");
    let (p_bad, proof_bad, root_bad) = seed_single_match(&mut h, 0x22);
    let tx_bad =
        build_settle_batched_tx_signed_by(&h, &impostor, 0, &p_bad, 0, &proof_bad, &root_bad);
    assert!(
        h.svm.send_transaction(tx_bad).is_err(),
        "settle signed by an unregistered key must be rejected",
    );
    assert!(
        !consumed_note_exists(&h, &p_bad.note_a_commitment),
        "the rejected settle must not have consumed its input note",
    );
}

// ---------------------------------------------------------------------------
// Per-shard reset: `reset_merkle_tree(1)` wipes ONLY shard 1's leaf state;
// shard 0 keeps its accumulated leaves. Confirms the reset ix is correctly
// scoped to a single `MerkleTree` account post-sharding (each shard resets
// independently — the devnet e2e harness relies on this to clean one shard
// without disturbing the others).
// ---------------------------------------------------------------------------

#[test]
fn test_reset_one_shard_leaves_others_untouched() {
    let mut h = Harness::setup();

    // Populate both shards: each settle appends its (note_c, note_d) pair.
    let (p0, proof0, root0) = seed_single_match(&mut h, 0x31);
    h.svm
        .send_transaction(build_settle_batched_tx(&h, 0, &p0, 0, &proof0, &root0))
        .expect("settle to shard 0");
    let (p1, proof1, root1) = seed_single_match(&mut h, 0x32);
    h.svm
        .send_transaction(build_settle_batched_tx(&h, 1, &p1, 0, &proof1, &root1))
        .expect("settle to shard 1");
    assert_eq!(tree_leaf_count(&h, 0), 2);
    assert_eq!(tree_leaf_count(&h, 1), 2);

    // Reset ONLY shard 1.
    let reset_ix = build_reset_merkle_tree_ix(&h, 1);
    let reset_tx = solana_transaction::Transaction::new(
        &[&h.admin],
        solana_message::Message::new(&[reset_ix], Some(&h.admin.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(reset_tx)
        .expect("reset_merkle_tree(1)");

    // Shard 1 back to empty; shard 0 untouched.
    assert_eq!(tree_leaf_count(&h, 1), 0, "shard 1 reset to empty");
    assert_eq!(
        tree_leaf_count(&h, 0),
        2,
        "shard 0 must be untouched by a shard-1 reset"
    );
}
