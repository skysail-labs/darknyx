//! Phase-5 integration tests for `vault::tee_forced_settle`.
//!
//! Exercises the full settle path: pre-seed note-locks → build a signed
//! MatchResultPayload → submit (Ed25519 precompile + tee_forced_settle)
//! in one tx → verify state transitions (consumed/nullifier PDAs,
//! Merkle leaf appends, re-lock PDAs, fee-note leaf).

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

// ---------- exact-fill vs partial-fill basics ----------

#[test]
fn test_exact_fill_no_change_note() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA1, 0x01);
    let note_b = fr_safe(0xB1, 0x01);
    let order_id_a = [1u8; 16];
    let order_id_b = [2u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 5_000); // quote
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 100); // base

    let p = MatchResultPayload::exact_fill(
        [0x11; 16],
        note_a,
        note_b,
        fr_safe(0x01, 0xC1),
        fr_safe(0x01, 0xD1),
        [0xEA; 32],
        [0xEB; 32],
        order_id_a,
        order_id_b,
        100,
        5_000,
    );

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let before = vault_leaf_count(&h);
    h.svm.send_transaction(tx).expect("exact-fill settle");

    // Exactly two leaves appended — no change, no fee.
    assert_eq!(vault_leaf_count(&h), before + 2);
    assert!(consumed_note_exists(&h, &note_a));
    assert!(consumed_note_exists(&h, &note_b));
    assert!(nullifier_exists(&h, &[0xEA; 32]));
    assert!(nullifier_exists(&h, &[0xEB; 32]));
    // Input locks should be closed (post-Anchor `close = tee_authority`).
    assert!(!note_lock_exists(&h, &note_a));
    assert!(!note_lock_exists(&h, &note_b));
}

#[test]
fn test_partial_fill_change_note() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA2, 0x01); // buyer: 100 USDC note used for 50 USDC trade
    let note_b = fr_safe(0xB2, 0x01);
    let order_id_a = [3u8; 16];
    let order_id_b = [4u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 10);

    let mut p = MatchResultPayload::exact_fill(
        [0x22; 16],
        note_a,
        note_b,
        fr_safe(0x02, 0xC2),
        fr_safe(0x02, 0xD2),
        [0xEC; 32],
        [0xED; 32],
        order_id_a,
        order_id_b,
        10, // base
        50, // quote
    );
    // Buyer pays 50 of 100 → 50 change. Seller exact-fill (no change).
    p.buyer_change_amt = 50;
    p.note_e_commitment = fr_safe(0x02, 0xE2);

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let before = vault_leaf_count(&h);
    h.svm.send_transaction(tx).expect("partial-fill settle");

    // Leaves: note_c, note_d, note_e (buyer change) = 3.
    assert_eq!(vault_leaf_count(&h), before + 3);
}

#[test]
fn test_both_sides_partial_two_change_notes() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA3, 0x01);
    let note_b = fr_safe(0xB3, 0x01);
    let order_id_a = [5u8; 16];
    let order_id_b = [6u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 20);

    let mut p = MatchResultPayload::exact_fill(
        [0x33; 16],
        note_a,
        note_b,
        fr_safe(0x03, 0xC3),
        fr_safe(0x03, 0xD3),
        [0xEE; 32],
        [0xEF; 32],
        order_id_a,
        order_id_b,
        10,
        50,
    );
    p.buyer_change_amt = 50;
    p.seller_change_amt = 10;
    p.note_e_commitment = fr_safe(0x03, 0xE3);
    p.note_f_commitment = fr_safe(0x03, 0xF3);

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let before = vault_leaf_count(&h);
    h.svm.send_transaction(tx).expect("two-change settle");

    // 4 leaves: note_c + note_d + note_e + note_f.
    assert_eq!(vault_leaf_count(&h), before + 4);
}

// ---------- conservation law ----------

#[test]
fn test_conservation_violation_rejects() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA4, 0x01);
    let note_b = fr_safe(0xB4, 0x01);
    let order_id_a = [7u8; 16];
    let order_id_b = [8u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 10);

    // Quote 50 + change 40 = 90, but lock is 100 → violation.
    let mut p = MatchResultPayload::exact_fill(
        [0x44; 16],
        note_a,
        note_b,
        fr_safe(0x04, 0xC4),
        fr_safe(0x04, 0xD4),
        [0x1A; 32],
        [0x1B; 32],
        order_id_a,
        order_id_b,
        10,
        50,
    );
    p.buyer_change_amt = 40;
    p.note_e_commitment = fr_safe(0x04, 0xE4);

    let before = vault_leaf_count(&h);
    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let err = h.svm.send_transaction(tx).expect_err("must reject");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("conservationviolation") || logs.contains("conservation"),
        "expected conservation error, got:\n{logs}"
    );
    // No state mutation.
    assert_eq!(vault_leaf_count(&h), before);
    assert!(!consumed_note_exists(&h, &note_a));
}

#[test]
fn test_change_note_inconsistent_rejects() {
    // buyer_change_amt > 0 but note_e_commitment == [0;32]
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA5, 0x01);
    let note_b = fr_safe(0xB5, 0x01);
    seed_note_lock(&mut h, &note_a, &[9u8; 16], 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &[10u8; 16], 1_000_000, 10);

    let mut p = MatchResultPayload::exact_fill(
        [0x55; 16],
        note_a,
        note_b,
        fr_safe(0x05, 0xC5),
        fr_safe(0x05, 0xD5),
        [0x2A; 32],
        [0x2B; 32],
        [9u8; 16],
        [10u8; 16],
        10,
        50,
    );
    p.buyer_change_amt = 50;
    // note_e_commitment stays [0;32] — inconsistent.

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let err = h.svm.send_transaction(tx).expect_err("must reject");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("changenote") || logs.contains("inconsistent"),
        "expected change-note-inconsistent error:\n{logs}"
    );
}

// ---------- nullifier double-spend ----------

#[test]
fn test_nullifier_double_spend_rejected() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA6, 0x01);
    let note_b = fr_safe(0xB6, 0x01);
    let order_id_a = [11u8; 16];
    let order_id_b = [12u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 100);

    let p = MatchResultPayload::exact_fill(
        [0x66; 16],
        note_a,
        note_b,
        fr_safe(0x06, 0xC6),
        fr_safe(0x06, 0xD6),
        [0x3A; 32],
        [0x3B; 32],
        order_id_a,
        order_id_b,
        100,
        5_000,
    );

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    h.svm.send_transaction(tx).expect("first settle");
    assert!(nullifier_exists(&h, &[0x3A; 32]));

    // Second settlement with the same nullifiers (even via fresh notes/locks)
    // must fail on the init of the already-existing nullifier PDA.
    let note_a2 = fr_safe(0xA7, 0x01);
    let note_b2 = fr_safe(0xB7, 0x01);
    seed_note_lock(&mut h, &note_a2, &[13u8; 16], 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b2, &[14u8; 16], 1_000_000, 100);

    let mut p2 = MatchResultPayload::exact_fill(
        [0x67; 16],
        note_a2,
        note_b2,
        fr_safe(0x07, 0xC7),
        fr_safe(0x07, 0xD7),
        [0x3A; 32],
        [0x3B; 32],
        [13u8; 16],
        [14u8; 16], // same nullifiers
        100,
        5_000,
    );
    p2.batch_slot = 1;
    h.svm.expire_blockhash();
    let tx2 = seed_marker_and_build_settle_batched_tx(&mut h, &p2);
    let err = h
        .svm
        .send_transaction(tx2)
        .expect_err("double-spend must reject");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("already in use")
            || logs.contains("already initialized")
            || logs.contains("0x0"), // system_program allocate on existing account
        "expected already-used error:\n{logs}"
    );
}

// ---------- wrong order_id / wrong lock ----------

#[test]
fn test_wrong_order_id_rejected() {
    let mut h = Harness::setup();
    let note_a = fr_safe(0xA8, 0x01);
    let note_b = fr_safe(0xB8, 0x01);
    seed_note_lock(&mut h, &note_a, &[0x01; 16], 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &[0x02; 16], 1_000_000, 10);

    let mut p = MatchResultPayload::exact_fill(
        [0x88; 16],
        note_a,
        note_b,
        fr_safe(0x08, 0xC8),
        fr_safe(0x08, 0xD8),
        [0x4A; 32],
        [0x4B; 32],
        [0x99; 16],
        [0x02; 16], // buyer order_id mismatch
        10,
        50,
    );
    p.buyer_change_amt = 50;
    p.note_e_commitment = fr_safe(0x08, 0xE8);

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let err = h.svm.send_transaction(tx).expect_err("wrong order_id");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("notenotlockedfororder") || logs.contains("not locked"),
        "expected NoteNotLockedForOrder error:\n{logs}"
    );
}

// ---------- re-lock ----------

#[test]
fn test_partial_fill_relocks_change_note() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA9, 0x01);
    let note_b = fr_safe(0xB9, 0x01);
    let order_id_a = [15u8; 16];
    let order_id_b = [16u8; 16];
    seed_note_lock(&mut h, &note_a, &order_id_a, 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &order_id_b, 1_000_000, 10);

    let note_e = fr_safe(0x09, 0xE9); // buyer change
    let mut p = MatchResultPayload::exact_fill(
        [0x99; 16],
        note_a,
        note_b,
        fr_safe(0x09, 0xC9),
        fr_safe(0x09, 0xD9),
        [0x5A; 32],
        [0x5B; 32],
        order_id_a,
        order_id_b,
        10,
        50,
    );
    p.buyer_change_amt = 50;
    p.note_e_commitment = note_e;
    p.buyer_relock_order_id = order_id_a; // relock same order
    p.buyer_relock_expiry = 2_000_000;

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    h.svm.send_transaction(tx).expect("relock settle");

    // New NoteLock PDA must exist for the change-note commitment.
    assert!(note_lock_exists(&h, &note_e));
    // Input locks closed.
    assert!(!note_lock_exists(&h, &note_a));
    assert!(!note_lock_exists(&h, &note_b));
}

#[test]
fn test_relock_without_change_note_returns_error() {
    let mut h = Harness::setup();
    let note_a = fr_safe(0xAA, 0x01);
    let note_b = fr_safe(0xBA, 0x01);
    seed_note_lock(&mut h, &note_a, &[17u8; 16], 1_000_000, 50);
    seed_note_lock(&mut h, &note_b, &[18u8; 16], 1_000_000, 10);

    let mut p = MatchResultPayload::exact_fill(
        [0x0A; 16],
        note_a,
        note_b,
        fr_safe(0x0A, 0xCA),
        fr_safe(0x0A, 0xDA),
        [0x6A; 32],
        [0x6B; 32],
        [17u8; 16],
        [18u8; 16],
        10,
        50,
    );
    // NO buyer_change_amt (0) and NO note_e_commitment ([0;32]), but
    // buyer_relock_order_id IS set — conservation holds (50 = 50+0+0)
    // but RelockRequiresChangeNote must fire.
    p.buyer_relock_order_id = [17u8; 16];
    p.buyer_relock_expiry = 2_000_000;

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let err = h.svm.send_transaction(tx).expect_err("must reject");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("relockrequires") || logs.contains("requireschange"),
        "expected RelockRequiresChangeNote:\n{logs}"
    );
}

// ---------- Ed25519 signature verification ----------

#[test]
fn test_tee_sig_verified_via_ed25519_precompile() {
    // The happy-path covered by every other test — this one asserts the
    // precompile is REQUIRED: strip it and the settle must fail.
    let mut h = Harness::setup();

    let note_a = fr_safe(0xAB, 0x01);
    let note_b = fr_safe(0xBB, 0x01);
    seed_note_lock(&mut h, &note_a, &[19u8; 16], 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &[20u8; 16], 1_000_000, 100);

    let p = MatchResultPayload::exact_fill(
        [0x0B; 16],
        note_a,
        note_b,
        fr_safe(0x0B, 0xCB),
        fr_safe(0x0B, 0xDB),
        [0x7A; 32],
        [0x7B; 32],
        [19u8; 16],
        [20u8; 16],
        100,
        5_000,
    );

    // Build the settle ix WITHOUT the precompile.
    let settle_ix = seed_marker_and_build_settle_batched_ix(&mut h, &p);
    let tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(
            &[compute_budget_ix(1_400_000), settle_ix],
            Some(&h.tee.pubkey()),
        ),
        h.svm.latest_blockhash(),
    );
    let err = h.svm.send_transaction(tx).expect_err("missing precompile");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("invalidteesignature") || logs.contains("invalid_tee"),
        "expected InvalidTeeSignature (missing precompile):\n{logs}"
    );
}

#[test]
fn test_tee_sig_wrong_key_rejected() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xAC, 0x01);
    let note_b = fr_safe(0xBC, 0x01);
    seed_note_lock(&mut h, &note_a, &[21u8; 16], 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &[22u8; 16], 1_000_000, 100);

    let p = MatchResultPayload::exact_fill(
        [0x0C; 16],
        note_a,
        note_b,
        fr_safe(0x0C, 0xCC),
        fr_safe(0x0C, 0xDC),
        [0x8A; 32],
        [0x8B; 32],
        [21u8; 16],
        [22u8; 16],
        100,
        5_000,
    );

    // Sign with a DIFFERENT key. The precompile will verify the sig
    // successfully (self-consistent), but our handler matches
    // expected_pubkey against the vault's stored tee_pubkey and rejects.
    let attacker = Keypair::new();
    let msg_hash = canonical_payload_hash(&p);
    let sig = attacker.sign_message(&msg_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());
    let ed_ix = build_ed25519_verify_ix(&attacker.pubkey().to_bytes(), &sig_bytes, &msg_hash);
    let settle_ix = seed_marker_and_build_settle_batched_ix(&mut h, &p);
    let tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(
            &[compute_budget_ix(1_400_000), ed_ix, settle_ix],
            Some(&h.tee.pubkey()),
        ),
        h.svm.latest_blockhash(),
    );
    let err = h.svm.send_transaction(tx).expect_err("wrong key");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("invalidteesignature") || logs.contains("invalid_tee"),
        "expected InvalidTeeSignature (wrong key):\n{logs}"
    );
}

#[test]
fn test_tee_sig_wrong_msg_rejected() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xAD, 0x01);
    let note_b = fr_safe(0xBD, 0x01);
    seed_note_lock(&mut h, &note_a, &[23u8; 16], 1_000_000, 5_000);
    seed_note_lock(&mut h, &note_b, &[24u8; 16], 1_000_000, 100);

    let p = MatchResultPayload::exact_fill(
        [0x0D; 16],
        note_a,
        note_b,
        fr_safe(0x0D, 0xCD),
        fr_safe(0x0D, 0xDD),
        [0x9A; 32],
        [0x9B; 32],
        [23u8; 16],
        [24u8; 16],
        100,
        5_000,
    );

    // Sign a DIFFERENT message (so the precompile-ix msg != SHA(payload)).
    let bogus_msg = [0xBEu8; 32];
    let sig = h.tee.sign_message(&bogus_msg);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig.as_ref());
    let ed_ix = build_ed25519_verify_ix(&h.tee.pubkey().to_bytes(), &sig_bytes, &bogus_msg);
    let settle_ix = seed_marker_and_build_settle_batched_ix(&mut h, &p);
    let tx = solana_transaction::Transaction::new(
        &[&h.tee],
        solana_message::Message::new(
            &[compute_budget_ix(1_400_000), ed_ix, settle_ix],
            Some(&h.tee.pubkey()),
        ),
        h.svm.latest_blockhash(),
    );
    let err = h.svm.send_transaction(tx).expect_err("wrong msg");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("invalidteesignature") || logs.contains("invalid_tee"),
        "expected InvalidTeeSignature (wrong msg):\n{logs}"
    );
}

// ---------- fee notes ----------

#[test]
fn test_fee_note_appended() {
    let mut h = Harness::setup();

    // Set protocol owner + fee rate in VaultConfig so the fee-note branch
    // is allowed.
    set_vault_fee_config(&mut h, [0x77u8; 32], 30);

    let note_a = fr_safe(0xAE, 0x01);
    let note_b = fr_safe(0xBE, 0x01);
    seed_note_lock(&mut h, &note_a, &[25u8; 16], 1_000_000, 115); // quote=100 + fee=15
    seed_note_lock(&mut h, &note_b, &[26u8; 16], 1_000_000, 103); // base=100 + fee=3

    let mut p = MatchResultPayload::exact_fill(
        [0x0E; 16],
        note_a,
        note_b,
        fr_safe(0x0E, 0xCE),
        fr_safe(0x0E, 0xDE),
        [0xAA; 32],
        [0xAB; 32],
        [25u8; 16],
        [26u8; 16],
        100,
        100,
    );
    p.buyer_fee_amt = 15;
    p.seller_fee_amt = 3;
    // Both per-batch fee notes: base (seller-side) + quote (buyer-side).
    p.note_fee_base_commitment = fr_safe(0x0E, 0x77);
    p.note_fee_quote_commitment = fr_safe(0x0E, 0x88);

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let before = vault_leaf_count(&h);
    h.svm.send_transaction(tx).expect("fee settle");

    // Leaves: note_c + note_d + base_fee + quote_fee = 4.
    assert_eq!(vault_leaf_count(&h), before + 4);
}

#[test]
fn test_zero_fee_no_note_created() {
    let mut h = Harness::setup();

    let note_a = fr_safe(0xAF, 0x01);
    let note_b = fr_safe(0xBF, 0x01);
    seed_note_lock(&mut h, &note_a, &[27u8; 16], 1_000_000, 100);
    seed_note_lock(&mut h, &note_b, &[28u8; 16], 1_000_000, 100);

    let p = MatchResultPayload::exact_fill(
        [0x0F; 16],
        note_a,
        note_b,
        fr_safe(0x0F, 0xCF),
        fr_safe(0x0F, 0xDF),
        [0xBA; 32],
        [0xBB; 32],
        [27u8; 16],
        [28u8; 16],
        100,
        100,
    );
    // fee fields are all zero; both note_fee_*_commitment stay [0;32].

    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let before = vault_leaf_count(&h);
    h.svm.send_transaction(tx).expect("zero-fee settle");

    // Only 2 leaves — no fee note flushed.
    assert_eq!(vault_leaf_count(&h), before + 2);
}

#[test]
fn test_fee_note_without_protocol_owner_rejected() {
    // protocol_owner_commitment stays [0;32] (default). Supplying a
    // fee-note commitment must be rejected as ProtocolOwnerUnset.
    let mut h = Harness::setup();

    let note_a = fr_safe(0xA1, 0x01);
    let note_b = fr_safe(0xB1, 0x01);
    seed_note_lock(&mut h, &note_a, &[29u8; 16], 1_000_000, 115);
    seed_note_lock(&mut h, &note_b, &[30u8; 16], 1_000_000, 103);

    let mut p = MatchResultPayload::exact_fill(
        [0x1B; 16],
        note_a,
        note_b,
        fr_safe(0x10, 0xC0),
        fr_safe(0x10, 0xD0),
        [0xCA; 32],
        [0xCB; 32],
        [29u8; 16],
        [30u8; 16],
        100,
        100,
    );
    p.buyer_fee_amt = 15;
    p.seller_fee_amt = 3;
    p.note_fee_quote_commitment = fr_safe(0x10, 0x99);

    let before = vault_leaf_count(&h);
    let tx = seed_marker_and_build_settle_batched_tx(&mut h, &p);
    let err = h.svm.send_transaction(tx).expect_err("must reject");
    let logs = err.meta.logs.join("\n").to_lowercase();
    assert!(
        logs.contains("protocolowner") || logs.contains("protocol_owner"),
        "expected ProtocolOwnerUnset error:\n{logs}"
    );
    assert_eq!(vault_leaf_count(&h), before);
}
