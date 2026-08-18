//! U-02 — `lock_note` must reject a note-use tag that has already been consumed
//! (settled or withdrawn). The tag-keyed `ConsumedNoteEntry` is the
//! shared consume-once guard; a note whose entry exists but whose Merkle leaf
//! survives could otherwise be re-locked by an authorized TEE holding a stale
//! VALID_INPUT proof (rent waste + stuck state).
//!
//! The guard fires BEFORE Groth16 verification, so this differential test needs
//! no real proof: with an identical dummy proof, a consumed tag is
//! rejected `NoteAlreadyConsumed` while an unconsumed one gets PAST the guard
//! and fails later at `InvalidProof` — proving the guard keys exactly on
//! consumed-ness.

mod common;
mod settle_harness;

use settle_harness::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Build a `lock_note` ix for `note_use_tag`, signed by the authorized TEE
/// key, with a syntactically-sized but invalid dummy proof and a recent root
/// (so the handler reaches the U-02 guard / proof verification rather than
/// tripping the auth or root-recency check first).
fn build_lock_note_ix(h: &Harness, note_commitment: &[u8; 32]) -> Instruction {
    let (vault_cfg, _) = vault_config_pda(&h.vault_id);
    let (merkle_tree, _) = merkle_tree_pda(&h.vault_id, 0);
    let (note_lock, _) = note_lock_pda(&h.vault_id, note_commitment);
    let (consumed_note, _) = consumed_note_pda(&h.vault_id, note_commitment);

    let mut data = Vec::with_capacity(385);
    data.extend_from_slice(&anchor_disc("lock_note"));
    data.push(0u8); // tree_id
    data.extend_from_slice(note_commitment);
    data.extend_from_slice(&[0x22u8; 16]); // order_id
    // Relative to the CURRENT slot, not a hardcoded 1_000. litesvm 0.13 started
    // at slot 0 so the literal happened to satisfy `expiry_slot > clock.slot`;
    // 0.15 does not, and the ix then failed InvalidExpirySlot (6011) BEFORE
    // reaching the proof check this test is actually about.
    let now_slot = h.svm.get_sysvar::<solana_clock::Clock>().slot;
    data.extend_from_slice(&(now_slot + 1_000).to_le_bytes()); // expiry_slot (> slot, < slot + TTL)
    data.extend_from_slice(&h.test_mint.to_bytes()); // token_mint
    data.extend_from_slice(&tree_current_root(h, 0)); // merkle_root (in the ring)
    data.extend_from_slice(&[0u8; 256]); // proof: pi_a || pi_b || pi_c (dummy → invalid)

    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(h.tee.pubkey(), true),
            AccountMeta::new_readonly(vault_cfg, false),
            AccountMeta::new_readonly(merkle_tree, false),
            AccountMeta::new(note_lock, false),
            AccountMeta::new_readonly(consumed_note, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn send_lock_note(h: &mut Harness, note_commitment: &[u8; 32]) -> Vec<String> {
    let ix = build_lock_note_ix(h, note_commitment);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    match h.svm.send_transaction(tx) {
        Ok(_) => panic!("lock_note with a dummy proof must never succeed"),
        Err(e) => e.meta.logs,
    }
}

#[test]
fn lock_note_rejects_already_consumed_commitment() {
    let mut h = Harness::setup();
    let consumed = fr_safe(0xC0, 0x01);

    // Simulate a prior settle/withdraw of this note.
    seed_consumed_note(&mut h, &consumed);
    assert!(consumed_note_exists(&h, &consumed));

    let logs = send_lock_note(&mut h, &consumed);
    assert!(
        logs_have_error_code(&logs.join("\n"), E_NOTE_ALREADY_CONSUMED),
        "expected NoteAlreadyConsumed rejection; logs:\n{}",
        logs.join("\n")
    );
}

#[test]
fn lock_note_allows_unconsumed_commitment_past_the_guard() {
    let mut h = Harness::setup();
    let fresh = fr_safe(0xC0, 0x02);

    // No ConsumedNoteEntry — the guard must NOT fire; the same dummy proof
    // then fails at Groth16 verification, proving we got past U-02.
    assert!(!consumed_note_exists(&h, &fresh));

    let logs = send_lock_note(&mut h, &fresh);
    assert!(
        !logs_have_error_code(&logs.join("\n"), E_NOTE_ALREADY_CONSUMED),
        "U-02 guard must not fire for an unconsumed note; logs:\n{}",
        logs.join("\n")
    );
    assert!(
        logs_have_error_code(&logs.join("\n"), E_INVALID_PROOF),
        "expected the flow to reach + fail proof verification; logs:\n{}",
        logs.join("\n")
    );
}
