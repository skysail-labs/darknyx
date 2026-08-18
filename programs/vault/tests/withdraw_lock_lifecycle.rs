//! T-15 — LiteSVM coverage for the withdraw side of the S-03 lock lifecycle.
//!
//! The S-03 remediation has three moving parts. Two of them were covered:
//! `merge_allows_an_input_whose_lock_has_expired` (merge_verify.rs) pins the
//! merge side, and the TEE-side sweeper has its own unit tests. The **withdraw**
//! side and `release_lock` itself had **no** LiteSVM coverage at all, even though
//! the S-03 tracker row claimed that evidence existed. Claiming coverage you do
//! not have is worse than admitting the gap — it stops anyone from going and
//! writing it.
//!
//! What S-03 changed on this path: `withdraw` used to reject on the mere
//! EXISTENCE of a `NoteLock` account. Nothing shipped could call `release_lock`,
//! so a single failed settle made a note permanently unwithdrawable — the
//! documented `MAX_LOCK_TTL_SLOTS` "bounded censorship window" was in practice
//! unbounded. The fix reads the lock's `expiry_slot` (data the handler was
//! already borrowing and discarding) and rejects only a LIVE lock.
//!
//! Three properties, each of which would silently regress without a test:
//!   1. a live lock still blocks withdraw (the guard was not simply deleted),
//!   2. at the expiry boundary withdraw succeeds with no release call at all,
//!   3. `release_lock` closes the PDA and refunds its rent to the caller,
//!      after which withdraw succeeds.
//!
//! The expiry comparison mirrors `release_lock`'s `slot >= expiry_slot`: the
//! lock is dead AT its expiry, so a CS-09 boundary settlement must land strictly
//! before it.

mod common;
mod settle_harness;

use settle_harness::*;
use solana_address::Address as Pubkey;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// `release_lock(note_use_tag)` — any signer may call it after expiry and
/// receives the PDA's rent.
fn build_release_lock_ix(
    h: &Harness,
    note_use_tag: &[u8; 32],
    rent_receiver: &Pubkey,
) -> Instruction {
    let (note_lock, _) = note_lock_pda(&h.vault_id, note_use_tag);
    let mut data = anchor_disc("release_lock").to_vec();
    data.extend_from_slice(note_use_tag);
    Instruction {
        program_id: h.vault_id,
        accounts: vec![
            AccountMeta::new(*rent_receiver, true),
            AccountMeta::new(note_lock, false),
        ],
        data,
    }
}

/// Deposit one note backed by a real SPL mint and hand back everything the
/// withdraw path needs. Shared by all three tests so they differ only in the
/// lock lifecycle, not the setup.
fn deposit_one(h: &mut Harness) -> (DepositedNote, Keypair, Pubkey) {
    let mint = create_spl_mint(h, 6);
    let depositor = Keypair::new();
    h.svm
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop depositor");
    let secret = NoteSecret::from_seeds(0x51, 0x52, 0x53);
    let note = deposit_note(h, &depositor, 0, secret, &mint, 2_500_000);
    let dest = create_spl_token_account(h, &mint, &depositor.pubkey(), 0);
    (note, depositor, dest)
}

/// A LIVE lock must still block withdraw. S-03 relaxed the guard from
/// "exists" to "is live"; this pins that it did not relax to "never blocks".
#[test]
fn withdraw_is_rejected_while_the_lock_is_live() {
    let mut h = Harness::setup();
    let (note, depositor, dest) = deposit_one(&mut h);

    let expiry = 5_000u64;
    seed_note_lock(&mut h, &note.use_tag, &[0x77u8; 16], expiry, 0);

    h.svm.warp_to_slot(expiry - 1);
    let tx = build_withdraw_tx(&h, &note, &depositor, &dest);
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("a lock that has not yet expired must still block withdraw");
    // `is_err()` alone would pass if the tx failed for ANY reason — a malformed
    // account list, a bad proof, a stale root. Pin the SPECIFIC error so this
    // test cannot keep passing for the wrong reason once the guard is gone.
    let log = format!("{:?}", err.meta.logs);
    assert!(
        log.contains("NoteAlreadyLocked"),
        "expected the live-lock guard to reject, got: {log}"
    );
    assert!(
        !consumed_note_exists(&h, &note.use_tag),
        "a rejected withdraw must not have consumed the note"
    );
}

/// AT expiry the lock is dead and withdraw proceeds — with nobody having called
/// `release_lock` first. This is the property that turns the old permanent
/// freeze back into a bounded window: recovery must not depend on a third party
/// choosing to act.
#[test]
fn withdraw_succeeds_at_the_expiry_boundary_without_a_release() {
    let mut h = Harness::setup();
    let (note, depositor, dest) = deposit_one(&mut h);

    let expiry = 5_000u64;
    seed_note_lock(&mut h, &note.use_tag, &[0x77u8; 16], expiry, 0);

    // Exactly AT expiry — the boundary, mirroring release_lock's `>=`.
    h.svm.warp_to_slot(expiry);
    h.svm.expire_blockhash();
    let tx = build_withdraw_tx(&h, &note, &depositor, &dest);
    h.svm
        .send_transaction(tx)
        .expect("an expired lock must not block withdraw");

    assert!(
        consumed_note_exists(&h, &note.use_tag),
        "a successful withdraw must init the commitment-keyed consume guard"
    );
}

/// `release_lock` closes the PDA, refunds its rent to whoever called it, and
/// leaves the note withdrawable. This is the SDK-driven recovery path (S-03(A)):
/// the client pre-flights a release before withdrawing.
#[test]
fn release_lock_refunds_rent_and_unblocks_withdraw() {
    let mut h = Harness::setup();
    let (note, depositor, dest) = deposit_one(&mut h);

    let expiry = 5_000u64;
    seed_note_lock(&mut h, &note.use_tag, &[0x77u8; 16], expiry, 0);
    let (lock_pda, _) = note_lock_pda(&h.vault_id, &note.use_tag);
    let lock_rent = h
        .svm
        .get_account(&lock_pda)
        .expect("seeded NoteLock must exist")
        .lamports;
    assert!(lock_rent > 0, "the seeded lock must hold rent to refund");

    // Before expiry the release is refused — otherwise anyone could cancel a
    // live settle reservation out from under the matcher.
    let early_ix = build_release_lock_ix(&h, &note.use_tag, &depositor.pubkey());
    let early_tx = Transaction::new(
        &[&depositor],
        Message::new(&[early_ix], Some(&depositor.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.warp_to_slot(expiry - 1);
    // Pin the SPECIFIC rejection, as with the live-lock withdraw above: a bare
    // is_err() would keep passing if this started failing for an unrelated
    // reason (bad accounts, wrong discriminator) long after the guard was gone.
    let early_err = h
        .svm
        .send_transaction(early_tx)
        .expect_err("release_lock before expiry must fail");
    let early_log = format!("{:?}", early_err.meta.logs);
    assert!(
        early_log.contains("LockNotExpired"),
        "expected LockNotExpired, got: {early_log}"
    );

    // At expiry, release succeeds and the rent lands with the caller.
    h.svm.warp_to_slot(expiry);
    h.svm.expire_blockhash();
    let before = h.svm.get_account(&depositor.pubkey()).unwrap().lamports;
    let ix = build_release_lock_ix(&h, &note.use_tag, &depositor.pubkey());
    let tx = Transaction::new(
        &[&depositor],
        Message::new(&[ix], Some(&depositor.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect("release_lock at expiry must succeed");

    assert!(
        h.svm.get_account(&lock_pda).is_none_or(|a| a.lamports == 0),
        "release_lock must close the NoteLock PDA"
    );
    // Assert the refund is the FULL lock rent, not merely "went up". A bare
    // `after > before` would still pass on a partial refund. The tx fee is
    // subtracted from the same balance, so bound it rather than pinning an
    // exact litesvm fee schedule — that would break spuriously if the fee model
    // ever changes, without catching anything extra.
    const MAX_TX_FEE_LAMPORTS: u64 = 10_000;
    let after = h.svm.get_account(&depositor.pubkey()).unwrap().lamports;
    let credited = after.saturating_sub(before);
    assert!(
        credited >= lock_rent.saturating_sub(MAX_TX_FEE_LAMPORTS),
        "expected the full NoteLock rent back (rent={lock_rent}, credited={credited}, \
         before={before}, after={after})"
    );

    // And the note is now withdrawable.
    h.svm.expire_blockhash();
    let wtx = build_withdraw_tx(&h, &note, &depositor, &dest);
    let wmeta = h
        .svm
        .send_transaction(wtx)
        .expect("withdraw must succeed after release_lock");
    eprintln!(
        "CU_PROFILE withdraw consumed={}",
        wmeta.compute_units_consumed
    );
    assert!(consumed_note_exists(&h, &note.use_tag));
}
