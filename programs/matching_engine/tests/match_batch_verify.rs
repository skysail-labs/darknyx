//! Real N=16 proof → on-chain `verify_match_batch` acceptance
//! (TEE v2 PR 4g.7 — real-N16 step 2).
//!
//! Step 1 (`crates/nyx-tee/tests/n16_assemble_prove_verify.rs`) proved
//! the settle assembler's witness yields a Groth16 proof that verifies
//! in ARK. This closes the remaining gap: the ark→on-chain BYTE
//! conversion (`prover::proof_to_onchain_bytes`) is accepted by the
//! ON-CHAIN groth16-solana verifier against `vk_match_batch_n16` — a
//! different verifier + VK serialization than ark's, so ark
//! acceptance does not imply on-chain acceptance.
//!
//! The proof is a committed fixture (288 B: `pi_a ‖ pi_b ‖ pi_c ‖
//! merkle_root`) produced by step 1's REAL prover, so this test stays
//! fast, deterministic, and free of the heavy prover dependency.
//! Regenerate after a circuit / converter change with:
//!
//! ```sh
//! RUN_N16_PROVE=1 DUMP_N16_FIXTURE=1 cargo test -p nyx-tee --release \
//!   --test n16_assemble_prove_verify
//! ```
//!
//! Requires `target/deploy/vault.so` (run `cargo build-sbf`).

mod common;

use common::*;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// 256-byte Borsh `Groth16Proof` followed by the 32-byte batch root.
const FIXTURE: &[u8] = include_bytes!("fixtures/match_batch_n16_proof.bin");

fn fixture() -> ([u8; 256], [u8; 32]) {
    assert_eq!(
        FIXTURE.len(),
        288,
        "fixture must be 256-byte proof + 32-byte root"
    );
    let mut proof = [0u8; 256];
    proof.copy_from_slice(&FIXTURE[..256]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&FIXTURE[256..]);
    (proof, root)
}

#[test]
fn real_n16_proof_accepted_onchain_creates_marker() {
    let mut h = Harness::setup();
    let (proof, root) = fixture();

    // Marker absent before verify.
    assert!(!batch_validity_marker_exists(&h, &root));

    // expiry ∈ (clock.slot, slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS=300];
    // litesvm boots at slot 0, so 200 sits safely inside the window.
    let ix = build_verify_match_batch_ix(&h, &h.tee.pubkey(), &root, 200, &proof);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect("on-chain groth16-solana must accept our real N=16 proof");

    // Marker created → the proof verified on-chain.
    assert!(
        batch_validity_marker_exists(&h, &root),
        "verify_match_batch must create the marker after accepting the proof"
    );
}

#[test]
fn tampered_proof_rejected_no_marker() {
    let mut h = Harness::setup();
    let (mut proof, root) = fixture();
    proof[0] ^= 0x01; // corrupt the pi_a G1 point

    let ix = build_verify_match_batch_ix(&h, &h.tee.pubkey(), &root, 200, &proof);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    let res = h.svm.send_transaction(tx);
    assert!(res.is_err(), "a tampered proof must be rejected on-chain");
    // The marker is `init`-allocated during account validation, but a
    // failed verify reverts the whole tx — so nothing persists.
    assert!(
        !batch_validity_marker_exists(&h, &root),
        "no marker may be created for a rejected proof"
    );
}
