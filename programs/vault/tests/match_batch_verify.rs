//! Real N=16 proof → on-chain `verify_match_batch` acceptance
//! (VALID_MATCH_BATCH v3 real-N16 step 2).
//!
//! Step 1 (`crates/darknyx-tee/tests/n16_assemble_prove_verify.rs`) proved
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
//! RUN_N16_PROVE=1 DUMP_N16_FIXTURE=1 cargo test -p darknyx-tee --release \
//!   --test n16_assemble_prove_verify
//! ```
//!
//! Requires `target/deploy/vault.so` (run `cargo build-sbf`).

mod settle_harness;

use settle_harness::*;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// 256-byte Borsh `Groth16Proof` followed by the 32-byte batch root.
const FIXTURE: &[u8] = include_bytes!("fixtures/match_batch_n16_proof.bin");

/// The protocol_owner_commitment the fixture (n16_assemble_prove_verify) was
/// proved with — `fr_safe(0x07)`. The on-chain verify reads this from
/// VaultConfig as the 3rd public input, so the test must seed it to match or
/// the proof's public inputs won't line up. (fee_rate_bps stays 0: the fixture
/// match is zero-fee.)
fn fixture_protocol_owner() -> [u8; 32] {
    let mut v = [0x07u8; 32];
    v[0] = 0;
    v
}

fn fixture_mints() -> (Pubkey, Pubkey) {
    let mut base = [0u8; 32];
    base[0] = 1;
    base[31] = 0xb1;
    let mut quote = [0u8; 32];
    quote[0] = 1;
    quote[31] = 0x9e;
    (Pubkey::new_from_array(base), Pubkey::new_from_array(quote))
}

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
    // The 3rd public input (protocol_owner) is read from VaultConfig; seed it
    // to the value the fixture proved with.
    set_vault_fee_config(&mut h, fixture_protocol_owner(), 0);
    let (base_mint, quote_mint) = fixture_mints();
    seed_market_config(&mut h, &base_mint, &quote_mint, 1, true);

    // Marker absent before verify.
    assert!(!batch_validity_marker_exists(&h, &root));

    // expiry ∈ (clock.slot, slot + MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS=300];
    // litesvm boots at slot 0, so 200 sits safely inside the window.
    let ix = build_verify_match_batch_ix(
        &h,
        &h.tee.pubkey(),
        &base_mint,
        &quote_mint,
        &root,
        200,
        &proof,
    );
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    let meta = h
        .svm
        .send_transaction(tx)
        .expect("on-chain groth16-solana must accept our real N=16 proof");

    // CU profiling + regression guard for darknyx-tee's per-tx ComputeUnitLimit
    // right-sizing (VERIFY_COMPUTE_UNIT_LIMIT in crates/darknyx-tee/src/settle/pipeline.rs,
    // now 180_000). v3's eight public inputs measure ~132.5k CU in litesvm.
    // The higher transaction limit preserves >20% headroom and covers the
    // modest devnet/runtime delta observed in prior verifier measurements.
    eprintln!(
        "CU_PROFILE verify_match_batch consumed={}",
        meta.compute_units_consumed
    );
    assert!(
        meta.compute_units_consumed < 150_000,
        "verify_match_batch CU {} grew — re-measure + re-check VERIFY_COMPUTE_UNIT_LIMIT (180_000) headroom vs devnet",
        meta.compute_units_consumed
    );
    assert!(
        meta.compute_units_consumed.saturating_mul(120) < 180_000 * 100,
        "verify_match_batch CU {} has less than 20% limit headroom",
        meta.compute_units_consumed
    );

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
    let (base_mint, quote_mint) = fixture_mints();
    seed_market_config(&mut h, &base_mint, &quote_mint, 1, true);

    let ix = build_verify_match_batch_ix(
        &h,
        &h.tee.pubkey(),
        &base_mint,
        &quote_mint,
        &root,
        200,
        &proof,
    );
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

#[test]
fn disabled_market_rejected_before_marker_creation() {
    let mut h = Harness::setup();
    let (proof, root) = fixture();
    set_vault_fee_config(&mut h, fixture_protocol_owner(), 0);
    let (base_mint, quote_mint) = fixture_mints();
    seed_market_config(&mut h, &base_mint, &quote_mint, 1, false);

    let ix = build_verify_match_batch_ix(
        &h,
        &h.tee.pubkey(),
        &base_mint,
        &quote_mint,
        &root,
        200,
        &proof,
    );
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    assert!(
        h.svm.send_transaction(tx).is_err(),
        "a proof for a disabled market must be rejected"
    );
    assert!(!batch_validity_marker_exists(&h, &root));
}

#[test]
fn proof_bound_to_different_price_scale_rejected() {
    let mut h = Harness::setup();
    let (proof, root) = fixture();
    set_vault_fee_config(&mut h, fixture_protocol_owner(), 0);
    let (base_mint, quote_mint) = fixture_mints();
    // The fixture proves scale=1. A governed scale change must invalidate it.
    seed_market_config(&mut h, &base_mint, &quote_mint, 2, true);

    let ix = build_verify_match_batch_ix(
        &h,
        &h.tee.pubkey(),
        &base_mint,
        &quote_mint,
        &root,
        200,
        &proof,
    );
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    assert!(
        h.svm.send_transaction(tx).is_err(),
        "a proof for a different governed price scale must be rejected"
    );
    assert!(!batch_validity_marker_exists(&h, &root));
}
