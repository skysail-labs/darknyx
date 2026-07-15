//! Real N=16 VALID_MATCH_BATCH proof, from the settle assembler
//! (TEE v2 PR 4g.7 — real-N16-proof, step 1 of 2).
//!
//! Closes the loop the `prover_roundtrip` (N=2, dummy slots) test
//! left open: take a witness produced by the REAL settle assembler
//! (`settle::assemble::assemble_match`, from a `MatchPair` + verified
//! input-note openings), pad it to the production N=16, generate a
//! REAL Groth16 proof against the `match_batch_n16` proving key, and
//! verify it against that zkey's own verifying key.
//!
//! A passing verify proves the whole chain is byte-consistent:
//! opening → assembler witness → circuit witness gen → root
//! cross-check → ark-groth16 prove → verify. Step 2 (a follow-up)
//! drives the same proof through the on-chain `verify_match_batch`
//! via litesvm for groth16-solana acceptance.
//!
//! ## Gated — opt in
//!
//! N=16 needs the pot18 ceremony + a 74 MB proving key; loading it
//! (debug) takes ~minutes, proving more. So this is gated behind
//! `RUN_N16_PROVE=1` AND artifact presence (`circuit.wasm` is
//! gitignored). Run it in release for a sane wall-clock:
//!
//! ```sh
//! RUN_N16_PROVE=1 cargo test -p nyx-tee --release \
//!   --test n16_assemble_prove_verify -- --nocapture
//! ```

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use darkpool_matcher::match_result::{MatchPair, MatchStatus};
use nyx_tee::matcher::openings::NoteOpening;
use nyx_tee::prover::{compute_batch_root, pad_batch, ArkMatchBatchProver, PRODUCTION_BATCH_N};
use nyx_tee::settle::{assemble_match, MatchAssemblyInputs};

fn circuits_build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("circuits")
        .join("build")
}

fn n16_artifacts_present(build_dir: &Path) -> bool {
    let base = build_dir.join("match_batch_n16");
    base.join("circuit_js").join("circuit.wasm").exists()
        && base.join("circuit_final.zkey").exists()
        && base.join("circuit.r1cs").exists()
}

fn fr_safe(b: u8) -> [u8; 32] {
    let mut v = [b; 32];
    v[0] = 0;
    v
}
fn base_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0xb1;
    m
}
fn quote_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0x9e;
    m
}

/// A single consistent exact-fill match (base=10, quote=1000) plus
/// its two input-note openings, with the input commitments derived
/// from the openings so the witness reconstructs in-circuit.
fn one_real_match() -> (MatchPair, NoteOpening, NoteOpening) {
    let buyer = NoteOpening {
        token_mint: quote_mint(),
        amount: 1000, // a_amount = quote(1000) + change(0) + fee(0)
        owner_commitment: fr_safe(0x44),
        inner_hash: fr_safe(0x11),
        nullifier: [0xAA; 32],
    };
    let seller = NoteOpening {
        token_mint: base_mint(),
        amount: 10, // b_amount = base(10) + change(0) + fee(0)
        owner_commitment: fr_safe(0x55),
        inner_hash: fr_safe(0x33),
        nullifier: [0xBB; 32],
    };
    let note_buyer = buyer.commitment().unwrap();
    let note_seller = seller.commitment().unwrap();

    let m = MatchPair {
        note_buyer,
        note_seller,
        note_e_commitment: [0; 32],
        note_f_commitment: [0; 32],
        owner_buyer: [0x77; 32],
        owner_seller: [0x88; 32],
        user_commitment_buyer: [0x99; 32],
        user_commitment_seller: [0xAA; 32],
        buyer_note_value: 1000,
        seller_note_value: 10,
        base_amt: 10,
        quote_amt: 1000,
        buyer_change_amt: 0,
        seller_change_amt: 0,
        buyer_fee_amt: 0,
        seller_fee_amt: 0,
        buyer_relock_order_id: [0; 16],
        buyer_relock_expiry: 0,
        seller_relock_order_id: [0; 16],
        seller_relock_expiry: 0,
        price: 100,
        pyth_at_match: 100,
        // The matcher stamps MatchPair.batch_slot with the actual on-chain
        // `now_slot` (a large value), NOT the batch index. C-08 binds
        // `batch_slot[i] === i` in-circuit, so the assembler MUST override this
        // with the slot index — feeding this now_slot into the leaf is exactly
        // the bug the live CVM caught (witness gen aborted on the assertion).
        // This value stays here on purpose so the prove below regresses that
        // the assembler uses `slot_index`, not `m.batch_slot`.
        batch_slot: 476_000_000,
        match_id: 42,
        status: MatchStatus::Filled,
    };
    (m, buyer, seller)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assembler_witness_proves_and_verifies_n16() {
    // Surface the prover's `prove breakdown` + `witness-gen split` info logs.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
    if std::env::var("RUN_N16_PROVE").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping assembler_witness_proves_and_verifies_n16: set RUN_N16_PROVE=1 to run \
             (N=16 prove is multi-minute; use --release)"
        );
        return;
    }
    let build_dir = circuits_build_dir();
    if !n16_artifacts_present(&build_dir) {
        eprintln!(
            "skipping assembler_witness_proves_and_verifies_n16: match_batch_n16 artifacts \
             absent at {} (run `bash scripts/build-circuits.sh`)",
            build_dir.display()
        );
        return;
    }

    // 1. The settle assembler turns one match + its openings into a
    //    circuit witness (proof side) + payload (signed side).
    let (m, buyer, seller) = one_real_match();
    let (witness, _payload) = assemble_match(MatchAssemblyInputs {
        match_pair: &m,
        buyer_opening: &buyer,
        seller_opening: &seller,
        order_id_a: [0x01; 16],
        order_id_b: [0x02; 16],
        base_mint: base_mint(),
        quote_mint: quote_mint(),
        protocol_owner_commitment: fr_safe(0x07),
        price_scale: 1,
        // This lone real match lands at batch index 0. The circuit binds
        // `batch_slot[0] === 0`; the assembler uses THIS, not the matcher's
        // `now_slot` above, so the proof succeeds.
        slot_index: 0,
        // Zero-fee exact-fill match → fee_rate_bps MUST be 0, or the in-circuit
        // fee floor `(fee+1)*10000 > notional*rate` would reject it (fee=0).
        fee_rate_bps: 0,
    })
    .expect("assemble the match");

    // 2. Pad to the production N=16 with dummy slots.
    let slots = pad_batch(&[witness], PRODUCTION_BATCH_N).expect("pad to N=16");
    assert_eq!(slots.len(), PRODUCTION_BATCH_N);

    // 3. REAL Groth16 proof against the N=16 proving key.
    let prover =
        ArkMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load N=16 prover");
    let (proof, public) = prover
        .prove_ark(&slots)
        .expect("prove the assembled N=16 batch");

    // 4. Pin the v3 public-input order. The prover already cross-checks the
    // root internally; assert the governed market fields here too.
    assert_eq!(public.public_inputs_be.len(), 8);
    assert_eq!(public.public_inputs_be[0], public.merkle_root);
    assert_eq!(public.public_inputs_be[1], [0u8; 32]);
    assert_eq!(public.public_inputs_be[2], fr_safe(0x07));
    assert_eq!(&public.public_inputs_be[3][16..], &base_mint()[16..]);
    assert_eq!(&public.public_inputs_be[4][16..], &base_mint()[..16]);
    assert_eq!(&public.public_inputs_be[5][16..], &quote_mint()[16..]);
    assert_eq!(&public.public_inputs_be[6][16..], &quote_mint()[..16]);
    assert_eq!(public.public_inputs_be[7][31], 1);
    assert_eq!(
        public.merkle_root,
        compute_batch_root(&public.leaves).expect("recompute root"),
        "assembler/leaf root disagrees with the circuit's public input"
    );

    // 5. The load-bearing assertion: the proof verifies against the
    //    zkey's own verifying key. If the assembler emitted a witness
    //    the circuit rejects, or the leaf/root port drifted, this is
    //    where it surfaces.
    let pvk = prepare_verifying_key(prover.verifying_key());
    let public_fr: Vec<Fr> = public
        .public_inputs_be
        .iter()
        .map(|b| Fr::from_be_bytes_mod_order(b))
        .collect();
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_fr).expect("verify_proof call");
    assert!(
        verified,
        "real N=16 proof from the assembler witness failed verification"
    );

    // 6. Optionally dump the on-chain proof bytes + root as a fixture
    //    for the litesvm on-chain-acceptance test (real-N16 step 2),
    //    so that test doesn't have to pull in the (heavy) prover.
    //    Layout: pi_a(64) ‖ pi_b(128) ‖ pi_c(64) ‖ merkle_root(32) = 288 B.
    if std::env::var("DUMP_N16_FIXTURE").ok().as_deref() == Some("1") {
        let onchain = nyx_tee::prover::proof_to_onchain_bytes(&proof);
        let mut buf = Vec::with_capacity(288);
        buf.extend_from_slice(&onchain.pi_a);
        buf.extend_from_slice(&onchain.pi_b);
        buf.extend_from_slice(&onchain.pi_c);
        buf.extend_from_slice(&public.merkle_root);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("programs")
            .join("vault")
            .join("tests")
            .join("fixtures")
            .join("match_batch_n16_proof.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &buf).unwrap();
        eprintln!(
            "wrote N=16 proof fixture ({} B) to {}",
            buf.len(),
            path.display()
        );
    }
}
