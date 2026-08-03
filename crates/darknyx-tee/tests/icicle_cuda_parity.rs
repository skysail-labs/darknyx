//! ICICLE **CUDA** prover parity gate (Phase 2 of the GPU-prove track).
//!
//! This is the **go/no-go correctness gate for GPU proving**. It proves a REAL
//! N=16 VALID_MATCH_BATCH (from the settle assembler) with the `icicle-snark`
//! backend on `device=CUDA`, then checks the resulting proof against the zkey's
//! OWN verifying key — the same VK the ark/rapidsnark backends use and the same
//! one `programs/vault/src/zk/vk_match_batch_n16.rs` was generated from. It also
//! proves the identical witness on ark (CPU) and asserts both backends agree on
//! the public inputs.
//!
//! Mirror of `icicle_parity.rs` (which covers `device=CPU`, Phase 1). Keep the
//! two in step: same fixture, same assertions, different device.
//!
//! ## What "parity" means here (and what it does NOT)
//!
//! Groth16 proving is **randomized** — two proves of the same witness produce
//! different proof bytes. So this does NOT (and cannot) assert byte-identical
//! proofs across backends. The meaningful gate is:
//!   1. the CUDA proof **verifies** against the committed zkey VK, and
//!   2. CUDA and ark agree **exactly** on the public inputs (batch Merkle root +
//!      governed-config digest), which is what the on-chain verifier binds.
//!
//! Together those say: CUDA slots into the existing pipeline with no proof-format
//! or public-input drift.
//!
//! ## Guard against a false pass
//!
//! A CUDA test that silently ran on CPU would be worse than no test. Two guards:
//!   * `DARKNYX_TEE_ICICLE_DEVICE` is read once in `IcicleMatchBatchProver::load`,
//!     so this test sets it BEFORE loading and then asserts `prover.device()`.
//!   * The ark-CPU A/B is printed. A "CUDA" run that is not dramatically faster
//!     than CPU prove_step is a red flag (logged loudly, not hard-asserted —
//!     absolute timings are hardware-dependent).
//!
//! ## Gated — opt in (feature + env + hardware)
//!
//! Compiles only with `--features icicle-cuda`; runs only with
//! `RUN_ICICLE_CUDA_PROVE=1` AND the N=16 artifacts present. Needs a real GPU
//! plus the ICICLE CUDA backend in the image (`ICICLE_BACKEND_INSTALL_DIR`).
//! Run in release:
//!
//! ```sh
//! RUN_ICICLE_CUDA_PROVE=1 cargo test -p darknyx-tee --release \
//!   --features icicle-cuda --test icicle_cuda_parity -- --nocapture
//! ```
//!
//! The test sets `DARKNYX_TEE_ICICLE_ALLOW_INSECURE_GPU=1` itself — SW-32 makes
//! `IcicleMatchBatchProver::load` refuse CUDA unless the driver reports
//! confidential compute, which commodity benchmark GPUs do not have. Nothing to
//! set on the command line; see the comment at the call.
//!
//! ⚠️ **Privacy note.** The witness carries the PRIVATE trade data (amounts,
//! clearing price, owner commitments, inners). Proving on a GPU moves that
//! across the CPU↔GPU boundary, so production GPU proving requires a
//! **confidential GPU** (CC mode / encrypted DMA). A passing parity gate says
//! nothing about that — see `docs/throughput-roadmap.md` (🟢 GPU gate).

#![cfg(feature = "icicle-cuda")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use darknyx_tee::matcher::openings::NoteOpening;
use darknyx_tee::prover::{
    compute_batch_root, pad_batch, ArkMatchBatchProver, IcicleMatchBatchProver, PRODUCTION_BATCH_N,
};
use darknyx_tee::settle::{assemble_match, MatchAssemblyInputs};
use darkpool_matcher::match_result::{MatchPair, MatchStatus};

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

/// A single consistent exact-fill match (base=10, quote=1000) plus its two
/// input-note openings — identical to `icicle_parity.rs` /
/// `n16_assemble_prove_verify` so every backend proves the same witness.
fn one_real_match() -> (MatchPair, NoteOpening, NoteOpening) {
    let buyer = NoteOpening {
        token_mint: quote_mint(),
        amount: 1000,
        owner_commitment: fr_safe(0x44),
        inner_hash: fr_safe(0x11),
    };
    let seller = NoteOpening {
        token_mint: base_mint(),
        amount: 10,
        owner_commitment: fr_safe(0x55),
        inner_hash: fr_safe(0x33),
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
        batch_slot: 7,
        match_id: 42,
        status: MatchStatus::Filled,
    };
    (m, buyer, seller)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn icicle_cuda_proves_and_verifies_n16() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
    if std::env::var("RUN_ICICLE_CUDA_PROVE").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping icicle_cuda_proves_and_verifies_n16: set RUN_ICICLE_CUDA_PROVE=1 to run \
             (needs a real GPU + the ICICLE CUDA backend; use --release)"
        );
        return;
    }
    let build_dir = circuits_build_dir();
    if !n16_artifacts_present(&build_dir) {
        eprintln!(
            "skipping icicle_cuda_proves_and_verifies_n16: match_batch_n16 artifacts absent at {} \
             (run `bash scripts/build-circuits.sh`)",
            build_dir.display()
        );
        return;
    }

    // 0. Select CUDA BEFORE `load` — the device is resolved once there. Setting
    //    it later would silently prove on CPU and report a false pass.
    std::env::set_var("DARKNYX_TEE_ICICLE_DEVICE", "CUDA");
    // SW-32 made `load` REFUSE CUDA unless the driver reports confidential
    // compute, and it fails closed — so without this the gate would stop
    // running on exactly the commodity H100/H200 boxes it is meant for (no CC
    // mode), and the refusal would look like a CUDA failure. This measurement
    // is correctness parity on a fixture, not real order flow, so proving on a
    // host-readable GPU is the intended trade here. It is a separate variable
    // from the device precisely so it has to be opted into in this one place.
    std::env::set_var("DARKNYX_TEE_ICICLE_ALLOW_INSECURE_GPU", "1");

    // 1. Assemble one real match + pad to N=16 (same witness path as ark/CPU).
    let (m, buyer, seller) = one_real_match();
    let (witness, _payload) = assemble_match(MatchAssemblyInputs {
        match_pair: &m,
        buyer_opening: &buyer,
        seller_opening: &seller,
        order_id_a: [0x01; 16],
        order_id_b: [0x02; 16],
        settlement_id: darknyx_tee::settle::assemble::derive_settlement_id(
            &[0x5A; 32],
            m.match_id,
            &[0x01; 16],
            &[0x02; 16],
        ),
        base_mint: base_mint(),
        quote_mint: quote_mint(),
        protocol_owner_commitment: fr_safe(0x07),
        price_scale: 1,
        // Single real match → batch index 0 (C-08: batch_slot[0] === 0).
        slot_index: 0,
        // Zero-fee exact-fill match → fee_rate_bps MUST be 0, or the in-circuit
        // EXACT fee constraint would reject it (fee=0).
        fee_rate_bps: 0,
    })
    .expect("assemble the match");
    let slots = pad_batch(&[witness], PRODUCTION_BATCH_N).expect("pad to N=16");
    assert_eq!(slots.len(), PRODUCTION_BATCH_N);

    // 2. The zkey's VK (via the ark prover) — the SHARED verify oracle. The CUDA
    //    proof must verify against the exact same VK the on-chain verifier holds.
    let ark = ArkMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load ark prover");
    let pvk = prepare_verifying_key(ark.verifying_key());

    // 3. icicle CUDA prove. First prove builds the zkey cache (warmup); the
    //    second is the steady-state number.
    let icicle = IcicleMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N)
        .expect("load icicle prover (CUDA)");
    assert_eq!(
        icicle.device(),
        "CUDA",
        "prover did not select the CUDA device — DARKNYX_TEE_ICICLE_DEVICE was not honoured, so \
         this run would prove on CPU and report a FALSE PASS"
    );

    let t0 = Instant::now();
    let (warm_proof, warm_public) = icicle
        .prove_to_ark(&slots)
        .expect("icicle CUDA warmup prove (is the CUDA backend installed + a GPU visible?)");
    let warmup_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let (proof, public) = icicle
        .prove_to_ark(&slots)
        .expect("icicle CUDA steady prove");
    let cuda_ms = t1.elapsed().as_millis();

    // 4. Correctness gate: the CUDA proof verifies against the zkey VK, and the
    //    public inputs are the compressed (root, config digest) pair.
    assert_eq!(public.public_inputs_be.len(), 2);
    assert_eq!(public.public_inputs_be[0], public.merkle_root);
    assert_eq!(public.public_inputs_be[1], public.config_digest);
    assert_eq!(
        public.merkle_root,
        compute_batch_root(&public.leaves).expect("recompute root"),
        "assembler/leaf root disagrees with the circuit's public input"
    );
    let public_fr: Vec<Fr> = public
        .public_inputs_be
        .iter()
        .map(|b| Fr::from_be_bytes_mod_order(b))
        .collect();
    for (label, p) in [("warmup", &warm_proof), ("steady", &proof)] {
        let ok = Groth16::<Bn254>::verify_proof(&pvk, p, &public_fr).expect("verify_proof call");
        assert!(
            ok,
            "icicle CUDA {label} proof failed verification against the zkey VK"
        );
    }
    // Public inputs are deterministic across proves (only the proof is randomized).
    assert_eq!(warm_public.merkle_root, public.merkle_root);
    assert_eq!(warm_public.config_digest, public.config_digest);

    // 5. ark (CPU) prove of the SAME witness — cross-backend public-input parity
    //    plus the A/B that makes a silent CPU fallback visible.
    let t2 = Instant::now();
    let (ark_proof, ark_public) = ark.prove_ark(&slots).expect("ark prove");
    let ark_ms = t2.elapsed().as_millis();
    assert!(
        Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &public_fr).expect("verify ark"),
        "ark proof failed verification (sanity)"
    );
    assert_eq!(
        ark_public.merkle_root, public.merkle_root,
        "ark + icicle-CUDA disagree on the batch public input (merkle root)"
    );
    assert_eq!(
        ark_public.config_digest, public.config_digest,
        "ark + icicle-CUDA disagree on the governed-config digest"
    );

    eprintln!(
        "ICICLE-CUDA prove N=16: warmup(incl zkey-cache build)={warmup_ms}ms steady={cuda_ms}ms \
         | ark-CPU(same machine)={ark_ms}ms — both verify against the zkey VK"
    );
    if cuda_ms * 2 > ark_ms {
        eprintln!(
            "WARNING: CUDA steady prove ({cuda_ms}ms) is not materially faster than ark-CPU \
             ({ark_ms}ms). Verify the CUDA backend actually loaded (ICICLE_BACKEND_INSTALL_DIR) \
             and that a GPU is visible — this pattern is what a silent CPU fallback looks like."
        );
    }
}
