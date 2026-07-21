//! ICICLE (CPU) prover parity + smoke test (Phase 1 of the GPU-prove track).
//!
//! Proves a REAL N=16 VALID_MATCH_BATCH (from the settle assembler) with the
//! `icicle-snark` backend on `device=CPU`, then verifies the resulting proof
//! against the zkey's OWN verifying key (the same VK the ark backend uses, and
//! the same the on-chain `verify_match_batch` was generated from). A passing
//! verify is the byte-correctness gate: it proves icicle's snarkjs-format proof,
//! parsed back into an ark `Proof` and routed through the shared converter,
//! agrees with our circuit — i.e. icicle slots into the existing pipeline with
//! no proof-format drift, WITHOUT needing a GPU or a CVM.
//!
//! It also proves the SAME batch with the ark backend on the same machine so the
//! run logs a rough icicle-CPU-vs-ark prove-time A/B (the apples-to-apples
//! icicle-CPU vs rapidsnark-CPU number on the production amd64 platform comes
//! later — this just confirms the backend is correct + non-pathological locally).
//!
//! ## Gated — opt in (feature + env)
//!
//! Compiles only with `--features icicle`; runs only with `RUN_ICICLE_PROVE=1`
//! AND the N=16 artifacts present. Run in release for a sane wall-clock:
//!
//! ```sh
//! RUN_ICICLE_PROVE=1 cargo test -p darknyx-tee --release --features icicle \
//!   --test icicle_parity -- --nocapture
//! ```

#![cfg(feature = "icicle")]

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
/// input-note openings — identical to `n16_assemble_prove_verify`'s fixture so
/// the two tests prove the same witness through different backends.
fn one_real_match() -> (MatchPair, NoteOpening, NoteOpening) {
    let buyer = NoteOpening {
        token_mint: quote_mint(),
        amount: 1000,
        owner_commitment: fr_safe(0x44),
        inner_hash: fr_safe(0x11),
        nullifier: [0xAA; 32],
    };
    let seller = NoteOpening {
        token_mint: base_mint(),
        amount: 10,
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
        batch_slot: 7,
        match_id: 42,
        status: MatchStatus::Filled,
    };
    (m, buyer, seller)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn icicle_cpu_proves_and_verifies_n16() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
    if std::env::var("RUN_ICICLE_PROVE").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping icicle_cpu_proves_and_verifies_n16: set RUN_ICICLE_PROVE=1 to run \
             (N=16 prove is heavy; use --release)"
        );
        return;
    }
    let build_dir = circuits_build_dir();
    if !n16_artifacts_present(&build_dir) {
        eprintln!(
            "skipping icicle_cpu_proves_and_verifies_n16: match_batch_n16 artifacts absent at {} \
             (run `bash scripts/build-circuits.sh`)",
            build_dir.display()
        );
        return;
    }

    // 1. Assemble one real match + pad to N=16 (same witness path as the ark test).
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
        // fee floor `(fee+1)*10000 > notional*rate` would reject it (fee=0).
        fee_rate_bps: 0,
    })
    .expect("assemble the match");
    let slots = pad_batch(&[witness], PRODUCTION_BATCH_N).expect("pad to N=16");
    assert_eq!(slots.len(), PRODUCTION_BATCH_N);

    // 2. The zkey's VK (via the ark prover) — the SHARED verify oracle. icicle's
    //    proof must verify against the exact same VK the on-chain verifier holds.
    let ark = ArkMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load ark prover");
    let pvk = prepare_verifying_key(ark.verifying_key());

    // 3. icicle CPU prove. First prove builds the zkey cache (warmup); the second
    //    is the steady-state number we report (cache hit).
    let icicle =
        IcicleMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load icicle prover");

    let t0 = Instant::now();
    let (warm_proof, warm_public) = icicle.prove_to_ark(&slots).expect("icicle warmup prove");
    let warmup_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let (proof, public) = icicle.prove_to_ark(&slots).expect("icicle steady prove");
    let icicle_ms = t1.elapsed().as_millis();

    // 4. Byte-correctness gate: the icicle proof verifies against the zkey VK.
    // Public inputs are the root and governed-config digest.
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
            "icicle CPU {label} proof failed verification against the zkey VK"
        );
    }
    // The off-circuit public input is identical across proves (deterministic).
    assert_eq!(warm_public.merkle_root, public.merkle_root);

    // 5. ark prove on the same machine for a rough local A/B (the production
    //    amd64 icicle-CPU vs rapidsnark-CPU number is captured separately).
    let t2 = Instant::now();
    let (ark_proof, ark_public) = ark.prove_ark(&slots).expect("ark prove");
    let ark_ms = t2.elapsed().as_millis();
    assert!(
        Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &public_fr).expect("verify ark"),
        "ark proof failed verification (sanity)"
    );
    assert_eq!(
        ark_public.merkle_root, public.merkle_root,
        "ark + icicle disagree on the batch public input (merkle root)"
    );

    eprintln!(
        "ICICLE-CPU prove N=16: warmup(incl zkey-cache build)={warmup_ms}ms steady={icicle_ms}ms \
         | ark(same machine)={ark_ms}ms — both verify against the zkey VK"
    );
}
