//! End-to-end prove + verify for the in-TEE VALID_MATCH_BATCH
//! prover (PR 4g.4b).
//!
//! Proves a 2-slot batch against the `match_batch_n2` zkey and
//! verifies the resulting Groth16 proof against the zkey's own
//! verifying key (in-ark). This exercises the full prove path:
//! input pushing → witness generation → root cross-check →
//! ark-groth16 proving → on-chain byte conversion.
//!
//! ## Why N=2 (not the production N=16)
//!
//! N=2 uses the pot16 ceremony (smaller, faster to prove) and the
//! same `MatchSlot()` template body as N=16 — only the Merkle tree
//! depth differs. Proving N=2 validates the entire pipeline at a
//! fraction of N=16's cost. The N=16-against-the-real-on-chain-VK
//! verification (via groth16-solana + litesvm) lands in PR 4g.6.
//!
//! ## Why this test is gated
//!
//! `circuit.wasm` is gitignored (only `circuit_final.zkey` is
//! committed; CLAUDE.md §11). When the artifacts aren't present —
//! e.g. a fresh checkout that hasn't run `scripts/build-circuits.sh`
//! — the test skips with a clear message rather than failing. This
//! matches the existing SDK prover-test convention.
//!
//! Run with: `cargo test -p nyx-tee --test prover_roundtrip`

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use nyx_tee::prover::{dummy_slot, ArkMatchBatchProver, Prover};

/// Resolve the repo's `circuits/build` directory from the crate
/// manifest dir (`crates/nyx-tee`). In the production image the
/// path is `/circuits/build`; tests use the in-repo copy.
fn circuits_build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("circuits")
        .join("build")
}

fn n2_artifacts_present(build_dir: &Path) -> bool {
    let base = build_dir.join("match_batch_n2");
    base.join("circuit_js").join("circuit.wasm").exists()
        && base.join("circuit_final.zkey").exists()
        && base.join("circuit.r1cs").exists()
}

// ark-circom's wasmer-backed witness calculator requires a Tokio
// reactor in scope (virtual-fs uses tokio). `prove()` is itself
// synchronous + CPU-heavy, so in production the settle-stage
// worker (PR 4g.6) must call it via `tokio::task::spawn_blocking`
// from inside the runtime. Here we just run the test body under a
// multi-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prove_and_verify_n2_dummy_batch() {
    let build_dir = circuits_build_dir();
    if !n2_artifacts_present(&build_dir) {
        eprintln!(
            "skipping prove_and_verify_n2_dummy_batch: match_batch_n2 artifacts \
             not present at {} (circuit.wasm is gitignored — run \
             `bash scripts/build-circuits.sh` to generate)",
            build_dir.display()
        );
        return;
    }

    let prover = ArkMatchBatchProver::load(&build_dir, 2).expect("load n2 prover");

    // Two all-zero dummy slots: conservation holds trivially
    // (0 = 0*0; 0 = 0+0+0), and the note openings collapse to the
    // dummy Poseidon7 hash the circuit recomputes. This is the
    // simplest circuit-valid witness.
    let slots = vec![dummy_slot(), dummy_slot()];

    // 1. Prove (raw ark proof + public inputs).
    let (proof, public) = prover.prove_ark(&slots).expect("prove n2 dummy batch");

    // 2. The public input vector is [merkle_root, fee_rate_bps,
    //    protocol_owner_commitment] (P1b-2: in-circuit fee floor +
    //    fee-note binding added fee_rate_bps + protocol_owner as the 2nd/3rd
    //    public inputs). The dummy slots carry fee_rate_bps=0 / owner=0.
    assert_eq!(public.public_inputs_be.len(), 3);
    assert_eq!(public.public_inputs_be[0], public.merkle_root);

    // 3. Verify the proof against the zkey's own VK, in-ark. This
    //    is the load-bearing assertion: if input pushing, witness
    //    gen, or the root cross-check were wrong, the proof would
    //    not verify.
    let pvk = prepare_verifying_key(prover.verifying_key());
    let public_fr: Vec<Fr> = public
        .public_inputs_be
        .iter()
        .map(|x| Fr::from_be_bytes_mod_order(x))
        .collect();
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_fr).expect("verify_proof call");
    assert!(verified, "freshly-produced N=2 proof failed verification");

    // 4. The on-chain byte conversion produces a well-formed
    //    256-byte proof (64 + 128 + 64). The actual on-chain
    //    groth16-solana acceptance lands in 4g.6 (N=16 + litesvm).
    let onchain = prover.prove(&slots).expect("prove → on-chain bytes");
    assert_eq!(onchain.proof.pi_a.len(), 64);
    assert_eq!(onchain.proof.pi_b.len(), 128);
    assert_eq!(onchain.proof.pi_c.len(), 64);
    // pi_a must not be all-zero (a real curve point).
    assert!(onchain.proof.pi_a.iter().any(|&b| b != 0));
}

#[test]
fn load_rejects_missing_artifacts() {
    // Pointing at a nonexistent build dir surfaces an Io error,
    // not a panic. (This runs regardless of artifact presence.)
    let bogus = PathBuf::from("/nonexistent/circuits/build");
    // `ArkMatchBatchProver` isn't Debug, so match instead of
    // unwrap_err().
    match ArkMatchBatchProver::load(&bogus, 2) {
        Ok(_) => panic!("expected load to fail for a nonexistent dir"),
        Err(err) => {
            let msg = format!("{err}");
            assert!(msg.contains("io") || msg.to_lowercase().contains("zkey"));
        }
    }
}

// `tokio::test`: since the witness-calc cache (Step 0) moved the circom wasm
// compile into `load()`, loading the prover spins up wasmer's virtual-fs, which
// needs a Tokio 1.x reactor. The batch-size rejection itself still happens in
// `prove()` before any witness gen — this just gives `load()` a runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prove_rejects_wrong_batch_size() {
    // A prover loaded for N=2 must reject a 1-slot batch BEFORE
    // touching any artifact — so this runs even when artifacts are
    // absent (load fails first if absent, so gate on presence).
    let build_dir = circuits_build_dir();
    if !n2_artifacts_present(&build_dir) {
        eprintln!("skipping prove_rejects_wrong_batch_size: artifacts absent");
        return;
    }
    let prover = ArkMatchBatchProver::load(&build_dir, 2).expect("load");
    let err = prover.prove(&[dummy_slot()]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("batch size"), "got: {msg}");
}
