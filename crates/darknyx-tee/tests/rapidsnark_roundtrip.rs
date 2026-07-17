//! End-to-end prove + verify for the rapidsnark backend (the perf swap).
//!
//! Proves a 2-slot batch with `RapidsnarkMatchBatchProver` (ark-circom witness
//! → `.wtns` → rapidsnark FFI) and verifies the resulting proof against the
//! zkey's own VK in-ark — the load-bearing check that the witness `.wtns`
//! serialization + the snarkjs-JSON→ark-proof parse are correct. Also asserts
//! cross-backend parity: ark and rapidsnark produce the SAME public input
//! (the batch Merkle root) for the same batch (the proofs themselves differ —
//! Groth16 is randomized).
//!
//! Gated TWICE: only built with `--features rapidsnark` (needs the static libs
//! linked via $RAPIDSNARK_LIB_DIR), and only runs when the match_batch_n2
//! artifacts are present (circuit.wasm is gitignored).
//!
//! Run with:
//!   RAPIDSNARK_LIB_DIR=... RAPIDSNARK_GMP_LIB_DIR=... \
//!     cargo test -p darknyx-tee --features rapidsnark --test rapidsnark_roundtrip

#![cfg(feature = "rapidsnark")]

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use darknyx_tee::prover::{dummy_slot, ArkMatchBatchProver, Prover, RapidsnarkMatchBatchProver};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapidsnark_proves_and_verifies_n2() {
    let build_dir = circuits_build_dir();
    if !n2_artifacts_present(&build_dir) {
        eprintln!(
            "skipping rapidsnark_proves_and_verifies_n2: match_batch_n2 artifacts not present \
             at {} (run `bash scripts/build-circuits.sh`)",
            build_dir.display()
        );
        return;
    }

    let rs = RapidsnarkMatchBatchProver::load(&build_dir, 2).expect("load rapidsnark n2 prover");
    // The ark prover gives us the zkey VK to verify against (same zkey).
    let ark = ArkMatchBatchProver::load(&build_dir, 2).expect("load ark n2 prover (for the VK)");

    let slots = vec![dummy_slot(), dummy_slot()];

    // 1. Prove with rapidsnark (raw ark Proof + public inputs).
    let (proof, public) = rs
        .prove_to_ark(&slots)
        .expect("rapidsnark prove n2 dummy batch");
    assert_eq!(public.public_inputs_be.len(), 1);
    assert_eq!(public.public_inputs_be[0], public.merkle_root);

    // 2. Verify the rapidsnark proof against the zkey VK, in-ark. If the .wtns
    //    serialization or the snarkjs-JSON parse were wrong, this fails.
    let pvk = prepare_verifying_key(ark.verifying_key());
    let public_fr = vec![Fr::from_be_bytes_mod_order(&public.merkle_root)];
    let verified =
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_fr).expect("verify_proof call");
    assert!(
        verified,
        "rapidsnark N=2 proof failed verification against the zkey VK"
    );

    // 3. Cross-backend parity: ark proves the same batch to the SAME public
    //    input (the merkle root). (Proofs differ — randomized — so we compare
    //    the public input, not the proof bytes.)
    let (_ark_proof, ark_public) = ark.prove_ark(&slots).expect("ark prove n2 dummy batch");
    assert_eq!(
        ark_public.merkle_root, public.merkle_root,
        "ark and rapidsnark disagree on the batch Merkle root"
    );

    // 4. The on-chain byte conversion produces a well-formed 256-byte proof.
    let onchain = rs.prove(&slots).expect("rapidsnark prove → on-chain bytes");
    assert_eq!(onchain.proof.pi_a.len(), 64);
    assert_eq!(onchain.proof.pi_b.len(), 128);
    assert_eq!(onchain.proof.pi_c.len(), 64);
    assert!(onchain.proof.pi_a.iter().any(|&b| b != 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapidsnark_rejects_wrong_batch_size() {
    let build_dir = circuits_build_dir();
    if !n2_artifacts_present(&build_dir) {
        eprintln!("skipping rapidsnark_rejects_wrong_batch_size: artifacts absent");
        return;
    }
    let rs = RapidsnarkMatchBatchProver::load(&build_dir, 2).expect("load");
    let err = rs.prove(&[dummy_slot()]).unwrap_err();
    assert!(format!("{err}").contains("batch size"));
}
