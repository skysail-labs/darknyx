//! Shared helpers for the snarkjs-format prover backends (rapidsnark + icicle).
//!
//! Both non-ark backends generate the witness the same way (native circom `--c`
//! C++ generator or the wasmer fallback), prove over the resulting `.wtns`, and
//! get a snarkjs-format proof + public-signal JSON back. This module owns the
//! pieces that are byte-identical across them:
//!
//!   - [`native_witness_wtns`] — run the native generator, return `.wtns` bytes.
//!   - [`parse_snarkjs_proof`] — snarkjs proof JSON → ark `Proof<Bn254>` (in the
//!     SAME representation `ArkMatchBatchProver` produces, so the single
//!     [`super::convert::proof_to_onchain_bytes`] converter applies to all three
//!     backends).
//!   - [`assert_public_inputs`] — the native path's drift guard over both
//!     compressed circuit public inputs.
//!
//! Keeping these in one place means a proof-format fix (e.g. a Fq2 limb-order
//! correction) lands once for every backend, and the n16 parity test guards them.

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::Proof;

use super::groth16::ProverError;

#[derive(serde::Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

/// Parse a snarkjs-format Groth16 proof JSON into an ark `Proof<Bn254>` in the
/// SAME representation `ArkMatchBatchProver` produces (points as-is, y NOT
/// negated, Fq2 in snarkjs (c0,c1) order) — `proof_to_onchain_bytes` then
/// applies the pi_a negation + pi_b Fq2 swap identically for all backends.
pub(crate) fn parse_snarkjs_proof(json: &str) -> Result<Proof<Bn254>, ProverError> {
    let p: SnarkjsProof = serde_json::from_str(json)
        .map_err(|e| ProverError::Prove(format!("parse snarkjs proof json: {e}")))?;
    if p.pi_a.len() < 2
        || p.pi_c.len() < 2
        || p.pi_b.len() < 2
        || p.pi_b[0].len() < 2
        || p.pi_b[1].len() < 2
    {
        return Err(ProverError::Prove(
            "snarkjs proof json has wrong shape".into(),
        ));
    }

    let a = G1Affine::new_unchecked(fq_dec(&p.pi_a[0])?, fq_dec(&p.pi_a[1])?);
    // snarkjs G2: x = (c0, c1), y = (c0, c1); ark Fq2::new(c0, c1).
    let b = G2Affine::new_unchecked(
        Fq2::new(fq_dec(&p.pi_b[0][0])?, fq_dec(&p.pi_b[0][1])?),
        Fq2::new(fq_dec(&p.pi_b[1][0])?, fq_dec(&p.pi_b[1][1])?),
    );
    let c = G1Affine::new_unchecked(fq_dec(&p.pi_c[0])?, fq_dec(&p.pi_c[1])?);

    Ok(Proof { a, b, c })
}

/// Decimal string → BN254 base-field element.
fn fq_dec(s: &str) -> Result<Fq, ProverError> {
    let b = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| ProverError::Prove(format!("bad Fq decimal: {s}")))?;
    Ok(Fq::from_le_bytes_mod_order(&b.to_bytes_le()))
}

static WTNS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run the native circom `--c` witness generator: write `input.json` + capture
/// the output `.wtns` in a private temp dir, invoke `<bin> input.json out.wtns`,
/// and return the raw `.wtns` bytes (the standard format `serialize_wtns` also
/// emits, so it feeds rapidsnark/icicle directly). The temp dir is removed on
/// every exit path. The settle worker proves serially, but the seq+pid dir name
/// keeps concurrent calls isolated regardless.
pub(crate) fn native_witness_wtns(bin: &Path, input_json: &str) -> Result<Vec<u8>, ProverError> {
    let seq = WTNS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("darknyx-wtns-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| ProverError::WitnessGen(format!("create wtns tmp dir: {e}")))?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    let in_path = dir.join("input.json");
    let out_path = dir.join("witness.wtns");
    std::fs::write(&in_path, input_json)
        .map_err(|e| ProverError::WitnessGen(format!("write input.json: {e}")))?;

    let out = std::process::Command::new(bin)
        .arg(&in_path)
        .arg(&out_path)
        .output()
        .map_err(|e| {
            ProverError::WitnessGen(format!("spawn native witness gen {}: {e}", bin.display()))
        })?;
    if !out.status.success() {
        // Surface the generator's own stderr (e.g. ".dat file not found",
        // a bad input signal) — it's the actionable part of the failure.
        return Err(ProverError::WitnessGen(format!(
            "native witness gen {} failed ({}): {}",
            bin.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    std::fs::read(&out_path).map_err(|e| ProverError::WitnessGen(format!("read .wtns: {e}")))
}

/// Assert both proof public inputs (computed root plus governed-config digest)
/// equal the off-circuit vector. snarkjs-format backends return the
/// public inputs as a JSON array of decimal strings; the root is Fr-safe so it
/// fits 32 BE bytes. This is the native witness path's equivalent of the wasmer
/// path's in-circuit drift guard.
pub(crate) fn assert_public_inputs(
    public_json: &str,
    expected: &[[u8; 32]],
) -> Result<(), ProverError> {
    let pubs: Vec<String> = serde_json::from_str(public_json)
        .map_err(|e| ProverError::Prove(format!("parse public json: {e}")))?;
    if pubs.len() != expected.len() {
        return Err(ProverError::Prove(format!(
            "prover returned {} public inputs, expected {}",
            pubs.len(),
            expected.len()
        )));
    }
    for (index, (value, want)) in pubs.iter().zip(expected).enumerate() {
        let got = num_bigint::BigUint::parse_bytes(value.as_bytes(), 10)
            .ok_or_else(|| ProverError::Prove(format!("bad public decimal: {value}")))?;
        let got_be = got.to_bytes_be();
        if got_be.len() > 32 {
            return Err(ProverError::Prove(format!(
                "public input[{index}] exceeds 32 bytes"
            )));
        }
        let mut got32 = [0u8; 32];
        got32[32 - got_be.len()..].copy_from_slice(&got_be);
        if &got32 != want {
            return Err(ProverError::WitnessGen(format!(
                "public input[{index}] mismatch: prover {} != computed {}",
                hex::encode(got32),
                hex::encode(want)
            )));
        }
    }
    Ok(())
}
