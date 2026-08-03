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
use super::scratch;

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

    // Validate what `new_unchecked` skipped (SW-15).
    //
    // Not a soundness hole: the bytes come from the enclave's own rapidsnark or
    // icicle backend, and a malformed point would fail the on-chain pairing
    // anyway. But that failure arrives as `InvalidProof (6000)` from the vault —
    // a message that names the circuit, not the backend that produced garbage —
    // after the settle transaction has been built, signed and paid for. Checking
    // here turns a confusing on-chain rejection into a local error that names
    // the prover.
    //
    // On-curve AND in-subgroup: a point can satisfy the curve equation while
    // living in a small-order subgroup, and only the second check excludes that.
    for (label, ok) in [
        (
            "pi_a",
            a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve(),
        ),
        (
            "pi_b",
            b.is_on_curve() && b.is_in_correct_subgroup_assuming_on_curve(),
        ),
        (
            "pi_c",
            c.is_on_curve() && c.is_in_correct_subgroup_assuming_on_curve(),
        ),
    ] {
        if !ok {
            return Err(ProverError::Prove(format!(
                "prover backend returned a {label} point that is not a valid \
                 BN254 group element (off-curve or wrong subgroup)"
            )));
        }
    }

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
    let dir = super::scratch::witness_scratch_base()
        .join(format!("darknyx-wtns-{}-{seq}", std::process::id()));
    // 0700, set AT CREATION rather than after. The base is frequently /dev/shm,
    // which is world-writable (1777) and shared by every process in the
    // container, so the per-run subdirectory is the only thing standing between
    // `input.json` and any other uid in that namespace. `create_dir_all` would
    // otherwise apply 0777 & ~umask — typically 0755, i.e. world-readable.
    // Creating it restricted closes the window in which a permissive directory
    // exists while the witness is being written into it.
    scratch::create_private_dir(&dir)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    /// A G1 point as snarkjs writes it: (x, y) decimal strings.
    type G1Parts = (Fq, Fq);
    /// A G2 point: ((x.c0, x.c1), (y.c0, y.c1)).
    type G2Parts = ((Fq, Fq), (Fq, Fq));

    /// Render an ark point pair back into the decimal-string JSON snarkjs emits,
    /// so every case below differs from the valid proof in exactly one point.
    fn proof_json(a: G1Parts, b: G2Parts, c: G1Parts) -> String {
        let d = |v: Fq| v.into_bigint().to_string();
        format!(
            r#"{{"pi_a":["{}","{}","1"],
                 "pi_b":[["{}","{}"],["{}","{}"],["1","0"]],
                 "pi_c":["{}","{}","1"]}}"#,
            d(a.0),
            d(a.1),
            d((b.0).0),
            d((b.0).1),
            d((b.1).0),
            d((b.1).1),
            d(c.0),
            d(c.1),
        )
    }

    /// Generators — a genuinely valid proof shape to mutate one point at a time.
    fn valid_parts() -> (G1Parts, G2Parts, G1Parts) {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        (
            (g1.x, g1.y),
            ((g2.x.c0, g2.x.c1), (g2.y.c0, g2.y.c1)),
            (g1.x, g1.y),
        )
    }

    #[test]
    fn a_well_formed_proof_parses() {
        // The baseline. Without this, every assertion below could be passing
        // because the parser rejects everything.
        let (a, b, c) = valid_parts();
        assert!(parse_snarkjs_proof(&proof_json(a, b, c)).is_ok());
    }

    /// SW-15 — `new_unchecked` accepted any coordinates at all.
    ///
    /// Off-curve is the easy case: perturbing y breaks y² = x³ + 3.
    #[test]
    fn an_off_curve_pi_a_is_rejected() {
        let (mut a, b, c) = valid_parts();
        a.1 += Fq::from(1u64);
        let err = parse_snarkjs_proof(&proof_json(a, b, c)).unwrap_err();
        assert!(
            format!("{err}").contains("pi_a"),
            "the error must name the offending point, got: {err}"
        );
    }

    #[test]
    fn an_off_curve_pi_c_is_rejected() {
        let (a, b, mut c) = valid_parts();
        c.1 += Fq::from(1u64);
        let err = parse_snarkjs_proof(&proof_json(a, b, c)).unwrap_err();
        assert!(format!("{err}").contains("pi_c"), "got: {err}");
    }

    #[test]
    fn an_off_curve_pi_b_is_rejected() {
        let (a, mut b, c) = valid_parts();
        (b.1).0 += Fq::from(1u64);
        let err = parse_snarkjs_proof(&proof_json(a, b, c)).unwrap_err();
        assert!(format!("{err}").contains("pi_b"), "got: {err}");
    }

    /// The case an on-curve check ALONE would wave through, and the reason the
    /// validation is two conditions rather than one.
    ///
    /// G2 over BN254 has a large cofactor, so a point can satisfy the curve
    /// equation while living outside the prime-order subgroup. This builds one
    /// by construction: `mul_by_cofactor_inv` maps the generator off the
    /// r-order subgroup while keeping it on the curve.
    #[test]
    fn an_on_curve_but_wrong_subgroup_pi_b_is_rejected() {
        // Walk x until one lands on the curve. G2's cofactor is enormous, so an
        // arbitrary curve point is overwhelmingly unlikely to fall in the
        // r-order subgroup — but the fixture asserts BOTH properties below
        // rather than assuming them. (`mul_by_cofactor_inv` on the generator
        // does NOT work here: the generator is already in the subgroup and
        // stays there, which the same assertions caught.)
        let mut off = None;
        for i in 1u64..200 {
            let x = Fq2::new(Fq::from(i), Fq::from(0u64));
            if let Some(p) = G2Affine::get_point_from_x_unchecked(x, true) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    off = Some(p);
                    break;
                }
            }
        }
        let off = off.expect("an on-curve, off-subgroup G2 point must exist");
        assert!(off.is_on_curve(), "fixture must be ON the curve");
        assert!(
            !off.is_in_correct_subgroup_assuming_on_curve(),
            "fixture must be OUTSIDE the prime-order subgroup, or this test \
             would pass for the wrong reason"
        );

        let (a, _, c) = valid_parts();
        let b = ((off.x.c0, off.x.c1), (off.y.c0, off.y.c1));
        let err = parse_snarkjs_proof(&proof_json(a, b, c)).unwrap_err();
        assert!(format!("{err}").contains("pi_b"), "got: {err}");
    }

    #[test]
    fn a_truncated_proof_is_rejected_before_any_point_math() {
        let err = parse_snarkjs_proof(r#"{"pi_a":["1"],"pi_b":[],"pi_c":[]}"#).unwrap_err();
        assert!(format!("{err}").contains("wrong shape"), "got: {err}");
    }
}
