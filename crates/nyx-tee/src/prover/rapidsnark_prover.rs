//! rapidsnark-backed `Prover` (the perf swap; `rapidsnark` feature only).
//!
//! Witness generation stays on ark-circom — `circom-witness-rs` was ruled out
//! by the Step-1 spike (it needs static witness-gen control flow, which our
//! circomlib `Num2Bits`/comparators violate). So this reuses
//! [`build_circom_and_check`] (shared with the ark backend: one witness-gen +
//! one Merkle-root drift guard), takes the in-memory `Vec<Fr>` witness,
//! serializes it to a `.wtns` buffer, and proves with rapidsnark over FFI.
//!
//! The rapidsnark proof comes back as snarkjs-format JSON; we parse it into an
//! ark `Proof<Bn254>` and route it through the EXISTING
//! [`proof_to_onchain_bytes`] so there is a single, already-tested on-chain
//! byte converter (pi_a negation + pi_b Fq2 swap) for both backends.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::Proof;

use super::ark_prover::build_circom_and_check;
use super::convert::proof_to_onchain_bytes;
use super::groth16::{ProofWithInputs, Prover, ProverError};
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
use super::rapidsnark_sys::RawProver;
use super::witness::MatchSlotWitness;
use super::wtns::serialize_wtns;

/// rapidsnark-backed prover for a fixed circuit instantiation N.
pub struct RapidsnarkMatchBatchProver {
    /// The rapidsnark prover handle (zkey parsed + precomputed once at load).
    /// Mutex-guarded so `prove(&self)` can serialize the C call — the settle
    /// worker proves one batch at a time, so there's no contention.
    raw: Mutex<RawProver>,
    /// ark-circom witness-calc inputs (the witness still comes from wasmer).
    wasm_path: PathBuf,
    r1cs_path: PathBuf,
    n: usize,
}

impl RapidsnarkMatchBatchProver {
    /// Resolve `match_batch_n{n}/` under `circuits_build_dir` and create the
    /// rapidsnark prover from its `circuit_final.zkey`. Mirrors
    /// `ArkMatchBatchProver::load` path resolution so the two backends are
    /// drop-in interchangeable.
    pub fn load(circuits_build_dir: impl AsRef<Path>, n: usize) -> Result<Self, ProverError> {
        let base = circuits_build_dir
            .as_ref()
            .join(format!("match_batch_n{n}"));
        let zkey_path = base.join("circuit_final.zkey");
        let wasm_path = base.join("circuit_js").join("circuit.wasm");
        let r1cs_path = base.join("circuit.r1cs");

        let zkey_str = zkey_path.to_str().ok_or_else(|| {
            ProverError::Io(format!("non-UTF8 zkey path {}", zkey_path.display()))
        })?;
        let raw = RawProver::create_from_zkey_file(zkey_str)
            .map_err(|e| ProverError::Io(format!("rapidsnark zkey load {zkey_str}: {e}")))?;

        Ok(Self {
            raw: Mutex::new(raw),
            wasm_path,
            r1cs_path,
            n,
        })
    }
}

impl RapidsnarkMatchBatchProver {
    /// Core proving path returning the RAW ark `Proof` + public inputs (before
    /// the on-chain byte conversion). Exposed so tests can verify the
    /// rapidsnark proof against the zkey VK in-ark (parallel to
    /// `ArkMatchBatchProver::prove_ark`).
    pub fn prove_to_ark(
        &self,
        slots: &[MatchSlotWitness],
    ) -> Result<(Proof<Bn254>, BatchPublicInputs), ProverError> {
        if slots.len() != self.n {
            return Err(ProverError::BatchSizeMismatch {
                expected: self.n,
                got: slots.len(),
            });
        }

        // Pre-flight + public inputs + witness + Merkle-root cross-check —
        // shared with the ark backend (same drift guard).
        super::constraints::validate_conservation(slots)?;
        let public = build_batch_public_inputs(slots)?;
        let circom = build_circom_and_check(&self.wasm_path, &self.r1cs_path, slots, &public)?;
        let witness = circom
            .witness
            .ok_or_else(|| ProverError::WitnessGen("ark-circom produced no witness".into()))?;

        // Serialize the witness + prove with rapidsnark (serialized via the Mutex).
        let wtns = serialize_wtns(&witness);
        let (proof_json, _public_json) = {
            let raw = self
                .raw
                .lock()
                .map_err(|_| ProverError::Prove("rapidsnark prover Mutex poisoned".into()))?;
            raw.prove(&wtns)
                .map_err(|e| ProverError::Prove(format!("rapidsnark prove: {e}")))?
        };

        let proof = parse_snarkjs_proof(&proof_json)?;
        Ok((proof, public))
    }
}

impl Prover for RapidsnarkMatchBatchProver {
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
        let (proof, public) = self.prove_to_ark(slots)?;
        // snarkjs JSON proof → ark Proof → on-chain bytes (the shared converter).
        Ok(ProofWithInputs {
            proof: proof_to_onchain_bytes(&proof),
            public,
        })
    }

    fn n(&self) -> usize {
        self.n
    }
}

#[derive(serde::Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

/// Parse a snarkjs-format Groth16 proof JSON into an ark `Proof<Bn254>` in the
/// SAME representation `ArkMatchBatchProver` produces (points as-is, y NOT
/// negated, Fq2 in snarkjs (c0,c1) order) — `proof_to_onchain_bytes` then
/// applies the pi_a negation + pi_b Fq2 swap identically for both backends.
fn parse_snarkjs_proof(json: &str) -> Result<Proof<Bn254>, ProverError> {
    let p: SnarkjsProof = serde_json::from_str(json)
        .map_err(|e| ProverError::Prove(format!("parse rapidsnark proof json: {e}")))?;
    if p.pi_a.len() < 2
        || p.pi_c.len() < 2
        || p.pi_b.len() < 2
        || p.pi_b[0].len() < 2
        || p.pi_b[1].len() < 2
    {
        return Err(ProverError::Prove(
            "rapidsnark proof json has wrong shape".into(),
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
