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

use ark_bn254::{Bn254, Fr};
use ark_circom::CircomConfig;
use ark_groth16::Proof;

use super::ark_prover::{build_circom_and_check, circom_input_json, load_circom_cfg};
use super::convert::proof_to_onchain_bytes;
use super::groth16::{ProofWithInputs, Prover, ProverError};
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
use super::rapidsnark_sys::RawProver;
use super::snarkjs::{assert_public_inputs, native_witness_wtns, parse_snarkjs_proof};
use super::witness::MatchSlotWitness;
use super::wtns::serialize_wtns;

/// rapidsnark-backed prover for a fixed circuit instantiation N.
pub struct RapidsnarkMatchBatchProver {
    /// The rapidsnark prover handle (zkey parsed + precomputed once at load).
    /// Mutex-guarded so `prove(&self)` can serialize the C call — the settle
    /// worker proves one batch at a time, so there's no contention.
    raw: Mutex<RawProver>,
    /// Cached ark-circom witness calculator (wasm compiled + r1cs parsed ONCE,
    /// reused per prove). The wasmer fallback when native witness is off.
    cfg: Mutex<CircomConfig<Fr>>,
    /// `Some(binary)` → use the native circom `--c` C++ witness generator
    /// (~18× faster than wasmer on amd64, byte-identical witness; see Step 1
    /// bench). Set when `NYX_TEE_WITNESS=native` AND the binary is present in
    /// the image. `None` → the wasmer path (`cfg`). Lets us A/B native vs
    /// wasmer on the SAME image by flipping the env, like `NYX_TEE_PROVER`.
    native_witness_bin: Option<PathBuf>,
    n: usize,
}

impl RapidsnarkMatchBatchProver {
    /// Resolve `match_batch_n{n}/` under `circuits_build_dir` and create the
    /// rapidsnark prover from its `circuit_final.zkey`. Mirrors
    /// `ArkMatchBatchProver::load` path resolution so the two backends are
    /// drop-in interchangeable.
    pub fn load(circuits_build_dir: impl AsRef<Path>, n: usize) -> Result<Self, ProverError> {
        let dir = circuits_build_dir.as_ref();
        let zkey_path = dir
            .join(format!("match_batch_n{n}"))
            .join("circuit_final.zkey");

        let zkey_str = zkey_path.to_str().ok_or_else(|| {
            ProverError::Io(format!("non-UTF8 zkey path {}", zkey_path.display()))
        })?;
        let raw = RawProver::create_from_zkey_file(zkey_str)
            .map_err(|e| ProverError::Io(format!("rapidsnark zkey load {zkey_str}: {e}")))?;

        let cfg = load_circom_cfg(dir, n)?;

        // Witness generator: native (the circom `--c` C++ gen — DEFAULT) | wasm
        // (wasmer). Native is CVM-validated + ~8-10× faster (witness_ms 201 vs
        // ~1.7-2.1s); the image ships the binary at
        // match_batch_n{n}/circuit_cpp/circuit. Fall back to wasmer (warn) if
        // the binary is absent so a missing artifact DEGRADES rather than bricks
        // boot; an explicit NYX_TEE_WITNESS=wasm forces wasmer.
        let want = std::env::var("NYX_TEE_WITNESS").unwrap_or_default();
        let native_witness_bin = if want == "wasm" {
            tracing::info!("witness generator: wasmer (NYX_TEE_WITNESS=wasm)");
            None
        } else {
            let bin = dir
                .join(format!("match_batch_n{n}"))
                .join("circuit_cpp")
                .join("circuit");
            if bin.exists() {
                tracing::info!(bin = %bin.display(), n, "native witness generator ENABLED");
                Some(bin)
            } else {
                tracing::warn!(
                    "native witness binary absent at {} — falling back to wasmer",
                    bin.display()
                );
                None
            }
        };

        Ok(Self {
            raw: Mutex::new(raw),
            cfg,
            native_witness_bin,
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

        // Witness → `.wtns` bytes. Native C++ generator if enabled (input.json
        // → subprocess → out.wtns), else the cached wasmer path. Both produce
        // the SAME witness (Step-1 bench confirmed byte-identical), so the
        // rapidsnark prove + on-chain verify are unaffected.
        let t_w = std::time::Instant::now();
        let wtns: Vec<u8> = match &self.native_witness_bin {
            Some(bin) => {
                let input_json = circom_input_json(slots, &public.merkle_root)?;
                native_witness_wtns(bin, &input_json)?
            }
            None => {
                let circom = build_circom_and_check(&self.cfg, slots, &public)?;
                let witness = circom.witness.ok_or_else(|| {
                    ProverError::WitnessGen("ark-circom produced no witness".into())
                })?;
                serialize_wtns(&witness)
            }
        };
        let witness_ms = t_w.elapsed().as_millis();

        // Prove with rapidsnark (serialized via the Mutex).
        let t_p = std::time::Instant::now();
        let (proof_json, public_json) = {
            let raw = self
                .raw
                .lock()
                .map_err(|_| ProverError::Prove("rapidsnark prover Mutex poisoned".into()))?;
            raw.prove(&wtns)
                .map_err(|e| ProverError::Prove(format!("rapidsnark prove: {e}")))?
        };
        // Drift guard: the wasmer path checks the circuit's public input inside
        // `build_circom_and_check`; the native path doesn't see the in-circuit
        // root, so assert the PROOF's public input (merkle_root) equals our
        // off-circuit root here. Cheap + a strict correctness check either way.
        assert_public_inputs(&public_json, &public.public_inputs_be)?;
        let proof = parse_snarkjs_proof(&proof_json)?;
        let prove_step_ms = t_p.elapsed().as_millis();
        tracing::info!(
            backend = "rapidsnark",
            witness = if self.native_witness_bin.is_some() {
                "native"
            } else {
                "wasmer"
            },
            witness_ms = witness_ms as u64,
            prove_step_ms = prove_step_ms as u64,
            "prove breakdown (witness-gen vs rapidsnark prove)"
        );

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
