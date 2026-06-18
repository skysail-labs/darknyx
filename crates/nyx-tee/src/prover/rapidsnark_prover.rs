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

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_circom::CircomConfig;
use ark_ff::PrimeField;
use ark_groth16::Proof;

use super::ark_prover::{build_circom_and_check, circom_input_json, load_circom_cfg};
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

        // Native witness generator (opt-in via NYX_TEE_WITNESS=native). The
        // image ships the circom `--c` C++ binary at
        // match_batch_n{n}/circuit_cpp/circuit (built on the amd64 CI runner).
        let native_witness_bin = if std::env::var("NYX_TEE_WITNESS").as_deref() == Ok("native") {
            let bin = dir
                .join(format!("match_batch_n{n}"))
                .join("circuit_cpp")
                .join("circuit");
            if !bin.exists() {
                return Err(ProverError::Io(format!(
                    "NYX_TEE_WITNESS=native but the native witness generator is missing at {}",
                    bin.display()
                )));
            }
            tracing::info!(bin = %bin.display(), n, "native witness generator ENABLED");
            Some(bin)
        } else {
            tracing::info!(
                "witness generator: wasmer (set NYX_TEE_WITNESS=native for the C++ gen)"
            );
            None
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
        assert_public_root(&public_json, &public.merkle_root)?;
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

static WTNS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run the native circom `--c` witness generator: write `input.json` + capture
/// the output `.wtns` in a private temp dir, invoke `<bin> input.json out.wtns`,
/// and return the raw `.wtns` bytes (the standard format `serialize_wtns` also
/// emits, so it feeds rapidsnark directly). The temp dir is removed on every
/// exit path. The settle worker proves serially, but the seq+pid dir name keeps
/// concurrent calls isolated regardless.
fn native_witness_wtns(bin: &Path, input_json: &str) -> Result<Vec<u8>, ProverError> {
    let seq = WTNS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("nyx-wtns-{}-{seq}", std::process::id()));
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

/// Assert the proof's single public input (the circuit's computed Merkle root)
/// equals our off-circuit `merkle_root`. rapidsnark returns the public inputs
/// as a JSON array of decimal strings; the root is Fr-safe so it fits 32 BE
/// bytes. This is the native path's equivalent of the wasmer path's in-circuit
/// drift guard.
fn assert_public_root(public_json: &str, expected: &[u8; 32]) -> Result<(), ProverError> {
    let pubs: Vec<String> = serde_json::from_str(public_json)
        .map_err(|e| ProverError::Prove(format!("parse rapidsnark public json: {e}")))?;
    let first = pubs
        .first()
        .ok_or_else(|| ProverError::Prove("rapidsnark returned no public inputs".into()))?;
    let got = num_bigint::BigUint::parse_bytes(first.as_bytes(), 10)
        .ok_or_else(|| ProverError::Prove(format!("bad public decimal: {first}")))?;
    let got_be = got.to_bytes_be();
    if got_be.len() > 32 {
        return Err(ProverError::RootMismatch {
            circuit: hex::encode(&got_be),
            computed: hex::encode(expected),
        });
    }
    let mut got32 = [0u8; 32];
    got32[32 - got_be.len()..].copy_from_slice(&got_be);
    if &got32 != expected {
        return Err(ProverError::RootMismatch {
            circuit: hex::encode(got32),
            computed: hex::encode(expected),
        });
    }
    Ok(())
}
