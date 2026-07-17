//! ICICLE-backed `Prover` (the GPU/CPU swap; `icicle` feature only).
//!
//! Like the rapidsnark backend, witness generation stays shared (native circom
//! `--c` C++ generator, or the wasmer fallback) — only the PROVE step changes.
//! This backend proves with the vendored `icicle-snark` crate, which reads our
//! standard snarkjs `.zkey` + `.wtns` and emits a snarkjs-format proof, so the
//! result routes through the SAME [`proof_to_onchain_bytes`] converter as ark +
//! rapidsnark. One crate covers both `device="CPU"` (Phase 1 — no GPU) and
//! `device="CUDA"` (Phase 2 — confidential-GPU TEE); the device is chosen per
//! prove via `DARKNYX_TEE_ICICLE_DEVICE` (default `CPU`).
//!
//! ## Threading
//!
//! `icicle-snark`'s `CacheManager` holds `DeviceVec` handles (raw device
//! pointers) and is therefore `!Send`, so it can't sit behind a `Mutex` inside
//! the `Arc<dyn Prover>` the settle worker holds. We confine ALL icicle calls to
//! one dedicated OS thread that owns the cache for the process lifetime; the
//! prover struct only holds the channel `Sender` (which is `Send + Sync`). The
//! settle worker already proves one batch at a time, so a single prover thread
//! is exactly the right shape — and it also keeps the icicle `set_device` /
//! cache state on a stable thread.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::Mutex;

use ark_bn254::{Bn254, Fr};
use ark_circom::CircomConfig;
use ark_groth16::Proof;
use icicle_snark::{groth16_prove, CacheManager};

use super::ark_prover::{build_circom_and_check, circom_input_json, load_circom_cfg};
use super::convert::proof_to_onchain_bytes;
use super::groth16::{ProofWithInputs, Prover, ProverError};
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
use super::snarkjs::{assert_public_inputs, native_witness_wtns, parse_snarkjs_proof};
use super::witness::MatchSlotWitness;
use super::wtns::serialize_wtns;

/// A prove request handed to the dedicated icicle thread: the `.wtns` bytes plus
/// a one-shot reply channel. The reply carries `(proof_json, public_json)` or a
/// stringified error (icicle's `Box<dyn Error>` is `!Send`, so we stringify on
/// the worker thread before sending it back).
type ProveReply = Result<(String, String), String>;
struct ProveJob {
    wtns: Vec<u8>,
    reply: Sender<ProveReply>,
}

/// ICICLE-backed prover for a fixed circuit instantiation N.
pub struct IcicleMatchBatchProver {
    /// Sender to the dedicated icicle thread (owns the `!Send` `CacheManager`).
    /// `Mutex` so `prove(&self)` can serialize submissions — the settle worker
    /// proves serially anyway, so there's no contention.
    job_tx: Mutex<Sender<ProveJob>>,
    /// Cached ark-circom witness calculator (wasm compiled + r1cs parsed ONCE);
    /// the wasmer fallback when native witness is off. Same as the other backends.
    cfg: Mutex<CircomConfig<Fr>>,
    /// `Some(binary)` → the native circom `--c` C++ witness generator (~8-10×
    /// faster than wasmer, byte-identical witness). `None` → the wasmer `cfg`.
    /// Selected by `DARKNYX_TEE_WITNESS` exactly like the rapidsnark backend.
    native_witness_bin: Option<PathBuf>,
    /// The icicle device the worker thread proves on: `CPU` (Phase 1) | `CUDA`.
    device: String,
    n: usize,
}

impl IcicleMatchBatchProver {
    /// Resolve `match_batch_n{n}/` under `circuits_build_dir`, set up witness
    /// gen, and spawn the dedicated icicle proving thread. Mirrors the other
    /// backends' `load` path resolution so they're drop-in interchangeable.
    pub fn load(circuits_build_dir: impl AsRef<Path>, n: usize) -> Result<Self, ProverError> {
        let dir = circuits_build_dir.as_ref();
        let zkey_path = dir
            .join(format!("match_batch_n{n}"))
            .join("circuit_final.zkey");
        if !zkey_path.exists() {
            return Err(ProverError::Io(format!(
                "icicle: zkey not found at {}",
                zkey_path.display()
            )));
        }
        let zkey_str = zkey_path
            .to_str()
            .ok_or_else(|| ProverError::Io(format!("non-UTF8 zkey path {}", zkey_path.display())))?
            .to_string();

        let cfg = load_circom_cfg(dir, n)?;

        // Witness generator: native (DEFAULT) | wasm — identical selection to
        // the rapidsnark backend (see its `load`); native degrades to wasmer
        // (warn) if the binary is absent so a missing artifact doesn't brick boot.
        let want = std::env::var("DARKNYX_TEE_WITNESS").unwrap_or_default();
        let native_witness_bin = if want == "wasm" {
            tracing::info!("witness generator: wasmer (DARKNYX_TEE_WITNESS=wasm)");
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

        // The icicle compute device. CPU needs no GPU (Phase 1); CUDA (Phase 2)
        // requires a confidential-GPU TEE + the ICICLE CUDA backend in the image
        // (and ICICLE_BACKEND_INSTALL_DIR set so it's loaded). Default CPU.
        let device = std::env::var("DARKNYX_TEE_ICICLE_DEVICE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "CPU".to_string());

        // Spawn the dedicated thread that owns the !Send CacheManager.
        let (job_tx, job_rx) = channel::<ProveJob>();
        let thread_zkey = zkey_str;
        let thread_device = device.clone();
        std::thread::Builder::new()
            .name("darknyx-icicle-prover".into())
            .spawn(move || {
                let mut cache = CacheManager::default();
                while let Ok(job) = job_rx.recv() {
                    // catch_unwind: icicle-snark is unwrap-heavy on bad input, so
                    // a malformed witness would otherwise kill this thread for the
                    // process lifetime. Catch it, reply with an error, and reset
                    // the cache (its state may be partial after a panic) so the
                    // NEXT good prove rebuilds cleanly.
                    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        icicle_prove_wtns(&job.wtns, &thread_zkey, &thread_device, &mut cache)
                    }));
                    let reply = match res {
                        Ok(r) => r,
                        Err(_) => {
                            cache = CacheManager::default();
                            Err("icicle prove panicked (see stderr) — cache reset".to_string())
                        }
                    };
                    let _ = job.reply.send(reply);
                }
            })
            .map_err(|e| ProverError::Io(format!("spawn icicle prover thread: {e}")))?;

        Ok(Self {
            job_tx: Mutex::new(job_tx),
            cfg,
            native_witness_bin,
            device,
            n,
        })
    }

    /// Core proving path returning the RAW ark `Proof` + public inputs (before
    /// the on-chain byte conversion). Exposed so tests can verify the icicle
    /// proof against the zkey VK in-ark (parallel to the other backends).
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
        // shared with the other backends (same drift guard).
        super::constraints::validate_conservation(slots)?;
        let public = build_batch_public_inputs(slots)?;

        // Witness → `.wtns` bytes (native C++ gen if enabled, else wasmer). Both
        // produce the SAME witness, so the icicle prove + on-chain verify are
        // backend-agnostic.
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

        // Prove on the dedicated icicle thread.
        let t_p = std::time::Instant::now();
        let (reply_tx, reply_rx) = channel::<ProveReply>();
        self.job_tx
            .lock()
            .map_err(|_| ProverError::Prove("icicle job sender Mutex poisoned".into()))?
            .send(ProveJob {
                wtns,
                reply: reply_tx,
            })
            .map_err(|_| ProverError::Prove("icicle prover thread is gone".into()))?;
        let (proof_json, public_json) = reply_rx
            .recv()
            .map_err(|_| ProverError::Prove("icicle prover thread dropped the reply".into()))?
            .map_err(ProverError::Prove)?;

        // Drift guard: the native witness path doesn't see the in-circuit root,
        // so assert the PROOF's public input (merkle_root) equals our off-circuit
        // root. Cheap + strict either way.
        assert_public_inputs(&public_json, &public.public_inputs_be)?;
        let proof = parse_snarkjs_proof(&proof_json)?;
        let prove_step_ms = t_p.elapsed().as_millis();
        tracing::info!(
            backend = "icicle",
            device = %self.device,
            witness = if self.native_witness_bin.is_some() {
                "native"
            } else {
                "wasmer"
            },
            witness_ms = witness_ms as u64,
            prove_step_ms = prove_step_ms as u64,
            "prove breakdown (witness-gen vs icicle prove)"
        );

        Ok((proof, public))
    }
}

impl Prover for IcicleMatchBatchProver {
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

/// Run one icicle prove on the worker thread: write the `.wtns` + capture the
/// proof/public JSON in a private temp dir, prove via `groth16_prove`, read the
/// outputs back. The `CacheManager` caches the preprocessed zkey across calls
/// (keyed by `zkey_path + device`), so only the first prove pays the parse.
fn icicle_prove_wtns(
    wtns: &[u8],
    zkey_path: &str,
    device: &str,
    cache: &mut CacheManager,
) -> ProveReply {
    let dir = std::env::temp_dir().join(format!(
        "darknyx-icicle-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create icicle tmp dir: {e}"))?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    let wtns_path = dir.join("witness.wtns");
    let proof_path = dir.join("proof.json");
    let public_path = dir.join("public.json");
    std::fs::write(&wtns_path, wtns).map_err(|e| format!("write wtns: {e}"))?;

    let to_str = |p: &Path| -> Result<String, String> {
        p.to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("non-UTF8 path {}", p.display()))
    };

    groth16_prove(
        &to_str(&wtns_path)?,
        zkey_path,
        &to_str(&proof_path)?,
        &to_str(&public_path)?,
        device,
        cache,
    )
    .map_err(|e| format!("icicle groth16_prove (device={device}): {e}"))?;

    let proof_json =
        std::fs::read_to_string(&proof_path).map_err(|e| format!("read proof.json: {e}"))?;
    let public_json =
        std::fs::read_to_string(&public_path).map_err(|e| format!("read public.json: {e}"))?;
    Ok((proof_json, public_json))
}
