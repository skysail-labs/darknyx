//! Groth16 prover interface.
//!
//! The trait + error type + output struct live here; the real
//! implementations are [`super::ark_prover`], plus the feature-gated
//! `rapidsnark_prover` and `icicle_prover`. The settle worker holds a
//! `Box<dyn Prover>`,
//! so the backend is selected at boot without any call-site knowing which one
//! is active.
//!
//! Image path for the production proving key:
//! `/circuits/build/match_batch_n16/circuit_final.zkey`. The path
//! is baked into the Dockerfile COPY step so a swap requires a
//! compose-hash bump (and therefore a multisig rotation).
//!
//! Format note: `prove` returns `Groth16ProofBytes` matching the
//! `programs/vault/src/zk/verifier.rs::Groth16Proof` Borsh layout —
//! 64 + 128 + 64 = 256 bytes. Identical bytes as the SDK's
//! `groth16-format.ts` produces from a snarkjs proof JSON; the
//! ark-groth16 → on-chain converter is [`super::convert`].

use thiserror::Error;

use super::constraints::ConstraintError;
use super::inputs::BatchPublicInputs;
use super::leaf::LeafError;
use super::witness::MatchSlotWitness;
use crate::settle::Groth16ProofBytes;

/// Default circuit instantiation wired on-chain. The matcher emits
/// up to N=16 matches per batch; this is the only N the production
/// `vk_match_batch_n16.rs` was generated for.
pub const PRODUCTION_BATCH_N: usize = 16;

/// Output of a successful prove.
#[derive(Debug, Clone)]
pub struct ProofWithInputs {
    pub proof: Groth16ProofBytes,
    pub public: BatchPublicInputs,
    /// Backend-reported wall times for the two materially different proving
    /// phases. Keeping these on the proof result lets the settlement metrics
    /// endpoint report the exact split without scraping tracing output.
    pub timings: ProverTimings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverTimings {
    pub backend: String,
    pub witness_backend: String,
    pub device: Option<String>,
    pub witness_ms: u64,
    pub prove_step_ms: u64,
}

#[derive(Error, Debug)]
pub enum ProverError {
    /// Conservation constraint violated. Surfaces the named-field
    /// violation from `constraints::validate_conservation`.
    #[error("constraint: {0}")]
    Constraint(#[from] ConstraintError),
    /// Leaf / root computation failed (typically a bad N or a
    /// Poseidon-Fr-safety error).
    #[error("leaf or root: {0}")]
    Leaf(#[from] LeafError),
    /// Caller passed N != the prover's circuit instantiation.
    #[error("batch size {got} does not match prover instantiation N={expected}")]
    BatchSizeMismatch { expected: usize, got: usize },
    /// File / zkey load failure (missing artifact, bad zkey).
    #[error("io: {0}")]
    Io(String),
    /// Witness generation failed (CircomConfig build, witness calc,
    /// or the circuit rejected the inputs).
    #[error("witness: {0}")]
    WitnessGen(String),
    /// Groth16 proof generation failed inside ark-groth16.
    #[error("prove: {0}")]
    Prove(String),
    /// The circuit's computed Merkle root (the first of two public inputs)
    /// disagrees with our off-circuit `compute_batch_root`. Means
    /// `prover/leaf.rs` drifted from the circuit's `MatchSlot()` /
    /// `MerkleRoot()` templates — a proof would be silently rejected
    /// on-chain, so we fail loud here instead.
    #[error("root mismatch: circuit={circuit} computed={computed}")]
    RootMismatch { circuit: String, computed: String },
}

/// Generic prover interface — same signature for the stub today
/// and the ark-groth16 impl. Call-sites (the
/// `Proving` stage worker) hold a `Box<dyn Prover>` so the swap
/// is internal to this module.
pub trait Prover: Send + Sync {
    /// Validate + compute public inputs + return a Groth16 proof
    /// over them.
    ///
    /// `slots` MUST be exactly `n()` entries. Caller pre-pads with
    /// `witness::pad_batch` if the matcher produced fewer than `n()`
    /// real matches.
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError>;

    /// The circuit instantiation this prover is wired for.
    /// Production = [`PRODUCTION_BATCH_N`] = 16.
    fn n(&self) -> usize;
}
