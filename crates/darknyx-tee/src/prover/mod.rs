//! In-enclave VALID_MATCH_BATCH proving.
//!
//! Generates the Groth16 proof that `verify_match_batch` (Tx B) checks on-chain.
//! This is the pipeline's dominant cost — an N=16 proof takes long enough that the
//! worker runs it under `spawn_blocking` — and the most byte-sensitive code in the
//! crate, because the witness it builds must agree exactly with what the circuit
//! expects.
//!
//! # Backends
//!
//! Selected at boot by `DARKNYX_TEE_PROVER`, all behind the [`groth16::Prover`]
//! trait so the settle worker is unaware of which is active:
//!
//! ```text
//!   ark_prover.rs        ark-circom: witness generation + zkey-backed proving
//!   rapidsnark_prover.rs rapidsnark via rapidsnark_sys.rs (FFI)
//!   icicle_prover.rs     ICICLE, device=CPU (default) or CUDA
//! ```
//!
//! A GPU backend is only safe where the GPU itself is in confidential-compute mode:
//! the witness holds private amounts, so a non-CC GPU would place them outside the
//! enclave boundary. `gpu_cc.rs` is that check, and it must fail **closed** — an
//! unrecognised device is not evidence of confidential compute.
//!
//! # Deterministic core
//!
//! The rest is byte-equality machinery mirroring
//! `packages/sdk/tests/helpers/match-batch-prover.ts`:
//!
//! ```text
//!   witness.rs      MatchSlotWitness, dummy_slot, and the all-zero padding
//!                   strategy for batches smaller than N
//!   leaf.rs         Poseidon leaf, Merkle root, inclusion path — must match the
//!                   circuit's MatchSlot() and MerkleRoot(N) templates exactly
//!   constraints.rs  conservation checks that fail with named errors before the
//!                   circuit sees a bad witness
//!   inputs.rs       the snarkjs-format public-input vector groth16-solana consumes
//!   convert.rs      ark-groth16 Proof<Bn254> → the on-chain 256-byte layout
//!   snarkjs.rs, wtns.rs, scratch.rs   witness-file and workspace plumbing
//! ```
//!
//! A drift in `leaf.rs` does not fail here. It fails inside the circuit, as
//! `merkle_root != merkle.root`, after a full proof has been generated — which is
//! why `match-batch-prototype.test.ts` pins the construction on the TypeScript side
//! too.

pub mod ark_prover;
pub mod constraints;
pub mod convert;
pub mod groth16;
pub mod inputs;
pub mod leaf;
pub mod witness;
pub mod wtns;

// The rapidsnark backend (perf swap). Witness gen stays on ark-circom; only
// the PROVE step is rapidsnark. Linked via build.rs from $RAPIDSNARK_LIB_DIR;
// off by default (incl. local builds without the static libs).
#[cfg(feature = "rapidsnark")]
pub mod rapidsnark_prover;
#[cfg(feature = "rapidsnark")]
mod rapidsnark_sys;

// The ICICLE backend (GPU/CPU perf swap; `icicle` feature). Witness gen shared;
// only the PROVE step is icicle-snark (vendored under third_party/icicle-snark).
// Off by default (the heavy cmake build is `dep:icicle-snark`, pulled in only by
// the feature).
#[cfg(feature = "icicle")]
pub mod icicle_prover;

// GPU confidential-compute gate (SW-32). Always compiled — see the module doc.
pub(crate) mod gpu_cc;

// Witness scratch-dir selection (SW-14). Always compiled — see the module doc.
pub(crate) mod scratch;

// Snarkjs-format proof helpers shared by the rapidsnark + icicle backends.
//
// Always compiled, for the same reason as `scratch` above: this module holds
// the SW-15 group-element validation, and gating it behind the backend features
// would mean its tests never run — `rapidsnark` does not build without a native
// library present, and neither feature is in the default gate. A validation
// whose tests only execute in an environment nobody builds locally is not
// validated. The dead-code allow is scoped to exactly the configuration where
// the callers are absent, so a real regression in a backend build still fails.
#[cfg_attr(not(any(feature = "rapidsnark", feature = "icicle")), allow(dead_code))]
mod snarkjs;

pub use ark_prover::ArkMatchBatchProver;
pub use constraints::{validate_conservation, ConstraintError};
pub use convert::proof_to_onchain_bytes;
pub use groth16::{ProofWithInputs, Prover, ProverError, ProverTimings, PRODUCTION_BATCH_N};
#[cfg(feature = "icicle")]
pub use icicle_prover::IcicleMatchBatchProver;
pub use inputs::{build_batch_public_inputs, BatchPublicInputs};
pub use leaf::{
    build_batch_merkle_paths, compute_batch_leaf, compute_batch_root, BatchMerklePaths, LeafError,
    DOMAIN_BATCH_ROOT, MAX_BATCH_DEPTH, MAX_BATCH_LEAVES,
};
#[cfg(feature = "rapidsnark")]
pub use rapidsnark_prover::RapidsnarkMatchBatchProver;
pub use witness::{dummy_slot, pad_batch, MatchSlotWitness, PadError};
