//! In-TEE VALID_MATCH_BATCH prover surface.
//!
//! Mirror of `packages/sdk/tests/helpers/match-batch-prover.ts`,
//! split across:
//!
//!   - [`witness`] — `MatchSlotWitness` type + `dummy_slot` +
//!     `pad_batch` (the all-zero-padding strategy for batches
//!     smaller than N).
//!   - [`leaf`] — Poseidon leaf + Merkle root + inclusion path,
//!     matching the circuit's `MatchSlot()` and `MerkleRoot(N)`
//!     templates byte-for-byte.
//!   - [`constraints`] — conservation validators that surface
//!     three named errors before the circuit ever sees a bad
//!     witness.
//!   - [`inputs`] — the snarkjs-format public-input vector
//!     `groth16-solana` consumes on-chain.
//!   - [`groth16`] — the `Prover` trait + error type + output
//!     struct (the stable abstraction the settle-stage worker
//!     depends on).
//!   - [`convert`] — ark-groth16 `Proof<Bn254>` → on-chain
//!     `groth16-solana` 256-byte layout (PR 4g.4b).
//!   - [`ark_prover`] — the real ark-circom-backed `Prover` impl
//!     (PR 4g.4b): witness gen + zkey-backed Groth16 prove.
//!
//! Architecturally: PR 4g.4a shipped the deterministic, byte-
//! equality foundation (witness / leaf / constraints / inputs).
//! PR 4g.4b wired the actual Groth16 proving behind the same
//! `Prover` trait — no public-API changes at the trait surface,
//! so a future rapidsnark swap stays internal.

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

// Snarkjs-format proof helpers shared by the rapidsnark + icicle backends.
#[cfg(any(feature = "rapidsnark", feature = "icicle"))]
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
    DOMAIN_BATCH_ROOT, DOMAIN_LEAF_V2, MAX_BATCH_DEPTH, MAX_BATCH_LEAVES,
};
#[cfg(feature = "rapidsnark")]
pub use rapidsnark_prover::RapidsnarkMatchBatchProver;
pub use witness::{dummy_slot, pad_batch, MatchSlotWitness, PadError};
