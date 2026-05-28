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
//!   - [`groth16`] — the `Prover` trait + a `NotYetWiredProver`
//!     stub (PR 4g.4a). The real ark-groth16 + circom-witnesscalc
//!     impl lands in PR 4g.4b.
//!
//! Architecturally: PR 4g.4a ships the deterministic, byte-equality
//! foundation. PR 4g.4b adds the actual Groth16 wiring behind the
//! same `Prover` trait — no public-API changes at the trait
//! surface.

pub mod constraints;
pub mod groth16;
pub mod inputs;
pub mod leaf;
pub mod witness;

pub use constraints::{validate_conservation, ConstraintError};
pub use groth16::{NotYetWiredProver, ProofWithInputs, Prover, ProverError, PRODUCTION_BATCH_N};
pub use inputs::{build_batch_public_inputs, BatchPublicInputs};
pub use leaf::{
    compute_batch_leaf, compute_batch_root, merkle_inclusion_path, InclusionPath, LeafError,
    DOMAIN_BATCH_ROOT, DOMAIN_LEAF_INNER, DOMAIN_LEAF_TOP,
};
pub use witness::{dummy_slot, pad_batch, MatchSlotWitness, PadError};
