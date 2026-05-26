//! In-TEE Groth16 prover for `VALID_MATCH_BATCH` N=16.
//! See `docs/tee-architecture.md` §9 + D4.
//!
//! Phase 1: stub. Phase-1 sign-off depends on a benchmark of this
//! against bare-metal — if TDX overhead > 3× we fall back to a
//! TEE-signed-public-input + external-prover design.

pub mod groth16;
pub mod witness;
