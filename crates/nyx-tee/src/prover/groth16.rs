//! Groth16 prover interface + a "not-yet-wired" stub impl.
//!
//! The real ark-groth16 wiring lands in PR 4g.4b. 4g.4a establishes
//! the interface so call-sites (the future `Proving` stage worker
//! in 4g.6) can be written against a stable signature today.
//!
//! Image path for the production proving key:
//! `/circuits/build/match_batch_n16/circuit_final.zkey`. The path
//! is baked into the Dockerfile COPY step so a swap requires a
//! compose-hash bump (and therefore a multisig rotation).
//!
//! Format note: `prove` returns `Groth16ProofBytes` matching the
//! `programs/vault/src/zk/verifier.rs::Groth16Proof` Borsh layout —
//! 64 + 128 + 64 = 256 bytes. Identical bytes as the SDK's
//! `groth16-format.ts` produces from a snarkjs proof JSON. PR
//! 4g.4b includes the ark-groth16 → on-chain-format converter.

use thiserror::Error;

use super::constraints::ConstraintError;
use super::inputs::{build_batch_public_inputs, BatchPublicInputs};
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
    /// PR 4g.4a stub — the ark-groth16 prover isn't wired yet.
    /// 4g.4b replaces this branch with a real proof.
    #[error("Groth16 proving not yet wired (PR 4g.4b)")]
    NotYetWired,
}

/// Generic prover interface — same signature for the stub today
/// and the ark-groth16 impl in 4g.4b. Call-sites (the future
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

/// 4g.4a stub. Runs the deterministic pre-flight (constraints +
/// leaves + root + public-input vector) so the inputs side of the
/// pipeline is fully tested today — then returns
/// [`ProverError::NotYetWired`] in place of the actual proof.
pub struct NotYetWiredProver {
    n: usize,
}

impl Default for NotYetWiredProver {
    fn default() -> Self {
        Self {
            n: PRODUCTION_BATCH_N,
        }
    }
}

impl NotYetWiredProver {
    pub fn new(n: usize) -> Self {
        Self { n }
    }
}

impl Prover for NotYetWiredProver {
    fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
        if slots.len() != self.n {
            return Err(ProverError::BatchSizeMismatch {
                expected: self.n,
                got: slots.len(),
            });
        }
        // The deterministic pre-flight DOES run — this proves the
        // 4g.4a foundation works end-to-end and surfaces bad
        // batches as named-constraint violations before 4g.4b ever
        // tries to prove them.
        super::constraints::validate_conservation(slots)?;
        let _public: BatchPublicInputs = build_batch_public_inputs(slots)?;
        // Stub: the actual Groth16 proof would be produced here in
        // 4g.4b. Return NotYetWired so call-sites in 4g.6 can
        // distinguish "inputs valid, prover unimplemented" from
        // "inputs invalid".
        Err(ProverError::NotYetWired)
    }

    fn n(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::{dummy_slot, pad_batch, MatchSlotWitness};

    fn valid_real_slot() -> MatchSlotWitness {
        MatchSlotWitness {
            base_amount: 10,
            clearing_price: 20,
            quote_amount: 200,
            a_amount: 200,
            b_amount: 10,
            ..MatchSlotWitness::default()
        }
    }

    #[test]
    fn stub_rejects_wrong_batch_size() {
        let prover = NotYetWiredProver::new(4);
        let err = prover.prove(&[dummy_slot()]).unwrap_err();
        assert!(matches!(
            err,
            ProverError::BatchSizeMismatch {
                expected: 4,
                got: 1
            }
        ));
    }

    #[test]
    fn stub_runs_preflight_then_returns_not_yet_wired() {
        let prover = NotYetWiredProver::new(2);
        let slots = pad_batch(&[valid_real_slot()], 2).unwrap();
        let err = prover.prove(&slots).unwrap_err();
        assert!(matches!(err, ProverError::NotYetWired));
    }

    #[test]
    fn stub_surfaces_constraint_violation_before_proving() {
        // A broken slot must fail with a Constraint variant — NOT
        // NotYetWired. That's the contract: 4g.4a's validation runs
        // FIRST so bad batches never even reach the (future)
        // prover. PR 4g.4b inherits this and saves the snarkjs/
        // ark-groth16 R1CS work.
        let prover = NotYetWiredProver::new(2);
        let mut bad = valid_real_slot();
        bad.quote_amount = 999; // violates quote = base * price
        let slots = pad_batch(&[bad], 2).unwrap();
        let err = prover.prove(&slots).unwrap_err();
        assert!(matches!(err, ProverError::Constraint(_)));
    }

    #[test]
    fn default_uses_production_n() {
        let prover = NotYetWiredProver::default();
        assert_eq!(prover.n(), PRODUCTION_BATCH_N);
        assert_eq!(prover.n(), 16);
    }
}
