//! Parity test gating the run_batch lift.
//!
//! This test is the cargo-test contract that lets us lift
//! `programs/matching_engine/src/instructions/run_batch.rs`
//! into this crate without changing matching behaviour.
//!
//! Until the lift lands the test is `#[ignore]`d — it would fail
//! against the stub `run_batch`. After the lift, remove
//! `#[ignore]` and the test becomes a CI gate.
//!
//! How the lift will work:
//!
//! 1. Move the algorithm body from
//!    `programs/matching_engine/src/instructions/run_batch.rs`
//!    into `crates/darkpool-matcher/src/run_batch.rs` (or split
//!    across `book.rs` / `match_result.rs` / a new `algorithm.rs`).
//! 2. Strip Anchor / Solana types from the body. Replace with the
//!    pure types in this crate.
//! 3. Have the original ix in `matching_engine` call into
//!    `darkpool_matcher::run_batch` (single source of truth).
//! 4. Un-ignore this test. It should pass byte-for-byte.

#[test]
#[ignore = "Phase-1: gates the run_batch lift from matching_engine into this crate. \
            Remove #[ignore] once the lift lands and verify against the existing \
            run_batch litesvm test cases."]
fn parity_against_litesvm_run_batch() {
    // TODO(phase1): for each scenario in
    //   programs/matching_engine/tests/run_batch.rs,
    // construct the same OrderBook + OracleSnapshot + MatchConfig
    // and assert run_batch(...) produces an identical
    // RunBatchOutput.
    panic!(
        "parity_against_litesvm_run_batch is gated — un-ignore after \
         the lift of run_batch from matching_engine into darkpool-matcher"
    );
}
