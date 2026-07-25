//! In-TEE settle scheduler.
//!
//! Consumes `RunBatchOutput`s from the matcher driver (PR 4c) and
//! orchestrates the five-tx settle pipeline documented in
//! `docs/tee-architecture.md` §6 + `CRYPTOGRAPHY.md` §9:
//!
//! ```text
//!   Tx A  lock_note × 2              (PR 4g.3)
//!   Tx B  verify_match_batch         (PR 4g.5 — Groth16 from 4g.4)
//!   Tx C  per-batch ALT create+ext   (PR 4g.5 — uses alt.rs)
//!   Tx D  tee_forced_settle_batched  (PR 4g.5 — uses payload.rs)
//!   Tx E  close_batch_validity_marker (PR 4g.6 — rent reclaim)
//! ```
//!
//! PR 4g.1 (current commit) lands the orchestration skeleton only.
//! The scheduler receives matcher outputs and queues per-match
//! jobs in an in-memory table; subsequent sub-PRs wire each
//! pipeline stage. Jobs stay in `Queued` until 4g.3 wires Tx A.
//!
//! Status surface: `GET /settlement/status/{batch_id}` returns
//! every job for a batch with its current stage + on-chain tx
//! signatures collected so far. Authenticated under the bearer
//! middleware (same scope as `/orders`).

pub mod job;
pub mod scheduler;

// Vault program constants + PDA derivation. Hand-mirrored from
// `programs/vault/src/state.rs` because we don't pull in
// anchor-lang here.
pub mod vault;

// Tx-construction modules — one per pipeline stage. PR 4g.3 lands
// `lock_note` (Tx A); 4g.5a `verify_match_batch` (Tx B); 4g.5b the
// payload; 4g.5c the per-batch ALT (Tx C) + settle_batched (Tx D)
// builders. 4g.6 wires the close marker (Tx E) + the stage workers.
pub mod alt;
pub mod alt_pool;
pub mod assemble;
pub mod close_marker;
pub mod ed25519;
pub mod fill_recovery;
pub mod lock_note;
pub mod lock_sweep;
pub mod marker_sweep;
pub mod metrics;
pub mod payload;
pub mod pipeline;
pub mod priority;
pub mod settle_batched;
pub mod sign;
pub mod submit;
pub mod submit_lock;
pub mod verify_match_batch;
pub mod worker;

#[cfg(test)]
pub(crate) mod test_support;

pub use alt::{
    alt_account, build_deactivate_alt_ix, build_extend_alt_ix, build_per_batch_alt_ixs,
    PerBatchAltIxs,
};
pub use alt_pool::{AltPlan, AltPool, MAX_ALT_ENTRIES};
pub use assemble::{
    assemble_batch, assemble_match, AssembleError, BatchAssemblyParams, MatchAssemblyInputs,
};
pub use close_marker::{build_close_marker_ix, CLOSE_MARKER_DISCRIMINATOR};
pub use ed25519::{build_ed25519_verify_ix, ED25519_PROGRAM_ID};
pub use job::{BatchId, MatchIdx, SettleJob, SettleJobId, SettleJobStage, SettlementOutcome};
pub use lock_note::{build_lock_note_ix, Groth16ProofBytes, LockNoteArgs};
pub use lock_sweep::{
    build_release_lock_ix, spawn_lock_sweeper, LOCK_SWEEP_INTERVAL, LOCK_SWEEP_MAX_PER_TX,
};
pub use marker_sweep::{spawn_marker_sweeper, MARKER_SWEEP_INTERVAL, MARKER_SWEEP_MAX_PER_TX};
pub use metrics::{
    emit_batch_record, BatchMetricsCompletion, SettlementBatchRecord, SettlementMetricsSnapshot,
    SettlementMetricsState, SettlementOutcomeCounts, SettlementStageTimings,
    SETTLEMENT_METRICS_SCHEMA_VERSION,
};
pub use payload::{MatchResultPayload, CANONICAL_DOMAIN};
pub use pipeline::{build_settle_v0_tx, build_settle_v0_tx_b64};
pub use scheduler::{SettleDriver, SettleDriverConfig, SettleScheduler, SettleSchedulerState};
pub use settle_batched::{
    build_settle_batched_ix, per_batch_alt_addresses, INSTRUCTIONS_SYSVAR_ID,
    SETTLE_BATCHED_DISCRIMINATOR,
};
pub use sign::sign_payload;
pub use submit::{
    confirm_signatures, send_and_confirm_many_with_rebroadcast, submit_ixs,
    submit_ixs_with_blockhash, ConfirmedTransaction, TransactionConfirmationOutcome,
};
pub use submit_lock::{confirm_lock_pair, submit_lock_note_pair, LockPairOutcome, LockSideInputs};
pub use verify_match_batch::{
    build_verify_match_batch_ix, VerifyMatchBatchArgs, VERIFY_MATCH_BATCH_DISCRIMINATOR,
};
pub use worker::{
    run_batch_settle, run_batch_settle_streaming, BatchSettleInputs, BatchSettlementReport,
    MatchSettleInputs, MatchSettlementResult, SettleWorkerCtx, WorkerError,
};
