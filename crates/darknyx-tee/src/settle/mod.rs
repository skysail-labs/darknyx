//! Settlement pipeline — turns matcher output into confirmed on-chain settlements.
//!
//! The scheduler consumes `RunBatchOutput`s from the matcher driver and drives one
//! job per match through a five-transaction sequence, documented in
//! `docs/tee-architecture.md` §6 and `CRYPTOGRAPHY.md` §9:
//!
//! ```text
//!   Tx A  lock_note × 2                 pin both inputs between match and settle
//!   Tx B  verify_match_batch            Groth16 VALID_MATCH_BATCH, writes the marker
//!   Tx C  per-batch ALT create/extend   payload-derived PDAs, all matches
//!   Tx D  tee_forced_settle_batched     the settlement itself (v0 tx, 2 ALTs)
//!   Tx E  close_batch_validity_marker   rent reclaim, at or after expiry
//! ```
//!
//! Tx D is the finality point. Tx E is asynchronous rent bookkeeping and a job is
//! `Done` without it.
//!
//! Tx C does not always create a fresh table: `alt_pool` keeps a rolling set and
//! reuses or extends one where it can, because ALT deactivation has a ~512-slot
//! cooldown. Its address set is the **union across every match in the batch**,
//! deduplicated — so it is not a fixed seven entries. An exact-fill match
//! contributes fewer (the `[0;32]` change-note locks collapse to one PDA); a
//! multi-match batch contributes more.
//!
//! Module map:
//!
//!   - `scheduler.rs` / `worker.rs` — the stage workers and the loop that advances
//!     jobs; `job.rs` is the per-match state machine.
//!   - `lock_note.rs`, `verify_match_batch.rs`, `settle_batched.rs`,
//!     `close_marker.rs` — one instruction builder per transaction above.
//!   - `assemble.rs` / `payload.rs` — build the settlement payload and its
//!     canonical hash; `sign.rs` / `ed25519.rs` produce the TEE signature over it.
//!   - `pipeline.rs` — assembles Tx D as a v0 transaction over two lookup tables.
//!   - `alt.rs` / `alt_pool.rs` — per-batch lookup tables and the rolling pool that
//!     amortises their ~512-slot deactivation cooldown.
//!   - `recover.rs` / `drain.rs` — crash recovery and planned shutdown.
//!   - `lock_sweep.rs` / `marker_sweep.rs` — reclaim expired locks and markers.
//!   - `vault.rs` — PDA derivations shared by every builder above.
//!
//! Two constraints govern changes here. Tx D sits at 1173 of the 1232-byte
//! transaction limit, so any new account or payload field must be checked against
//! `CRYPTOGRAPHY.md` §9. And settlement is idempotent by construction: the
//! consume-once PDAs make a replayed transaction fail rather than double-spend, so
//! recovery re-runs a job rather than tracking whether it already ran.
//!
//! Status is exposed read-only via `GET /settlement/status/{batch_id}`, under the
//! same bearer scope as `/orders`.

pub mod job;
pub mod scheduler;

// Vault program constants + PDA derivation. Hand-mirrored from
// `programs/vault/src/state.rs` because we don't pull in
// anchor-lang here.
pub mod vault;

// Instruction builders — one per pipeline transaction.
pub mod alt;
pub mod alt_pool;
pub mod assemble;
pub mod close_marker;
pub mod drain;
pub mod ed25519;
pub mod fill_recovery;
pub mod lock_note;
pub mod lock_sweep;
pub mod marker_sweep;
pub mod metrics;
pub mod payload;
pub mod pipeline;
pub mod priority;
pub mod recover;
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
