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
// `lock_note`. PRs 4g.5 / 4g.6 will populate the rest of the
// shells below (currently doc-only placeholders).
pub mod alt;
pub mod lock_note;
pub mod payload;
pub mod pipeline;
pub mod sign;
pub mod submit;
pub mod submit_lock;
pub mod verify_match_batch;

pub use job::{BatchId, MatchIdx, SettleJob, SettleJobId, SettleJobStage};
pub use lock_note::{build_lock_note_ix, Groth16ProofBytes, LockNoteArgs};
pub use scheduler::{SettleScheduler, SettleSchedulerState};
pub use submit::{confirm_signatures, submit_ixs, submit_ixs_with_blockhash};
pub use submit_lock::{confirm_lock_pair, submit_lock_note_pair, LockPairOutcome, LockSideInputs};
pub use verify_match_batch::{
    build_verify_match_batch_ix, VerifyMatchBatchArgs, VERIFY_MATCH_BATCH_DISCRIMINATOR,
};
