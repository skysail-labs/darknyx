//! Per-match settle job — identity + state machine + status snapshot.
//!
//! One [`SettleJob`] per match in a `RunBatchOutput`. The scheduler
//! enqueues jobs in `Queued` and (in PRs 4g.3–4g.6) drives them
//! through the pipeline stages. Status is exposed read-only via
//! `GET /settlement/status/{batch_id}`.
//!
//! `MatchPair` is snapshotted at enqueue time so each downstream
//! stage has everything it needs to construct the on-chain ix
//! without re-looking-up the matcher's state.

use std::time::{SystemTime, UNIX_EPOCH};

use darkpool_matcher::match_result::MatchPair;
use serde::Serialize;

/// Monotonic per-process counter assigned to each batch the
/// scheduler receives. NOT the on-chain `batch_slot` — that lives
/// inside the `MatchPair` and is the canonical reference. This is
/// purely a TEE-local handle so operators can refer to "this
/// batch" via a stable URL.
pub type BatchId = u64;

/// Position of a match within its batch. The matcher produces at
/// most `MatchBatch::N = 16` matches per output; `u8` covers it
/// with headroom.
pub type MatchIdx = u8;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct SettleJobId {
    pub batch_id: BatchId,
    pub match_idx: MatchIdx,
}

/// The states a job moves through. Order matters — successor
/// stages can only be reached from their listed predecessor. The
/// scheduler is the only authority that mutates this; observers
/// (status endpoint, future WS push) read clones.
///
/// `Failed` carries a human-readable reason. The scheduler does
/// not currently retry; operators consume the reason via
/// `/settlement/status/{batch_id}` and decide what to do.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SettleJobStage {
    /// Enqueued; no stage worker has picked it up yet.
    Queued,
    /// Tx A (lock_note × 2) in flight. PR 4g.3.
    LockingNotes,
    /// Groth16 proof generation in progress. PR 4g.4.
    Proving,
    /// Tx B (verify_match_batch) in flight. PR 4g.5.
    Verifying,
    /// Tx C (per-batch ALT) + Tx D (tee_forced_settle_batched) in
    /// flight. PR 4g.5.
    Settling,
    /// Tx E (close_batch_validity_marker) in flight. PR 4g.6.
    Closing,
    /// All five txs confirmed.
    Done,
    /// Terminal error. The stage that failed is implied by the
    /// signatures filled in so far (`lock_buyer_sig=Some` +
    /// everything after `None` = failed at Verifying, etc.).
    Failed { reason: String },
}

impl SettleJobStage {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::LockingNotes => "locking_notes",
            Self::Proving => "proving",
            Self::Verifying => "verifying",
            Self::Settling => "settling",
            Self::Closing => "closing",
            Self::Done => "done",
            Self::Failed { .. } => "failed",
        }
    }
}

/// One settle job. Snapshot-shaped — every read clones the whole
/// struct so the scheduler's lock isn't held across HTTP request
/// boundaries.
#[derive(Clone, Debug)]
pub struct SettleJob {
    pub id: SettleJobId,
    pub stage: SettleJobStage,
    pub created_at: SystemTime,
    pub last_transition_at: SystemTime,
    /// The match this job is settling. Includes the buyer/seller
    /// notes, change-note commitments, fee amounts — everything
    /// the on-chain ix builders need.
    pub match_pair: MatchPair,
    /// Base58 signature of `lock_note` for the buyer's input note.
    /// Filled by 4g.3.
    pub lock_buyer_sig: Option<String>,
    /// Symmetric — seller's input note lock. Filled by 4g.3.
    pub lock_seller_sig: Option<String>,
    /// `verify_match_batch` tx signature. Filled by 4g.5.
    pub verify_sig: Option<String>,
    /// `tee_forced_settle_batched` tx signature. Filled by 4g.5.
    pub settle_sig: Option<String>,
    /// `close_batch_validity_marker` tx signature. Filled by 4g.6.
    pub close_sig: Option<String>,
}

impl SettleJob {
    pub fn new(id: SettleJobId, match_pair: MatchPair) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            stage: SettleJobStage::Queued,
            created_at: now,
            last_transition_at: now,
            match_pair,
            lock_buyer_sig: None,
            lock_seller_sig: None,
            verify_sig: None,
            settle_sig: None,
            close_sig: None,
        }
    }

    /// Set the stage + stamp `last_transition_at`. Callers (the
    /// stage workers in 4g.3+) must hold the scheduler's write
    /// lock when invoking.
    pub fn transition(&mut self, next: SettleJobStage) {
        self.stage = next;
        self.last_transition_at = SystemTime::now();
    }

    /// Convenience: mark the job failed with a reason. Equivalent
    /// to `transition(SettleJobStage::Failed { reason })`.
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.transition(SettleJobStage::Failed {
            reason: reason.into(),
        });
    }
}

// ─── Wire-shape view (used by the HTTP status endpoint) ─────────────────────

/// Returned by `GET /settlement/status/{batch_id}` per job.
/// Distinct from [`SettleJob`] because the wire shape excludes
/// `MatchPair` (~600 bytes per match, too much for a status poll
/// response) and converts `SystemTime` to unix-ms.
#[derive(Debug, Clone, Serialize)]
pub struct JobStatus {
    pub batch_id: BatchId,
    pub match_idx: MatchIdx,
    pub stage: &'static str,
    /// Present only when stage = "failed".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_reason: Option<String>,
    pub created_at_ms: u64,
    pub last_transition_at_ms: u64,
    /// Confirmed on-chain tx signatures, populated as stages
    /// complete. All five are `null` until the corresponding
    /// stage lands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_buyer_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_seller_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_sig: Option<String>,
}

impl From<&SettleJob> for JobStatus {
    fn from(job: &SettleJob) -> Self {
        let failed_reason = match &job.stage {
            SettleJobStage::Failed { reason } => Some(reason.clone()),
            _ => None,
        };
        Self {
            batch_id: job.id.batch_id,
            match_idx: job.id.match_idx,
            stage: job.stage.label(),
            failed_reason,
            created_at_ms: to_unix_ms(job.created_at),
            last_transition_at_ms: to_unix_ms(job.last_transition_at),
            lock_buyer_sig: job.lock_buyer_sig.clone(),
            lock_seller_sig: job.lock_seller_sig.clone(),
            verify_sig: job.verify_sig.clone(),
            settle_sig: job.settle_sig.clone(),
            close_sig: job.close_sig.clone(),
        }
    }
}

fn to_unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_match() -> MatchPair {
        MatchPair {
            note_buyer: [0x11; 32],
            note_seller: [0x22; 32],
            note_e_commitment: [0x33; 32],
            note_f_commitment: [0x44; 32],
            owner_buyer: [0x55; 32],
            owner_seller: [0x66; 32],
            user_commitment_buyer: [0x77; 32],
            user_commitment_seller: [0x88; 32],
            buyer_note_value: 100,
            seller_note_value: 10,
            base_amt: 10,
            quote_amt: 100,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            price: 10,
            pyth_at_match: 10,
            batch_slot: 1,
            match_id: 0,
            status: darkpool_matcher::match_result::MatchStatus::Filled,
        }
    }

    #[test]
    fn new_job_starts_in_queued() {
        let job = SettleJob::new(
            SettleJobId {
                batch_id: 1,
                match_idx: 0,
            },
            dummy_match(),
        );
        assert_eq!(job.stage, SettleJobStage::Queued);
        assert!(!job.stage.is_terminal());
    }

    #[test]
    fn transition_updates_last_transition_at() {
        let mut job = SettleJob::new(
            SettleJobId {
                batch_id: 1,
                match_idx: 0,
            },
            dummy_match(),
        );
        let before = job.last_transition_at;
        // Sleep is unreliable in tests; instead just check the
        // transition fn updates the stamp via a monotonic check.
        std::thread::sleep(std::time::Duration::from_millis(2));
        job.transition(SettleJobStage::LockingNotes);
        assert!(job.last_transition_at > before);
        assert_eq!(job.stage, SettleJobStage::LockingNotes);
    }

    #[test]
    fn fail_marks_terminal_with_reason() {
        let mut job = SettleJob::new(
            SettleJobId {
                batch_id: 1,
                match_idx: 0,
            },
            dummy_match(),
        );
        job.fail("blockhash not found");
        assert!(job.stage.is_terminal());
        match &job.stage {
            SettleJobStage::Failed { reason } => assert_eq!(reason, "blockhash not found"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn stage_labels_are_stable() {
        // The status endpoint serialises `stage` as a string; the
        // wire contract relies on these labels. Pin them so a
        // refactor doesn't silently break SDK consumers.
        assert_eq!(SettleJobStage::Queued.label(), "queued");
        assert_eq!(SettleJobStage::LockingNotes.label(), "locking_notes");
        assert_eq!(SettleJobStage::Proving.label(), "proving");
        assert_eq!(SettleJobStage::Verifying.label(), "verifying");
        assert_eq!(SettleJobStage::Settling.label(), "settling");
        assert_eq!(SettleJobStage::Closing.label(), "closing");
        assert_eq!(SettleJobStage::Done.label(), "done");
        assert_eq!(
            SettleJobStage::Failed {
                reason: "x".to_string()
            }
            .label(),
            "failed"
        );
    }

    #[test]
    fn job_status_view_omits_none_sigs() {
        let job = SettleJob::new(
            SettleJobId {
                batch_id: 7,
                match_idx: 3,
            },
            dummy_match(),
        );
        let view = JobStatus::from(&job);
        let json = serde_json::to_string(&view).unwrap();
        // None fields should be omitted, not serialised as `null`,
        // so a brand-new queued job's status is compact on the wire.
        assert!(
            !json.contains("\"lock_buyer_sig\""),
            "expected lock_buyer_sig to be omitted; got: {json}"
        );
        assert!(json.contains("\"stage\":\"queued\""));
        assert!(json.contains("\"batch_id\":7"));
        assert!(json.contains("\"match_idx\":3"));
    }
}
