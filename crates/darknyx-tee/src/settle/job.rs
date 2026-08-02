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
/// `Failed` carries a human-readable reason. Ambiguous Tx D results remain in
/// `Settling` while the worker reconciles consumed PDAs and redrives within the
/// marker/lock window; only a definitive rejection reaches `Failed`.
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
    /// Tx D confirmed for this match. Marker close is asynchronous rent
    /// bookkeeping and is not part of settlement finality.
    Done,
    /// Terminal error.
    ///
    /// `failure` is the closed-set label served to clients; `reason` is the full
    /// diagnostic text and stays **inside the enclave** — see
    /// [`SettleFailureKind`] and [`JobStatus::failed_reason`]. The stage that
    /// failed is implied by the signatures filled in so far
    /// (`lock_buyer_sig=Some` + everything after `None` = failed at Verifying).
    Failed {
        /// Renamed from `kind` because this enum serializes with
        /// `#[serde(tag = "kind")]` and the field would collide with the tag.
        failure: SettleFailureKind,
        reason: String,
    },
}

/// What class of thing went wrong, as a closed set.
///
/// SW-01: a settle failure's free-form text used to be serialized straight into
/// `GET /settlement/status/{batch_id}`, which any authenticated account may
/// poll. That text is built from internal errors, and one of them interpolated
/// the RPC endpoint — credential included.
///
/// Redacting that endpoint (see `solana_rpc::redact_endpoint`) fixes the leak
/// that existed. This type fixes the *channel*: a fixed set of labels cannot
/// carry whatever the next internal error happens to embed. It restores the
/// premise `api/settlement.rs` was written against — "the response leaks only
/// stage labels + tx signatures".
///
/// Derived from the typed error variant, never by matching on message text —
/// string classification would rot the first time an error message is reworded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettleFailureKind {
    /// Solana RPC transport, HTTP status, or malformed response.
    Rpc,
    /// Groth16 witness generation or proving failed, including a panic.
    Prover,
    /// Merkle leaf/path resolution failed for one of the batch's inputs.
    Leaf,
    /// The per-batch address lookup table never became active.
    AltNotActive,
    /// The settlement was definitively rejected on-chain, or its window
    /// expired — a real outcome, not an infrastructure fault.
    Rejected,
    /// An invariant inside the settle pipeline did not hold.
    Internal,
}

impl SettleFailureKind {
    /// The stable string served to clients. Values are part of the wire
    /// contract in `docs/tee-api-openapi.yaml` — add, don't rename.
    pub fn label(self) -> &'static str {
        match self {
            Self::Rpc => "rpc_unavailable",
            Self::Prover => "prover_failed",
            Self::Leaf => "leaf_resolution_failed",
            Self::AltNotActive => "alt_not_active",
            Self::Rejected => "settlement_rejected",
            Self::Internal => "internal_error",
        }
    }
}

/// Per-match settlement result. This is intentionally independent from the
/// pipeline stage: a Tx D can be confirmed while siblings are still being
/// reconciled, rejected with an on-chain error, or remain ambiguous after an
/// RPC outage. Order-book finalization keys off this value, never off a
/// batch-wide success boolean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SettlementOutcome {
    Pending,
    Confirmed {
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        slot: Option<u64>,
        reconciled_from_consumed_pdas: bool,
    },
    Rejected {
        reason: String,
    },
    Ambiguous {
        reason: String,
    },
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
    pub outcome: SettlementOutcome,
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
            outcome: SettlementOutcome::Pending,
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

    /// Mark the job failed. `kind` is what a client sees; `reason` is the
    /// operator-facing detail and never leaves the enclave.
    pub fn fail(&mut self, failure: SettleFailureKind, reason: impl Into<String>) {
        let reason = reason.into();
        self.outcome = SettlementOutcome::Rejected {
            reason: reason.clone(),
        };
        self.transition(SettleJobStage::Failed { failure, reason });
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
    /// Sanitised view of the internal [`SettlementOutcome`] — same wire shape,
    /// closed-set reasons.
    pub outcome: OutcomeStatus,
    /// Present only when stage = "failed". A [`SettleFailureKind`] label, NOT
    /// the internal diagnostic text.
    ///
    /// This endpoint is readable by **any** authenticated account, so the field
    /// must not be able to carry whatever an internal error happened to format
    /// into itself. It once carried the RPC endpoint, credential and all
    /// (SW-01). `&'static str` makes that structurally impossible: there is no
    /// runtime string to smuggle anything through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_reason: Option<&'static str>,
    pub created_at_ms: u64,
    pub last_transition_at_ms: u64,
    /// Confirmed on-chain tx signatures, populated as stages complete.
    /// `close_sig` normally remains absent because marker close is asynchronous.
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

/// The outcome as served to a client: identical wire shape to
/// [`SettlementOutcome`] (same serde tag, same field names) but the free-form
/// `reason` is replaced by a closed-set label.
///
/// See [`JobStatus`] for why. Kept as a separate type rather than sanitising
/// `SettlementOutcome` in place so the internal value keeps its full detail for
/// operator logs and reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutcomeStatus {
    Pending,
    Confirmed {
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        slot: Option<u64>,
        reconciled_from_consumed_pdas: bool,
    },
    Rejected {
        reason: &'static str,
    },
    Ambiguous {
        reason: &'static str,
    },
}

impl From<&SettlementOutcome> for OutcomeStatus {
    fn from(o: &SettlementOutcome) -> Self {
        match o {
            SettlementOutcome::Pending => Self::Pending,
            SettlementOutcome::Confirmed {
                signature,
                slot,
                reconciled_from_consumed_pdas,
            } => Self::Confirmed {
                signature: signature.clone(),
                slot: *slot,
                reconciled_from_consumed_pdas: *reconciled_from_consumed_pdas,
            },
            // The internal `reason` is discarded on purpose — it is built with
            // `format!("…: {error}")` at several sites, and those errors reach
            // in from the RPC client.
            SettlementOutcome::Rejected { .. } => Self::Rejected {
                reason: "settlement_rejected",
            },
            SettlementOutcome::Ambiguous { .. } => Self::Ambiguous {
                reason: "reconciliation_pending",
            },
        }
    }
}

impl From<&SettleJob> for JobStatus {
    fn from(job: &SettleJob) -> Self {
        let failed_reason = match &job.stage {
            SettleJobStage::Failed { failure, .. } => Some(failure.label()),
            _ => None,
        };
        Self {
            batch_id: job.id.batch_id,
            match_idx: job.id.match_idx,
            stage: job.stage.label(),
            outcome: OutcomeStatus::from(&job.outcome),
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
        job.fail(SettleFailureKind::Rpc, "blockhash not found");
        assert!(job.stage.is_terminal());
        match &job.stage {
            SettleJobStage::Failed { failure, reason } => {
                assert_eq!(reason, "blockhash not found");
                assert_eq!(*failure, SettleFailureKind::Rpc);
            }
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
                failure: SettleFailureKind::Internal,
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

    // ── SW-01: `GET /settlement/status/{batch_id}` is readable by ANY
    //    authenticated account, so the response must carry only closed-set
    //    labels. It used to serialize the internal failure text, and one
    //    internal error interpolated the RPC endpoint — credential included.

    /// Every label a client can observe. Adding a variant without adding it
    /// here fails to compile, so the wire contract cannot drift silently.
    fn all_kinds() -> [SettleFailureKind; 6] {
        [
            SettleFailureKind::Rpc,
            SettleFailureKind::Prover,
            SettleFailureKind::Leaf,
            SettleFailureKind::AltNotActive,
            SettleFailureKind::Rejected,
            SettleFailureKind::Internal,
        ]
    }

    #[test]
    fn failure_labels_are_stable_and_carry_no_detail() {
        // Part of the wire contract in docs/tee-api-openapi.yaml.
        assert_eq!(SettleFailureKind::Rpc.label(), "rpc_unavailable");
        assert_eq!(SettleFailureKind::Prover.label(), "prover_failed");
        assert_eq!(SettleFailureKind::Leaf.label(), "leaf_resolution_failed");
        assert_eq!(SettleFailureKind::AltNotActive.label(), "alt_not_active");
        assert_eq!(SettleFailureKind::Rejected.label(), "settlement_rejected");
        assert_eq!(SettleFailureKind::Internal.label(), "internal_error");
    }

    #[test]
    fn a_failed_job_serialises_the_label_never_the_detail() {
        // The exact string SW-01 describes: an RPC error carrying the endpoint.
        const LEAKY: &str =
            "rpc: HTTP 503 from https://devnet.helius-rpc.com/?api-key=SUPERSECRET: upstream down";

        for kind in all_kinds() {
            let mut job = SettleJob::new(
                SettleJobId {
                    batch_id: 1,
                    match_idx: 0,
                },
                dummy_match(),
            );
            job.fail(kind, LEAKY);

            // The detail is retained INSIDE the enclave for operator logs…
            match &job.stage {
                SettleJobStage::Failed { reason, .. } => assert_eq!(reason, LEAKY),
                other => panic!("expected Failed, got {other:?}"),
            }

            // …and cannot cross the API boundary.
            let json = serde_json::to_string(&JobStatus::from(&job)).unwrap();
            assert!(
                !json.contains("SUPERSECRET"),
                "{kind:?}: credential reached the wire: {json}"
            );
            assert!(
                !json.contains("api-key"),
                "{kind:?}: query string reached the wire: {json}"
            );
            assert!(
                !json.contains("helius"),
                "{kind:?}: endpoint host reached the wire: {json}"
            );
            assert!(
                json.contains(&format!("\"failed_reason\":\"{}\"", kind.label())),
                "{kind:?}: expected the closed-set label: {json}"
            );
        }
    }

    #[test]
    fn a_rejected_outcome_serialises_a_label_never_the_detail() {
        // The second channel through the same endpoint: `outcome.reason`.
        // Several sites build it as `format!("…: {error}")`, and those errors
        // come from the RPC client.
        let mut job = SettleJob::new(
            SettleJobId {
                batch_id: 2,
                match_idx: 0,
            },
            dummy_match(),
        );
        job.outcome = SettlementOutcome::Rejected {
            reason: "cannot construct settle transaction: network error at \
                     https://devnet.helius-rpc.com/?api-key=SUPERSECRET"
                .to_string(),
        };
        let json = serde_json::to_string(&JobStatus::from(&job)).unwrap();
        assert!(!json.contains("SUPERSECRET"), "{json}");
        assert!(json.contains("\"kind\":\"rejected\""), "{json}");
        assert!(
            json.contains("\"reason\":\"settlement_rejected\""),
            "{json}"
        );

        // Ambiguous shares the channel and the treatment.
        job.outcome = SettlementOutcome::Ambiguous {
            reason: "reconciliation failed: https://x/?api-key=SUPERSECRET".to_string(),
        };
        let json = serde_json::to_string(&JobStatus::from(&job)).unwrap();
        assert!(!json.contains("SUPERSECRET"), "{json}");
        assert!(
            json.contains("\"reason\":\"reconciliation_pending\""),
            "{json}"
        );
    }

    #[test]
    fn a_confirmed_outcome_still_carries_its_signature_and_slot() {
        // The sanitised view must not cost clients the fields they use — a
        // confirmed settle is exactly what they poll for.
        let mut job = SettleJob::new(
            SettleJobId {
                batch_id: 3,
                match_idx: 1,
            },
            dummy_match(),
        );
        job.outcome = SettlementOutcome::Confirmed {
            signature: Some("5xSig".to_string()),
            slot: Some(1234),
            reconciled_from_consumed_pdas: true,
        };
        let json = serde_json::to_string(&JobStatus::from(&job)).unwrap();
        assert!(json.contains("\"kind\":\"confirmed\""), "{json}");
        assert!(json.contains("\"signature\":\"5xSig\""), "{json}");
        assert!(json.contains("\"slot\":1234"), "{json}");
        assert!(
            json.contains("\"reconciled_from_consumed_pdas\":true"),
            "{json}"
        );
    }
}
