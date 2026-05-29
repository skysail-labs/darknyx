//! The scheduler task — consumes `RunBatchOutput`s from the
//! matcher's mpsc and queues per-match jobs.
//!
//! PR 4g.1 scope: ingestion + status table only. Subsequent
//! sub-PRs (4g.3 / 4g.5 / 4g.6) plug stage workers into the same
//! state by reading the queue + writing back stage transitions
//! under the existing RwLock.
//!
//! Concurrency model:
//!
//! - One scheduler task owns the matcher's `mpsc::Receiver` and
//!   bumps a `next_batch_id` counter.
//! - All other readers/writers go through
//!   `Arc<RwLock<SettleSchedulerState>>` — same pattern as the
//!   matcher's `MatcherState`. Read-mostly: status queries take
//!   the read lock; the scheduler + future stage workers take
//!   brief write locks.
//!
//! Retention: jobs accumulate forever in 4g.1. PR 4g.6 adds an
//! eviction policy (keep last N batches, or last T minutes).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use darkpool_matcher::match_result::RunBatchOutput;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use super::job::{BatchId, JobStatus, MatchIdx, SettleJob, SettleJobId};

/// Shared state exposed to status handlers + future stage workers.
/// `Default` because it's trivially constructible.
#[derive(Default)]
pub struct SettleSchedulerState {
    /// All jobs the scheduler has ever seen, keyed by id.
    /// 4g.6 evicts terminal jobs older than N seconds.
    jobs: HashMap<SettleJobId, SettleJob>,
    /// Per-batch index — ordered set of `match_idx` values for
    /// each batch_id. `BTreeSet` so iteration order is stable.
    by_batch: HashMap<BatchId, BTreeSet<MatchIdx>>,
    /// Next batch_id to assign. Bumped under the write lock so
    /// the scheduler doesn't need a separate atomic.
    next_batch_id: BatchId,
}

impl SettleSchedulerState {
    pub fn batch_count(&self) -> usize {
        self.by_batch.len()
    }

    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    /// Snapshot of every job in the requested batch, in match-idx
    /// order. Returns `None` if the batch is unknown.
    pub fn status_for_batch(&self, batch_id: BatchId) -> Option<Vec<JobStatus>> {
        let indices = self.by_batch.get(&batch_id)?;
        let out: Vec<JobStatus> = indices
            .iter()
            .filter_map(|idx| {
                self.jobs
                    .get(&SettleJobId {
                        batch_id,
                        match_idx: *idx,
                    })
                    .map(JobStatus::from)
            })
            .collect();
        Some(out)
    }

    /// Snapshot of a single job. Used by stage workers in 4g.3+
    /// to fetch the latest state without holding the lock across
    /// long-running operations (Solana RPC, Groth16 proving).
    pub fn get_job(&self, id: &SettleJobId) -> Option<SettleJob> {
        self.jobs.get(id).cloned()
    }

    // ─── Mutating helpers — used by the scheduler + future stage
    // workers under the write lock. ─────────────────────────────────

    /// Reserve + return the next batch id under the same write
    /// lock as the subsequent insert so the scheduler doesn't
    /// see torn state.
    pub fn next_batch_id(&mut self) -> BatchId {
        let id = self.next_batch_id;
        self.next_batch_id = self.next_batch_id.wrapping_add(1);
        id
    }

    /// Insert a freshly-enqueued job. The scheduler's ingest path
    /// drives this once per match per batch.
    pub fn insert(&mut self, job: SettleJob) {
        let batch_id = job.id.batch_id;
        let match_idx = job.id.match_idx;
        self.jobs.insert(job.id, job);
        self.by_batch.entry(batch_id).or_default().insert(match_idx);
    }

    /// Mutate a job in place — used by stage workers to advance
    /// the stage / record tx sigs. Returns false if the job has
    /// been evicted (4g.6) and the worker should drop its handle.
    pub fn update<F>(&mut self, id: &SettleJobId, f: F) -> bool
    where
        F: FnOnce(&mut SettleJob),
    {
        match self.jobs.get_mut(id) {
            Some(job) => {
                f(job);
                true
            }
            None => false,
        }
    }
}

/// The scheduler task itself. Spawned by `main.rs`; owns the
/// receiver end of the matcher's matches channel.
pub struct SettleScheduler {
    rx: mpsc::Receiver<RunBatchOutput>,
    state: Arc<RwLock<SettleSchedulerState>>,
}

impl SettleScheduler {
    /// Construct + spawn. Returns the join handle (for shutdown)
    /// and the shared state (for status queries + future stage
    /// workers). The caller must hold onto the state — dropping
    /// it doesn't stop the scheduler, but it makes the status
    /// endpoint unable to read.
    pub fn spawn(
        rx: mpsc::Receiver<RunBatchOutput>,
    ) -> (JoinHandle<()>, Arc<RwLock<SettleSchedulerState>>) {
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        let scheduler = Self {
            rx,
            state: state.clone(),
        };
        let handle = tokio::spawn(scheduler.run());
        (handle, state)
    }

    async fn run(mut self) {
        tracing::warn!(
            "settle scheduler: jobs accumulate in Queued. The full settle \
             worker (lock→prove→verify→ALT→settle→close) lands in \
             `settle::worker::run_batch_settle` as of PR 4g.6, but the \
             MatchPair→BatchSettleInputs assembler that feeds it (note_c/d \
             + nullifier derivation + the VALID_INPUT proof relay) is PR \
             4g.7 — until then nothing drives jobs past Queued"
        );

        while let Some(output) = self.rx.recv().await {
            self.enqueue_batch(output).await;
        }

        tracing::info!("settle scheduler: matches channel closed; exiting");
    }

    async fn enqueue_batch(&self, output: RunBatchOutput) {
        let count = output.matches.len();
        if count == 0 {
            // The matcher only sends outputs with non-empty
            // matches (per `interval.rs::tick`), so this branch
            // shouldn't fire in practice. Guard anyway so
            // observers can't be confused by empty-batch entries.
            return;
        }
        if count > u8::MAX as usize {
            // The on-chain VALID_MATCH_BATCH circuit instantiation
            // tops out at N=16; the matcher should never emit
            // more. Defensive.
            tracing::error!(
                count,
                "settle scheduler: RunBatchOutput has more matches than u8 — truncating"
            );
        }

        let mut state = self.state.write().await;
        let batch_id = state.next_batch_id();
        let take = count.min(u8::MAX as usize);
        for (idx, match_pair) in output.matches.into_iter().take(take).enumerate() {
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            state.insert(SettleJob::new(id, match_pair));
        }
        tracing::info!(
            batch_id,
            match_count = take,
            total_batches = state.batch_count(),
            "settle scheduler: enqueued batch"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkpool_matcher::match_result::{MatchPair, MatchStatus};

    fn dummy_match(slot: u64) -> MatchPair {
        MatchPair {
            note_buyer: [0x11; 32],
            note_seller: [0x22; 32],
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
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
            batch_slot: slot,
            match_id: 0,
            status: MatchStatus::Filled,
        }
    }

    fn dummy_output(n: usize) -> RunBatchOutput {
        // Build via the matcher's `empty` ctor to inherit any
        // future field additions, then assign the matches.
        let mut out = RunBatchOutput::empty(1, 10, 0);
        out.matches = (0..n).map(|i| dummy_match(i as u64 + 1)).collect();
        out
    }

    #[tokio::test]
    async fn enqueue_lands_one_job_per_match() {
        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let (_handle, state) = SettleScheduler::spawn(rx);

        tx.send(dummy_output(3)).await.unwrap();

        // Wait briefly for the scheduler to drain the channel.
        // 50 ms is overkill — the scheduler runs the moment
        // `recv()` returns.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let st = state.read().await;
        assert_eq!(st.batch_count(), 1);
        assert_eq!(st.job_count(), 3);

        let status = st
            .status_for_batch(0)
            .expect("batch_id 0 should exist after one send");
        assert_eq!(status.len(), 3);
        for (i, s) in status.iter().enumerate() {
            assert_eq!(s.batch_id, 0);
            assert_eq!(s.match_idx as usize, i);
            assert_eq!(s.stage, "queued");
            // No tx sigs collected yet; the wire shape omits None.
            assert!(s.lock_buyer_sig.is_none());
        }
    }

    #[tokio::test]
    async fn two_batches_get_distinct_batch_ids() {
        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let (_handle, state) = SettleScheduler::spawn(rx);

        tx.send(dummy_output(2)).await.unwrap();
        tx.send(dummy_output(1)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let st = state.read().await;
        assert_eq!(st.batch_count(), 2);
        assert_eq!(st.job_count(), 3);
        assert!(st.status_for_batch(0).is_some());
        assert!(st.status_for_batch(1).is_some());
        assert!(st.status_for_batch(2).is_none());
    }

    #[tokio::test]
    async fn empty_batch_is_dropped() {
        // The matcher's `tick` skips sending when no matches
        // produced; defensive guard inside the scheduler should
        // be a no-op even if it somehow does. No jobs land.
        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let (_handle, state) = SettleScheduler::spawn(rx);

        tx.send(dummy_output(0)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let st = state.read().await;
        assert_eq!(st.batch_count(), 0);
        assert_eq!(st.job_count(), 0);
    }

    #[tokio::test]
    async fn status_for_unknown_batch_returns_none() {
        let (_tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let (_handle, state) = SettleScheduler::spawn(rx);

        let st = state.read().await;
        assert!(st.status_for_batch(999).is_none());
    }

    #[tokio::test]
    async fn update_advances_a_jobs_stage() {
        // Foreshadows the pattern PR 4g.3+ uses: pick a job,
        // mutate its stage via `state.update(id, |j| ...)`.
        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let (_handle, state) = SettleScheduler::spawn(rx);

        tx.send(dummy_output(1)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let id = SettleJobId {
            batch_id: 0,
            match_idx: 0,
        };

        {
            let mut st = state.write().await;
            let updated = st.update(&id, |j| {
                j.transition(super::super::job::SettleJobStage::LockingNotes);
                j.lock_buyer_sig = Some("sig-A".to_string());
            });
            assert!(updated, "job should still be in the table");
        }

        let st = state.read().await;
        let job = st.get_job(&id).expect("job present");
        assert_eq!(job.stage, super::super::job::SettleJobStage::LockingNotes);
        assert_eq!(job.lock_buyer_sig.as_deref(), Some("sig-A"));
    }
}
