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
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

/// Conservative production default. Cross-batch pipelining is opt-in through
/// `DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY` and remains bounded to eight.
pub(crate) const DEFAULT_SETTLE_CONCURRENCY: usize = 1;

use super::assemble::{assemble_batch, BatchAssemblyParams};
use super::job::{BatchId, JobStatus, MatchIdx, SettleJob, SettleJobId, SettlementOutcome};
use super::metrics::{SettlementMetricsSnapshot, SettlementMetricsState};
use super::vault::market_config_pda;
use super::worker::{run_batch_settle_streaming, MatchSettlementResult, SettleWorkerCtx};
use crate::matcher::MatcherState;

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
    /// Bounded, privacy-preserving benchmark state. Unlike `jobs`, this has a
    /// strict recent-record cap and never retains order ids, commitments,
    /// amounts, prices or proof witnesses.
    metrics: SettlementMetricsState,
}

impl SettleSchedulerState {
    /// Ensure the next assigned `batch_id` is at least `min`.
    ///
    /// `next_batch_id` starts at 0 in every process, so the journal key
    /// `(batch_id, match_idx)` is boot-relative. Recovery preserves entries it
    /// could not resolve, and without this the first new batch would be batch 0
    /// and would overwrite exactly the records an operator was asked to inspect.
    /// Seeding above the highest recovered id makes the collision impossible
    /// rather than unlikely.
    pub fn seed_next_batch_id(&mut self, min: BatchId) {
        if self.next_batch_id < min {
            self.next_batch_id = min;
        }
    }

    pub fn batch_count(&self) -> usize {
        self.by_batch.len()
    }

    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    pub fn metrics_snapshot(
        &self,
        after_seq: Option<u64>,
        limit: usize,
    ) -> SettlementMetricsSnapshot {
        self.metrics.snapshot(after_seq, limit)
    }

    pub fn mark_batch_started(&mut self, batch_id: BatchId, padded_slots: usize) {
        self.metrics.mark_started(batch_id, padded_slots);
    }

    pub fn metrics_mut(&mut self) -> &mut SettlementMetricsState {
        &mut self.metrics
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

/// Static per-market context the settle driver needs that a single
/// `RunBatchOutput` doesn't carry.
#[derive(Clone)]
pub struct SettleDriverConfig {
    /// Same random boot id advertised by `/info` and bound into order
    /// signatures; also domains the 16-byte settlement identifiers.
    pub boot_session_id: [u8; 32],
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    /// Owner commitment the protocol's fee notes pay to.
    pub protocol_owner_commitment: [u8; 32],
    /// Protocol fee rate (bps) — the circuit exact-fee public input
    /// (`VaultConfig.fee_rate_bps`, reconciled at boot).
    pub fee_rate_bps: u64,
    /// Governed fixed-point price denominator.
    pub price_scale: u64,
    /// Circuit instantiation N the witness set is padded to (16).
    pub circuit_n: usize,
    /// Whole settlement batches allowed in flight.
    pub settle_batch_concurrency: usize,
}

/// The live-settle driver. Present only when the TEE is fully
/// configured (signer + RPC + prover); `None` leaves the scheduler in
/// enqueue-only mode (unit tests / explicit local test mode).
pub struct SettleDriver {
    /// The worker context (RPC, TEE keypair, signer, prover, the same
    /// `SettleSchedulerState` the scheduler holds, confirm timeout).
    pub ctx: SettleWorkerCtx,
    /// The matcher state — read for assembly and finalized independently as
    /// each match confirms or definitively rejects.
    pub matcher_state: Arc<RwLock<MatcherState>>,
    pub cfg: SettleDriverConfig,
}

/// The scheduler task itself. Spawned by `main.rs`; owns the
/// receiver end of the matcher's matches channel.
pub struct SettleScheduler {
    rx: mpsc::Receiver<RunBatchOutput>,
    state: Arc<RwLock<SettleSchedulerState>>,
    /// `Some` drives each batch through the full on-chain pipeline;
    /// `None` is enqueue-only. `Arc` so each batch's pipeline runs in its own
    /// spawned task (bounded concurrency from [`SettleDriverConfig`]).
    settle: Option<Arc<SettleDriver>>,
    /// Optional venue-wide limit shared by every per-market scheduler.
    /// Without this, N market receivers would each admit C proof pipelines.
    shared_semaphore: Option<Arc<Semaphore>>,
}

impl SettleScheduler {
    /// Enqueue-only spawn (no settle driver). Returns the join handle
    /// and the shared state for status queries. Used by the degraded
    /// boot path and unit tests.
    pub fn spawn(
        rx: mpsc::Receiver<RunBatchOutput>,
    ) -> (JoinHandle<()>, Arc<RwLock<SettleSchedulerState>>) {
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        let handle = Self::spawn_inner(rx, state.clone(), None, None);
        (handle, state)
    }

    /// Spawn with a caller-created `state` (so it can be shared into
    /// the driver's `SettleWorkerCtx` AND held for the status
    /// endpoint) and an optional settle driver. `None` is
    /// enqueue-only — the same as [`Self::spawn`] but without
    /// creating the state internally.
    pub fn spawn_with_settle(
        rx: mpsc::Receiver<RunBatchOutput>,
        state: Arc<RwLock<SettleSchedulerState>>,
        driver: Option<SettleDriver>,
    ) -> JoinHandle<()> {
        Self::spawn_inner(rx, state, driver, None)
    }

    /// Multi-market variant: independent market receivers/drivers share one
    /// venue-wide batch semaphore, so `SETTLE_BATCH_CONCURRENCY=C` means C
    /// proofs across the whole CVM rather than C per market.
    pub fn spawn_with_shared_limit(
        rx: mpsc::Receiver<RunBatchOutput>,
        state: Arc<RwLock<SettleSchedulerState>>,
        driver: Option<SettleDriver>,
        semaphore: Arc<Semaphore>,
    ) -> JoinHandle<()> {
        Self::spawn_inner(rx, state, driver, Some(semaphore))
    }

    fn spawn_inner(
        rx: mpsc::Receiver<RunBatchOutput>,
        state: Arc<RwLock<SettleSchedulerState>>,
        settle: Option<SettleDriver>,
        shared_semaphore: Option<Arc<Semaphore>>,
    ) -> JoinHandle<()> {
        let scheduler = Self {
            rx,
            state,
            settle: settle.map(Arc::new),
            shared_semaphore,
        };
        tokio::spawn(scheduler.run())
    }

    async fn run(mut self) {
        let settle_concurrency = self
            .settle
            .as_ref()
            .map(|driver| driver.cfg.settle_batch_concurrency.clamp(1, 8))
            .unwrap_or(DEFAULT_SETTLE_CONCURRENCY);
        if self.settle.is_some() {
            tracing::info!(
                settle_concurrency,
                "settle scheduler: live driver attached — each batch is \
                 assembled + driven through lock→prove→verify→ALT→settle→close"
            );
        } else {
            tracing::warn!(
                "settle scheduler: enqueue-only (no settle driver — degraded \
                 boot or test); jobs accumulate in Queued"
            );
        }

        // Bounded settle pipeline: each batch is driven in its own task, up to
        // `settle_concurrency` at once. The semaphore permit is acquired BEFORE
        // spawning, so when the pipeline is full the recv loop blocks on
        // `acquire` — back-pressuring the matcher channel rather than fanning
        // out unbounded work. The JoinSet lets us drain in-flight batches when
        // the channel closes (so a shutdown — and tests — wait for completion).
        let semaphore = self
            .shared_semaphore
            .clone()
            .unwrap_or_else(|| Arc::new(Semaphore::new(settle_concurrency)));
        let mut tasks: JoinSet<()> = JoinSet::new();

        while let Some(output) = self.rx.recv().await {
            let market_id = self
                .settle
                .as_ref()
                .map(|driver| {
                    market_config_pda(&driver.cfg.base_mint, &driver.cfg.quote_mint)
                        .0
                        .to_string()
                })
                .unwrap_or_else(|| "unconfigured".to_string());
            if let Some(batch_id) = self.enqueue_batch(&output, market_id).await {
                if let Some(driver) = self.settle.clone() {
                    // `acquire_owned` never errors here — the semaphore is never
                    // closed while the loop runs.
                    let permit = semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("settle semaphore");
                    let state = self.state.clone();
                    // Move the owned `output` into the task — it isn't used again
                    // in this iteration (enqueue_batch above only borrowed it), so
                    // there's no need to deep-clone RunBatchOutput (up to 16 matches
                    // + fees) per batch.
                    tasks.spawn(async move {
                        let _permit = permit; // released when the batch finishes
                        drive_batch(&driver, &state, batch_id, &output).await;
                    });
                }
            }
            // Reap completed tasks so the JoinSet doesn't grow unbounded.
            while tasks.try_join_next().is_some() {}
        }

        // Channel closed — drain the batches still settling before exiting.
        while tasks.join_next().await.is_some() {}
        tracing::info!("settle scheduler: matches channel closed; exiting");
    }

    /// Insert per-match jobs for a batch. Returns the assigned
    /// `batch_id`, or `None` for an empty batch.
    async fn enqueue_batch(&self, output: &RunBatchOutput, market_id: String) -> Option<BatchId> {
        let count = output.matches.len();
        if count == 0 {
            // The matcher only sends outputs with non-empty matches
            // (per `interval.rs::tick`); guard anyway.
            return None;
        }
        if count > u8::MAX as usize {
            // The on-chain VALID_MATCH_BATCH circuit instantiation
            // tops out at N=16; the matcher should never emit more.
            tracing::error!(
                count,
                "settle scheduler: RunBatchOutput has more matches than u8 — truncating"
            );
        }

        let mut state = self.state.write().await;
        let batch_id = state.next_batch_id();
        let take = count.min(u8::MAX as usize);
        state.metrics.enqueue_batch(
            batch_id,
            market_id,
            output
                .matches
                .iter()
                .take(take)
                .map(|matched| matched.match_id.to_string())
                .collect(),
        );
        for (idx, match_pair) in output.matches.iter().take(take).enumerate() {
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            state.insert(SettleJob::new(id, match_pair.clone()));
        }
        tracing::info!(
            batch_id,
            match_count = take,
            total_batches = state.batch_count(),
            "settle scheduler: enqueued batch"
        );
        Some(batch_id)
    }
}

/// Assemble and settle one batch. Each final Tx D outcome is applied to the
/// matcher as soon as it is known, so a confirmed sibling is never held behind
/// another match's reconciliation/redrive loop. A free fn (not a method) so it
/// can run in its own spawned task off `Arc<SettleDriver>` + shared state.
async fn drive_batch(
    driver: &SettleDriver,
    state: &Arc<RwLock<SettleSchedulerState>>,
    batch_id: BatchId,
    output: &RunBatchOutput,
) {
    state
        .write()
        .await
        .mark_batch_started(batch_id, driver.cfg.circuit_n);
    let params = BatchAssemblyParams {
        batch_id,
        boot_session_id: driver.cfg.boot_session_id,
        base_mint: driver.cfg.base_mint,
        quote_mint: driver.cfg.quote_mint,
        protocol_owner_commitment: driver.cfg.protocol_owner_commitment,
        fee_rate_bps: driver.cfg.fee_rate_bps,
        price_scale: driver.cfg.price_scale,
        circuit_n: driver.cfg.circuit_n,
    };

    // Assemble under a brief read lock on the opening store, then
    // release it before the (long, RPC + proving) settle.
    let assembled = {
        let st = driver.matcher_state.read().await;
        assemble_batch(output, st.openings(), params)
    };
    let inputs = match assembled {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(batch_id, error = %e, "settle: batch assembly failed");
            {
                let mut matcher = driver.matcher_state.write().await;
                matcher.reject_batch(output, &format!("settlement assembly failed: {e}"));
            }
            fail_batch(
                state,
                batch_id,
                output.matches.len(),
                driver.cfg.settle_batch_concurrency,
                driver.ctx.settle_send_concurrency,
                "assembly_error".to_string(),
                format!("assembly: {e}"),
            )
            .await;
            return;
        }
    };

    let (outcome_tx, mut outcome_rx) = mpsc::unbounded_channel::<MatchSettlementResult>();
    let finalize_outcomes = async {
        let mut counts = [0usize; 3];
        while let Some(result) = outcome_rx.recv().await {
            let mut matcher = driver.matcher_state.write().await;
            match &result.outcome {
                SettlementOutcome::Confirmed { .. } => {
                    let settle_tree_id =
                        (result.match_index % driver.ctx.tee_keypairs.len().max(1)) as u8;
                    if let Err(error) =
                        matcher.commit_confirmed_match(output, result.match_index, settle_tree_id)
                    {
                        tracing::error!(
                            batch_id,
                            match_idx = result.match_index,
                            %error,
                            "confirmed settlement could not commit matcher state"
                        );
                    } else {
                        counts[0] += 1;
                    }
                }
                SettlementOutcome::Rejected { reason } => {
                    if let Err(error) = matcher.reject_match(output, result.match_index, reason) {
                        tracing::error!(
                            batch_id,
                            match_idx = result.match_index,
                            %error,
                            "rejected settlement could not finalize matcher state"
                        );
                    }
                    counts[1] += 1;
                }
                SettlementOutcome::Ambiguous { .. } | SettlementOutcome::Pending => {
                    // Keep the matched orders and input openings reserved. They
                    // are not rebooked and no fill/update is published.
                    counts[2] += 1;
                }
            }
        }
        counts
    };
    let (report, counts) = tokio::join!(
        run_batch_settle_streaming(&driver.ctx, inputs, outcome_tx),
        finalize_outcomes
    );
    if let Err(e) = report {
        // A failure before per-match Tx D outcomes exist is terminal for every
        // still-reserved order. Already-confirmed siblings were finalized by
        // the outcome stream and are left untouched.
        tracing::error!(batch_id, error = ?e, "settle: batch settle failed");
        let mut matcher = driver.matcher_state.write().await;
        matcher.reject_batch(output, &format!("settlement pipeline failed: {e:?}"));
        return;
    }
    tracing::info!(
        batch_id,
        matches = output.matches.len(),
        confirmed = counts[0],
        rejected = counts[1],
        ambiguous = counts[2],
        "settle: batch outcomes finalized independently"
    );
}

async fn fail_batch(
    state: &Arc<RwLock<SettleSchedulerState>>,
    batch_id: BatchId,
    n: usize,
    settle_batch_concurrency: usize,
    settle_send_concurrency: usize,
    metrics_failure: String,
    job_reason: String,
) {
    let mut state = state.write().await;
    for idx in 0..n.min(u8::MAX as usize) {
        let id = SettleJobId {
            batch_id,
            match_idx: idx as u8,
        };
        state.update(&id, |j| j.fail(job_reason.clone()));
    }
    if let Some(record) = state.metrics_mut().fail_batch(
        batch_id,
        settle_batch_concurrency,
        settle_send_concurrency,
        metrics_failure,
    ) {
        super::metrics::emit_batch_record(&record);
    }
}

#[cfg(test)]
mod tests {

    /// Recovery keeps entries it could not resolve, and `batch_id` restarts at 0
    /// every process — so without seeding, the first new batch would overwrite
    /// exactly the records held back for an operator.
    #[test]
    fn seeding_prevents_a_new_batch_from_reusing_a_recovered_id() {
        let mut st = SettleSchedulerState::default();
        assert_eq!(st.next_batch_id(), 0, "a fresh process starts at 0");

        let mut st = SettleSchedulerState::default();
        st.seed_next_batch_id(5); // highest recovered batch_id was 4
        assert_eq!(st.next_batch_id(), 5, "must not reissue a retained id");
        assert_eq!(st.next_batch_id(), 6);
    }

    /// Seeding must never move the counter backwards — that would reintroduce
    /// the collision it exists to prevent.
    #[test]
    fn seeding_never_rewinds_the_counter() {
        let mut st = SettleSchedulerState::default();
        st.seed_next_batch_id(10);
        let _ = st.next_batch_id(); // 10
        st.seed_next_batch_id(3);
        assert_eq!(st.next_batch_id(), 11, "a lower seed must be ignored");
    }
    use super::*;
    use darkpool_matcher::match_result::{MatchPair, MatchStatus};
    use std::sync::atomic::AtomicU64;

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

    // ─── Live settle driver (4g.7e) ───────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn live_driver_settles_a_batch_and_evicts_openings() {
        use crate::matcher::openings::{NoteOpening, OrderOpening};
        use crate::settle::lock_note::Groth16ProofBytes;
        use crate::settle::test_support::{spawn_mock_rpc, FakeProver};
        use crate::settle::worker::SettleWorkerCtx;
        use crate::solana_rpc::SolanaRpcClient;
        use darkpool_matcher::book::{
            Order, OrderSide, OrderStatus, OrderType, OrderUpdate, OrderUpdateKind,
        };
        use ed25519_dalek::SigningKey;
        use solana_keypair::Keypair;
        use std::time::Duration;

        let base_mint = {
            let mut m = [0u8; 32];
            m[0] = 1;
            m[31] = 0xb1;
            m
        };
        let quote_mint = {
            let mut m = [0u8; 32];
            m[0] = 1;
            m[31] = 0x9e;
            m
        };
        let fr_safe = |b: u8| {
            let mut v = [b; 32];
            v[0] = 0;
            v
        };

        // A consistent exact-fill match: base=10, quote=1000.
        let buyer_open = NoteOpening {
            token_mint: quote_mint,
            amount: 1000,
            owner_commitment: fr_safe(0x44),
            inner_hash: fr_safe(0x11),
        };
        let seller_open = NoteOpening {
            token_mint: base_mint,
            amount: 10,
            owner_commitment: fr_safe(0x55),
            inner_hash: fr_safe(0x33),
        };
        let note_buyer = buyer_open.commitment().unwrap();
        let note_seller = seller_open.commitment().unwrap();

        // Matcher state seeded with both openings (as intake would).
        let matcher_state = Arc::new(RwLock::new(
            MatcherState::new().with_market(base_mint, quote_mint),
        ));
        let proof = Groth16ProofBytes {
            pi_a: [1u8; 64],
            pi_b: [2u8; 128],
            pi_c: [3u8; 64],
        };
        {
            let mut st = matcher_state.write().await;
            st.openings_mut().insert(
                note_buyer,
                OrderOpening {
                    opening: buyer_open,
                    order_id: [0x01; 16],
                    expiry_slot: 2000,
                    merkle_root: [0xDD; 32],
                    tree_id: 0,
                    valid_input_proof: proof.clone(),
                    from_relock: false,
                    viewing_pubkey: None,
                },
            );
            st.openings_mut().insert(
                note_seller,
                OrderOpening {
                    opening: seller_open,
                    order_id: [0x02; 16],
                    expiry_slot: 2000,
                    merkle_root: [0xDD; 32],
                    tree_id: 0,
                    valid_input_proof: proof,
                    from_relock: false,
                    viewing_pubkey: None,
                },
            );
            for order in [
                Order {
                    trading_key: [0x77; 32],
                    side: OrderSide::Bid,
                    order_type: OrderType::Limit,
                    status: OrderStatus::Pending,
                    arrival_slot: 1,
                    expiry_slot: 2000,
                    price_limit: 100,
                    amount: 10,
                    total_quantity: 10,
                    filled_quantity: 0,
                    min_fill_qty: 0,
                    note_amount: 1000,
                    collateral_note: note_buyer,
                    user_commitment: [0x99; 32],
                    owner_commitment: fr_safe(0x44),
                    order_id: [0x01; 16],
                    order_inclusion_commitment: [0x31; 32],
                },
                Order {
                    trading_key: [0x88; 32],
                    side: OrderSide::Ask,
                    order_type: OrderType::Limit,
                    status: OrderStatus::Pending,
                    arrival_slot: 2,
                    expiry_slot: 2000,
                    price_limit: 100,
                    amount: 10,
                    total_quantity: 10,
                    filled_quantity: 0,
                    min_fill_qty: 0,
                    note_amount: 10,
                    collateral_note: note_seller,
                    user_commitment: [0xAA; 32],
                    owner_commitment: fr_safe(0x55),
                    order_id: [0x02; 16],
                    order_inclusion_commitment: [0x32; 32],
                },
            ] {
                st.book_mut().submit(order).unwrap();
            }
            assert_eq!(st.openings().len(), 2);
        }

        let m = MatchPair {
            note_buyer,
            note_seller,
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            owner_buyer: [0x77; 32],
            owner_seller: [0x88; 32],
            user_commitment_buyer: [0x99; 32],
            user_commitment_seller: [0xAA; 32],
            buyer_note_value: 1000,
            seller_note_value: 10,
            base_amt: 10,
            quote_amt: 1000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            price: 100,
            pyth_at_match: 100,
            batch_slot: 7,
            match_id: 42,
            status: MatchStatus::Filled,
        };

        // Worker ctx (mock RPC + fake prover) + driver.
        let url = spawn_mock_rpc().await;
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        let ctx = SettleWorkerCtx {
            rpc: SolanaRpcClient::new(url).unwrap(),
            tee_keypairs: vec![Arc::new(Keypair::new_from_array([0x42; 32]))],
            signing_keys: vec![Arc::new(SigningKey::from_bytes(&[0x42; 32]))],
            prover: Arc::new(FakeProver { n: 2 }),
            // Mirror production's stacked ALTs — the v8 +128 recovery bundle
            // overflows the 1232 cap with the per-batch ALT alone.
            static_alt: Some(crate::settle::alt::alt_account(
                solana_address::Address::new_from_array([0x44; 32]),
                crate::settle::settle_batched::static_alt_addresses(4),
            )),
            alt_pool: Arc::new(tokio::sync::Mutex::new(
                crate::settle::alt_pool::AltPool::new(),
            )),
            settle_state: state.clone(),
            confirm_timeout: Duration::from_secs(5),
            current_priority_fee: Arc::new(AtomicU64::new(0)),
            settle_send_concurrency: 8,
            settle_batch_concurrency: 1,
            // Throwaway sender (rx dropped) — enqueue is a best-effort no-op here.
            marker_sweep_tx: tokio::sync::mpsc::unbounded_channel().0,
            lock_sweep_tx: tokio::sync::mpsc::unbounded_channel().0,
            journal: Arc::new(tokio::sync::Mutex::new(
                crate::persistence::journal::SettleJournal::in_memory(),
            )),
        };
        let driver = SettleDriver {
            ctx,
            matcher_state: matcher_state.clone(),
            cfg: SettleDriverConfig {
                boot_session_id: [0x5A; 32],
                base_mint,
                quote_mint,
                protocol_owner_commitment: fr_safe(0x07),
                fee_rate_bps: 0,
                price_scale: 1,
                circuit_n: 2,
                settle_batch_concurrency: 1,
            },
        };

        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let _handle = SettleScheduler::spawn_with_settle(rx, state.clone(), Some(driver));

        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m];
        output.order_updates = vec![
            OrderUpdate {
                trading_key: [0x77; 32],
                order_id: [0x01; 16],
                kind: OrderUpdateKind::FullyFilled {
                    filled_quantity: 10,
                },
            },
            OrderUpdate {
                trading_key: [0x88; 32],
                order_id: [0x02; 16],
                kind: OrderUpdateKind::FullyFilled {
                    filled_quantity: 10,
                },
            },
        ];
        matcher_state.write().await.reserve_batch(&output).unwrap();
        tx.send(output).await.unwrap();

        // Poll until the single job reaches Done (the mock settle is
        // fast but async across several tx round-trips).
        let id = SettleJobId {
            batch_id: 0,
            match_idx: 0,
        };
        let mut done = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let st = state.read().await;
            if let Some(j) = st.get_job(&id) {
                match &j.stage {
                    super::super::job::SettleJobStage::Done => {
                        assert!(matches!(j.outcome, SettlementOutcome::Confirmed { .. }));
                        done = true;
                        break;
                    }
                    super::super::job::SettleJobStage::Failed { reason } => {
                        panic!("settle job failed: {reason}");
                    }
                    _ => {}
                }
            }
        }
        assert!(done, "job did not reach Done within the deadline");

        // The settled batch's openings are evicted.
        let st = matcher_state.read().await;
        assert!(
            st.openings().is_empty(),
            "openings must be evicted after a batch settles"
        );
    }
}
