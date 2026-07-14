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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use darkpool_matcher::match_result::RunBatchOutput;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

/// Max batches the settle pipeline drives CONCURRENTLY.
///
/// **Must be 1.** Two batch-level invariants require serial batches, both of
/// which `>1` violated (a live multi-scenario loadgen run, 2026-06-17, hit
/// both): (a) the **rolling per-batch ALT** is shared + extended across batches
/// (`worker.rs::alt_pool`, "settle batches run serially today") — concurrent
/// batches extend the SAME ALT, so each batch's v0 settle tx is compiled
/// against a shifting ALT → wrong account indices → the ed25519/settle ix
/// fails; (b) a **partial-fill continuation** batch consumes a note whose
/// NoteLock is created by the PRIOR batch's settle (the re-lock) — it must not
/// settle until that prior batch lands, else `lock_note` is missing
/// (`AccountOwnedByWrongProgram 3007`). The matcher emits the whole
/// continuation chain in one tick (pages 0,1,2…), so dependent batches are
/// already queued; serial FIFO processing settles them in dependency order.
///
/// The throughput win is the WITHIN-batch concurrency (locks + settles fire in
/// parallel across a batch's matches + K shards — `settle_send_concurrency`,
/// the tree-sharding co-inclusion, unchanged). Cross-batch pipelining is the
/// lost optimization.
///
/// Re-enabling it is only worth it AFTER GPU proving: on CPU, ark/rapidsnark
/// already multithread a single prove across all cores, so concurrent batch
/// proves just contend — no gain (and it's what broke the shared ALT). Once a
/// GPU backend (rapidsnark+ICICLE) drops each prove to ~tens of ms, the
/// bottleneck shifts to the on-chain settle round-trips, and overlapping batch
/// N+1's cheap prove+lock with batch N's settle-IO pays off. At that point set
/// this `> 1` AND fix the two blockers: a per-batch DISTINCT ALT (not the shared
/// rolling pool) + explicit continuation-dependency ordering (a child batch
/// waits for its parent's relock). Acquiring a permit before each batch
/// back-pressures the matcher channel.
const SETTLE_CONCURRENCY: usize = 1;

use super::assemble::{assemble_batch, BatchAssemblyParams};
use super::job::{BatchId, JobStatus, MatchIdx, SettleJob, SettleJobId};
use super::worker::{run_batch_settle, SettleWorkerCtx};
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

/// Static per-market context the settle driver needs that a single
/// `RunBatchOutput` doesn't carry.
pub struct SettleDriverConfig {
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    /// Owner commitment the protocol's fee notes pay to.
    pub protocol_owner_commitment: [u8; 32],
    /// Protocol fee rate (bps) — the circuit fee-floor public input
    /// (`VaultConfig.fee_rate_bps`, reconciled at boot).
    pub fee_rate_bps: u64,
    /// Circuit instantiation N the witness set is padded to (16).
    pub circuit_n: usize,
}

/// The live-settle driver. Present only when the TEE is fully
/// configured (signer + RPC + prover); `None` leaves the scheduler in
/// enqueue-only mode (unit tests / explicit local test mode).
pub struct SettleDriver {
    /// The worker context (RPC, TEE keypair, signer, prover, the same
    /// `SettleSchedulerState` the scheduler holds, confirm timeout).
    pub ctx: SettleWorkerCtx,
    /// The matcher state — read for the opening store at assembly,
    /// written to evict openings after a batch settles.
    pub matcher_state: Arc<RwLock<MatcherState>>,
    /// Slot source for the fee-note derivation + marker expiry.
    pub current_slot: Arc<AtomicU64>,
    pub cfg: SettleDriverConfig,
}

/// The scheduler task itself. Spawned by `main.rs`; owns the
/// receiver end of the matcher's matches channel.
pub struct SettleScheduler {
    rx: mpsc::Receiver<RunBatchOutput>,
    state: Arc<RwLock<SettleSchedulerState>>,
    /// `Some` drives each batch through the full on-chain pipeline;
    /// `None` is enqueue-only. `Arc` so each batch's pipeline runs in its own
    /// spawned task (bounded concurrency — see [`SETTLE_CONCURRENCY`]).
    settle: Option<Arc<SettleDriver>>,
}

impl SettleScheduler {
    /// Enqueue-only spawn (no settle driver). Returns the join handle
    /// and the shared state for status queries. Used by the degraded
    /// boot path and unit tests.
    pub fn spawn(
        rx: mpsc::Receiver<RunBatchOutput>,
    ) -> (JoinHandle<()>, Arc<RwLock<SettleSchedulerState>>) {
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        let handle = Self::spawn_inner(rx, state.clone(), None);
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
        Self::spawn_inner(rx, state, driver)
    }

    fn spawn_inner(
        rx: mpsc::Receiver<RunBatchOutput>,
        state: Arc<RwLock<SettleSchedulerState>>,
        settle: Option<SettleDriver>,
    ) -> JoinHandle<()> {
        let scheduler = Self {
            rx,
            state,
            settle: settle.map(Arc::new),
        };
        tokio::spawn(scheduler.run())
    }

    async fn run(mut self) {
        if self.settle.is_some() {
            tracing::info!(
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
        // SETTLE_CONCURRENCY at once. The semaphore permit is acquired BEFORE
        // spawning, so when the pipeline is full the recv loop blocks on
        // `acquire` — back-pressuring the matcher channel rather than fanning
        // out unbounded work. The JoinSet lets us drain in-flight batches when
        // the channel closes (so a shutdown — and tests — wait for completion).
        let semaphore = Arc::new(Semaphore::new(SETTLE_CONCURRENCY));
        let mut tasks: JoinSet<()> = JoinSet::new();

        while let Some(output) = self.rx.recv().await {
            if let Some(batch_id) = self.enqueue_batch(&output).await {
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
    async fn enqueue_batch(&self, output: &RunBatchOutput) -> Option<BatchId> {
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

/// Assemble + settle one batch, then evict its openings. Failures mark the
/// batch's jobs `Failed` (assembly errors here; on-chain errors inside
/// `run_batch_settle`). A free fn (not a method) so it can run in its own
/// spawned task off `Arc<SettleDriver>` + the shared scheduler state.
async fn drive_batch(
    driver: &SettleDriver,
    state: &Arc<RwLock<SettleSchedulerState>>,
    batch_id: BatchId,
    output: &RunBatchOutput,
) {
    let now_slot = driver.current_slot.load(Ordering::Relaxed);
    let params = BatchAssemblyParams {
        batch_id,
        base_mint: driver.cfg.base_mint,
        quote_mint: driver.cfg.quote_mint,
        protocol_owner_commitment: driver.cfg.protocol_owner_commitment,
        fee_slot: now_slot,
        fee_rate_bps: driver.cfg.fee_rate_bps,
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
            fail_batch(
                state,
                batch_id,
                output.matches.len(),
                format!("assembly: {e}"),
            )
            .await;
            return;
        }
    };

    if let Err(e) = run_batch_settle(&driver.ctx, inputs).await {
        // run_batch_settle already marked the jobs Failed. Debug-format
        // so the RpcError `data` (preflight sim logs — which program +
        // log line reverted) is captured, not just code+message.
        tracing::error!(batch_id, error = ?e, "settle: batch settle failed");
        return;
    }

    // Success — drop the now-spent openings (after close confirmed).
    {
        let mut st = driver.matcher_state.write().await;
        for m in &output.matches {
            st.openings_mut().remove(&m.note_buyer);
            st.openings_mut().remove(&m.note_seller);
        }
    }
    tracing::info!(
        batch_id,
        matches = output.matches.len(),
        "settle: batch settled; openings evicted"
    );
}

async fn fail_batch(
    state: &Arc<RwLock<SettleSchedulerState>>,
    batch_id: BatchId,
    n: usize,
    reason: String,
) {
    let mut state = state.write().await;
    for idx in 0..n.min(u8::MAX as usize) {
        let id = SettleJobId {
            batch_id,
            match_idx: idx as u8,
        };
        state.update(&id, |j| j.fail(reason.clone()));
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

    // ─── Live settle driver (4g.7e) ───────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn live_driver_settles_a_batch_and_evicts_openings() {
        use crate::matcher::openings::{NoteOpening, OrderOpening};
        use crate::settle::lock_note::Groth16ProofBytes;
        use crate::settle::test_support::{spawn_mock_rpc, FakeProver};
        use crate::settle::worker::SettleWorkerCtx;
        use crate::solana_rpc::SolanaRpcClient;
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
            nullifier: [0xAA; 32],
        };
        let seller_open = NoteOpening {
            token_mint: base_mint,
            amount: 10,
            owner_commitment: fr_safe(0x55),
            inner_hash: fr_safe(0x33),
            nullifier: [0xBB; 32],
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
            // Throwaway sender (rx dropped) — enqueue is a best-effort no-op here.
            marker_sweep_tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        let driver = SettleDriver {
            ctx,
            matcher_state: matcher_state.clone(),
            current_slot: Arc::new(AtomicU64::new(1000)),
            cfg: SettleDriverConfig {
                base_mint,
                quote_mint,
                protocol_owner_commitment: fr_safe(0x07),
                fee_rate_bps: 0,
                circuit_n: 2,
            },
        };

        let (tx, rx) = mpsc::channel::<RunBatchOutput>(4);
        let _handle = SettleScheduler::spawn_with_settle(rx, state.clone(), Some(driver));

        let mut output = RunBatchOutput::empty(7, 100, 0);
        output.matches = vec![m];
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
