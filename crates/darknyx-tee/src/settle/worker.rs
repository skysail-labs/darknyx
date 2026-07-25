//! Batch settle worker — drives one matched batch through the full
//! on-chain pipeline, updating each match's `SettleJob` stage as it
//! goes.
//!
//! The `SettleScheduler` (4g.1) enqueues per-match jobs in `Queued`;
//! this worker is what actually moves them to `Done`. One call
//! settles ONE batch (the VALID_MATCH_BATCH proof + the
//! `BatchValidityMarker` are per-batch, 1:N):
//!
//! ```text
//!   1. LockingNotes  per match: lock_note × 2 (Tx A)
//!   2. Proving       once: prover.prove(witnesses) in spawn_blocking
//!   3. Verifying     once: verify_match_batch (Tx B) + per-batch ALT (Tx C)
//!   4. Settling      per match: tee_forced_settle_batched v0 tx (Tx D)
//!   5. Closing       once: close_batch_validity_marker (Tx E)
//! ```
//!
//! Stage workers in 4g.7 will assemble [`BatchSettleInputs`] from a
//! `RunBatchOutput` (the note_c/d + nullifier derivation) and wire
//! this worker to the live scheduler; here it takes pre-assembled
//! inputs so the orchestration is testable against the mock RPC
//! with a fake `Prover` (no circuit artifacts, no minutes-long
//! N=16 proof).
//!
//! `prove()` is synchronous + CPU-heavy AND needs a Tokio reactor
//! in scope (wasmer); it runs inside `tokio::task::spawn_blocking`
//! so it doesn't stall a runtime worker.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use tokio::sync::{mpsc, RwLock};

use super::alt::{
    build_deactivate_alt_ix, build_extend_alt_ix_chunks, build_per_batch_alt_ixs,
    parse_alt_addresses,
};
use super::alt_pool::{AltPlan, AltPool};
use super::ed25519::build_ed25519_verify_ix;
use super::job::{SettleJobId, SettleJobStage, SettlementOutcome};
use super::payload::MatchResultPayload;
use super::pipeline::{budget_ixs, build_settle_v0_tx_b64, VERIFY_COMPUTE_UNIT_LIMIT};
use super::scheduler::SettleSchedulerState;
use super::settle_batched::{batch_alt_addresses, build_settle_batched_ix};
use super::sign::sign_payload;
use super::submit::{
    build_tx_b64, confirm_signatures, send_and_confirm_many_with_rebroadcast,
    send_and_confirm_with_rebroadcast, submit_ixs, submit_ixs_with_blockhash,
    TransactionConfirmationOutcome,
};
use super::submit_lock::{build_lock_tx_b64, LockSideInputs};
use super::verify_match_batch::{build_verify_match_batch_ix, VerifyMatchBatchArgs};
use crate::prover::{build_batch_public_inputs, MatchSlotWitness, Prover};
use crate::settle::vault::{consumed_note_pda, vault_program_id};
use crate::solana_rpc::{RpcError, SolanaRpcClient};

/// Per-match inputs the worker needs to settle one match.
pub struct MatchSettleInputs {
    /// The settle payload (assembled from the match — 4g.7).
    pub payload: MatchResultPayload,
    /// VALID_INPUT lock inputs for the buyer + seller notes (Tx A).
    pub buyer_lock: LockSideInputs,
    pub seller_lock: LockSideInputs,
    /// This match's position in the batch (0..N-1), selecting the
    /// Merkle inclusion path.
    pub match_index: u8,
}

/// Everything needed to settle one batch.
pub struct BatchSettleInputs {
    /// Scheduler batch id — keys the per-match `SettleJob`s.
    pub batch_id: u64,
    /// One entry per real match.
    pub matches: Vec<MatchSettleInputs>,
    /// The padded N-slot witness set fed to the prover. Its leaves
    /// + root drive the per-match Merkle inclusion paths.
    pub witnesses: Vec<MatchSlotWitness>,
}

/// Final per-match result returned to the scheduler. The scheduler applies the
/// corresponding order-book mutation independently for every match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchSettlementResult {
    pub match_index: usize,
    pub outcome: SettlementOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSettlementReport {
    pub outcomes: Vec<MatchSettlementResult>,
}

/// Shared context the worker holds across a batch.
pub struct SettleWorkerCtx {
    pub rpc: SolanaRpcClient,
    /// The K per-shard TEE keypairs (one fee-payer + `tee_authority` per
    /// Merkle-tree shard). `[0]` is the PRIMARY: it pays the per-batch txs
    /// (lock Tx A, verify Tx B, ALT Tx C, close Tx E). The concurrent settle
    /// Tx D's round-robin `(tee_keypairs[j], merkle_tree[j])` per match so they
    /// share no writable account (distinct shard + distinct fee-payer) → the
    /// leader can co-include + parallelize them. Length == `num_trees`.
    pub tee_keypairs: Vec<Arc<Keypair>>,
    /// The K Ed25519 signing keys (same material as `tee_keypairs`), used to
    /// sign each settle payload for the precompile ix. `signing_keys[j]` pairs
    /// with `tee_keypairs[j]`.
    pub signing_keys: Vec<Arc<SigningKey>>,
    /// The Groth16 prover. `Arc<dyn Prover>` so the backend
    /// (ark-circom now, rapidsnark later) is swappable + so tests
    /// inject a fast fake.
    pub prover: Arc<dyn Prover>,
    /// The static settle ALT (vault_config / instructions_sysvar /
    /// system_program), created at devnet-setup. `None` until that
    /// lands — the worker then relies on the per-batch ALT alone
    /// (slightly larger tx, still under cap for small batches).
    pub static_alt: Option<solana_message::AddressLookupTableAccount>,
    /// Rolling per-batch ALT pool. Reused across batches (extend, not
    /// create) and rotated near the 256-address cap — see
    /// [`super::alt_pool`]. Behind a `Mutex` because the pool mutates as
    /// each batch extends/rotates it; settle batches run serially today,
    /// so contention is nil.
    pub alt_pool: Arc<tokio::sync::Mutex<AltPool>>,
    /// Shared scheduler state — the worker updates job stages here.
    pub settle_state: Arc<RwLock<SettleSchedulerState>>,
    /// Per-leg confirmation timeout.
    pub confirm_timeout: Duration,
    /// Current compute-unit price bid (micro-lamports/CU), refreshed by the
    /// priority-fee poller (main.rs) from `getRecentPrioritizationFees`. Read
    /// once per batch; prepended as a `SetComputeUnitPrice` ix on every
    /// settle-path tx. 0 on a quiet network → no price ix.
    pub current_priority_fee: Arc<AtomicU64>,
    /// Max settle Tx D's sent CONCURRENTLY within a batch. The settle txs
    /// confirm together when the leader co-includes them in a block (the
    /// throughput lever — vs sending one-at-a-time and paying ~1.13s
    /// confirmation per match). `DARKNYX_TEE_SETTLE_SEND_CONCURRENCY`.
    pub settle_send_concurrency: usize,
    /// Enqueues a settled batch's Merkle root for ASYNCHRONOUS, expiry-gated
    /// marker close (Tx E). The sweeper reads the on-chain expiry and never
    /// submits early. Drained by `marker_sweep::spawn_marker_sweeper`.
    pub marker_sweep_tx: mpsc::UnboundedSender<[u8; 32]>,
}

/// Fire a set of per-batch ALT `extend` ixs CONCURRENTLY (one tx each, bounded),
/// confirming all. The extends write-conflict on the ALT account, so the leader
/// co-includes them in ONE block — collapsing the old sequential-confirm latency
/// (~1.13s × chunks) into a single confirmation window + a single activation
/// window. Their on-chain append order is leader-chosen; the caller re-reads the
/// ALT's canonical order afterward (see [`parse_alt_addresses`]).
async fn send_extends_concurrent(
    rpc: &SolanaRpcClient,
    payer: &Keypair,
    extend_ixs: Vec<Instruction>,
    blockhash: Hash,
    timeout: Duration,
    concurrency: usize,
) -> Result<(), WorkerError> {
    if extend_ixs.is_empty() {
        return Ok(());
    }
    // Build+sign each extend tx up front (sharing the blockhash), then fire.
    let mut txs: Vec<String> = Vec::with_capacity(extend_ixs.len());
    for ix in extend_ixs {
        txs.push(build_tx_b64(payer, &[ix], blockhash)?);
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut set: tokio::task::JoinSet<Result<(), WorkerError>> = tokio::task::JoinSet::new();
    for tx_b64 in txs {
        let rpc = rpc.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("extend semaphore");
            send_and_confirm_with_rebroadcast(&rpc, &tx_b64, timeout, Duration::from_millis(1500))
                .await?;
            Ok(())
        });
    }
    while let Some(joined) = set.join_next().await {
        joined
            .map_err(|e| WorkerError::Rpc(RpcError::Schema(format!("extend send task: {e}"))))??;
    }
    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum WorkerError {
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    #[error("prover: {0}")]
    Prover(String),
    #[error("prover task panicked: {0}")]
    ProverPanic(String),
    #[error("leaf/path: {0}")]
    Leaf(String),
    #[error("batch has {0} matches but witnesses has {1} slots")]
    Mismatch(usize, usize),
    #[error("per-batch ALT not active after wait (landed slot {0}); not settling against an unloadable lookup table")]
    AltNotActive(u64),
}

impl SettleWorkerCtx {
    /// The PRIMARY TEE keypair (`tee_keypairs[0]`) — pays the per-batch
    /// lock/verify/ALT/close txs.
    fn primary_keypair(&self) -> &Arc<Keypair> {
        &self.tee_keypairs[0]
    }

    /// The primary TEE pubkey (the per-batch fee-payer / authority).
    fn tee_pubkey(&self) -> Address {
        self.tee_keypairs[0].pubkey()
    }

    /// Number of shards the settle Tx D's round-robin across (== K keys).
    fn num_settle_shards(&self) -> usize {
        self.tee_keypairs.len().max(1)
    }

    /// Transition every job in the batch to `stage`. Best-effort —
    /// an evicted job (4g.6 retention) is skipped.
    async fn set_all_stages(&self, batch_id: u64, n: usize, stage: SettleJobStage) {
        let mut st = self.settle_state.write().await;
        for idx in 0..n {
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            st.update(&id, |j| j.transition(stage.clone()));
        }
    }

    async fn fail_all(&self, batch_id: u64, n: usize, reason: impl Into<String>) {
        let reason = reason.into();
        let mut st = self.settle_state.write().await;
        for idx in 0..n {
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            st.update(&id, |j| {
                if matches!(
                    j.outcome,
                    SettlementOutcome::Pending | SettlementOutcome::Ambiguous { .. }
                ) {
                    j.fail(reason.clone());
                }
            });
        }
    }

    async fn mark_ambiguous(&self, batch_id: u64, match_idx: usize, reason: String) {
        let id = SettleJobId {
            batch_id,
            match_idx: match_idx as u8,
        };
        let mut state = self.settle_state.write().await;
        state.update(&id, |job| {
            job.outcome = SettlementOutcome::Ambiguous { reason };
            job.transition(SettleJobStage::Settling);
        });
    }
}

async fn record_final_outcome(
    ctx: &SettleWorkerCtx,
    batch_id: u64,
    match_idx: usize,
    outcome: SettlementOutcome,
    results: &mut [Option<SettlementOutcome>],
    outcome_tx: Option<&mpsc::UnboundedSender<MatchSettlementResult>>,
) {
    if results[match_idx].is_some() {
        return;
    }
    let id = SettleJobId {
        batch_id,
        match_idx: match_idx as u8,
    };
    {
        let mut state = ctx.settle_state.write().await;
        state.update(&id, |job| {
            job.outcome = outcome.clone();
            match &outcome {
                SettlementOutcome::Confirmed { signature, .. } => {
                    job.settle_sig = signature.clone();
                    job.transition(SettleJobStage::Done);
                }
                SettlementOutcome::Rejected { reason } => {
                    job.transition(SettleJobStage::Failed {
                        reason: reason.clone(),
                    });
                }
                SettlementOutcome::Ambiguous { .. } | SettlementOutcome::Pending => {
                    job.transition(SettleJobStage::Settling);
                }
            }
        });
    }
    results[match_idx] = Some(outcome.clone());
    if let Some(tx) = outcome_tx {
        let _ = tx.send(MatchSettlementResult {
            match_index: match_idx,
            outcome,
        });
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ConsumedPdaState {
    BothConsumed,
    NeitherConsumed,
    Inconsistent,
}

/// Reconcile a Tx D independently from its RPC signature status. Tx D creates
/// both commitment-keyed consumed-note PDAs atomically, so both vault-owned
/// accounts existing is durable proof that the match settled; neither means a
/// redrive is still safe while the marker/locks are valid. Exactly one can only
/// be an inconsistent RPC view or external consumption of one input and must
/// never be guessed into a confirmed result.
async fn reconcile_consumed_pdas(
    rpc: &SolanaRpcClient,
    match_inputs: &MatchSettleInputs,
) -> Result<ConsumedPdaState, RpcError> {
    let (buyer, _) = consumed_note_pda(&match_inputs.payload.note_a_commitment);
    let (seller, _) = consumed_note_pda(&match_inputs.payload.note_b_commitment);
    let buyer = rpc.get_account_info(&buyer).await?;
    let seller = rpc.get_account_info(&seller).await?;
    let vault = vault_program_id();
    let buyer_consumed = buyer.as_ref().is_some_and(|account| account.owner == vault);
    let seller_consumed = seller
        .as_ref()
        .is_some_and(|account| account.owner == vault);
    Ok(match (buyer_consumed, seller_consumed) {
        (true, true) => ConsumedPdaState::BothConsumed,
        (false, false) => ConsumedPdaState::NeitherConsumed,
        _ => ConsumedPdaState::Inconsistent,
    })
}

fn settlement_deadline(match_inputs: &MatchSettleInputs, marker_expiry_slot: u64) -> u64 {
    marker_expiry_slot
        .min(match_inputs.buyer_lock.expiry_slot)
        .min(match_inputs.seller_lock.expiry_slot)
}

/// Drive one batch through the full settle pipeline. On any error
/// the batch's jobs are marked `Failed` with the reason; on success
/// they end at `Done`.
pub async fn run_batch_settle(
    ctx: &SettleWorkerCtx,
    inputs: BatchSettleInputs,
) -> Result<BatchSettlementReport, WorkerError> {
    run_batch_settle_with_outcomes(ctx, inputs, None).await
}

/// Drive a batch while publishing each match's final outcome as soon as it is
/// known. The scheduler uses this stream to commit confirmed siblings without
/// waiting for an ambiguous match's reconciliation/redrive loop.
pub async fn run_batch_settle_streaming(
    ctx: &SettleWorkerCtx,
    inputs: BatchSettleInputs,
    outcome_tx: mpsc::UnboundedSender<MatchSettlementResult>,
) -> Result<BatchSettlementReport, WorkerError> {
    run_batch_settle_with_outcomes(ctx, inputs, Some(outcome_tx)).await
}

async fn run_batch_settle_with_outcomes(
    ctx: &SettleWorkerCtx,
    inputs: BatchSettleInputs,
    outcome_tx: Option<mpsc::UnboundedSender<MatchSettlementResult>>,
) -> Result<BatchSettlementReport, WorkerError> {
    let n = inputs.matches.len();
    if n == 0 {
        return Ok(BatchSettlementReport {
            outcomes: Vec::new(),
        });
    }
    let batch_id = inputs.batch_id;

    let result = run_batch_settle_inner(ctx, &inputs, outcome_tx.as_ref()).await;
    if let Err(e) = &result {
        ctx.fail_all(batch_id, n, format!("{e}")).await;
    }
    result
}

async fn run_batch_settle_inner(
    ctx: &SettleWorkerCtx,
    inputs: &BatchSettleInputs,
    outcome_tx: Option<&mpsc::UnboundedSender<MatchSettlementResult>>,
) -> Result<BatchSettlementReport, WorkerError> {
    let batch_id = inputs.batch_id;
    let n = inputs.matches.len();
    let tee_pubkey = ctx.tee_pubkey();

    // A batch can't have more real matches than the witness set has
    // slots — the matcher pads up to N, never down.
    if n > inputs.witnesses.len() {
        return Err(WorkerError::Mismatch(n, inputs.witnesses.len()));
    }

    // Snapshot the priority-fee bid once for the whole batch (the poller keeps
    // it fresh; a stable value across one batch's txs is fine). Prepended as a
    // SetComputeUnitPrice ix on every settle-path tx below.
    let priority_fee = ctx.current_priority_fee.load(Ordering::Relaxed);

    // Per-stage latency profiling. `t` is reset at each stage boundary; a
    // single structured summary is emitted at the end (parseable from
    // `phala cvms logs`). This separates the TWO things the on-chain landing
    // timeline conflates: real in-enclave compute (prove_ms — the only heavy
    // ZK step) vs Solana tx-confirmation latency (lock/verify/settle/close ms)
    // vs the ALT-activation slot-wait (alt_wait_ms). Optimize the dominant one.
    let t_pipeline = Instant::now();

    // The batch's public inputs (merkle_root + per-match leaves) are a cheap
    // Poseidon fold of the match leaves — NOT the heavy Groth16 prove — and are
    // byte-identical to what the prover emits (the prover cross-checks the
    // circuit witness against exactly these). Computing them up front lets the
    // per-batch ALT (whose `batch_validity_marker` PDA is seeded by merkle_root)
    // be built CONCURRENTLY with proving instead of waiting for it.
    let public = build_batch_public_inputs(&inputs.witnesses)
        .map_err(|e| WorkerError::Prover(format!("public inputs: {e}")))?;
    let merkle_root = public.merkle_root;
    // `build_batch_public_inputs` retained the exact levels it used for this
    // root. Extract every Tx D path from that ONE 15-hash N=16 build instead of
    // hashing the tree again per match (the old path performed 240 hashes).
    let batch_paths = public.merkle_paths;

    // ── Stages 1-3 run CONCURRENTLY ─────────────────────────────
    // lock (Tx A), prove→verify (Tx B), and per-batch ALT create+activate
    // (Tx C) are mutually independent: the ALT uses the pre-computed
    // merkle_root, not the proof; verify is the only thing that needs the
    // proof. Overlapping them collapses the pre-settle critical path from the
    // SUM of their latencies to ~the MAX — and, crucially, starts the ALT's
    // activation clock ~one prove earlier, so the settle's ALT-loadability wait
    // is shorter. Each branch reports its own internal timing; `parallel_ms` is
    // the wall-clock of the overlapped phase.
    ctx.set_all_stages(batch_id, n, SettleJobStage::Proving)
        .await;
    let t_par = Instant::now();

    // Branch A — lock the input notes (Tx A), CONCURRENTLY. Mirrors the
    // settle send pass: the old per-match `submit → confirm → next` loop paid a
    // full ~1.13s block-confirmation SERIALLY per match (lock_ms scaled ~1.4s ×
    // N — the post-sharding bottleneck). The locks are independent (distinct
    // NoteLock PDAs) and only READ `merkle_tree`, so firing them together lets
    // the leader co-include them; round-robining the fee-payer/authority across
    // the K shard keys removes the last shared writable account (the fee-payer)
    // so they parallelize, exactly like Tx D.
    let lock_branch = async {
        let t = Instant::now();
        // Pass 1 — build+sign every lock tx up front, sharing ONE blockhash.
        let bh = ctx.rpc.get_latest_blockhash().await?;
        let blockhash = Hash::new_from_array(bh.blockhash);
        // (match_idx, is_buyer, tx_b64)
        let mut lock_txs: Vec<(usize, bool, String)> = Vec::with_capacity(2 * n);
        for (idx, m) in inputs.matches.iter().enumerate() {
            let kp = &ctx.tee_keypairs[idx % ctx.num_settle_shards()];
            if let Some(tx) = build_lock_tx_b64(kp, blockhash, &m.buyer_lock, priority_fee)? {
                lock_txs.push((idx, true, tx));
            }
            if let Some(tx) = build_lock_tx_b64(kp, blockhash, &m.seller_lock, priority_fee)? {
                lock_txs.push((idx, false, tx));
            }
        }

        // Pass 2 — send+confirm all locks concurrently (bounded), rebroadcasting
        // until each lands (same primitive Tx D uses).
        let sem = Arc::new(tokio::sync::Semaphore::new(
            ctx.settle_send_concurrency.max(1),
        ));
        let mut set: tokio::task::JoinSet<Result<(usize, bool, String), WorkerError>> =
            tokio::task::JoinSet::new();
        for (idx, is_buyer, tx_b64) in lock_txs {
            let rpc = ctx.rpc.clone();
            let timeout = ctx.confirm_timeout;
            let sem = sem.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("lock semaphore");
                let (sig, _slot) = send_and_confirm_with_rebroadcast(
                    &rpc,
                    &tx_b64,
                    timeout,
                    Duration::from_millis(1500),
                )
                .await?;
                Ok((idx, is_buyer, sig))
            });
        }
        while let Some(joined) = set.join_next().await {
            let (idx, is_buyer, sig) = joined.map_err(|e| {
                WorkerError::Rpc(RpcError::Schema(format!("lock send task: {e}")))
            })??;
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            let mut st = ctx.settle_state.write().await;
            st.update(&id, |j| {
                if is_buyer {
                    j.lock_buyer_sig = Some(sig.clone());
                } else {
                    j.lock_seller_sig = Some(sig.clone());
                }
            });
        }
        Ok::<u64, WorkerError>(t.elapsed().as_millis() as u64)
    };

    // Branch B — prove (spawn_blocking) then verify_match_batch (Tx B).
    let prove_verify_branch = async {
        let t = Instant::now();
        let prover = ctx.prover.clone();
        let witnesses = inputs.witnesses.clone();
        let proof_out = tokio::task::spawn_blocking(move || prover.prove(&witnesses))
            .await
            .map_err(|e| WorkerError::ProverPanic(e.to_string()))?
            .map_err(|e| WorkerError::Prover(format!("{e}")))?;
        let proof_bytes = proof_out.proof;
        let prove_ms = t.elapsed().as_millis() as u64;

        let t = Instant::now();
        // BatchValidityMarker expiry is bounded on BOTH sides by
        // verify_match_batch.rs: it must be (a) strictly in the future AND
        // (b) within MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS (= 300) of the
        // on-chain clock.
        //
        // S-04: this value is NO LONGER SENT — the program derives the marker's
        // TTL as `exec_slot + 300` so a replayer cannot choose a short one. We
        // still compute it locally because `settlement_deadline` needs to know
        // when to stop redriving.
        //
        // Keeping the 250 margin makes our local figure a deliberate
        // UNDER-estimate of the real on-chain expiry (`exec_slot + 300`, where
        // `exec_slot >= marker_slot`). That is the safe direction: the worker
        // gives up slightly EARLY rather than redriving a settle past a marker
        // that has actually expired.
        const MARKER_EXPIRY_MARGIN_SLOTS: u64 = 250;
        let marker_slot = ctx.rpc.get_latest_blockhash().await?.context_slot;
        let marker_expiry_slot = marker_slot.saturating_add(MARKER_EXPIRY_MARGIN_SLOTS);
        let verify_ix = build_verify_match_batch_ix(
            &tee_pubkey,
            &inputs.witnesses[0].base_mint,
            &inputs.witnesses[0].quote_mint,
            VerifyMatchBatchArgs {
                merkle_root,
                proof: proof_bytes,
            },
        );
        let mut verify_ixs = budget_ixs(VERIFY_COMPUTE_UNIT_LIMIT, priority_fee);
        verify_ixs.push(verify_ix);
        let verify_sig = submit_ixs(&ctx.rpc, ctx.primary_keypair(), &verify_ixs).await?;
        confirm_signatures(
            &ctx.rpc,
            std::slice::from_ref(&verify_sig),
            ctx.confirm_timeout,
        )
        .await?;
        {
            let mut st = ctx.settle_state.write().await;
            for idx in 0..n {
                let id = SettleJobId {
                    batch_id,
                    match_idx: idx as u8,
                };
                st.update(&id, |j| j.verify_sig = Some(verify_sig.clone()));
            }
        }
        Ok::<(u64, u64, u64), WorkerError>((
            prove_ms,
            t.elapsed().as_millis() as u64,
            marker_expiry_slot,
        ))
    };

    // Branch C — per-batch ALT create/extend (Tx C) + activation wait.
    let alt_branch = async {
        let t = Instant::now();
        // Per-batch ALT via the rolling pool: reuse a long-lived `current`
        // ALT (extend it with this batch's derivable PDAs) and only create a
        // fresh one — deactivating the old — when it nears the 256-address
        // cap. The address set is the UNION of EVERY match's note-lock PDAs +
        // the single shared batch marker — so a multi-match batch's settle txs
        // all stay under the 1232-byte cap, not just match 0's.
        let alt_addrs =
            batch_alt_addresses(inputs.matches.iter().map(|m| &m.payload), &merkle_root);
        // Hold the pool lock across the WHOLE ALT op (plan + create/extend tx +
        // commit + capturing THIS batch's table), so concurrent batches (the
        // pipelined scheduler) serialize ONLY here — their prove + settle-wait
        // still overlap. Capturing `settle_account()` while still locked is
        // required: once we release, another in-flight batch may extend/rotate
        // the pool and a later read would return the wrong table.
        let in_mem_alt = {
            let mut pool = ctx.alt_pool.lock().await;
            let plan = pool.plan(alt_addrs.len());
            let bh = ctx.rpc.get_latest_blockhash().await?;
            match plan {
                AltPlan::Create { deactivate } => {
                    // Rotation: best-effort deactivate the old, full ALT so its
                    // rent can be reclaimed after the 512-slot cooldown. A
                    // failure here must NOT block the settle — the old ALT just
                    // lingers (a later reclaim sweep can retry).
                    let mut deactivated = None;
                    if let Some(old) = deactivate {
                        let deact_ix = build_deactivate_alt_ix(&tee_pubkey, &old);
                        match submit_ixs_with_blockhash(
                            &ctx.rpc,
                            ctx.primary_keypair(),
                            &[deact_ix],
                            Hash::new_from_array(bh.blockhash),
                        )
                        .await
                        {
                            Ok(sig) => {
                                let _ =
                                    confirm_signatures(&ctx.rpc, &[sig], ctx.confirm_timeout).await;
                                deactivated = Some((old, bh.context_slot));
                            }
                            Err(e) => tracing::warn!(error = ?e, alt = %old,
                                "deactivate rotated-out ALT failed; leaving it for a later reclaim"),
                        }
                    }
                    // `CreateLookupTable` rejects a `recent_slot` not present in
                    // the SlotHashes sysvar of the bank that processes it. A
                    // load-balanced RPC can answer getLatestBlockhash from a
                    // replica a few slots AHEAD of the simulating bank → "is not
                    // a recent slot". Back off 32 (within the 512-slot window).
                    const ALT_RECENT_SLOT_BACKOFF: u64 = 32;
                    let alt_recent_slot = bh.context_slot.saturating_sub(ALT_RECENT_SLOT_BACKOFF);
                    let alt_build =
                        build_per_batch_alt_ixs(&tee_pubkey, alt_recent_slot, &alt_addrs);
                    // tx0: create + the FIRST extend chunk (keeps small batches a
                    // single tx). The create must confirm before the rest can
                    // reference the ALT.
                    let mut extends = alt_build.extend_ixs.into_iter();
                    let mut tx0 = vec![alt_build.create_ix];
                    tx0.extend(extends.next());
                    let create_sig = submit_ixs_with_blockhash(
                        &ctx.rpc,
                        ctx.primary_keypair(),
                        &tx0,
                        Hash::new_from_array(bh.blockhash),
                    )
                    .await?;
                    confirm_signatures(&ctx.rpc, &[create_sig], ctx.confirm_timeout).await?;
                    // Remaining chunks CONCURRENTLY — they write-conflict on the
                    // ALT so the leader co-includes them in one block (a single
                    // activation window instead of one slot per chunk). Order is
                    // leader-chosen → we re-read the ALT's canonical order below.
                    send_extends_concurrent(
                        &ctx.rpc,
                        ctx.primary_keypair(),
                        extends.collect(),
                        Hash::new_from_array(bh.blockhash),
                        ctx.confirm_timeout,
                        ctx.settle_send_concurrency,
                    )
                    .await?;
                    pool.commit_create(alt_build.alt_address, alt_addrs.clone(), deactivated);
                }
                AltPlan::Extend { alt } => {
                    // Append this batch's addresses; chunks fired CONCURRENTLY
                    // (co-include → single activation window).
                    send_extends_concurrent(
                        &ctx.rpc,
                        ctx.primary_keypair(),
                        build_extend_alt_ix_chunks(&tee_pubkey, &alt, &alt_addrs),
                        Hash::new_from_array(bh.blockhash),
                        ctx.confirm_timeout,
                        ctx.settle_send_concurrency,
                    )
                    .await?;
                    pool.commit_extend(&alt_addrs);
                }
            }
            // The pool's in-memory table (key + the addresses in submit order).
            // Used as the fallback below if the on-chain re-read comes back empty
            // (e.g. a transient RPC blip, or the mock RPC in unit tests).
            pool.settle_account()
                .expect("pool has a current ALT after plan/commit")
        };
        let alt_tx_ms = t.elapsed().as_millis() as u64;

        // A freshly created OR extended ALT's new addresses are NOT loadable
        // until the slot AFTER the extend lands. Wait until the chain advances
        // past the slot we observed the extend confirmed at, or fail loudly
        // (sending Tx D against an unloadable ALT → silently dropped). No lock
        // needed here — `per_batch_alt` is already captured.
        let t = Instant::now();
        let alt_landed_slot = ctx.rpc.get_latest_blockhash().await?.context_slot;
        let mut activated = false;
        for _ in 0..30 {
            if ctx.rpc.get_latest_blockhash().await?.context_slot > alt_landed_slot {
                activated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        if !activated {
            tracing::error!(
                alt_landed_slot,
                "per-batch ALT activation timed out; aborting settle"
            );
            return Err(WorkerError::AltNotActive(alt_landed_slot));
        }

        // Re-read the ALT's CANONICAL on-chain address order. The extends were
        // fired concurrently, so the leader (not us) chose their append order;
        // the Tx D v0 message resolves each account to its index in this list,
        // which MUST mirror the on-chain ALT exactly. Fall back to the pool's
        // in-memory table if the read comes back empty (transient RPC / tests).
        let alt_key = in_mem_alt.key;
        let on_chain = ctx
            .rpc
            .get_account_info(&alt_key)
            .await?
            .map(|acc| parse_alt_addresses(&acc.data))
            .unwrap_or_default();
        let per_batch_alt = if on_chain.is_empty() {
            tracing::warn!(alt = %alt_key, "per-batch ALT re-read empty; using in-memory order");
            in_mem_alt
        } else {
            solana_message::AddressLookupTableAccount {
                key: alt_key,
                addresses: on_chain,
            }
        };
        tracing::info!(
            alt = %per_batch_alt.key,
            entries = per_batch_alt.addresses.len(),
            "per-batch ALT ready (canonical order re-read after concurrent extends)"
        );
        Ok::<_, WorkerError>((per_batch_alt, alt_tx_ms, t.elapsed().as_millis() as u64))
    };

    let (lock_r, pv_r, alt_r) = tokio::join!(lock_branch, prove_verify_branch, alt_branch);
    let lock_ms = lock_r?;
    let (prove_ms, verify_ms, marker_expiry_slot) = pv_r?;
    let (per_batch_alt, alt_tx_ms, alt_wait_ms) = alt_r?;
    let parallel_ms = t_par.elapsed().as_millis() as u64;

    let mut t = Instant::now();

    // ── 4. Settle each match (Tx D, v0) — CONCURRENT sends ──────
    ctx.set_all_stages(batch_id, n, SettleJobStage::Settling)
        .await;
    let mut alts = Vec::new();
    if let Some(static_alt) = &ctx.static_alt {
        alts.push(static_alt.clone());
    }
    alts.push(per_batch_alt);

    // Each match now resolves independently. A round uses one fresh blockhash
    // for only the unresolved matches, gathers every signature result, and
    // reconciles ambiguous/rejected results against the two atomic consumed
    // PDAs. Transient/ambiguous matches are redriven while BOTH their input
    // locks and the shared batch marker remain valid.
    let mut unresolved: Vec<usize> = (0..n).collect();
    let mut results: Vec<Option<SettlementOutcome>> = vec![None; n];
    let mut last_signatures: Vec<Option<String>> = vec![None; n];
    let mut slots: Vec<u64> = Vec::with_capacity(n);
    while !unresolved.is_empty() {
        let bh = match ctx.rpc.get_latest_blockhash().await {
            Ok(bh) => bh,
            Err(error) => {
                let reason = format!("cannot read settlement window: {error}");
                for &idx in &unresolved {
                    ctx.mark_ambiguous(batch_id, idx, reason.clone()).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        // Expired windows cannot be redriven. Reconcile one final time: both
        // PDAs means the prior send landed; neither is a definitive terminal
        // rejection. A read failure stays ambiguous and is retried.
        let mut active = Vec::with_capacity(unresolved.len());
        for idx in unresolved.drain(..) {
            if bh.context_slot < settlement_deadline(&inputs.matches[idx], marker_expiry_slot) {
                active.push(idx);
                continue;
            }
            let outcome = loop {
                match reconcile_consumed_pdas(&ctx.rpc, &inputs.matches[idx]).await {
                    Ok(ConsumedPdaState::BothConsumed) => {
                        break SettlementOutcome::Confirmed {
                            signature: last_signatures[idx].clone(),
                            slot: None,
                            reconciled_from_consumed_pdas: true,
                        };
                    }
                    Ok(ConsumedPdaState::NeitherConsumed) => {
                        break SettlementOutcome::Rejected {
                            reason: format!(
                                "settlement window expired at slot {} without consumed-note PDAs",
                                settlement_deadline(&inputs.matches[idx], marker_expiry_slot)
                            ),
                        };
                    }
                    Ok(ConsumedPdaState::Inconsistent) => {
                        break SettlementOutcome::Rejected {
                            reason: "only one input was consumed; this match can no longer settle"
                                .to_string(),
                        };
                    }
                    Err(error) => {
                        let reason = format!("final consumed-note reconciliation failed: {error}");
                        ctx.mark_ambiguous(batch_id, idx, reason).await;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            };
            record_final_outcome(ctx, batch_id, idx, outcome, &mut results, outcome_tx).await;
        }
        if active.is_empty() {
            break;
        }

        let blockhash = Hash::new_from_array(bh.blockhash);
        let mut txs: Vec<(usize, String)> = Vec::with_capacity(active.len());
        let mut attempted = Vec::with_capacity(active.len());
        for &idx in &active {
            let m = &inputs.matches[idx];
            let built = (|| -> Result<String, WorkerError> {
                let siblings = batch_paths
                    .path(m.match_index as usize)
                    .map_err(|e| WorkerError::Leaf(format!("{e}")))?;
                let shard = idx % ctx.num_settle_shards();
                let shard_keypair = &ctx.tee_keypairs[shard];
                let (msg, sig) = sign_payload(&ctx.signing_keys[shard], &m.payload);
                let ed_ix = build_ed25519_verify_ix(&shard_keypair.pubkey().to_bytes(), &sig, &msg);
                let settle_ix = build_settle_batched_ix(
                    &shard_keypair.pubkey(),
                    shard as u8,
                    &m.payload,
                    m.match_index,
                    siblings,
                    &merkle_root,
                );
                Ok(build_settle_v0_tx_b64(
                    shard_keypair,
                    ed_ix,
                    settle_ix,
                    &alts,
                    blockhash,
                )?)
            })();
            match built {
                Ok(tx_b64) => {
                    attempted.push(idx);
                    txs.push((idx, tx_b64));
                }
                Err(error) => {
                    record_final_outcome(
                        ctx,
                        batch_id,
                        idx,
                        SettlementOutcome::Rejected {
                            reason: format!("cannot construct settle transaction: {error}"),
                        },
                        &mut results,
                        outcome_tx,
                    )
                    .await;
                }
            }
        }
        if txs.is_empty() {
            continue;
        }

        let round = send_and_confirm_many_with_rebroadcast(
            &ctx.rpc,
            txs,
            ctx.confirm_timeout,
            Duration::from_millis(1500),
            ctx.settle_send_concurrency,
        )
        .await;
        let mut seen = std::collections::HashSet::with_capacity(round.len());
        let mut retry = Vec::new();
        for raw in round {
            let idx = raw.transaction_index();
            seen.insert(idx);
            let resolved = match raw {
                TransactionConfirmationOutcome::Confirmed(outcome) => {
                    if let Some(slot) = outcome.slot {
                        slots.push(slot);
                    }
                    last_signatures[idx] = Some(outcome.signature.clone());
                    tracing::info!(
                        batch_id,
                        match_idx = idx,
                        settle_tx_ms = outcome.elapsed_ms,
                        confirmed_slot = outcome.slot,
                        rebroadcasts = outcome.rebroadcasts,
                        "settle Tx D confirmed (per-match)"
                    );
                    Some(SettlementOutcome::Confirmed {
                        signature: Some(outcome.signature),
                        slot: outcome.slot,
                        reconciled_from_consumed_pdas: false,
                    })
                }
                TransactionConfirmationOutcome::Rejected {
                    signature, reason, ..
                } => {
                    last_signatures[idx] = Some(signature);
                    match reconcile_consumed_pdas(&ctx.rpc, &inputs.matches[idx]).await {
                        Ok(ConsumedPdaState::BothConsumed) => Some(SettlementOutcome::Confirmed {
                            signature: last_signatures[idx].clone(),
                            slot: None,
                            reconciled_from_consumed_pdas: true,
                        }),
                        Ok(_) => Some(SettlementOutcome::Rejected { reason }),
                        Err(error) => {
                            let reason =
                                format!("{reason}; consumed-note reconciliation failed: {error}");
                            ctx.mark_ambiguous(batch_id, idx, reason).await;
                            retry.push(idx);
                            None
                        }
                    }
                }
                TransactionConfirmationOutcome::Ambiguous {
                    signature, reason, ..
                } => {
                    if signature.is_some() {
                        last_signatures[idx] = signature;
                    }
                    ctx.mark_ambiguous(batch_id, idx, reason.clone()).await;
                    match reconcile_consumed_pdas(&ctx.rpc, &inputs.matches[idx]).await {
                        Ok(ConsumedPdaState::BothConsumed) => Some(SettlementOutcome::Confirmed {
                            signature: last_signatures[idx].clone(),
                            slot: None,
                            reconciled_from_consumed_pdas: true,
                        }),
                        Ok(ConsumedPdaState::NeitherConsumed) => {
                            match ctx.rpc.get_latest_blockhash().await {
                                Ok(now)
                                    if now.context_slot
                                        < settlement_deadline(
                                            &inputs.matches[idx],
                                            marker_expiry_slot,
                                        ) =>
                                {
                                    tracing::warn!(
                                        batch_id,
                                        match_idx = idx,
                                        reason,
                                        "ambiguous Tx D absent on-chain; redriving while valid"
                                    );
                                    retry.push(idx);
                                    None
                                }
                                Ok(_) => Some(SettlementOutcome::Rejected {
                                    reason: format!(
                                        "{reason}; settlement window expired without consumed-note PDAs"
                                    ),
                                }),
                                Err(error) => {
                                    let reason = format!(
                                        "{reason}; cannot determine remaining settlement window: {error}"
                                    );
                                    ctx.mark_ambiguous(batch_id, idx, reason).await;
                                    retry.push(idx);
                                    None
                                }
                            }
                        }
                        Ok(ConsumedPdaState::Inconsistent) => Some(SettlementOutcome::Rejected {
                            reason: format!(
                                "{reason}; only one input was consumed and the match cannot settle"
                            ),
                        }),
                        Err(error) => {
                            let reason =
                                format!("{reason}; consumed-note reconciliation failed: {error}");
                            ctx.mark_ambiguous(batch_id, idx, reason).await;
                            retry.push(idx);
                            None
                        }
                    }
                }
            };
            if let Some(outcome) = resolved {
                record_final_outcome(ctx, batch_id, idx, outcome, &mut results, outcome_tx).await;
            }
        }

        // A panicked send task is not attributable inside the confirmation
        // helper. Preserve every caller index by treating any missing result as
        // ambiguous; the scheduler keeps those orders reserved.
        for idx in attempted {
            if !seen.contains(&idx) {
                let reason = "settle send task ended without an attributable result".to_string();
                ctx.mark_ambiguous(batch_id, idx, reason).await;
                retry.push(idx);
            }
        }
        unresolved = retry;
        if !unresolved.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    for idx in 0..results.len() {
        if results[idx].is_none() {
            record_final_outcome(
                ctx,
                batch_id,
                idx,
                SettlementOutcome::Ambiguous {
                    reason: "settlement result missing after reconciliation".to_string(),
                },
                &mut results,
                outcome_tx,
            )
            .await;
        }
    }
    let normalized: Vec<SettlementOutcome> = results.into_iter().flatten().collect();

    // Co-inclusion factor = matches ÷ distinct_slots. Near n → the leader
    // batched the settles into one/few blocks (the concurrent-send win); near 1
    // → they spread ~1 per slot (the leader serialized same-account writes → the
    // signal that tree-sharding is needed to go further).
    slots.sort_unstable();
    let distinct_slots = {
        let mut s = slots.clone();
        s.dedup();
        s.len()
    };
    tracing::info!(
        batch_id,
        n,
        distinct_slots,
        slots = ?slots,
        "settle co-inclusion (matches ÷ distinct_slots = co-inclusion factor)"
    );

    let settle_ms = t.elapsed().as_millis() as u64;
    t = Instant::now();

    // ── 5. Enqueue expiry-gated marker sweep (Tx E) — ASYNC ──
    // The marker is 1:N rent-reclaim bookkeeping; nothing downstream depends on
    // it (the next batch has a different Merkle root → a different marker PDA).
    // Sending + confirming it INLINE used to block the serial pipeline's next
    // batch on a full confirmation for a tx that touches no user funds. Hand the
    // root to the background sweeper (`marker_sweep::spawn_marker_sweeper`),
    // which reads the marker expiry and waits until E before closing. A closed
    // `marker_sweep_tx` (sweeper gone) is a
    // best-effort no-op — the marker stays open until a later boot replays it
    // from the persisted pending set.
    if ctx.marker_sweep_tx.send(merkle_root).is_err() {
        tracing::warn!(
            batch_id,
            "marker sweeper channel closed; marker close deferred to next boot"
        );
    }

    // `close_ms` is now just the enqueue (≈0) — the on-chain close is async.
    let close_ms = t.elapsed().as_millis() as u64;
    let total_ms = t_pipeline.elapsed().as_millis() as u64;
    // The fine-grained per-stage latency profile. lock/prove+verify/alt run
    // CONCURRENTLY: `parallel_ms` is the wall-clock of that overlapped phase
    // (≈ the max of the branches, vs the old sum of lock+prove+verify+alt).
    // `prove_ms` is the only in-enclave ZK compute; `alt_wait_ms` is the
    // Solana ALT-activation slot-wait; lock/verify/settle/close are tx
    // submit+confirm latency.
    tracing::info!(
        batch_id,
        n,
        lock_ms,
        prove_ms,
        verify_ms,
        alt_tx_ms,
        alt_wait_ms,
        parallel_ms,
        settle_ms,
        close_ms,
        total_ms,
        "settle pipeline timing (per-stage ms)"
    );

    Ok(BatchSettlementReport {
        outcomes: normalized
            .into_iter()
            .enumerate()
            .map(|(match_index, outcome)| MatchSettlementResult {
                match_index,
                outcome,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{build_batch_public_inputs, dummy_slot, ProofWithInputs, ProverError};
    use crate::settle::Groth16ProofBytes;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::super::job::{SettleJob, SettleJobId};
    use darkpool_matcher::match_result::{MatchPair, MatchStatus};

    // ─── A fast in-process Prover that skips Groth16 ───────────────
    //
    // It computes the REAL public inputs (leaves + root) from the
    // witnesses — so the Merkle inclusion paths + marker PDA the
    // worker derives are genuine — but returns a canned proof. The
    // mock RPC doesn't verify proofs, so this exercises the full
    // orchestration without circuit artifacts or a multi-minute
    // N=16 prove.
    struct FakeProver {
        n: usize,
    }

    impl Prover for FakeProver {
        fn prove(&self, slots: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
            let public = build_batch_public_inputs(slots)?;
            Ok(ProofWithInputs {
                proof: Groth16ProofBytes {
                    pi_a: [0x07; 64],
                    pi_b: [0x07; 128],
                    pi_c: [0x07; 64],
                },
                public,
            })
        }
        fn n(&self) -> usize {
            self.n
        }
    }

    // ─── A minimal JSON-RPC mock server (axum) ─────────────────────
    //
    // Routes every POST to one handler that dispatches on the
    // request's `method` field and returns the canned envelope the
    // `SolanaRpcClient` expects. sendTransaction returns a distinct
    // base58 signature per call (so the worker records non-colliding
    // sigs); getSignatureStatuses always returns "confirmed".

    async fn spawn_mock_rpc() -> String {
        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::{json, Value};

        async fn handle(
            State(counter): State<Arc<AtomicU64>>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let result = match method {
                "getLatestBlockhash" => {
                    // Advance the slot every call so the worker's per-batch
                    // ALT-activation wait breaks (it errors if the slot
                    // never moves past the extend's landing slot).
                    let slot = 1000 + counter.fetch_add(1, Ordering::SeqCst);
                    json!({
                        "context": { "slot": slot },
                        "value": {
                            "blockhash": bs58::encode([7u8; 32]).into_string(),
                            "lastValidBlockHeight": 2000u64,
                        }
                    })
                }
                "sendTransaction" => {
                    // 64-byte sig, distinct per call so the worker's
                    // per-job sig fields don't collide.
                    let nth = counter.fetch_add(1, Ordering::SeqCst);
                    let mut sig = [0u8; 64];
                    sig[..8].copy_from_slice(&nth.to_le_bytes());
                    json!(bs58::encode(sig).into_string())
                }
                "getSignatureStatuses" => {
                    let want = req
                        .get("params")
                        .and_then(|p| p.get(0))
                        .and_then(|s| s.as_array())
                        .map(|a| a.len())
                        .unwrap_or(1);
                    let value: Vec<Value> = (0..want)
                        .map(|_| json!({ "confirmationStatus": "confirmed", "err": null }))
                        .collect();
                    json!({ "context": { "slot": 1000 }, "value": value })
                }
                // Per-batch ALT re-read → null so the worker falls back to its
                // in-memory ALT order (the mock doesn't model account state).
                "getAccountInfo" => json!({ "context": { "slot": 1000 }, "value": null }),
                other => json!({ "error": format!("unexpected method {other}") }),
            };
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }

        let counter = Arc::new(AtomicU64::new(0));
        let app = Router::new().route("/", post(handle)).with_state(counter);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Like [`spawn_mock_rpc`] but also CAPTURES every `sendTransaction`
    /// base64 payload into the returned `Vec`, so a test can decode the
    /// settle Tx D's and assert which shard key fee-paid each one.
    async fn spawn_capturing_mock_rpc() -> (String, Arc<tokio::sync::Mutex<Vec<String>>>) {
        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::{json, Value};

        type Cap = Arc<tokio::sync::Mutex<Vec<String>>>;

        async fn handle(
            State((counter, cap)): State<(Arc<AtomicU64>, Cap)>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let result = match method {
                "getLatestBlockhash" => {
                    let slot = 1000 + counter.fetch_add(1, Ordering::SeqCst);
                    json!({
                        "context": { "slot": slot },
                        "value": {
                            "blockhash": bs58::encode([7u8; 32]).into_string(),
                            "lastValidBlockHeight": 2000u64,
                        }
                    })
                }
                "sendTransaction" => {
                    if let Some(tx_b64) = req
                        .get("params")
                        .and_then(|p| p.get(0))
                        .and_then(|s| s.as_str())
                    {
                        cap.lock().await.push(tx_b64.to_string());
                    }
                    let nth = counter.fetch_add(1, Ordering::SeqCst);
                    let mut sig = [0u8; 64];
                    sig[..8].copy_from_slice(&nth.to_le_bytes());
                    json!(bs58::encode(sig).into_string())
                }
                "getSignatureStatuses" => {
                    let want = req
                        .get("params")
                        .and_then(|p| p.get(0))
                        .and_then(|s| s.as_array())
                        .map(|a| a.len())
                        .unwrap_or(1);
                    let value: Vec<Value> = (0..want)
                        .map(|_| json!({ "confirmationStatus": "confirmed", "err": null }))
                        .collect();
                    json!({ "context": { "slot": 1000 }, "value": value })
                }
                // Per-batch ALT re-read → null so the worker falls back to its
                // in-memory ALT order (the mock doesn't model account state).
                "getAccountInfo" => json!({ "context": { "slot": 1000 }, "value": null }),
                other => json!({ "error": format!("unexpected method {other}") }),
            };
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }

        let counter = Arc::new(AtomicU64::new(0));
        let cap: Cap = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(handle))
            .with_state((counter, cap.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), cap)
    }

    fn proof_bytes() -> Groth16ProofBytes {
        Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        }
    }

    fn lock_inputs(seed: u8) -> LockSideInputs {
        LockSideInputs {
            tree_id: 0,
            note_commitment: [seed; 32],
            order_id: [seed; 16],
            expiry_slot: 2000,
            token_mint: [0xCC; 32],
            merkle_root: [0xDD; 32],
            proof: proof_bytes(),
            already_locked: false,
        }
    }

    fn payload(seed: u8) -> MatchResultPayload {
        MatchResultPayload {
            match_id: [seed; 16],
            note_a_commitment: [seed; 32],
            note_b_commitment: [seed.wrapping_add(1); 32],
            note_c_commitment: [seed.wrapping_add(2); 32],
            note_d_commitment: [seed.wrapping_add(3); 32],
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            order_id_a: [seed; 16],
            order_id_b: [seed.wrapping_add(1); 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            batch_slot: 7,
            fill_recovery: [0u8; 128],
        }
    }

    fn dummy_match_pair() -> MatchPair {
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
            batch_slot: 1,
            match_id: 0,
            status: MatchStatus::Filled,
        }
    }

    /// Pre-seed the scheduler with `n` Queued jobs for `batch_id`, so
    /// the worker's stage updates land (mirrors what the scheduler's
    /// ingest path does before a worker picks the batch up).
    async fn seed_jobs(state: &Arc<RwLock<SettleSchedulerState>>, batch_id: u64, n: u8) {
        let mut st = state.write().await;
        for idx in 0..n {
            let id = SettleJobId {
                batch_id,
                match_idx: idx,
            };
            st.insert(SettleJob::new(id, dummy_match_pair()));
        }
    }

    fn ctx_for(url: String, state: Arc<RwLock<SettleSchedulerState>>, n: usize) -> SettleWorkerCtx {
        SettleWorkerCtx {
            rpc: SolanaRpcClient::new(url).unwrap(),
            tee_keypairs: vec![Arc::new(Keypair::new_from_array([0x42; 32]))],
            signing_keys: vec![Arc::new(SigningKey::from_bytes(&[0x42; 32]))],
            prover: Arc::new(FakeProver { n }),
            // Production stacks the static settle ALT under the per-batch ALT;
            // with the v8 +128 recovery bundle the per-batch ALT alone overflows
            // the 1232-byte cap, so the worker tests must mirror production and
            // provide it too (vault_config + sysvar + system + 4 merkle shards).
            static_alt: Some(crate::settle::alt::alt_account(
                solana_address::Address::new_from_array([0x44; 32]),
                crate::settle::settle_batched::static_alt_addresses(4),
            )),
            alt_pool: Arc::new(tokio::sync::Mutex::new(AltPool::new())),
            settle_state: state,
            confirm_timeout: Duration::from_secs(5),
            current_priority_fee: Arc::new(AtomicU64::new(0)),
            settle_send_concurrency: 8,
            // Throwaway sender — the rx is dropped, so the worker's enqueue is a
            // harmless best-effort no-op (the marker-sweep path is unit-tested
            // separately in `marker_sweep`).
            marker_sweep_tx: mpsc::unbounded_channel().0,
        }
    }

    async fn spawn_consumed_account_rpc(existing: Vec<Address>) -> String {
        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::collections::HashSet;

        async fn handle(
            State(existing): State<Arc<HashSet<String>>>,
            Json(req): Json<Value>,
        ) -> Json<Value> {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let address = req["params"][0].as_str().unwrap_or_default();
            let value = existing.contains(address).then(|| {
                json!({
                    "lamports": 1,
                    "owner": vault_program_id().to_string(),
                    "data": ["", "base64"],
                    "executable": false,
                    "rentEpoch": 0,
                })
            });
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "context": { "slot": 10 }, "value": value },
            }))
        }

        let existing = Arc::new(
            existing
                .into_iter()
                .map(|address| address.to_string())
                .collect(),
        );
        let app = Router::new().route("/", post(handle)).with_state(existing);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn consumed_pda_reconciliation_requires_the_atomic_pair() {
        let match_inputs = MatchSettleInputs {
            payload: payload(0xA0),
            buyer_lock: lock_inputs(0x01),
            seller_lock: lock_inputs(0x02),
            match_index: 0,
        };
        let buyer = consumed_note_pda(&match_inputs.payload.note_a_commitment).0;
        let seller = consumed_note_pda(&match_inputs.payload.note_b_commitment).0;

        for (existing, expected) in [
            (vec![buyer, seller], ConsumedPdaState::BothConsumed),
            (vec![], ConsumedPdaState::NeitherConsumed),
            (vec![buyer], ConsumedPdaState::Inconsistent),
        ] {
            let rpc = SolanaRpcClient::new(spawn_consumed_account_rpc(existing).await).unwrap();
            assert_eq!(
                reconcile_consumed_pdas(&rpc, &match_inputs).await.unwrap(),
                expected
            );
        }
    }

    /// Like [`ctx_for`] but with `k` distinct shard keypairs (the K-fee-payer
    /// round-robin set). `tee_keypairs[j]` is seeded from `[0x40 + j; 32]` so
    /// each shard's fee-payer pubkey is distinct + reproducible.
    fn ctx_for_k(
        url: String,
        state: Arc<RwLock<SettleSchedulerState>>,
        n: usize,
        k: usize,
    ) -> SettleWorkerCtx {
        let mut ctx = ctx_for(url, state, n);
        ctx.tee_keypairs = (0..k)
            .map(|j| Arc::new(Keypair::new_from_array([0x40 + j as u8; 32])))
            .collect();
        ctx.signing_keys = (0..k)
            .map(|j| Arc::new(SigningKey::from_bytes(&[0x40 + j as u8; 32])))
            .collect();
        ctx
    }

    /// Decode the fee-payer (`static_account_keys()[0]`) of a base64
    /// VersionedTransaction, returning `None` for a legacy (non-v0) tx so the
    /// caller can filter the settle Tx D's (the only v0 txs) from the
    /// lock/verify/ALT/close legacy txs.
    fn v0_fee_payer(tx_b64: &str) -> Option<Address> {
        use base64::Engine as _;
        use solana_transaction::versioned::VersionedTransaction;
        let wire = base64::engine::general_purpose::STANDARD
            .decode(tx_b64)
            .ok()?;
        let tx: VersionedTransaction = bincode::deserialize(&wire).ok()?;
        match tx.message {
            solana_message::VersionedMessage::V0(m) => m.account_keys.first().copied(),
            _ => None,
        }
    }

    /// Fee-payer (`account_keys[0]`) of a base64 LEGACY tx, returning `None`
    /// for a v0 tx — so a test can filter the legacy lock txs (Tx A) from the
    /// v0 settle txs (Tx D).
    fn legacy_fee_payer(tx_b64: &str) -> Option<Address> {
        use base64::Engine as _;
        let wire = base64::engine::general_purpose::STANDARD
            .decode(tx_b64)
            .ok()?;
        let tx: solana_transaction::Transaction = bincode::deserialize(&wire).ok()?;
        tx.message.account_keys.first().copied()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn settle_round_robins_distinct_shard_fee_payers() {
        // K=2 shard keys, a 2-match batch → the two settle Tx D's must be
        // fee-paid (and signed) by the TWO DISTINCT shard keys (match 0 → key
        // 0, match 1 → key 1). That's the whole point of the K-fee-payer lever:
        // the concurrent Tx D's share no writable account.
        let (url, cap) = spawn_capturing_mock_rpc().await;
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        seed_jobs(&state, 0, 2).await;
        let ctx = ctx_for_k(url, state.clone(), 2, 2);
        assert_eq!(ctx.num_settle_shards(), 2);

        let inputs = BatchSettleInputs {
            batch_id: 0,
            matches: vec![
                MatchSettleInputs {
                    payload: payload(0xA0),
                    buyer_lock: lock_inputs(0x01),
                    seller_lock: lock_inputs(0x02),
                    match_index: 0,
                },
                MatchSettleInputs {
                    payload: payload(0xB0),
                    buyer_lock: lock_inputs(0x03),
                    seller_lock: lock_inputs(0x04),
                    match_index: 1,
                },
            ],
            witnesses: vec![dummy_slot(), dummy_slot()],
        };
        run_batch_settle(&ctx, inputs).await.expect("batch settle");

        // The settle Tx D's are the only v0 txs; collect their fee-payers.
        let sent = cap.lock().await.clone();
        let settle_payers: Vec<Address> = sent.iter().filter_map(|t| v0_fee_payer(t)).collect();
        assert_eq!(settle_payers.len(), 2, "expected two v0 settle Tx D's");
        assert_ne!(
            settle_payers[0], settle_payers[1],
            "the two settle Tx D's must be fee-paid by DISTINCT shard keys"
        );
        let key0 = Keypair::new_from_array([0x40; 32]).pubkey();
        let key1 = Keypair::new_from_array([0x41; 32]).pubkey();
        assert!(
            settle_payers.contains(&key0),
            "shard-0 key must pay a settle"
        );
        assert!(
            settle_payers.contains(&key1),
            "shard-1 key must pay a settle"
        );

        // The LOCK txs (Tx A, legacy) must ALSO round-robin the two shard keys —
        // match 0's locks paid by key0, match 1's by key1 (idx % K).
        let lock_payers: Vec<Address> = sent.iter().filter_map(|t| legacy_fee_payer(t)).collect();
        assert!(lock_payers.contains(&key0), "shard-0 key must pay a lock");
        assert!(lock_payers.contains(&key1), "shard-1 key must pay a lock");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_drives_all_jobs_to_done() {
        let url = spawn_mock_rpc().await;
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        seed_jobs(&state, 0, 2).await;
        let ctx = ctx_for(url, state.clone(), 2);

        // N=2 batch: two real matches, two witness slots.
        let inputs = BatchSettleInputs {
            batch_id: 0,
            matches: vec![
                MatchSettleInputs {
                    payload: payload(0xA0),
                    buyer_lock: lock_inputs(0x01),
                    seller_lock: lock_inputs(0x02),
                    match_index: 0,
                },
                MatchSettleInputs {
                    payload: payload(0xB0),
                    buyer_lock: lock_inputs(0x03),
                    seller_lock: lock_inputs(0x04),
                    match_index: 1,
                },
            ],
            witnesses: vec![dummy_slot(), dummy_slot()],
        };

        run_batch_settle(&ctx, inputs).await.expect("batch settle");

        let st = state.read().await;
        for idx in 0..2u8 {
            let job = st
                .get_job(&SettleJobId {
                    batch_id: 0,
                    match_idx: idx,
                })
                .expect("job present");
            assert_eq!(job.stage, SettleJobStage::Done, "match {idx} not Done");
            // Every stage's sig got recorded.
            assert!(job.lock_buyer_sig.is_some(), "match {idx} lock_buyer");
            assert!(job.lock_seller_sig.is_some(), "match {idx} lock_seller");
            assert!(job.verify_sig.is_some(), "match {idx} verify");
            assert!(job.settle_sig.is_some(), "match {idx} settle");
            // The marker close is now ASYNC (enqueued to the sweeper, closed
            // off-batch), so the worker no longer records a close sig on the job.
            assert!(job.close_sig.is_none(), "match {idx} close is async");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prover_failure_marks_jobs_failed() {
        // A prover that always errors → the batch fails, every job
        // ends Failed with the reason (no panic, no stuck Queued).
        struct BoomProver;
        impl Prover for BoomProver {
            fn prove(&self, _: &[MatchSlotWitness]) -> Result<ProofWithInputs, ProverError> {
                Err(ProverError::Prove("boom".into()))
            }
            fn n(&self) -> usize {
                2
            }
        }

        let url = spawn_mock_rpc().await;
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        seed_jobs(&state, 0, 1).await;
        let mut ctx = ctx_for(url, state.clone(), 2);
        ctx.prover = Arc::new(BoomProver);

        let inputs = BatchSettleInputs {
            batch_id: 0,
            matches: vec![MatchSettleInputs {
                payload: payload(0xA0),
                buyer_lock: lock_inputs(0x01),
                seller_lock: lock_inputs(0x02),
                match_index: 0,
            }],
            witnesses: vec![dummy_slot(), dummy_slot()],
        };

        let err = run_batch_settle(&ctx, inputs).await.unwrap_err();
        assert!(matches!(err, WorkerError::Prover(_)));

        let st = state.read().await;
        let job = st
            .get_job(&SettleJobId {
                batch_id: 0,
                match_idx: 0,
            })
            .unwrap();
        assert!(job.stage.is_terminal());
        match &job.stage {
            SettleJobStage::Failed { reason } => assert!(reason.contains("boom")),
            other => panic!("expected Failed, got {other:?}"),
        }
        // Locking happened (it precedes proving); proving failed, so
        // verify/settle/close never recorded sigs.
        assert!(job.lock_buyer_sig.is_some());
        assert!(job.verify_sig.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn more_matches_than_witnesses_is_rejected() {
        let url = spawn_mock_rpc().await;
        let state = Arc::new(RwLock::new(SettleSchedulerState::default()));
        seed_jobs(&state, 0, 2).await;
        let ctx = ctx_for(url, state, 2);

        let inputs = BatchSettleInputs {
            batch_id: 0,
            matches: vec![
                MatchSettleInputs {
                    payload: payload(0xA0),
                    buyer_lock: lock_inputs(0x01),
                    seller_lock: lock_inputs(0x02),
                    match_index: 0,
                },
                MatchSettleInputs {
                    payload: payload(0xB0),
                    buyer_lock: lock_inputs(0x03),
                    seller_lock: lock_inputs(0x04),
                    match_index: 1,
                },
            ],
            // Only one witness slot — fewer than the two matches.
            witnesses: vec![dummy_slot()],
        };

        let err = run_batch_settle(&ctx, inputs).await.unwrap_err();
        assert!(matches!(err, WorkerError::Mismatch(2, 1)));
    }
}
