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

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_signer::Signer;
use tokio::sync::RwLock;

use super::alt::{alt_account, build_per_batch_alt_ixs};
use super::close_marker::build_close_marker_ix;
use super::ed25519::build_ed25519_verify_ix;
use super::job::{SettleJobId, SettleJobStage};
use super::payload::MatchResultPayload;
use super::pipeline::build_settle_v0_tx_b64;
use super::scheduler::SettleSchedulerState;
use super::settle_batched::{build_settle_batched_ix, per_batch_alt_addresses};
use super::sign::sign_payload;
use super::submit::{confirm_signatures, submit_ixs, submit_ixs_with_blockhash};
use super::submit_lock::{confirm_lock_pair, submit_lock_note_pair, LockSideInputs};
use super::verify_match_batch::{build_verify_match_batch_ix, VerifyMatchBatchArgs};
use crate::prover::{merkle_inclusion_path, MatchSlotWitness, Prover};
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
    /// Marker TTL for `verify_match_batch`.
    pub expiry_slot: u64,
}

/// Shared context the worker holds across a batch.
pub struct SettleWorkerCtx {
    pub rpc: SolanaRpcClient,
    /// TEE keypair — fee-payer + `tee_authority` for every tx.
    pub tee_keypair: Arc<Keypair>,
    /// Ed25519 signing key (same key material) for the settle
    /// payload signature inlined into the precompile ix.
    pub signing_key: Arc<SigningKey>,
    /// The Groth16 prover. `Arc<dyn Prover>` so the backend
    /// (ark-circom now, rapidsnark later) is swappable + so tests
    /// inject a fast fake.
    pub prover: Arc<dyn Prover>,
    /// The static settle ALT (vault_config / instructions_sysvar /
    /// system_program), created at devnet-setup. `None` until that
    /// lands — the worker then relies on the per-batch ALT alone
    /// (slightly larger tx, still under cap for small batches).
    pub static_alt: Option<solana_message::AddressLookupTableAccount>,
    /// Shared scheduler state — the worker updates job stages here.
    pub settle_state: Arc<RwLock<SettleSchedulerState>>,
    /// Per-leg confirmation timeout.
    pub confirm_timeout: Duration,
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
}

impl SettleWorkerCtx {
    fn tee_pubkey(&self) -> Address {
        self.tee_keypair.pubkey()
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
            st.update(&id, |j| j.fail(reason.clone()));
        }
    }
}

/// Drive one batch through the full settle pipeline. On any error
/// the batch's jobs are marked `Failed` with the reason; on success
/// they end at `Done`.
pub async fn run_batch_settle(
    ctx: &SettleWorkerCtx,
    inputs: BatchSettleInputs,
) -> Result<(), WorkerError> {
    let n = inputs.matches.len();
    if n == 0 {
        return Ok(());
    }
    let batch_id = inputs.batch_id;

    let result = run_batch_settle_inner(ctx, &inputs).await;
    if let Err(e) = &result {
        ctx.fail_all(batch_id, n, format!("{e}")).await;
    }
    result
}

async fn run_batch_settle_inner(
    ctx: &SettleWorkerCtx,
    inputs: &BatchSettleInputs,
) -> Result<(), WorkerError> {
    let batch_id = inputs.batch_id;
    let n = inputs.matches.len();
    let tee_pubkey = ctx.tee_pubkey();

    // A batch can't have more real matches than the witness set has
    // slots — the matcher pads up to N, never down.
    if n > inputs.witnesses.len() {
        return Err(WorkerError::Mismatch(n, inputs.witnesses.len()));
    }

    // ── 1. Lock notes (Tx A) ────────────────────────────────────
    ctx.set_all_stages(batch_id, n, SettleJobStage::LockingNotes)
        .await;
    for (idx, m) in inputs.matches.iter().enumerate() {
        let outcome = submit_lock_note_pair(
            &ctx.rpc,
            &ctx.tee_keypair,
            m.buyer_lock.clone(),
            m.seller_lock.clone(),
        )
        .await?;
        confirm_lock_pair(&ctx.rpc, &outcome, ctx.confirm_timeout).await?;
        let id = SettleJobId {
            batch_id,
            match_idx: idx as u8,
        };
        let mut st = ctx.settle_state.write().await;
        st.update(&id, |j| {
            j.lock_buyer_sig = Some(outcome.buyer_sig.clone());
            j.lock_seller_sig = Some(outcome.seller_sig.clone());
        });
    }

    // ── 2. Prove the batch (spawn_blocking) ─────────────────────
    ctx.set_all_stages(batch_id, n, SettleJobStage::Proving)
        .await;
    let prover = ctx.prover.clone();
    let witnesses = inputs.witnesses.clone();
    let proof_out = tokio::task::spawn_blocking(move || prover.prove(&witnesses))
        .await
        .map_err(|e| WorkerError::ProverPanic(e.to_string()))?
        .map_err(|e| WorkerError::Prover(format!("{e}")))?;
    let proof_bytes = proof_out.proof;
    let leaves = proof_out.public.leaves;
    let merkle_root = proof_out.public.merkle_root;

    // ── 3. verify_match_batch (Tx B) + per-batch ALT (Tx C) ─────
    ctx.set_all_stages(batch_id, n, SettleJobStage::Verifying)
        .await;
    // BatchValidityMarker expiry is bounded on BOTH sides by
    // verify_match_batch.rs: it must be (a) strictly in the future AND
    // (b) within MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS (= 300) of the
    // on-chain clock. Stamp it from a slot fetched FRESH here, not from
    // `inputs.expiry_slot` (which the scheduler computes from the
    // background slot poller's cached value — if that lags/stalls the
    // lower bound reverts). The margin must stay UNDER 300 (a margin of
    // 1000 overshot the upper bound — same InvalidMarkerExpiry code from
    // the other side); 250 leaves ~50 slots of headroom against the cap
    // for confirmed-commitment lag + verify-tx landing, and still gives
    // ~200 slots (~80 s) of settle runway after verify lands.
    const MARKER_EXPIRY_MARGIN_SLOTS: u64 = 250;
    let marker_slot = ctx.rpc.get_latest_blockhash().await?.context_slot;
    let verify_ix = build_verify_match_batch_ix(
        &tee_pubkey,
        VerifyMatchBatchArgs {
            merkle_root,
            expiry_slot: marker_slot.saturating_add(MARKER_EXPIRY_MARGIN_SLOTS),
            proof: proof_bytes,
        },
    );
    let verify_sig = submit_ixs(&ctx.rpc, &ctx.tee_keypair, &[verify_ix]).await?;
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

    // Per-batch ALT: covers note_lock_a/b/e/f + marker for the
    // FIRST match. (A multi-match batch ALT pool is 4g.7+; here the
    // ALT addresses are derived from match 0's payload — sufficient
    // for the single-match settle path the tests exercise.)
    let bh = ctx.rpc.get_latest_blockhash().await?;
    let alt_addrs = per_batch_alt_addresses(&inputs.matches[0].payload, &merkle_root);
    // `CreateLookupTable` rejects a `recent_slot` not present in the
    // SlotHashes sysvar of the bank that processes it. A load-balanced
    // RPC (Helius) can answer getLatestBlockhash from a replica a few
    // slots AHEAD of the one that runs preflight simulation, so the
    // confirmed `context_slot` lands "in the future" for the simulating
    // bank → "is not a recent slot" / InvalidInstructionData. Back off a
    // small margin so the slot is already rooted on any replica; 32 is
    // far within the 512-slot SlotHashes window so it can't age out
    // before the tx lands.
    const ALT_RECENT_SLOT_BACKOFF: u64 = 32;
    let alt_recent_slot = bh.context_slot.saturating_sub(ALT_RECENT_SLOT_BACKOFF);
    let alt_build = build_per_batch_alt_ixs(&tee_pubkey, alt_recent_slot, &alt_addrs);
    let alt_sig = submit_ixs_with_blockhash(
        &ctx.rpc,
        &ctx.tee_keypair,
        &alt_build.ixs,
        Hash::new_from_array(bh.blockhash),
    )
    .await?;
    confirm_signatures(&ctx.rpc, &[alt_sig], ctx.confirm_timeout).await?;
    let per_batch_alt = alt_account(alt_build.alt_address, alt_addrs);

    // A freshly extended ALT's addresses are NOT loadable until the
    // slot AFTER the extend lands. Sending Tx D immediately makes the
    // leader fail to resolve the ALT lookups and silently drop the tx —
    // it never confirms (the "did not confirm within 60s: [None]"
    // symptom). Wait until the chain advances past the slot at which we
    // observed the extend confirmed. Mirrors the SDK settleViaBatched
    // slot-wait. (We can't reuse `alt_recent_slot` here — the -32
    // backoff puts it in the past, so it'd be an instant no-op.)
    let alt_landed_slot = ctx.rpc.get_latest_blockhash().await?.context_slot;
    for _ in 0..30 {
        if ctx.rpc.get_latest_blockhash().await?.context_slot > alt_landed_slot {
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    // ── 4. Settle each match (Tx D, v0) ─────────────────────────
    ctx.set_all_stages(batch_id, n, SettleJobStage::Settling)
        .await;
    let mut alts = Vec::new();
    if let Some(static_alt) = &ctx.static_alt {
        alts.push(static_alt.clone());
    }
    alts.push(per_batch_alt);

    for (idx, m) in inputs.matches.iter().enumerate() {
        let path = merkle_inclusion_path(&leaves, m.match_index as usize)
            .map_err(|e| WorkerError::Leaf(format!("{e}")))?;
        // The on-chain ix takes a fixed [[u8;32];4]; pad the path
        // (a smaller-N test tree has fewer levels — left-pad with
        // zeros, which the handler ignores beyond the real depth).
        let mut siblings = [[0u8; 32]; 4];
        for (i, s) in path.siblings.iter().take(4).enumerate() {
            siblings[i] = *s;
        }

        let (msg, sig) = sign_payload(&ctx.signing_key, &m.payload);
        let ed_ix = build_ed25519_verify_ix(&ctx.tee_keypair.pubkey().to_bytes(), &sig, &msg);
        let settle_ix = build_settle_batched_ix(
            &tee_pubkey,
            &m.payload,
            m.match_index,
            &siblings,
            &merkle_root,
        );

        let bh = ctx.rpc.get_latest_blockhash().await?;
        let tx_b64 = build_settle_v0_tx_b64(
            &ctx.tee_keypair,
            ed_ix,
            settle_ix,
            &alts,
            Hash::new_from_array(bh.blockhash),
        )?;
        let settle_sig = ctx.rpc.send_transaction(&tx_b64).await?;
        confirm_signatures(
            &ctx.rpc,
            std::slice::from_ref(&settle_sig),
            ctx.confirm_timeout,
        )
        .await?;

        let id = SettleJobId {
            batch_id,
            match_idx: idx as u8,
        };
        let mut st = ctx.settle_state.write().await;
        st.update(&id, |j| j.settle_sig = Some(settle_sig.clone()));
    }

    // ── 5. Close the marker (Tx E), once ────────────────────────
    ctx.set_all_stages(batch_id, n, SettleJobStage::Closing)
        .await;
    let close_ix = build_close_marker_ix(&tee_pubkey, &tee_pubkey, &merkle_root);
    let close_sig = submit_ixs(&ctx.rpc, &ctx.tee_keypair, &[close_ix]).await?;
    confirm_signatures(
        &ctx.rpc,
        std::slice::from_ref(&close_sig),
        ctx.confirm_timeout,
    )
    .await?;

    // ── Done ────────────────────────────────────────────────────
    {
        let mut st = ctx.settle_state.write().await;
        for idx in 0..n {
            let id = SettleJobId {
                batch_id,
                match_idx: idx as u8,
            };
            st.update(&id, |j| {
                j.close_sig = Some(close_sig.clone());
                j.transition(SettleJobStage::Done);
            });
        }
    }
    Ok(())
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
                "getLatestBlockhash" => json!({
                    "context": { "slot": 1000 },
                    "value": {
                        "blockhash": bs58::encode([7u8; 32]).into_string(),
                        "lastValidBlockHeight": 2000u64,
                    }
                }),
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

    fn proof_bytes() -> Groth16ProofBytes {
        Groth16ProofBytes {
            pi_a: [0x11; 64],
            pi_b: [0x22; 128],
            pi_c: [0x33; 64],
        }
    }

    fn lock_inputs(seed: u8) -> LockSideInputs {
        LockSideInputs {
            note_commitment: [seed; 32],
            order_id: [seed; 16],
            expiry_slot: 2000,
            amount: 100,
            token_mint: [0xCC; 32],
            merkle_root: [0xDD; 32],
            proof: proof_bytes(),
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
            nullifier_a: [seed.wrapping_add(4); 32],
            nullifier_b: [seed.wrapping_add(5); 32],
            order_id_a: [seed; 16],
            order_id_b: [seed.wrapping_add(1); 16],
            base_amount: 100,
            quote_amount: 5_000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            clearing_price: 50,
            batch_slot: 7,
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
            tee_keypair: Arc::new(Keypair::new_from_array([0x42; 32])),
            signing_key: Arc::new(SigningKey::from_bytes(&[0x42; 32])),
            prover: Arc::new(FakeProver { n }),
            static_alt: None,
            settle_state: state,
            confirm_timeout: Duration::from_secs(5),
        }
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
            expiry_slot: 2000,
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
            assert!(job.close_sig.is_some(), "match {idx} close");
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
            expiry_slot: 2000,
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
            expiry_slot: 2000,
        };

        let err = run_batch_settle(&ctx, inputs).await.unwrap_err();
        assert!(matches!(err, WorkerError::Mismatch(2, 1)));
    }
}
