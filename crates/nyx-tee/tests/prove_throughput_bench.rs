//! Local prover-throughput bench — informs the "parallel provers vs on-chain
//! settle-batching" decision (see the settle-latency perf work).
//!
//! Measures two things with the REAL N=16 VALID_MATCH_BATCH prover:
//!   1. SINGLE-prove latency → the serial prover ceiling (proves/s, matches/s
//!      at the full N=16 batch). This is what the pipelined scheduler tops out
//!      at, since the prover is serial.
//!   2. CONCURRENT-prove headroom → run M independent prover instances at once
//!      and compare the wall-clock to M× the single-prove time. If the M proves
//!      run nearly for free (effective parallelism ≈ M), one prove leaves cores
//!      idle → MORE prover instances on the same box would raise throughput
//!      (parallel provers help locally). If they serialize (≈ 1×), one prove
//!      already saturates the cores → parallel provers need MORE hardware (a
//!      bigger box / GPU), not more instances.
//!
//! ark backend (always available; rapidsnark is core-bound the same way). The
//! ABSOLUTE numbers are for THIS host (an arm64 Mac ≠ the 8-vCPU TDX CVM); the
//! decision-relevant signal is the *ratio* (effective parallelism), which is
//! architectural and transfers.
//!
//! Gated behind RUN_PROVE_BENCH=1 + artifact presence. Run in --release:
//! ```sh
//! RUN_PROVE_BENCH=1 cargo test -p nyx-tee --release \
//!   --test prove_throughput_bench -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use darkpool_matcher::match_result::{MatchPair, MatchStatus};
use nyx_tee::matcher::openings::NoteOpening;
use nyx_tee::prover::{pad_batch, ArkMatchBatchProver, MatchSlotWitness, PRODUCTION_BATCH_N};
use nyx_tee::settle::{assemble_match, MatchAssemblyInputs};

fn circuits_build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("circuits")
        .join("build")
}

fn n16_artifacts_present(build_dir: &Path) -> bool {
    let base = build_dir.join("match_batch_n16");
    base.join("circuit_js").join("circuit.wasm").exists()
        && base.join("circuit_final.zkey").exists()
        && base.join("circuit.r1cs").exists()
}

fn fr_safe(b: u8) -> [u8; 32] {
    let mut v = [b; 32];
    v[0] = 0;
    v
}
fn base_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0xb1;
    m
}
fn quote_mint() -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = 1;
    m[31] = 0x9e;
    m
}

/// One consistent exact-fill match + its two input-note openings (same fixture
/// the n16_assemble_prove_verify test uses), assembled + padded to N=16.
fn build_slots() -> Vec<MatchSlotWitness> {
    let buyer = NoteOpening {
        token_mint: quote_mint(),
        amount: 1000,
        owner_commitment: fr_safe(0x44),
        inner_hash: fr_safe(0x11),
        nullifier: [0xAA; 32],
    };
    let seller = NoteOpening {
        token_mint: base_mint(),
        amount: 10,
        owner_commitment: fr_safe(0x55),
        inner_hash: fr_safe(0x33),
        nullifier: [0xBB; 32],
    };
    let note_buyer = buyer.commitment().unwrap();
    let note_seller = seller.commitment().unwrap();
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
    let (witness, _payload) = assemble_match(MatchAssemblyInputs {
        match_pair: &m,
        buyer_opening: &buyer,
        seller_opening: &seller,
        order_id_a: [0x01; 16],
        order_id_b: [0x02; 16],
        base_mint: base_mint(),
        quote_mint: quote_mint(),
        protocol_owner_commitment: fr_safe(0x07),
        price_scale: 1,
        // Single real match → batch index 0 (C-08: batch_slot[0] === 0).
        slot_index: 0,
        fee_rate_bps: 0,
    })
    .expect("assemble the match");
    pad_batch(&[witness], PRODUCTION_BATCH_N).expect("pad to N=16")
}

async fn prove_once(prover: Arc<ArkMatchBatchProver>, slots: Arc<Vec<MatchSlotWitness>>) {
    // Same offload the settle worker uses: prove on a blocking thread.
    tokio::task::spawn_blocking(move || prover.prove_ark(&slots))
        .await
        .expect("prove task join")
        .expect("prove");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prove_throughput() {
    if std::env::var("RUN_PROVE_BENCH").ok().as_deref() != Some("1") {
        eprintln!("skipping prove_throughput: set RUN_PROVE_BENCH=1 to run (use --release)");
        return;
    }
    let build_dir = circuits_build_dir();
    if !n16_artifacts_present(&build_dir) {
        eprintln!("skipping prove_throughput: match_batch_n16 artifacts absent");
        return;
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let slots = Arc::new(build_slots());
    eprintln!("BENCH host_cores={cores} backend=ark batch_n={PRODUCTION_BATCH_N}");

    // ── 1. Single-prove ceiling (median of K, after a warmup) ──
    let prover = Arc::new(ArkMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load"));
    prove_once(prover.clone(), slots.clone()).await; // warm caches
    const K: usize = 5;
    let mut ms: Vec<u64> = Vec::with_capacity(K);
    for _ in 0..K {
        let t = Instant::now();
        prove_once(prover.clone(), slots.clone()).await;
        ms.push(t.elapsed().as_millis() as u64);
    }
    ms.sort_unstable();
    let single = ms[K / 2].max(1);
    eprintln!(
        "BENCH single: median_ms={single} all_ms={ms:?} proves_per_s={:.2} matches_per_s={:.1}",
        1000.0 / single as f64,
        16.0 * 1000.0 / single as f64,
    );

    // ── 2. Concurrent-prove headroom (the parallel-provers signal) ──
    for m in [2usize, 4] {
        let provers: Vec<Arc<ArkMatchBatchProver>> = (0..m)
            .map(|_| {
                Arc::new(ArkMatchBatchProver::load(&build_dir, PRODUCTION_BATCH_N).expect("load"))
            })
            .collect();
        let t = Instant::now();
        let mut handles = Vec::with_capacity(m);
        for p in &provers {
            handles.push(tokio::spawn(prove_once(p.clone(), slots.clone())));
        }
        for h in handles {
            h.await.expect("join");
        }
        let wall = (t.elapsed().as_millis() as u64).max(1);
        // ≈ m  → proves ran in parallel for free (cores idle under 1 prove)
        // ≈ 1  → proves serialized (1 prove already saturates the cores)
        let eff_par = (m as f64 * single as f64) / wall as f64;
        eprintln!(
            "BENCH concurrent m={m}: wall_ms={wall} per_prove_ms={} effective_parallelism={eff_par:.2}x_of_{m}",
            wall / m as u64,
        );
    }
    eprintln!(
        "BENCH interpretation: effective_parallelism near m => idle cores => parallel provers \
         help on ONE box; near 1 => one prove saturates cores => parallel provers need MORE \
         hardware (bigger box / GPU)."
    );
}
