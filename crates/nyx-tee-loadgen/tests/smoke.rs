//! End-to-end smoke test.
//!
//! Spins up a real `nyx-tee` instance in-process on an ephemeral
//! TCP port (built with `--features debug_endpoints`), boots the
//! `MatcherDriver`, then drives `run_load_gen` against it for a
//! few seconds. Asserts:
//!
//!   - submit success rate ≥ 95%
//!   - the matcher emitted at least one match (the workload is
//!     deliberately crossing — bids + asks both target prices
//!     around the seeded oracle midpoint, so most batches yield
//!     matches).
//!   - the rendered markdown report has the expected sections.
//!
//! This test proves the four 4e sub-PRs + the 4f debug endpoint +
//! the 4f.2 loadgen all compose. It's the load-bearing CI gate
//! for the whole 4f surface — if anything wire-level breaks, this
//! test fails fast.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use darkpool_matcher::config::MatchConfig;
use darkpool_matcher::match_result::RunBatchOutput;
use nyx_tee::api::{build_router, ApiState};
use nyx_tee::matcher::{DriverConfig, MatcherDriver, MatcherState, DEFAULT_MAX_ORACLE_AGE_MS};
use nyx_tee::oracle::OracleCache;
use nyx_tee_loadgen::config::{AuthMode, RunConfig, Scenario};
use nyx_tee_loadgen::run_load_gen;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

const FEED_ID: &str = "ef0d8b6fdac3e4cba65d8c1be8ea3b6b88c1d4e2c9d4d9b5e1d4a8e9f0a1b2c3";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loadgen_drives_real_tee_and_produces_matches() {
    // ─── 1. Shared runtime (mirrors main.rs's setup) ────────────────
    // Seed the matcher's market with the SAME mints the driver +
    // loadgen use (dev_match_config: base 0x..b1 / quote 0x..9e). The
    // order intake recomputes each note's collateral commitment with
    // `market_mints()` (bid→quote, ask→base), so the loadgen's signed
    // note_commitment only verifies if MatcherState carries these
    // mints — `MatcherState::new()` leaves them zeroed, which is what
    // made every submit 400 before.
    let match_config = dev_match_config();
    let matcher_state = Arc::new(RwLock::new(
        MatcherState::new().with_market(match_config.base_mint, match_config.quote_mint),
    ));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (matches_tx, mut matches_rx) = mpsc::channel::<RunBatchOutput>(64);

    let api_state = ApiState::for_tests().with_matcher_runtime(
        matcher_state.clone(),
        current_slot.clone(),
        oracle.clone(),
    );
    let app = build_router(Arc::new(api_state));

    // ─── 2. Spawn matcher driver ────────────────────────────────────
    let driver = MatcherDriver {
        state: matcher_state.clone(),
        oracle: oracle.clone(),
        current_slot: current_slot.clone(),
        matches_tx,
        cfg: DriverConfig {
            match_config: match_config.clone(),
            feed_id: FEED_ID.to_string(),
            // Fast tick for the smoke test so we see multiple
            // matching cycles during the 5-second run window.
            batch_ms: 300,
            max_oracle_age_ms: DEFAULT_MAX_ORACLE_AGE_MS,
            max_matches_per_batch: 16,
        },
    };
    let _driver_handle = driver.spawn();

    // ─── 3. Bind ephemeral port + spawn axum server ─────────────────
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve");
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ─── 4. Collector for matches the driver emits ──────────────────
    // We need to drain `matches_rx` so the driver doesn't
    // backpressure; count messages for the assertion.
    let match_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mc = match_counter.clone();
    let collector = tokio::spawn(async move {
        while let Some(out) = matches_rx.recv().await {
            mc.fetch_add(
                out.matches.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    });

    // ─── 5. Run the loadgen ─────────────────────────────────────────
    let cfg = RunConfig {
        endpoint: format!("http://{}", addr),
        traders: 10,
        orders_per_trader_per_sec: 5.0,
        duration_secs: 5,
        scenario: Scenario::ExactMatch,
        // Placeholder dev mints (the in-process matcher's dev_match_config).
        base_mint: "01000000000000000000000000000000000000000000000000000000000000b1".to_string(),
        quote_mint: "010000000000000000000000000000000000000000000000000000000000009e".to_string(),
        symbol: "SOL-USDC".to_string(),
        over_collateral_bps: 2000,
        status_preflight: false,
        poll_orders: 0.0,
        real_settle: false,
        rpc_url: None,
        admin_keypair: None,
        circuits_dir: "circuits/build".to_string(),
        real_num_trees: 4,
        real_qty: 2000,
        real_mix: "exact-match:100".to_string(),
        real_multi_anchor_asks: 3,
        cancel_rate: 0.20,
        auth_mode: AuthMode::PerTrader,
        feed_id: FEED_ID.to_string(),
        seed_oracle: true,
        oracle_twap: 150_000_000,
        oracle_exponent: -8,
        report: None,
        api_key: "nyx-test-api-key".to_string(),
        api_secret: "nyx-test-secret".to_string(),
        passphrase: "nyx-test-passphrase".to_string(),
        // Matches the in-process MatchConfig (fee_rate_bps = 0) so the
        // synthetic note_amount = nominal (fee-free) lines up with intake.
        fee_rate_bps: 0,
        // Far above the in-process matcher's current_slot so orders
        // aren't swept as expired before they match.
        expiry_slot: 2_000_000_000,
    };

    let outcome = run_load_gen(cfg).await.expect("loadgen run completed");

    // Give the matcher driver a few extra ticks to drain anything
    // pending in the book after the last submit.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // ─── 6. Assertions ─────────────────────────────────────────────
    let counters = outcome.metrics.snapshot_counters();
    eprintln!("smoke counters: {counters:#?}");
    eprintln!("smoke report:\n{}", outcome.markdown_report);

    assert!(
        counters.submits_total > 50,
        "expected ≥ 50 total submits over 5s × 10 × 5/s; got {}",
        counters.submits_total
    );
    // All 10 traders authenticate as the SAME account, so the per-account rate
    // limiter (added in the API-hardening phase) throttles part of the 50/s
    // flood with 429s — that's the limiter working as designed, NOT a loadgen
    // failure (the trader backs off on Retry-After). So exclude 429s from the
    // success metric, but DO assert there are no OTHER (real intake) 4xx — a
    // commitment/nonce/auth regression would show up there.
    let real_4xx = counters.submits_4xx.saturating_sub(counters.submits_429);
    assert_eq!(
        real_4xx, 0,
        "unexpected non-429 client errors ({real_4xx}) — an intake regression? see counters above"
    );
    let non_throttled = counters.submits_total.saturating_sub(counters.submits_429);
    let success_rate = if non_throttled > 0 {
        counters.submits_ok as f64 / non_throttled as f64
    } else {
        0.0
    };
    assert!(
        success_rate >= 0.95,
        "non-throttled submit success rate {:.2}% below 95% — see counters above",
        100.0 * success_rate
    );

    let matches_seen = match_counter.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        matches_seen > 0,
        "matcher never emitted a match. submits_ok={}",
        counters.submits_ok
    );

    // Spot-check the report has the expected section headers.
    assert!(outcome
        .markdown_report
        .contains("# nyx-tee-loadgen benchmark"));
    assert!(outcome.markdown_report.contains("## Throughput"));
    assert!(outcome.markdown_report.contains("## Submit outcomes"));
    assert!(outcome.markdown_report.contains("## Latency (ms)"));

    // ─── 7. Shut down ──────────────────────────────────────────────
    server_handle.abort();
    collector.abort();
}

fn dev_match_config() -> MatchConfig {
    let mut base_mint = [0u8; 32];
    base_mint[0] = 1;
    base_mint[31] = 0xb1;
    let mut quote_mint = [0u8; 32];
    quote_mint[0] = 1;
    quote_mint[31] = 0x9e;
    MatchConfig {
        base_mint,
        quote_mint,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 100_000,
        batch_ms: 300,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}
