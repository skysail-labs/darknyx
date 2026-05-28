//! Top-level loadgen entry point.
//!
//! `run_load_gen` is the library function the binary's `main` and
//! the smoke test both call. It:
//!
//!   1. Acquires bearer tokens per `RunConfig::auth_mode`.
//!   2. (Optionally) seeds the oracle via `POST /__debug/oracle/seed`.
//!   3. Spawns N trader tasks, each with its own workload + signing
//!      key + RNG.
//!   4. Waits for the duration to elapse.
//!   5. Renders the markdown report.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use tokio::time::Instant as TokioInstant;

use crate::auth::acquire_bearer;
use crate::config::{AuthMode, RunConfig};
use crate::metrics::RunMetrics;
use crate::report::{render_markdown, ReportInputs};
use crate::trader::{trader_task, TraderCtx};
use crate::workload::make_workload;

pub struct RunOutcome {
    pub metrics: Arc<RunMetrics>,
    pub markdown_report: String,
}

pub async fn run_load_gen(cfg: RunConfig) -> Result<RunOutcome> {
    let http = Client::builder()
        .pool_max_idle_per_host(cfg.traders.max(8))
        .build()?;

    // ─── 1. Bearer acquisition ────────────────────────────────────
    let bearers = match cfg.auth_mode {
        AuthMode::Shared => {
            let token = acquire_bearer(
                &http,
                &cfg.endpoint,
                &cfg.api_key,
                &cfg.api_secret,
                &cfg.passphrase,
            )
            .await?;
            vec![token; cfg.traders]
        }
        AuthMode::PerTrader => {
            // All authenticate against the same test account in
            // v1 (the only one seeded by `ApiState::for_tests` /
            // any Phala devnet boot). The per-trader story is
            // about distinct bearer issuance — each call goes
            // through Layer A independently. Real multi-account
            // mode is a future PR (`--accounts-csv`).
            let mut out = Vec::with_capacity(cfg.traders);
            for _ in 0..cfg.traders {
                out.push(
                    acquire_bearer(
                        &http,
                        &cfg.endpoint,
                        &cfg.api_key,
                        &cfg.api_secret,
                        &cfg.passphrase,
                    )
                    .await?,
                );
            }
            out
        }
    };
    tracing::info!(
        traders = cfg.traders,
        mode = ?cfg.auth_mode,
        "acquired bearer tokens"
    );

    // ─── 2. Optional oracle seed (local-simulator only) ───────────
    if cfg.seed_oracle {
        let url = format!("{}/__debug/oracle/seed", cfg.endpoint);
        let body = json!({
            "feed_id": cfg.feed_id,
            "twap": cfg.oracle_twap,
            "confidence": 0u64,
            "exponent": cfg.oracle_exponent,
        });
        let resp = http.post(&url).json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!(
                "oracle seed POST {url} returned {status} — \
                 is the TEE built with --features debug_endpoints?"
            );
        }
        tracing::info!(feed_id = cfg.feed_id, "oracle seeded via debug endpoint");
    }

    // ─── 3. Spawn traders ─────────────────────────────────────────
    let cfg_arc = Arc::new(cfg.clone());
    let metrics = RunMetrics::new();
    let start = Instant::now();
    let deadline = TokioInstant::now() + cfg.duration();

    let mut handles = Vec::with_capacity(cfg.traders);
    for (idx, bearer) in bearers.into_iter().enumerate() {
        let workload = make_workload(cfg.workload, cfg.oracle_twap);
        let ctx = TraderCtx {
            idx,
            http: http.clone(),
            endpoint: cfg.endpoint.clone(),
            bearer,
            cancel_rate: cfg.cancel_rate,
            cfg: cfg_arc.clone(),
            metrics: metrics.clone(),
        };
        handles.push(tokio::spawn(trader_task(ctx, workload, deadline)));
    }

    // ─── 4. Wait for traders to finish ────────────────────────────
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed();
    tracing::info!(
        elapsed_s = elapsed.as_secs_f64(),
        submits_total = metrics
            .submits_total
            .load(std::sync::atomic::Ordering::Relaxed),
        "loadgen run complete"
    );

    // ─── 5. Render report ────────────────────────────────────────
    let markdown = render_markdown(ReportInputs {
        cfg: &cfg,
        metrics: &metrics,
        elapsed,
    })
    .await;

    Ok(RunOutcome {
        metrics,
        markdown_report: markdown,
    })
}
