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

    let base_mint = cfg.base_mint_bytes()?;
    let quote_mint = cfg.quote_mint_bytes()?;

    // ─── 0. Status preflight — fail fast on a degraded / misconfigured CVM ──
    // Also capture the live current_slot so `--expiry-slot 0` (auto) can place
    // orders within MAX_LOCK_TTL_SLOTS of it (F-05).
    let mut live_slot: Option<u64> = None;
    if cfg.status_preflight {
        let url = format!("{}/system/status", cfg.endpoint);
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                live_slot = body.get("current_slot").and_then(|v| v.as_u64());
                let degraded = body
                    .get("degraded")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                tracing::info!(
                    degraded,
                    matcher_running = ?body.get("matcher_running"),
                    settle_enabled = ?body.get("settle_enabled"),
                    current_slot = ?body.get("current_slot"),
                    "preflight /system/status"
                );
                if degraded {
                    anyhow::bail!(
                        "CVM reports degraded (matcher/settle down) — aborting. \
                         Pass --no-status-preflight to override."
                    );
                }
            }
            Ok(resp) => tracing::warn!(
                status = %resp.status(),
                "preflight /system/status non-200 (older CVM?); continuing"
            ),
            Err(e) => tracing::warn!(error = %e, "preflight /system/status failed; continuing"),
        }
    }

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

    // Resolve the order expiry. `--expiry-slot 0` (default) = auto: the live
    // slot + a safe offset inside MAX_LOCK_TTL_SLOTS (F-05), so intake accepts
    // it (`expiry_too_far` otherwise). An explicit value is used as-is.
    const AUTO_EXPIRY_OFFSET_SLOTS: u64 = 4_000; // < MAX_LOCK_TTL_SLOTS (4_500)
    let order_expiry_slot = if cfg.expiry_slot == 0 {
        let slot = match live_slot {
            Some(s) => s,
            None => {
                let body: serde_json::Value = http
                    .get(format!("{}/system/status", cfg.endpoint))
                    .send()
                    .await?
                    .json()
                    .await
                    .unwrap_or_default();
                body.get("current_slot")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "could not read current_slot to auto-resolve order expiry; \
                             pass --expiry-slot <live_slot + up to 4000> explicitly"
                        )
                    })?
            }
        };
        slot + AUTO_EXPIRY_OFFSET_SLOTS
    } else {
        cfg.expiry_slot
    };
    tracing::info!(order_expiry_slot, "resolved order expiry (F-05 cap-aware)");

    // ─── 3. Spawn traders ─────────────────────────────────────────
    let cfg_arc = Arc::new(cfg.clone());
    let metrics = RunMetrics::new();
    let start = Instant::now();
    let deadline = TokioInstant::now() + cfg.duration();

    let mut handles = Vec::with_capacity(cfg.traders);
    for (idx, bearer) in bearers.into_iter().enumerate() {
        let workload = make_workload(
            cfg.scenario,
            cfg.oracle_twap,
            order_expiry_slot,
            cfg.symbol.clone(),
            cfg.over_collateral_bps,
            idx as u64,
        );
        let ctx = TraderCtx {
            idx,
            http: http.clone(),
            endpoint: cfg.endpoint.clone(),
            bearer,
            cancel_rate: cfg.cancel_rate,
            cfg: cfg_arc.clone(),
            metrics: metrics.clone(),
            base_mint,
            quote_mint,
        };
        handles.push(tokio::spawn(trader_task(ctx, workload, deadline)));
    }

    // ─── 4. Wait for traders to finish ────────────────────────────
    // Surface (don't swallow) a panicked/cancelled trader task — a
    // silently-dropped JoinError would skew the benchmark numbers.
    for (i, h) in handles.into_iter().enumerate() {
        if let Err(e) = h.await {
            tracing::warn!(trader = i, error = %e, "trader task did not exit cleanly");
        }
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
