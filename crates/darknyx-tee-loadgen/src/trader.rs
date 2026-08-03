//! Per-virtual-trader state machine.
//!
//! Runs in its own tokio task. Wakes up every
//! `RunConfig::submit_interval()`, samples one [`OrderIntent`]
//! from its workload, signs it, and POSTs `/orders`. With
//! probability `cancel_rate` it follows up by cancelling a
//! previously-placed order (drawn from the in-flight set).
//!
//! Each trader holds its OWN signing key + its OWN arrival_nonce
//! counter — the matcher sees them as distinct traders.
//!
//! The deadline is checked at the top of every iteration so the
//! trader exits promptly when the run's duration elapses.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::Rng;
use rand::SeedableRng;
use reqwest::Client;
use tokio::time::Instant as TokioInstant;

use crate::auth::{build_signed_cancel_body, build_signed_place_body};
use crate::config::RunConfig;
use crate::metrics::{CancelOutcome, RunMetrics, SubmitOutcome};
use crate::workload::Workload;

/// Per-trader handle held by the run driver. The task itself runs
/// inside `trader_task`.
pub struct TraderHandle {
    pub idx: usize,
}

#[derive(Clone)]
pub struct TraderCtx {
    pub idx: usize,
    pub http: Client,
    pub endpoint: String,
    pub bearer: String,
    pub cancel_rate: f64,
    pub cfg: Arc<RunConfig>,
    pub metrics: Arc<RunMetrics>,
    /// ASK-side collateral mint (parsed from `--base-mint`).
    pub base_mint: [u8; 32],
    /// BID-side collateral mint (parsed from `--quote-mint`).
    pub quote_mint: [u8; 32],
    /// Fresh process-boot session fetched from `/info` for this run.
    pub boot_session_id: [u8; 32],
}

pub async fn trader_task(ctx: TraderCtx, mut workload: Box<dyn Workload>, deadline: TokioInstant) {
    let signing_key = {
        let mut seed = [0u8; 32];
        // Deterministic per-trader seed → reproducible runs. The
        // first 8 bytes encode the trader idx so distinct traders
        // get distinct keys.
        seed[..8].copy_from_slice(&(ctx.idx as u64).to_le_bytes());
        SigningKey::from_bytes(&seed)
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xA0A0A0 ^ ctx.idx as u64);

    // Order-id counter scoped per trader. We bake the trader idx
    // into the order_id's first 4 bytes so collisions across
    // traders are structurally impossible.
    let mut order_id_counter: u64 = 1;
    let mut arrival_nonce: u64 = 1;

    // Recent-orders FIFO — what we'd cancel. Bounded so a long-
    // running trader doesn't accumulate forever.
    let mut recent_order_ids: VecDeque<[u8; 16]> = VecDeque::with_capacity(64);

    let mut ticker = tokio::time::interval(ctx.cfg.submit_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Tick + deadline check. select! so the trader exits the
        // instant the deadline passes — doesn't wait for the next
        // ticker fire.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = tokio::time::sleep_until(deadline) => break,
        }
        if TokioInstant::now() >= deadline {
            break;
        }

        // Maybe cancel an in-flight order (don't drop into the
        // submit branch — keeps the per-trader rate honest).
        let do_cancel =
            !recent_order_ids.is_empty() && rng.gen_bool(ctx.cancel_rate.clamp(0.0, 1.0));
        if do_cancel {
            // Pick a random in-flight order to cancel.
            let pick_idx = rng.gen_range(0..recent_order_ids.len());
            let order_id = recent_order_ids.remove(pick_idx).expect("idx in range");
            run_cancel(&ctx, &signing_key, order_id, arrival_nonce).await;
            arrival_nonce = arrival_nonce.wrapping_add(1);
            continue;
        }

        // Submit a new order.
        let intent = workload.sample();
        let order_id = build_order_id(ctx.idx as u32, order_id_counter);
        order_id_counter = order_id_counter.wrapping_add(1);

        let body = build_signed_place_body(
            &signing_key,
            intent.side,
            intent.order_type,
            intent.amount,
            intent.price_limit,
            intent.expiry_slot,
            order_id,
            arrival_nonce,
            &intent.symbol,
            ctx.cfg.fee_rate_bps,
            ctx.cfg.price_scale,
            &ctx.base_mint,
            &ctx.quote_mint,
            intent.collateral_surplus_bps,
            ctx.boot_session_id,
        );
        arrival_nonce = arrival_nonce.wrapping_add(1);

        let submit_at = Instant::now();
        let outcome = run_submit(&ctx, &body).await;
        if matches!(outcome, SubmitOutcome::Ok) {
            // Track for potential cancel later. Drop oldest if
            // we're at capacity.
            if recent_order_ids.len() == recent_order_ids.capacity() {
                recent_order_ids.pop_front();
            }
            recent_order_ids.push_back(order_id);

            // Observability: sample a fraction of accepted orders and measure
            // submit→match latency via GET /orders/{id}, into match_latency_us.
            // Spawned (not awaited) so the bounded poll loop never skews this
            // trader's submit throughput; sampling bounds the spawned-task count.
            if ctx.cfg.poll_orders > 0.0 && rng.gen_bool(ctx.cfg.poll_orders.clamp(0.0, 1.0)) {
                spawn_match_poll(ctx.clone(), order_id, submit_at);
            }
        }
    }
}

async fn run_submit(ctx: &TraderCtx, body: &serde_json::Value) -> SubmitOutcome {
    let url = format!("{}/orders", ctx.endpoint);
    let start = Instant::now();
    let result = ctx
        .http
        .post(&url)
        .bearer_auth(&ctx.bearer)
        .json(body)
        .send()
        .await;
    let elapsed_us = start.elapsed().as_micros() as u64;
    let outcome = match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                SubmitOutcome::Ok
            } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                // Respect the rate limiter's Retry-After so the loadgen measures
                // throughput, not an error storm. Cap the backoff so a huge
                // header value can't stall the whole run.
                let retry = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(1)
                    .clamp(1, 5);
                tokio::time::sleep(std::time::Duration::from_secs(retry)).await;
                SubmitOutcome::RateLimited
            } else if status.is_client_error() {
                SubmitOutcome::Status4xx
            } else {
                SubmitOutcome::Status5xx
            }
        }
        Err(_) => SubmitOutcome::NetworkError,
    };
    ctx.metrics.note_submit(outcome);
    ctx.metrics
        .record_submit_latency_us(elapsed_us, outcome)
        .await;
    outcome
}

/// Best-effort lifecycle read of a placed order (`GET /orders/{id}`). Records the
/// round-trip latency into the submit histogram's sibling stream is overkill, so
/// we just log at debug — the value is confirming the order is observable, not a
/// new latency number. Never fails the run.
/// Spawn a bounded poller that measures submit→match latency for one sampled
/// order and records it into `match_latency_us`. Polls `GET /orders/{id}` until
/// the order leaves `pending` (`matched` — or `filled`/`partially_filled` if the
/// status vocabulary grows), then records `submit_at.elapsed()`. Gives up at the
/// deadline (the order may never match under this workload). Detached from the
/// trader's submit loop so it adds no throughput skew; the call-site sampling
/// (`poll_orders`) bounds how many of these run concurrently.
fn spawn_match_poll(ctx: TraderCtx, order_id: [u8; 16], submit_at: Instant) {
    const MATCH_POLL_DEADLINE: Duration = Duration::from_secs(5);
    const MATCH_POLL_INTERVAL: Duration = Duration::from_millis(150);
    tokio::spawn(async move {
        let url = format!("{}/orders/{}", ctx.endpoint, hex::encode(order_id));
        loop {
            if submit_at.elapsed() >= MATCH_POLL_DEADLINE {
                break; // never matched within the window — no sample
            }
            if let Ok(resp) = ctx.http.get(&url).bearer_auth(&ctx.bearer).send().await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        if matches!(status, "matched" | "filled" | "partially_filled") {
                            ctx.metrics
                                .record_match_latency_us(submit_at.elapsed().as_micros() as u64)
                                .await;
                            tracing::debug!(
                                trader = ctx.idx,
                                order = %hex::encode(order_id),
                                status,
                                latency_ms = submit_at.elapsed().as_millis() as u64,
                                "poll /orders/{{id}}: matched",
                            );
                            break;
                        }
                    }
                }
            }
            tokio::time::sleep(MATCH_POLL_INTERVAL).await;
        }
    });
}

async fn run_cancel(
    ctx: &TraderCtx,
    key: &SigningKey,
    order_id: [u8; 16],
    cancel_nonce: u64,
) -> CancelOutcome {
    let url = format!("{}/orders/{}", ctx.endpoint, hex::encode(order_id));
    let body = build_signed_cancel_body(key, order_id, cancel_nonce, ctx.boot_session_id);
    let start = Instant::now();
    let result = ctx
        .http
        .delete(&url)
        .bearer_auth(&ctx.bearer)
        .json(&body)
        .send()
        .await;
    let elapsed_us = start.elapsed().as_micros() as u64;
    let outcome = match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                CancelOutcome::Ok
            } else if status.is_client_error() {
                CancelOutcome::Status4xx
            } else {
                CancelOutcome::Status5xx
            }
        }
        Err(_) => CancelOutcome::Status5xx, // best-effort bucketing
    };
    ctx.metrics.note_cancel(outcome);
    ctx.metrics.record_cancel_latency_us(elapsed_us).await;
    outcome
}

/// Build a 16-byte order_id from `(trader_idx, counter)`. First 4
/// bytes are the trader idx (LE), next 8 are the counter (LE),
/// last 4 are 0 (with the very last byte = 1 to keep order_id !=
/// [0; 16] — the matcher rejects all-zero).
fn build_order_id(trader_idx: u32, counter: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&trader_idx.to_le_bytes());
    out[4..12].copy_from_slice(&counter.to_le_bytes());
    out[15] = 1;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_ids_are_distinct_across_traders() {
        let a = build_order_id(0, 1);
        let b = build_order_id(1, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn order_ids_are_distinct_across_counters() {
        let a = build_order_id(0, 1);
        let b = build_order_id(0, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn order_id_never_all_zero() {
        let oid = build_order_id(0, 0);
        assert_ne!(oid, [0u8; 16]);
    }
}
