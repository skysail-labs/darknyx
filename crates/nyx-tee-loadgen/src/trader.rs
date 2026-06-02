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
use std::time::Instant;

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
        );
        arrival_nonce = arrival_nonce.wrapping_add(1);

        let outcome = run_submit(&ctx, &body).await;
        if matches!(outcome, SubmitOutcome::Ok) {
            // Track for potential cancel later. Drop oldest if
            // we're at capacity.
            if recent_order_ids.len() == recent_order_ids.capacity() {
                recent_order_ids.pop_front();
            }
            recent_order_ids.push_back(order_id);
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
            } else if status.is_client_error() {
                SubmitOutcome::Status4xx
            } else {
                SubmitOutcome::Status5xx
            }
        }
        Err(_) => SubmitOutcome::NetworkError,
    };
    ctx.metrics.note_submit(outcome);
    ctx.metrics.record_submit_latency_us(elapsed_us).await;
    outcome
}

async fn run_cancel(
    ctx: &TraderCtx,
    key: &SigningKey,
    order_id: [u8; 16],
    cancel_nonce: u64,
) -> CancelOutcome {
    let url = format!("{}/orders/{}", ctx.endpoint, hex::encode(order_id));
    let body = build_signed_cancel_body(key, order_id, cancel_nonce);
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
