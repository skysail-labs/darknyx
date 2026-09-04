//! Client for the TEE's bounded settlement telemetry and deterministic report
//! helpers used by real-settle CPU/GPU comparisons.

use std::fmt::Write;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OutcomeCounts {
    pub confirmed: u64,
    pub rejected: u64,
    pub ambiguous: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StageTimings {
    pub lock_ms: Option<u64>,
    pub witness_ms: Option<u64>,
    pub prove_step_ms: Option<u64>,
    pub prove_ms: Option<u64>,
    pub verify_ms: Option<u64>,
    pub parallel_ms: Option<u64>,
    pub settle_ms: Option<u64>,
    pub close_ms: Option<u64>,
    pub total_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchMetric {
    pub seq: u64,
    pub batch_id: u64,
    pub market_id: String,
    pub match_ids: Vec<String>,
    pub active_matches: u16,
    pub padded_slots: u16,
    pub enqueued_at_ms: u64,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub queue_wait_ms: u64,
    pub prover_backend: String,
    pub witness_backend: String,
    pub prover_device: Option<String>,
    pub settle_concurrency: u16,
    pub settle_send_concurrency: u16,
    pub timings: StageTimings,
    pub outcomes: OutcomeCounts,
    pub confirmed_slots: u16,
    pub distinct_confirmed_slots: u16,
    pub rebroadcasts: u32,
    pub pipeline_failure: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueueSnapshot {
    pub depth: u64,
    pub waiting_batches: u64,
    pub running_batches: u64,
    pub oldest_batch_age_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricsSnapshot {
    pub boot_session_id: String,
    pub app_id: String,
    pub compose_hash: String,
    pub version: String,
    pub schema_version: u16,
    pub generated_at_ms: u64,
    pub latest_seq: u64,
    pub oldest_available_seq: Option<u64>,
    pub cursor_gap: bool,
    pub queue: QueueSnapshot,
    pub recent_batches: Vec<BatchMetric>,
}

pub async fn fetch_metrics(
    http: &reqwest::Client,
    endpoint: &str,
    bearer: &str,
    after_seq: Option<u64>,
) -> Result<MetricsSnapshot> {
    let mut request = http
        .get(format!("{endpoint}/admin/metrics/settlement"))
        .bearer_auth(bearer)
        .query(&[("limit", "1000".to_string())]);
    if let Some(cursor) = after_seq {
        request = request.query(&[("after_seq", cursor.to_string())]);
    }
    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "settlement metrics returned {status}: {}",
            body.chars().take(300).collect::<String>()
        ));
    }
    let snapshot: MetricsSnapshot = response.json().await?;
    if snapshot.schema_version != 1 {
        return Err(anyhow!(
            "unsupported settlement metrics schema {}",
            snapshot.schema_version
        ));
    }
    if snapshot.cursor_gap {
        return Err(anyhow!(
            "settlement metrics cursor fell behind bounded retention; benchmark is incomplete"
        ));
    }
    Ok(snapshot)
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientProveSummary {
    pub proof_count: u64,
    pub concurrency: usize,
    pub wall_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkArtifact {
    pub schema_version: u16,
    pub label: String,
    pub endpoint: String,
    pub app_id: String,
    pub compose_hash: String,
    pub boot_session_id: String,
    pub expected_matches: u64,
    pub submitted_orders: u64,
    pub accepted_orders: u64,
    pub target_submit_rate_orders_per_second: f64,
    pub submission_attempts: u64,
    pub rate_limited_retries: u64,
    pub transient_retries: u64,
    pub client_prove: ClientProveSummary,
    pub warmup_batches_excluded: usize,
    pub submitted_at_ms: u64,
    pub submission_completed_at_ms: u64,
    pub collected_at_ms: u64,
    pub batches: Vec<BatchMetric>,
}

impl BenchmarkArtifact {
    pub fn measured_batches(&self) -> &[BatchMetric] {
        let skip = self.warmup_batches_excluded.min(self.batches.len());
        &self.batches[skip..]
    }

    pub fn observed_matches(&self) -> u64 {
        self.batches
            .iter()
            .map(|batch| {
                batch.outcomes.confirmed + batch.outcomes.rejected + batch.outcomes.ambiguous
            })
            .sum()
    }

    pub fn render_markdown(&self) -> String {
        let measured = self.measured_batches();
        let confirmed: u64 = measured.iter().map(|b| b.outcomes.confirmed).sum();
        let rejected: u64 = measured.iter().map(|b| b.outcomes.rejected).sum();
        let ambiguous: u64 = measured.iter().map(|b| b.outcomes.ambiguous).sum();
        let first_started = measured.iter().map(|b| b.started_at_ms).min();
        let last_completed = measured.iter().map(|b| b.completed_at_ms).max();
        let window_ms = first_started
            .zip(last_completed)
            .map(|(first, last)| last.saturating_sub(first))
            .unwrap_or(0);
        let throughput = confirmed as f64 / (window_ms as f64 / 1_000.0).max(1e-9);
        let submit_window_ms = self
            .submission_completed_at_ms
            .saturating_sub(self.submitted_at_ms);
        let offered_orders_per_second =
            self.accepted_orders as f64 / (submit_window_ms as f64 / 1_000.0).max(1e-9);
        let active: u64 = measured.iter().map(|b| b.active_matches as u64).sum();
        let padded: u64 = measured.iter().map(|b| b.padded_slots as u64).sum();
        let packing = if padded == 0 {
            0.0
        } else {
            100.0 * active as f64 / padded as f64
        };
        let confirmed_slots: u64 = measured.iter().map(|b| b.confirmed_slots as u64).sum();
        let distinct_slots: u64 = measured
            .iter()
            .map(|b| b.distinct_confirmed_slots as u64)
            .sum();
        let co_inclusion = if confirmed_slots == 0 {
            0.0
        } else {
            100.0 * (confirmed_slots.saturating_sub(distinct_slots)) as f64 / confirmed_slots as f64
        };
        let rebroadcasts: u64 = measured.iter().map(|b| b.rebroadcasts as u64).sum();
        let rebroadcasts_per_confirmed = if confirmed == 0 {
            0.0
        } else {
            rebroadcasts as f64 / confirmed as f64
        };
        let client_proofs_per_second = self.client_prove.proof_count as f64
            / (self.client_prove.wall_us as f64 / 1_000_000.0).max(1e-9);

        let mut out = String::new();
        let _ = writeln!(out, "# Darknyx settlement benchmark — {}", self.label);
        let _ = writeln!(out);
        let _ = writeln!(out, "| Identity | Value |");
        let _ = writeln!(out, "|---|---|");
        let _ = writeln!(out, "| app_id | `{}` |", self.app_id);
        let _ = writeln!(out, "| compose_hash | `{}` |", self.compose_hash);
        let _ = writeln!(out, "| boot_session_id | `{}` |", self.boot_session_id);
        let _ = writeln!(
            out,
            "| warm-up batches excluded | {} |",
            self.warmup_batches_excluded.min(self.batches.len())
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Outcomes and capacity\n");
        let _ = writeln!(out, "| Metric | Value |");
        let _ = writeln!(out, "|---|---|");
        let _ = writeln!(out, "| measured batches | {} |", measured.len());
        let _ = writeln!(out, "| confirmed matches | {confirmed} |");
        let _ = writeln!(out, "| rejected matches | {rejected} |");
        let _ = writeln!(out, "| ambiguous matches | {ambiguous} |");
        let _ = writeln!(out, "| submitted orders | {} |", self.submitted_orders);
        let _ = writeln!(out, "| accepted orders | {} |", self.accepted_orders);
        let _ = writeln!(
            out,
            "| target order offer rate | {:.3} orders/s |",
            self.target_submit_rate_orders_per_second
        );
        let _ = writeln!(
            out,
            "| accepted-order offer rate | {offered_orders_per_second:.3} orders/s |"
        );
        let _ = writeln!(
            out,
            "| submission attempts | {} |",
            self.submission_attempts
        );
        let _ = writeln!(
            out,
            "| rate-limit retries | {} |",
            self.rate_limited_retries
        );
        let _ = writeln!(out, "| transient retries | {} |", self.transient_retries);
        let _ = writeln!(
            out,
            "| steady-state window | {:.3} s |",
            window_ms as f64 / 1_000.0
        );
        let _ = writeln!(
            out,
            "| confirmed match throughput | {throughput:.3} matches/s |"
        );
        let _ = writeln!(out, "| N=16 packing efficiency | {packing:.2}% |");
        let _ = writeln!(out, "| Tx D co-inclusion ratio | {co_inclusion:.2}% |");
        let _ = writeln!(out, "| rebroadcasts | {rebroadcasts} |");
        let _ = writeln!(
            out,
            "| rebroadcasts per confirmed match | {rebroadcasts_per_confirmed:.3} |"
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Client VALID_INPUT proving\n");
        let _ = writeln!(out, "| Metric | Value |");
        let _ = writeln!(out, "|---|---:|");
        let _ = writeln!(out, "| proofs | {} |", self.client_prove.proof_count);
        let _ = writeln!(out, "| concurrency | {} |", self.client_prove.concurrency);
        let _ = writeln!(
            out,
            "| wall time | {:.3} s |",
            self.client_prove.wall_us as f64 / 1_000_000.0
        );
        let _ = writeln!(
            out,
            "| throughput | {client_proofs_per_second:.3} proofs/s |"
        );
        let _ = writeln!(
            out,
            "| P50 | {:.3} ms |",
            self.client_prove.p50_us as f64 / 1_000.0
        );
        let _ = writeln!(
            out,
            "| P95 | {:.3} ms |",
            self.client_prove.p95_us as f64 / 1_000.0
        );
        let _ = writeln!(
            out,
            "| P99 | {:.3} ms |",
            self.client_prove.p99_us as f64 / 1_000.0
        );
        let _ = writeln!(
            out,
            "| max | {:.3} ms |",
            self.client_prove.max_us as f64 / 1_000.0
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Batch latency (ms)\n");
        let _ = writeln!(out, "| Stage | count | P50 | P95 | P99 | max |");
        let _ = writeln!(out, "|---|---:|---:|---:|---:|---:|");
        for (label, values) in [
            (
                "queue_wait",
                measured.iter().map(|b| Some(b.queue_wait_ms)).collect(),
            ),
            ("lock", measured.iter().map(|b| b.timings.lock_ms).collect()),
            (
                "witness",
                measured.iter().map(|b| b.timings.witness_ms).collect(),
            ),
            (
                "prove_step",
                measured.iter().map(|b| b.timings.prove_step_ms).collect(),
            ),
            (
                "prove",
                measured.iter().map(|b| b.timings.prove_ms).collect(),
            ),
            (
                "verify",
                measured.iter().map(|b| b.timings.verify_ms).collect(),
            ),
            (
                "parallel",
                measured.iter().map(|b| b.timings.parallel_ms).collect(),
            ),
            (
                "settle",
                measured.iter().map(|b| b.timings.settle_ms).collect(),
            ),
            (
                "close",
                measured.iter().map(|b| b.timings.close_ms).collect(),
            ),
            (
                "total",
                measured.iter().map(|b| b.timings.total_ms).collect(),
            ),
            (
                "workload_start_to_batch_terminal",
                measured
                    .iter()
                    .map(|b| Some(b.completed_at_ms.saturating_sub(self.submitted_at_ms)))
                    .collect(),
            ),
            (
                "post_offer_drain_to_batch_terminal",
                measured
                    .iter()
                    .map(|b| {
                        Some(
                            b.completed_at_ms
                                .saturating_sub(self.submission_completed_at_ms),
                        )
                    })
                    .collect(),
            ),
        ] {
            write_percentiles(&mut out, label, values);
        }
        out
    }
}

fn write_percentiles(out: &mut String, label: &str, values: Vec<Option<u64>>) {
    let mut values: Vec<u64> = values.into_iter().flatten().collect();
    values.sort_unstable();
    if values.is_empty() {
        let _ = writeln!(out, "| {label} | 0 | — | — | — | — |");
        return;
    }
    let at = |q: f64| {
        let index = ((values.len() - 1) as f64 * q).round() as usize;
        values[index]
    };
    let _ = writeln!(
        out,
        "| {label} | {} | {} | {} | {} | {} |",
        values.len(),
        at(0.50),
        at(0.95),
        at(0.99),
        values.last().copied().unwrap_or(0)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(seq: u64, confirmed: u64, prove_ms: u64) -> BatchMetric {
        BatchMetric {
            seq,
            batch_id: seq,
            market_id: "market".to_string(),
            match_ids: vec![seq.to_string()],
            active_matches: 1,
            padded_slots: 16,
            enqueued_at_ms: seq * 1_000,
            started_at_ms: seq * 1_000,
            completed_at_ms: seq * 1_000 + 2_000,
            queue_wait_ms: 0,
            prover_backend: "icicle".to_string(),
            witness_backend: "native".to_string(),
            prover_device: Some("CUDA".to_string()),
            settle_concurrency: 1,
            settle_send_concurrency: 16,
            timings: StageTimings {
                prove_step_ms: Some(prove_ms),
                total_ms: Some(2_000),
                ..StageTimings::default()
            },
            outcomes: OutcomeCounts {
                confirmed,
                ..OutcomeCounts::default()
            },
            confirmed_slots: 1,
            distinct_confirmed_slots: 1,
            rebroadcasts: 0,
            pipeline_failure: None,
        }
    }

    #[test]
    fn report_excludes_warmup_and_names_steady_state_metrics() {
        let artifact = BenchmarkArtifact {
            schema_version: 2,
            label: "gpu".to_string(),
            endpoint: "https://example".to_string(),
            app_id: "app".to_string(),
            compose_hash: "hash".to_string(),
            boot_session_id: "boot".to_string(),
            expected_matches: 2,
            submitted_orders: 4,
            accepted_orders: 4,
            target_submit_rate_orders_per_second: 15.0,
            submission_attempts: 5,
            rate_limited_retries: 1,
            transient_retries: 0,
            client_prove: ClientProveSummary {
                proof_count: 4,
                concurrency: 1,
                wall_us: 400_000,
                p50_us: 95_000,
                p95_us: 110_000,
                p99_us: 110_000,
                max_us: 110_000,
            },
            warmup_batches_excluded: 1,
            submitted_at_ms: 0,
            submission_completed_at_ms: 10,
            collected_at_ms: 5_000,
            batches: vec![batch(1, 1, 1_800), batch(2, 1, 50)],
        };
        let report = artifact.render_markdown();
        assert!(report.contains("warm-up batches excluded | 1"));
        assert!(report.contains("| prove_step | 1 | 50 | 50 | 50 | 50 |"));
        assert!(report.contains("workload_start_to_batch_terminal"));
        assert!(report.contains("post_offer_drain_to_batch_terminal"));
        assert!(report.contains("rate-limit retries | 1"));
        assert!(report.contains("confirmed match throughput"));
        assert!(report.contains("Client VALID_INPUT proving"));
        assert!(report.contains("10.000 proofs/s"));
        assert!(report.contains("| lock | 0 | — | — | — | — |"));
        assert!(report.contains("rebroadcasts per confirmed match"));
    }
}
