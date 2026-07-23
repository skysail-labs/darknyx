//! Privacy-preserving settlement benchmark telemetry.
//!
//! This state is intentionally in-memory and bounded. It records only batch
//! identity, timing, queueing, prover configuration and terminal outcome
//! counts. Prices, amounts, order ids, commitments, owners and witnesses never
//! enter this module.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::job::SettlementOutcome;

pub const SETTLEMENT_METRICS_SCHEMA_VERSION: u16 = 1;
pub const SETTLEMENT_METRICS_RECENT_CAP: usize = 1_024;

const LATENCY_BUCKET_UPPER_BOUNDS_MS: &[u64] = &[
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    20_000,
    40_000,
    80_000,
    160_000,
    u64::MAX,
];

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettlementStageTimings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_step_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_tx_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_wait_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettlementOutcomeCounts {
    pub confirmed: u64,
    pub rejected: u64,
    pub ambiguous: u64,
}

impl SettlementOutcomeCounts {
    pub fn from_outcomes(outcomes: &[SettlementOutcome]) -> Self {
        let mut counts = Self::default();
        for outcome in outcomes {
            match outcome {
                SettlementOutcome::Confirmed { .. } => counts.confirmed += 1,
                SettlementOutcome::Rejected { .. } => counts.rejected += 1,
                SettlementOutcome::Ambiguous { .. } | SettlementOutcome::Pending => {
                    counts.ambiguous += 1
                }
            }
        }
        counts
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SettlementBatchRecord {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_device: Option<String>,
    pub settle_concurrency: u16,
    pub settle_send_concurrency: u16,
    pub timings: SettlementStageTimings,
    pub outcomes: SettlementOutcomeCounts,
    pub confirmed_slots: u16,
    pub distinct_confirmed_slots: u16,
    pub rebroadcasts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_failure: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BatchMetricsCompletion {
    pub prover_backend: String,
    pub witness_backend: String,
    pub prover_device: Option<String>,
    pub settle_concurrency: usize,
    pub settle_send_concurrency: usize,
    pub timings: SettlementStageTimings,
    pub outcomes: SettlementOutcomeCounts,
    pub confirmed_slots: usize,
    pub distinct_confirmed_slots: usize,
    pub rebroadcasts: u32,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettlementMetricsCounters {
    pub batches_enqueued: u64,
    pub batches_started: u64,
    pub batches_completed: u64,
    pub batches_failed_before_outcomes: u64,
    pub matches_confirmed: u64,
    pub matches_rejected: u64,
    pub matches_ambiguous: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct QueueMarketSnapshot {
    pub waiting_batches: u64,
    pub running_batches: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettlementQueueSnapshot {
    pub depth: u64,
    pub waiting_batches: u64,
    pub running_batches: u64,
    pub oldest_batch_age_ms: u64,
    pub by_market: BTreeMap<String, QueueMarketSnapshot>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LatencyBucket {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper_bound_ms: Option<u64>,
    pub count: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct LatencyHistogramSnapshot {
    pub count: u64,
    pub sum_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<u64>,
    pub buckets: Vec<LatencyBucket>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SettlementHistogramSnapshot {
    pub queue_wait_ms: LatencyHistogramSnapshot,
    pub witness_ms: LatencyHistogramSnapshot,
    pub prove_step_ms: LatencyHistogramSnapshot,
    pub prove_ms: LatencyHistogramSnapshot,
    pub settle_ms: LatencyHistogramSnapshot,
    pub total_ms: LatencyHistogramSnapshot,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SettlementMetricsSnapshot {
    pub schema_version: u16,
    pub generated_at_ms: u64,
    pub latest_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_available_seq: Option<u64>,
    pub cursor_gap: bool,
    pub counters: SettlementMetricsCounters,
    pub queue: SettlementQueueSnapshot,
    pub histograms: SettlementHistogramSnapshot,
    pub recent_batches: Vec<SettlementBatchRecord>,
}

#[derive(Clone, Debug)]
struct InFlightBatch {
    market_id: String,
    match_ids: Vec<String>,
    active_matches: u16,
    padded_slots: u16,
    enqueued_at_ms: u64,
    started_at_ms: Option<u64>,
}

#[derive(Clone, Debug)]
struct LatencyHistogram {
    counts: Vec<u64>,
    count: u64,
    sum_ms: u128,
    min_ms: Option<u64>,
    max_ms: Option<u64>,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            counts: vec![0; LATENCY_BUCKET_UPPER_BOUNDS_MS.len()],
            count: 0,
            sum_ms: 0,
            min_ms: None,
            max_ms: None,
        }
    }
}

impl LatencyHistogram {
    fn observe(&mut self, value: u64) {
        self.count = self.count.saturating_add(1);
        self.sum_ms = self.sum_ms.saturating_add(value as u128);
        self.min_ms = Some(self.min_ms.map_or(value, |old| old.min(value)));
        self.max_ms = Some(self.max_ms.map_or(value, |old| old.max(value)));
        if let Some(index) = LATENCY_BUCKET_UPPER_BOUNDS_MS
            .iter()
            .position(|upper| value <= *upper)
        {
            self.counts[index] = self.counts[index].saturating_add(1);
        }
    }

    fn snapshot(&self) -> LatencyHistogramSnapshot {
        LatencyHistogramSnapshot {
            count: self.count,
            sum_ms: self.sum_ms,
            min_ms: self.min_ms,
            max_ms: self.max_ms,
            buckets: LATENCY_BUCKET_UPPER_BOUNDS_MS
                .iter()
                .zip(&self.counts)
                .map(|(upper, count)| LatencyBucket {
                    upper_bound_ms: (*upper != u64::MAX).then_some(*upper),
                    count: *count,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SettlementHistograms {
    queue_wait_ms: LatencyHistogram,
    witness_ms: LatencyHistogram,
    prove_step_ms: LatencyHistogram,
    prove_ms: LatencyHistogram,
    settle_ms: LatencyHistogram,
    total_ms: LatencyHistogram,
}

impl SettlementHistograms {
    fn observe(&mut self, record: &SettlementBatchRecord) {
        self.queue_wait_ms.observe(record.queue_wait_ms);
        if let Some(value) = record.timings.witness_ms {
            self.witness_ms.observe(value);
        }
        if let Some(value) = record.timings.prove_step_ms {
            self.prove_step_ms.observe(value);
        }
        if let Some(value) = record.timings.prove_ms {
            self.prove_ms.observe(value);
        }
        if let Some(value) = record.timings.settle_ms {
            self.settle_ms.observe(value);
        }
        if let Some(value) = record.timings.total_ms {
            self.total_ms.observe(value);
        }
    }

    fn snapshot(&self) -> SettlementHistogramSnapshot {
        SettlementHistogramSnapshot {
            queue_wait_ms: self.queue_wait_ms.snapshot(),
            witness_ms: self.witness_ms.snapshot(),
            prove_step_ms: self.prove_step_ms.snapshot(),
            prove_ms: self.prove_ms.snapshot(),
            settle_ms: self.settle_ms.snapshot(),
            total_ms: self.total_ms.snapshot(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SettlementMetricsState {
    next_seq: u64,
    in_flight: HashMap<u64, InFlightBatch>,
    recent: VecDeque<SettlementBatchRecord>,
    counters: SettlementMetricsCounters,
    histograms: SettlementHistograms,
}

impl SettlementMetricsState {
    pub fn enqueue_batch(&mut self, batch_id: u64, market_id: String, match_ids: Vec<String>) {
        let active_matches = match_ids.len().min(u16::MAX as usize) as u16;
        self.in_flight.insert(
            batch_id,
            InFlightBatch {
                market_id,
                match_ids,
                active_matches,
                padded_slots: active_matches,
                enqueued_at_ms: unix_ms(),
                started_at_ms: None,
            },
        );
        self.counters.batches_enqueued = self.counters.batches_enqueued.saturating_add(1);
    }

    pub fn mark_started(&mut self, batch_id: u64, padded_slots: usize) {
        let Some(batch) = self.in_flight.get_mut(&batch_id) else {
            return;
        };
        if batch.started_at_ms.is_none() {
            batch.started_at_ms = Some(unix_ms());
            batch.padded_slots = padded_slots.min(u16::MAX as usize) as u16;
            self.counters.batches_started = self.counters.batches_started.saturating_add(1);
        }
    }

    pub fn complete_batch(
        &mut self,
        batch_id: u64,
        completion: BatchMetricsCompletion,
    ) -> Option<SettlementBatchRecord> {
        let batch = self.in_flight.remove(&batch_id)?;
        let completed_at_ms = unix_ms();
        let started_at_ms = batch.started_at_ms.unwrap_or(batch.enqueued_at_ms);
        let seq = self.take_seq();
        let record = SettlementBatchRecord {
            seq,
            batch_id,
            market_id: batch.market_id,
            match_ids: batch.match_ids,
            active_matches: batch.active_matches,
            padded_slots: batch.padded_slots,
            enqueued_at_ms: batch.enqueued_at_ms,
            started_at_ms,
            completed_at_ms,
            queue_wait_ms: started_at_ms.saturating_sub(batch.enqueued_at_ms),
            prover_backend: completion.prover_backend,
            witness_backend: completion.witness_backend,
            prover_device: completion.prover_device,
            settle_concurrency: completion.settle_concurrency.min(u16::MAX as usize) as u16,
            settle_send_concurrency: completion.settle_send_concurrency.min(u16::MAX as usize)
                as u16,
            timings: completion.timings,
            outcomes: completion.outcomes,
            confirmed_slots: completion.confirmed_slots.min(u16::MAX as usize) as u16,
            distinct_confirmed_slots: completion.distinct_confirmed_slots.min(u16::MAX as usize)
                as u16,
            rebroadcasts: completion.rebroadcasts,
            pipeline_failure: None,
        };
        self.counters.batches_completed = self.counters.batches_completed.saturating_add(1);
        self.observe_terminal(&record);
        self.push_record(record.clone());
        Some(record)
    }

    pub fn fail_batch(
        &mut self,
        batch_id: u64,
        settle_concurrency: usize,
        settle_send_concurrency: usize,
        reason: String,
    ) -> Option<SettlementBatchRecord> {
        let batch = self.in_flight.remove(&batch_id)?;
        let completed_at_ms = unix_ms();
        let started_at_ms = batch.started_at_ms.unwrap_or(batch.enqueued_at_ms);
        let seq = self.take_seq();
        let record = SettlementBatchRecord {
            seq,
            batch_id,
            market_id: batch.market_id,
            match_ids: batch.match_ids,
            active_matches: batch.active_matches,
            padded_slots: batch.padded_slots,
            enqueued_at_ms: batch.enqueued_at_ms,
            started_at_ms,
            completed_at_ms,
            queue_wait_ms: started_at_ms.saturating_sub(batch.enqueued_at_ms),
            prover_backend: "unavailable".to_string(),
            witness_backend: "unavailable".to_string(),
            prover_device: None,
            settle_concurrency: settle_concurrency.min(u16::MAX as usize) as u16,
            settle_send_concurrency: settle_send_concurrency.min(u16::MAX as usize) as u16,
            timings: SettlementStageTimings {
                total_ms: Some(completed_at_ms.saturating_sub(started_at_ms)),
                ..SettlementStageTimings::default()
            },
            outcomes: SettlementOutcomeCounts {
                rejected: batch.active_matches as u64,
                ..SettlementOutcomeCounts::default()
            },
            confirmed_slots: 0,
            distinct_confirmed_slots: 0,
            rebroadcasts: 0,
            pipeline_failure: Some(reason),
        };
        self.counters.batches_failed_before_outcomes = self
            .counters
            .batches_failed_before_outcomes
            .saturating_add(1);
        self.observe_terminal(&record);
        self.push_record(record.clone());
        Some(record)
    }

    pub fn snapshot(&self, after_seq: Option<u64>, limit: usize) -> SettlementMetricsSnapshot {
        let now = unix_ms();
        let oldest_available_seq = self.recent.front().map(|record| record.seq);
        let cursor_gap = after_seq
            .zip(oldest_available_seq)
            .is_some_and(|(after, oldest)| after.saturating_add(1) < oldest);
        let recent_batches = self
            .recent
            .iter()
            .filter(|record| after_seq.is_none_or(|after| record.seq > after))
            .take(limit.clamp(1, 1_000))
            .cloned()
            .collect();

        SettlementMetricsSnapshot {
            schema_version: SETTLEMENT_METRICS_SCHEMA_VERSION,
            generated_at_ms: now,
            latest_seq: self.next_seq.saturating_sub(1),
            oldest_available_seq,
            cursor_gap,
            counters: self.counters.clone(),
            queue: self.queue_snapshot(now),
            histograms: self.histograms.snapshot(),
            recent_batches,
        }
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq.max(1);
        self.next_seq = seq.saturating_add(1);
        seq
    }

    fn observe_terminal(&mut self, record: &SettlementBatchRecord) {
        self.counters.matches_confirmed = self
            .counters
            .matches_confirmed
            .saturating_add(record.outcomes.confirmed);
        self.counters.matches_rejected = self
            .counters
            .matches_rejected
            .saturating_add(record.outcomes.rejected);
        self.counters.matches_ambiguous = self
            .counters
            .matches_ambiguous
            .saturating_add(record.outcomes.ambiguous);
        self.histograms.observe(record);
    }

    fn push_record(&mut self, record: SettlementBatchRecord) {
        if self.recent.len() >= SETTLEMENT_METRICS_RECENT_CAP {
            self.recent.pop_front();
        }
        self.recent.push_back(record);
    }

    fn queue_snapshot(&self, now_ms: u64) -> SettlementQueueSnapshot {
        let mut queue = SettlementQueueSnapshot {
            depth: self.in_flight.len() as u64,
            oldest_batch_age_ms: self
                .in_flight
                .values()
                .map(|batch| now_ms.saturating_sub(batch.enqueued_at_ms))
                .max()
                .unwrap_or(0),
            ..SettlementQueueSnapshot::default()
        };
        for batch in self.in_flight.values() {
            let market = queue.by_market.entry(batch.market_id.clone()).or_default();
            if batch.started_at_ms.is_some() {
                queue.running_batches = queue.running_batches.saturating_add(1);
                market.running_batches = market.running_batches.saturating_add(1);
            } else {
                queue.waiting_batches = queue.waiting_batches.saturating_add(1);
                market.waiting_batches = market.waiting_batches.saturating_add(1);
            }
        }
        queue
    }
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Emit the same non-sensitive batch summary retained by the admin endpoint as
/// one structured tracing event. Failures are retained only as stable,
/// low-cardinality labels; raw errors can contain provider URLs and are kept
/// out of both logs and the authenticated benchmark response.
pub fn emit_batch_record(record: &SettlementBatchRecord) {
    tracing::info!(
        settlement_metrics_schema_version = SETTLEMENT_METRICS_SCHEMA_VERSION,
        settlement_metrics_seq = record.seq,
        batch_id = record.batch_id,
        market_id = %record.market_id,
        match_ids = ?record.match_ids,
        active_matches = record.active_matches,
        padded_slots = record.padded_slots,
        queue_wait_ms = record.queue_wait_ms,
        prover_backend = %record.prover_backend,
        witness_backend = %record.witness_backend,
        prover_device = ?record.prover_device,
        settle_concurrency = record.settle_concurrency,
        settle_send_concurrency = record.settle_send_concurrency,
        lock_ms = record.timings.lock_ms,
        witness_ms = record.timings.witness_ms,
        prove_step_ms = record.timings.prove_step_ms,
        prove_ms = record.timings.prove_ms,
        verify_ms = record.timings.verify_ms,
        alt_tx_ms = record.timings.alt_tx_ms,
        alt_wait_ms = record.timings.alt_wait_ms,
        parallel_ms = record.timings.parallel_ms,
        settle_ms = record.timings.settle_ms,
        close_ms = record.timings.close_ms,
        total_ms = record.timings.total_ms,
        confirmed = record.outcomes.confirmed,
        rejected = record.outcomes.rejected,
        ambiguous = record.outcomes.ambiguous,
        confirmed_slots = record.confirmed_slots,
        distinct_confirmed_slots = record.distinct_confirmed_slots,
        rebroadcasts = record.rebroadcasts,
        pipeline_failed = record.pipeline_failure.is_some(),
        "settlement benchmark record"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_batches_are_cursor_addressable_and_bounded_to_public_metadata() {
        let mut metrics = SettlementMetricsState::default();
        metrics.enqueue_batch(
            7,
            "market-pda".to_string(),
            vec!["40".to_string(), "41".to_string()],
        );
        metrics.mark_started(7, 16);
        let record = metrics
            .complete_batch(
                7,
                BatchMetricsCompletion {
                    prover_backend: "rapidsnark".to_string(),
                    witness_backend: "native".to_string(),
                    prover_device: Some("CPU".to_string()),
                    settle_concurrency: 1,
                    settle_send_concurrency: 16,
                    timings: SettlementStageTimings {
                        witness_ms: Some(200),
                        prove_step_ms: Some(1_400),
                        prove_ms: Some(1_600),
                        total_ms: Some(12_000),
                        ..SettlementStageTimings::default()
                    },
                    outcomes: SettlementOutcomeCounts {
                        confirmed: 2,
                        ..SettlementOutcomeCounts::default()
                    },
                    confirmed_slots: 2,
                    distinct_confirmed_slots: 1,
                    rebroadcasts: 0,
                },
            )
            .expect("in-flight record");
        assert_eq!(record.seq, 1);
        assert_eq!(record.active_matches, 2);
        assert_eq!(record.padded_slots, 16);

        let first = metrics.snapshot(None, 100);
        assert_eq!(first.recent_batches.len(), 1);
        assert_eq!(first.counters.matches_confirmed, 2);
        assert_eq!(first.queue.depth, 0);
        assert_eq!(first.histograms.prove_step_ms.count, 1);

        let after = metrics.snapshot(Some(1), 100);
        assert!(after.recent_batches.is_empty());
    }

    #[test]
    fn queue_snapshot_is_partitioned_by_market_and_stage() {
        let mut metrics = SettlementMetricsState::default();
        metrics.enqueue_batch(1, "a".to_string(), vec!["1".to_string()]);
        metrics.enqueue_batch(2, "b".to_string(), vec!["2".to_string()]);
        metrics.mark_started(2, 16);
        let snapshot = metrics.snapshot(None, 100);
        assert_eq!(snapshot.queue.depth, 2);
        assert_eq!(snapshot.queue.waiting_batches, 1);
        assert_eq!(snapshot.queue.running_batches, 1);
        assert_eq!(snapshot.queue.by_market["a"].waiting_batches, 1);
        assert_eq!(snapshot.queue.by_market["b"].running_batches, 1);
    }
}
