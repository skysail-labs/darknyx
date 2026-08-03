//! Shared metrics — one `Arc<RunMetrics>` cloned into each trader.
//!
//! Histograms use `hdrhistogram` with a 1 µs precision over a
//! 60 s range. Lock-contention is negligible because:
//!   - record() is sub-µs,
//!   - we record one value per HTTP request (~10s of µs per
//!     trader),
//!   - the lock is dropped before any other work.
//!
//! Final percentile read happens once at run end, outside the
//! traders' loops.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hdrhistogram::Histogram;
use tokio::sync::Mutex;

/// One `Histogram<u64>` per latency stream + atomic counters for
/// the lock-free totals. Wrapped in `Arc<...>` by the run driver.
pub struct RunMetrics {
    /// Latency of ACCEPTED submits only.
    ///
    /// SW-27: this recorded every outcome — `Ok`, 4xx, 429, 5xx and network
    /// errors alike — and the report printed the resulting P50/P95/P99 with no
    /// qualifier. An intake rejection is fast, because it fails before any
    /// matcher work, so a rejection-heavy run reported *better* percentiles than
    /// a healthy one. The number moved the wrong way under exactly the
    /// conditions you would be measuring.
    pub submit_latency_us: Mutex<Histogram<u64>>,
    /// Latency of REJECTED submits, kept separately rather than discarded — a
    /// rejection storm has its own shape worth seeing.
    pub submit_latency_rejected_us: Mutex<Histogram<u64>>,
    pub cancel_latency_us: Mutex<Histogram<u64>>,
    pub match_latency_us: Mutex<Histogram<u64>>,

    pub submits_total: AtomicU64,
    pub submits_ok: AtomicU64,
    pub submits_4xx: AtomicU64,
    /// Subset of 4xx that were `429 Too Many Requests` (the rate limiter).
    /// Counted in BOTH `submits_4xx` and here so the report can call them out.
    pub submits_429: AtomicU64,
    pub submits_5xx: AtomicU64,
    pub submits_neterr: AtomicU64,

    pub cancels_total: AtomicU64,
    pub cancels_ok: AtomicU64,
    pub cancels_4xx: AtomicU64,
    pub cancels_5xx: AtomicU64,
}

impl RunMetrics {
    pub fn new() -> Arc<Self> {
        // Range 1 µs..=60 s, sigfig 3 → ~5% relative error in the
        // bucket the recorded value lands in. Plenty of resolution
        // for the kind of numbers we'll see.
        let new_hist =
            || Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("valid hist bounds");
        Arc::new(Self {
            submit_latency_us: Mutex::new(new_hist()),
            submit_latency_rejected_us: Mutex::new(new_hist()),
            cancel_latency_us: Mutex::new(new_hist()),
            match_latency_us: Mutex::new(new_hist()),
            submits_total: AtomicU64::new(0),
            submits_ok: AtomicU64::new(0),
            submits_4xx: AtomicU64::new(0),
            submits_429: AtomicU64::new(0),
            submits_5xx: AtomicU64::new(0),
            submits_neterr: AtomicU64::new(0),
            cancels_total: AtomicU64::new(0),
            cancels_ok: AtomicU64::new(0),
            cancels_4xx: AtomicU64::new(0),
            cancels_5xx: AtomicU64::new(0),
        })
    }

    // Latencies are clamped to the histogram's [1, 60_000_000] µs
    // bounds (see `new_with_bounds`) BEFORE recording: an out-of-range
    // value makes `record` return Err, which — discarded — would
    // silently DROP the sample and bias the tail (P99) downward.
    // Clamping records it at the max bucket instead.
    /// Record a submit's latency into the histogram matching its OUTCOME
    /// (SW-27). Accepted and rejected submits measure different things and must
    /// not share a percentile.
    pub async fn record_submit_latency_us(&self, us: u64, outcome: SubmitOutcome) {
        let hist = if matches!(outcome, SubmitOutcome::Ok) {
            &self.submit_latency_us
        } else {
            &self.submit_latency_rejected_us
        };
        let _ = hist.lock().await.record(us.clamp(1, 60_000_000));
    }

    pub async fn record_cancel_latency_us(&self, us: u64) {
        let _ = self
            .cancel_latency_us
            .lock()
            .await
            .record(us.clamp(1, 60_000_000));
    }

    pub async fn record_match_latency_us(&self, us: u64) {
        let _ = self
            .match_latency_us
            .lock()
            .await
            .record(us.clamp(1, 60_000_000));
    }

    pub fn note_submit(&self, outcome: SubmitOutcome) {
        self.submits_total.fetch_add(1, Ordering::Relaxed);
        let bucket = match outcome {
            SubmitOutcome::Ok => &self.submits_ok,
            SubmitOutcome::Status4xx => &self.submits_4xx,
            SubmitOutcome::RateLimited => {
                // 429 is a 4xx; count it in both so totals stay consistent.
                self.submits_4xx.fetch_add(1, Ordering::Relaxed);
                &self.submits_429
            }
            SubmitOutcome::Status5xx => &self.submits_5xx,
            SubmitOutcome::NetworkError => &self.submits_neterr,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_cancel(&self, outcome: CancelOutcome) {
        self.cancels_total.fetch_add(1, Ordering::Relaxed);
        let bucket = match outcome {
            CancelOutcome::Ok => &self.cancels_ok,
            CancelOutcome::Status4xx => &self.cancels_4xx,
            CancelOutcome::Status5xx => &self.cancels_5xx,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of every counter, taken as a single u64 read each.
    /// Not atomic across counters — the values may not represent
    /// the same instant — but the granularity is plenty for the
    /// end-of-run report.
    pub fn snapshot_counters(&self) -> CounterSnapshot {
        CounterSnapshot {
            submits_total: self.submits_total.load(Ordering::Relaxed),
            submits_ok: self.submits_ok.load(Ordering::Relaxed),
            submits_4xx: self.submits_4xx.load(Ordering::Relaxed),
            submits_429: self.submits_429.load(Ordering::Relaxed),
            submits_5xx: self.submits_5xx.load(Ordering::Relaxed),
            submits_neterr: self.submits_neterr.load(Ordering::Relaxed),
            cancels_total: self.cancels_total.load(Ordering::Relaxed),
            cancels_ok: self.cancels_ok.load(Ordering::Relaxed),
            cancels_4xx: self.cancels_4xx.load(Ordering::Relaxed),
            cancels_5xx: self.cancels_5xx.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SubmitOutcome {
    Ok,
    Status4xx,
    /// `429 Too Many Requests` — the per-account rate limiter (code 1401).
    RateLimited,
    Status5xx,
    NetworkError,
}

#[derive(Debug, Clone, Copy)]
pub enum CancelOutcome {
    Ok,
    Status4xx,
    Status5xx,
}

#[derive(Debug, Clone)]
pub struct CounterSnapshot {
    pub submits_total: u64,
    pub submits_ok: u64,
    pub submits_4xx: u64,
    pub submits_429: u64,
    pub submits_5xx: u64,
    pub submits_neterr: u64,
    pub cancels_total: u64,
    pub cancels_ok: u64,
    pub cancels_4xx: u64,
    pub cancels_5xx: u64,
}

impl CounterSnapshot {
    pub fn submit_success_rate(&self) -> f64 {
        if self.submits_total == 0 {
            return 0.0;
        }
        self.submits_ok as f64 / self.submits_total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SW-27 — accepted and rejected submits must not share a histogram.
    ///
    /// They measure different things: a rejection fails at intake, before any
    /// matcher work, so it is systematically FASTER. Pooled, a rejection-heavy
    /// run reported BETTER percentiles than a healthy one — the number moved
    /// the wrong way under exactly the conditions being measured, which is
    /// worse than having no number.
    ///
    /// One sample in each, at values far enough apart that a leak in either
    /// direction changes the other's max.
    #[tokio::test]
    async fn each_outcome_lands_in_its_own_histogram() {
        let m = RunMetrics::new();
        m.record_submit_latency_us(1_000, SubmitOutcome::Ok).await;
        m.record_submit_latency_us(9_000, SubmitOutcome::Status4xx)
            .await;

        let accepted = m.submit_latency_us.lock().await;
        let rejected = m.submit_latency_rejected_us.lock().await;
        assert_eq!(accepted.len(), 1, "accepted histogram holds its one sample");
        assert_eq!(rejected.len(), 1, "rejected histogram holds its one sample");
        // `count_at`, not `max()`: HDR reports a bucket's highest equivalent
        // value, so `max()` on a 9_000 sample is 9_007 and an equality
        // assertion there would be pinning quantization, not routing.
        assert_eq!(accepted.count_at(1_000), 1, "accept recorded in its own");
        assert_eq!(
            accepted.count_at(9_000),
            0,
            "rejection must NOT appear here"
        );
        assert_eq!(rejected.count_at(9_000), 1, "rejection recorded in its own");
        assert_eq!(rejected.count_at(1_000), 0, "accept must NOT appear here");
    }

    /// Every non-Ok outcome is a rejection, not just `Status4xx`. A `match` arm
    /// added later that forgot one would silently pollute the accepted
    /// percentiles again.
    #[tokio::test]
    async fn every_non_ok_outcome_counts_as_rejected() {
        let m = RunMetrics::new();
        for outcome in [
            SubmitOutcome::Status4xx,
            SubmitOutcome::RateLimited,
            SubmitOutcome::Status5xx,
            SubmitOutcome::NetworkError,
        ] {
            m.record_submit_latency_us(5_000, outcome).await;
        }
        assert_eq!(m.submit_latency_us.lock().await.len(), 0);
        assert_eq!(m.submit_latency_rejected_us.lock().await.len(), 4);
    }

    /// The split has to reach the REPORT, not just the histograms — an operator
    /// reads the rendered table, and an unlabelled "submit" row is what made
    /// the pooled number misleading in the first place.
    #[tokio::test]
    async fn the_report_labels_both_submit_rows() {
        use crate::config::RunConfig;
        use crate::report::{render_markdown, ReportInputs};
        use clap::Parser;

        let cfg = RunConfig::parse_from([
            "darknyx-tee-loadgen",
            "--endpoint",
            "http://127.0.0.1:8080",
            "--oracle-twap",
            "100",
        ]);
        let m = RunMetrics::new();
        m.record_submit_latency_us(1_000, SubmitOutcome::Ok).await;
        m.record_submit_latency_us(9_000, SubmitOutcome::Status4xx)
            .await;

        let out = render_markdown(ReportInputs {
            cfg: &cfg,
            metrics: &m,
            elapsed: std::time::Duration::from_secs(1),
        })
        .await;

        assert!(
            out.contains("submit (accepted)"),
            "report must label the accepted row"
        );
        assert!(
            out.contains("submit (rejected)"),
            "report must label the rejected row"
        );
    }
}
