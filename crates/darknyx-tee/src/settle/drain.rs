//! Orderly drain for planned redeploys (audit finding T-06, option C).
//!
//! # What this is, and what it deliberately is not
//!
//! A redeploy is the documented way to roll an image or change env, and it is
//! the most common reason this enclave stops. Drain makes that stop *orderly*:
//! new trading closes, resting orders are explicitly cancelled rather than
//! silently lost, and the operator is told when no settlement is still in flight.
//!
//! It is **not** crash recovery and must never be mistaken for it. Drain only
//! helps when someone chooses to stop; a crash, an OOM, or an involuntary host
//! migration gets no such courtesy. That is precisely why the write-ahead journal
//! exists and why drain is the smaller, secondary mechanism — if the two are ever
//! conflated, the journal will be quietly weakened on the argument that "we drain
//! before redeploys anyway".
//!
//! # Why resting orders are cancelled here but not restored on boot
//!
//! These look contradictory and are not. A resting order lives only in enclave
//! memory and its collateral note is **not** locked on-chain until settlement, so
//! losing one costs the client a re-place and freezes nothing. Cancelling on the
//! way down converts that silent loss into an explicit `order.cancel` the client
//! already knows how to handle — the same courtesy cancel-on-disconnect provides.
//!
//! Restoring them on the way up would be different in kind: an order is a signed
//! client intent carrying a nonce and a session binding, and re-entering one
//! after an arbitrary gap would re-book at a price chosen under conditions that
//! no longer hold. The daemon resubmits a fresh signed order instead. Recorded as
//! a decision in the T-06 notes, not an oversight.
//!
//! # Readiness is measured against the journal, not the clock
//!
//! "Safe to stop" means no settlement is in flight — and the only durable answer
//! to that is the journal, which is also what a restart would read. Using a timer
//! ("wait 30 seconds") would report readiness that no on-chain state supports,
//! which is the failure this whole slice is about.

use std::sync::Arc;

use serde::Serialize;

use crate::matcher::{TradingGate, TradingPauseReason};
use crate::persistence::journal::{JournalWriteStats, SettleJournal};

/// A point-in-time view of the drain.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DrainStatus {
    /// Whether a drain has been requested on this instance.
    pub draining: bool,
    /// Resting orders cancelled by the drain request (0 on a status read).
    pub cancelled_resting: usize,
    /// Settlements still journaled as in flight. Zero is the condition for
    /// `safe_to_stop`.
    pub in_flight_settlements: usize,
    /// True when trading is closed AND nothing is still settling. Only then does
    /// stopping the CVM risk nothing that the journal would have to recover.
    pub safe_to_stop: bool,
    /// Durable-write cost for this process's journal, in microseconds
    /// (T-06's cost-table row).
    ///
    /// Exposed HERE, on an endpoint, rather than left to the log emitter alone.
    /// The log summary is throttled to one line per interval, and a single-match
    /// settle performs all of its journal writes inside one window — they all
    /// precede the long settle wait — so the only line it ever produces reads
    /// `writes=1`, which is a sample and not a percentile. That is exactly what
    /// the 2026-08-04 drill hit. A read-on-demand field has no such window: the
    /// drill already polls this endpoint to find its kill moment, so it now
    /// captures the distribution at the same instant, and after recovery too.
    ///
    /// `None` before the first successful write — distinct from a zeroed
    /// struct, because "not measured" and "measured as zero" must not render
    /// identically to whoever reads this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_write_us: Option<JournalWriteStats>,
    /// Present when the journal is not persistent — the readiness answer is then
    /// about this process's memory only, and a restart would recover nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
}

/// Close trading for a planned stop and cancel what is resting.
///
/// Idempotent: calling it twice pauses once and reports the second call
/// truthfully rather than double-counting.
pub fn begin(gate: &TradingGate) -> bool {
    gate.pause_for(TradingPauseReason::Drain)
}

/// Abandon a drain and re-open trading.
///
/// Only clears the drain reason — an oracle or governance pause set while
/// draining stays set, so cancelling a redeploy cannot accidentally re-open a
/// venue that some other condition had independently closed.
pub fn cancel(gate: &TradingGate) -> bool {
    gate.resume_for(TradingPauseReason::Drain)
}

/// Observe the drain.
pub async fn status(
    gate: &TradingGate,
    journal: &Arc<tokio::sync::Mutex<SettleJournal>>,
    cancelled_resting: usize,
) -> DrainStatus {
    // One lock acquisition for all three reads — a second lock would let the
    // reported write stats belong to a different instant than the in-flight
    // count they are printed beside.
    let (in_flight, persistent, journal_write_us) = {
        let j = journal.lock().await;
        (j.len(), j.is_persistent(), j.write_stats())
    };
    let draining = gate.is_paused_for(TradingPauseReason::Drain);
    DrainStatus {
        draining,
        cancelled_resting,
        in_flight_settlements: in_flight,
        // Both conditions, not either. A quiet journal while trading is still
        // open means nothing: a match could be enqueued in the next tick.
        safe_to_stop: draining && in_flight == 0,
        journal_write_us,
        caveat: (!persistent).then(|| {
            "settle journal is not persistent (no state dir configured); this instance \
             cannot recover in-flight settlements across a restart regardless of drain"
                .to_string()
        }),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::persistence::journal::{JournalEntry, JournalStage};
    use crate::settle::lock_note::Groth16ProofBytes;
    use crate::settle::payload::MatchResultPayload;
    use crate::settle::submit_lock::LockSideInputs;

    pub(super) fn journal(entries: usize) -> Arc<tokio::sync::Mutex<SettleJournal>> {
        let mut j = SettleJournal::in_memory();
        for idx in 0..entries {
            j.record(JournalEntry {
                batch_id: 1,
                match_idx: idx as u8,
                stage: JournalStage::Settling,
                payload: MatchResultPayload {
                    match_id: [0x11; 16],
                    note_a_use_tag: [0xA1; 32],
                    note_b_use_tag: [0xB1; 32],
                    note_c_commitment: [0xC1; 32],
                    note_d_commitment: [0xD1; 32],
                    note_e_commitment: [0xE1; 32],
                    note_f_commitment: [0xF1; 32],
                    order_id_a: [0x01; 16],
                    order_id_b: [0x02; 16],
                    note_fee_base_commitment: [0; 32],
                    note_fee_quote_commitment: [0; 32],
                    buyer_relock_order_id: [0; 16],
                    buyer_relock_expiry: 0,
                    seller_relock_order_id: [0; 16],
                    seller_relock_expiry: 0,
                    note_e_use_tag: [0u8; 32],
                    note_f_use_tag: [0u8; 32],
                    batch_slot: 7,
                    fill_recovery: [0u8; 128],
                },
                buyer_lock: lock(0xA1),
                seller_lock: lock(0xB1),
                batch_root: Some([0xAB; 32]),
                lock_expiry_slot: 1_000,
                marker_expiry_slot: Some(1_000),
                settle_sig: None,
                updated_at_ms: 0,
            })
            .unwrap();
        }
        Arc::new(tokio::sync::Mutex::new(j))
    }

    fn lock(note: u8) -> LockSideInputs {
        LockSideInputs {
            tree_id: 0,
            note_use_tag: [note; 32],
            order_id: [note; 16],
            expiry_slot: 1_000,
            token_mint: [0x0F; 32],
            merkle_root: [0x7C; 32],
            proof: Groth16ProofBytes {
                pi_a: [0; 64],
                pi_b: [0; 128],
                pi_c: [0; 64],
            },
            already_locked: false,
        }
    }

    #[tokio::test]
    async fn a_quiet_journal_is_not_safe_to_stop_while_trading_is_open() {
        let gate = TradingGate::default();
        let s = status(&gate, &journal(0), 0).await;
        assert!(!s.draining);
        assert_eq!(s.in_flight_settlements, 0);
        assert!(
            !s.safe_to_stop,
            "an empty journal means nothing while trading is open — the next tick \
             can enqueue a match"
        );
    }

    #[tokio::test]
    async fn draining_with_settlements_in_flight_is_not_yet_safe() {
        let gate = TradingGate::default();
        assert!(begin(&gate));
        let s = status(&gate, &journal(3), 0).await;
        assert!(s.draining);
        assert_eq!(s.in_flight_settlements, 3);
        assert!(!s.safe_to_stop, "must wait for in-flight settlements");
    }

    #[tokio::test]
    async fn draining_with_an_empty_journal_is_safe_to_stop() {
        let gate = TradingGate::default();
        begin(&gate);
        let s = status(&gate, &journal(0), 7).await;
        assert!(s.safe_to_stop);
        assert_eq!(s.cancelled_resting, 7);
    }

    #[tokio::test]
    async fn begin_is_idempotent() {
        let gate = TradingGate::default();
        assert!(begin(&gate), "first request pauses");
        assert!(
            !begin(&gate),
            "second request reports truthfully, pauses once"
        );
        assert!(gate.is_paused_for(TradingPauseReason::Drain));
    }

    #[tokio::test]
    async fn cancelling_a_drain_does_not_clear_an_independent_pause() {
        let gate = TradingGate::default();
        begin(&gate);
        gate.pause_for(TradingPauseReason::Oracle);
        cancel(&gate);
        assert!(!gate.is_paused_for(TradingPauseReason::Drain));
        assert!(
            gate.is_paused_for(TradingPauseReason::Oracle),
            "abandoning a redeploy must not re-open a venue an oracle fault closed"
        );
        assert!(!gate.is_open());
    }

    /// A non-persistent journal can report zero in flight while being incapable
    /// of recovering anything. Reporting `safe_to_stop` without saying so would
    /// be technically true and practically misleading.
    #[tokio::test]
    async fn a_non_persistent_journal_is_flagged_in_the_status() {
        let gate = TradingGate::default();
        begin(&gate);
        let s = status(&gate, &journal(0), 0).await;
        assert!(s.safe_to_stop);
        let caveat = s.caveat.expect("non-persistent journal must be disclosed");
        assert!(caveat.contains("not persistent"), "got: {caveat}");
    }
}

#[cfg(test)]
mod write_stats_exposure_tests {
    use super::*;
    // Reuse the sibling module's fixture rather than a second copy: the point
    // is that the stats come from a real `record` path, and two fixtures would
    // let them drift.
    use super::tests::journal;

    fn gate() -> TradingGate {
        TradingGate::default()
    }

    /// T-06 — the write-cost row must be readable ON DEMAND, not only when the
    /// throttled log emitter happens to fire.
    ///
    /// The 2026-08-04 drill is the motivating case: a single-match settle does
    /// all four journal writes inside one 10 s throttle window, so the only log
    /// line it produces reads `writes=1`. The drill already polls this endpoint
    /// to find its kill moment, so surfacing the stats here captures the
    /// distribution at that exact instant instead.
    #[tokio::test]
    async fn drain_status_carries_the_journal_write_cost() {
        let journal = journal(5);
        let s = status(&gate(), &journal, 0).await;
        let w = s.journal_write_us.expect("write cost must be reported");
        assert_eq!(w.count, 5, "every write counts, not just the emitted ones");
        assert!(w.p95_us >= w.p50_us && w.max_us >= w.p95_us);
    }

    /// Before any write there is no measurement, and that must be absent from
    /// the JSON rather than rendered as zeros — an operator reading
    /// `p50_us: 0` would conclude the journal is free.
    #[tokio::test]
    async fn an_unwritten_journal_reports_no_measurement_rather_than_zeros() {
        let journal = journal(0);
        let s = status(&gate(), &journal, 0).await;
        assert!(s.journal_write_us.is_none());

        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("journal_write_us"),
            "an absent measurement must be omitted, not zeroed: {json}"
        );
    }
}
