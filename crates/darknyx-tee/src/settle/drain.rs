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
use crate::persistence::journal::SettleJournal;

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
    let (in_flight, persistent) = {
        let j = journal.lock().await;
        (j.len(), j.is_persistent())
    };
    let draining = gate.is_paused_for(TradingPauseReason::Drain);
    DrainStatus {
        draining,
        cancelled_resting,
        in_flight_settlements: in_flight,
        // Both conditions, not either. A quiet journal while trading is still
        // open means nothing: a match could be enqueued in the next tick.
        safe_to_stop: draining && in_flight == 0,
        caveat: (!persistent).then(|| {
            "settle journal is not persistent (no state dir configured); this instance \
             cannot recover in-flight settlements across a restart regardless of drain"
                .to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::journal::{JournalEntry, JournalStage};
    use crate::settle::lock_note::Groth16ProofBytes;
    use crate::settle::payload::MatchResultPayload;
    use crate::settle::submit_lock::LockSideInputs;

    fn journal(entries: usize) -> Arc<tokio::sync::Mutex<SettleJournal>> {
        let mut j = SettleJournal::in_memory();
        for idx in 0..entries {
            j.record(JournalEntry {
                batch_id: 1,
                match_idx: idx as u8,
                stage: JournalStage::Settling,
                payload: MatchResultPayload {
                    match_id: [0x11; 16],
                    note_a_commitment: [0xA1; 32],
                    note_b_commitment: [0xB1; 32],
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
                    batch_slot: 7,
                    fill_recovery: [0u8; 128],
                },
                buyer_lock: lock(0xA1),
                seller_lock: lock(0xB1),
                match_index: idx as u8,
                batch_root: Some([0xAB; 32]),
                lock_expiry_slot: 1_000,
                lock_buyer_sig: None,
                lock_seller_sig: None,
                verify_sig: None,
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
            note_commitment: [note; 32],
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
