//! Shared fail-closed gate for new trading.
//!
//! Governance monitoring can pause intake and matching without stopping
//! cancellation or settlement reconciliation. The gate is one atomic reason
//! bitmask: the public API exposes only ready/degraded, while the detailed
//! cause stays in operator logs. Reasons are independent bits, so recovery of
//! one subsystem cannot accidentally clear another subsystem's pause.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TradingPauseReason {
    Governance = 1 << 0,
    Oracle = 1 << 1,
    /// A planned, operator-initiated drain ahead of a redeploy or shutdown.
    ///
    /// Independent of the others on purpose: a governance resume must not
    /// silently un-drain a CVM that is being taken down, and an oracle recovery
    /// must not re-open trading into a draining enclave.
    Drain = 1 << 2,
}

#[derive(Clone, Debug)]
pub struct TradingGate {
    reasons: Arc<AtomicU8>,
}

impl Default for TradingGate {
    fn default() -> Self {
        Self {
            reasons: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl TradingGate {
    pub fn is_open(&self) -> bool {
        self.reasons.load(Ordering::Acquire) == 0
    }

    /// Governance-compatible convenience wrapper.
    pub fn pause(&self) -> bool {
        self.pause_for(TradingPauseReason::Governance)
    }

    /// Governance-compatible convenience wrapper. Clearing governance never
    /// clears an outstanding oracle pause.
    pub fn resume(&self) -> bool {
        self.resume_for(TradingPauseReason::Governance)
    }

    /// Set one independent pause reason. Returns `true` only if this call added
    /// the reason bit.
    pub fn pause_for(&self, reason: TradingPauseReason) -> bool {
        let bit = reason as u8;
        self.reasons.fetch_or(bit, Ordering::AcqRel) & bit == 0
    }

    /// Clear one independent pause reason. Returns `true` only when this call
    /// transitions the complete gate from paused to open.
    pub fn resume_for(&self, reason: TradingPauseReason) -> bool {
        let bit = reason as u8;
        let previous = self.reasons.fetch_and(!bit, Ordering::AcqRel);
        previous & bit != 0 && previous & !bit == 0
    }

    pub fn is_paused_for(&self, reason: TradingPauseReason) -> bool {
        self.reasons.load(Ordering::Acquire) & reason as u8 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_transitions() {
        let gate = TradingGate::default();
        let clone = gate.clone();
        assert!(gate.is_open());
        assert!(clone.pause());
        assert!(!gate.is_open());
        assert!(!gate.pause());
        assert!(gate.resume());
        assert!(clone.is_open());
    }

    /// A drain must survive both other reasons clearing. Un-draining a CVM
    /// that is being taken down would admit orders it is about to lose.
    #[test]
    fn a_drain_is_not_cleared_by_governance_or_oracle_recovery() {
        let gate = TradingGate::default();
        assert!(gate.pause_for(TradingPauseReason::Drain));
        assert!(gate.pause_for(TradingPauseReason::Oracle));
        assert!(
            !gate.resume(),
            "governance resume must not open a draining gate"
        );
        // `resume_for` reports whether the WHOLE gate opened, not whether the
        // bit cleared — so it is correctly `false` here with the drain still set.
        assert!(!gate.resume_for(TradingPauseReason::Oracle));
        assert!(
            !gate.is_paused_for(TradingPauseReason::Oracle),
            "oracle bit cleared"
        );
        assert!(
            !gate.is_open(),
            "oracle recovery must not re-open trading into a draining enclave"
        );
        assert!(gate.is_paused_for(TradingPauseReason::Drain));
        assert!(gate.resume_for(TradingPauseReason::Drain));
        assert!(gate.is_open());
    }

    #[test]
    fn independent_reasons_cannot_resume_each_other() {
        let gate = TradingGate::default();
        assert!(gate.pause_for(TradingPauseReason::Governance));
        assert!(gate.pause_for(TradingPauseReason::Oracle));
        assert!(!gate.resume());
        assert!(!gate.is_open());
        assert!(gate.is_paused_for(TradingPauseReason::Oracle));
        assert!(gate.resume_for(TradingPauseReason::Oracle));
        assert!(gate.is_open());
    }
}
