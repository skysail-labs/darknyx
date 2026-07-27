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
