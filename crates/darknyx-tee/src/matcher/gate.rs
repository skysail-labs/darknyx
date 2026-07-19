//! Shared fail-closed gate for new trading.
//!
//! Governance monitoring can pause intake and matching without stopping
//! cancellation or settlement reconciliation. The gate is deliberately a
//! single atomic bit: the public API exposes only ready/degraded, while the
//! detailed cause stays in operator logs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TradingGate {
    open: Arc<AtomicBool>,
}

impl Default for TradingGate {
    fn default() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl TradingGate {
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Pause new place/modify operations and matcher ticks. Returns `true` only
    /// for the transition from open to paused, which keeps logs edge-triggered.
    pub fn pause(&self) -> bool {
        self.open.swap(false, Ordering::AcqRel)
    }

    /// Resume trading. Returns `true` only for the paused-to-open transition.
    pub fn resume(&self) -> bool {
        !self.open.swap(true, Ordering::AcqRel)
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
}
