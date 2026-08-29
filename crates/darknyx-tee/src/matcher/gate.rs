//! Layered fail-closed gate for new trading.
//!
//! Governance monitoring can pause intake and matching without stopping
//! cancellation or settlement reconciliation. Governance and drain reasons are
//! shared by every market in the venue; oracle health is local to one market.
//! Recovery of one subsystem or one feed cannot accidentally clear another
//! subsystem's or market's pause.

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
    /// A Merkle mirror shard's root disagrees with its on-chain `MerkleTree`.
    ///
    /// Venue-wide rather than per-market: the shards are a property of the
    /// vault, not of any one book, and intake's root check reads them for every
    /// market. Accepting orders against a mirror that holds a root the chain
    /// never had produces proofs `lock_note` will reject — after a match, with
    /// an honest counterparty's collateral already locked.
    MerkleDivergence = 1 << 3,
    /// Initial Merkle history replay has not reconciled every shard yet.
    ///
    /// Kept independent from divergence so an oracle or governance refresh
    /// cannot open intake during the cold-boot window. The Merkle sync clears
    /// this only after every mirror exactly matches its on-chain shard.
    MerkleReadiness = 1 << 4,
}

#[derive(Clone, Debug)]
pub struct TradingGate {
    /// Reasons that must close every market in the CVM.
    venue_reasons: Arc<AtomicU8>,
    /// Reasons scoped to this one market. Today only the oracle bit belongs
    /// here; keeping the storage separate prevents a healthy feed from clearing
    /// another market's stale-feed pause.
    market_reasons: Arc<AtomicU8>,
}

impl Default for TradingGate {
    fn default() -> Self {
        Self {
            venue_reasons: Arc::new(AtomicU8::new(0)),
            market_reasons: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl TradingGate {
    /// Create another market gate in the same venue.
    ///
    /// Governance/drain state is shared, while oracle state starts independent.
    /// Ordinary [`Clone`] keeps both layers shared and is used by the API,
    /// matcher driver, and oracle binding for the *same* market.
    pub fn fork_market(&self) -> Self {
        Self {
            venue_reasons: self.venue_reasons.clone(),
            market_reasons: Arc::new(AtomicU8::new(0)),
        }
    }

    pub fn is_open(&self) -> bool {
        self.venue_reasons.load(Ordering::Acquire) == 0
            && self.market_reasons.load(Ordering::Acquire) == 0
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
        self.reasons_for(reason).fetch_or(bit, Ordering::AcqRel) & bit == 0
    }

    /// Clear one independent pause reason. Returns `true` only when this call
    /// transitions the complete gate from paused to open.
    pub fn resume_for(&self, reason: TradingPauseReason) -> bool {
        let bit = reason as u8;
        let previous = self.reasons_for(reason).fetch_and(!bit, Ordering::AcqRel);
        previous & bit != 0 && self.is_open()
    }

    pub fn is_paused_for(&self, reason: TradingPauseReason) -> bool {
        self.reasons_for(reason).load(Ordering::Acquire) & reason as u8 != 0
    }

    fn reasons_for(&self, reason: TradingPauseReason) -> &AtomicU8 {
        match reason {
            TradingPauseReason::Oracle => &self.market_reasons,
            TradingPauseReason::Governance
            | TradingPauseReason::Drain
            | TradingPauseReason::MerkleDivergence
            | TradingPauseReason::MerkleReadiness => &self.venue_reasons,
        }
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
        // Governance must actually be PAUSED first. Without this, `resume()`
        // returns false merely because the bit was never set, and the assertion
        // below passes without exercising the independence it claims to check.
        assert!(gate.pause_for(TradingPauseReason::Governance));
        assert!(gate.pause_for(TradingPauseReason::Drain));
        assert!(gate.pause_for(TradingPauseReason::Oracle));
        assert!(
            !gate.resume(),
            "a REAL governance resume must not open a draining gate"
        );
        assert!(
            !gate.is_paused_for(TradingPauseReason::Governance),
            "the governance bit did clear — it just did not open the gate"
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

    #[test]
    fn market_forks_share_venue_reasons_but_isolate_oracles() {
        assert_eq!(
            std::mem::size_of::<TradingGate>(),
            2 * std::mem::size_of::<Arc<AtomicU8>>(),
            "a gate is exactly two Arc handles: venue and market"
        );
        let sol = TradingGate::default();
        let btc = sol.fork_market();

        assert!(sol.pause_for(TradingPauseReason::Oracle));
        assert!(!sol.is_open());
        assert!(
            btc.is_open(),
            "SOL oracle failure must not pause the BTC market"
        );

        assert!(btc.pause_for(TradingPauseReason::Governance));
        assert!(!sol.is_open());
        assert!(!btc.is_open());
        assert!(sol.is_paused_for(TradingPauseReason::Governance));
        assert!(btc.is_paused_for(TradingPauseReason::Governance));

        assert!(
            !sol.resume(),
            "SOL remains closed for its independent oracle reason"
        );
        assert!(
            btc.is_open(),
            "clearing shared governance re-opens a healthy market"
        );
        assert!(!sol.is_open());

        assert!(sol.resume_for(TradingPauseReason::Oracle));
        assert!(sol.is_open());
        assert!(btc.is_open());
    }
}
