//! Order generators.
//!
//! v1 ships `Uniform`:
//!   - side: 50/50 bid/ask
//!   - price: uniform in `oracle_twap × [0.95, 1.05]`
//!   - size: lognormal around 1.0 SOL (μ=0.0, σ=0.8 in log-space),
//!     bounded `[100k, 5_000_000_000]` to avoid the matcher's
//!     `note_amount = amount * price_limit` saturating to u64::MAX.
//!   - order_type: limit
//!   - expiry_slot: `current_slot + 1_000_000` (plenty of headroom)
//!
//! Future workloads (`lognormal`, `mass-quote`, `replay-from-file`)
//! land here; the `Workload` trait below is the extension point.

use darkpool_matcher::book::{OrderSide, OrderType};
use rand::Rng;
use rand_distr::{Distribution, LogNormal};

use crate::config::WorkloadKind;

/// One sampled order intent, ready to hand to
/// [`crate::auth::build_signed_place_body`].
#[derive(Debug, Clone)]
pub struct OrderIntent {
    pub side: OrderSide,
    pub order_type: OrderType,
    pub amount: u64,
    pub price_limit: u64,
    pub expiry_slot: u64,
    pub symbol: String,
}

/// Workload generator trait — `sample()` produces one intent per
/// call. Holds its own RNG so traders can run in parallel without
/// contention.
pub trait Workload: Send + 'static {
    fn sample(&mut self) -> OrderIntent;
}

pub fn make_workload(kind: WorkloadKind, oracle_twap: u64, expiry_slot: u64) -> Box<dyn Workload> {
    match kind {
        WorkloadKind::Uniform => Box::new(UniformWorkload::new(oracle_twap, expiry_slot)),
    }
}

// ─── Uniform ────────────────────────────────────────────────────────────────

pub struct UniformWorkload {
    rng: rand::rngs::StdRng,
    oracle_twap: u64,
    /// Slot every sampled order expires at. MUST exceed the matcher's
    /// `current_slot` (the real Solana slot, fed by the TEE's slot
    /// poller) for the order's whole lifetime, else the matcher sweeps
    /// it as expired before it can match. See [`crate::config`].
    expiry_slot: u64,
    /// Lognormal size sampler. μ=0, σ=0.8 → median 1.0, P95 ≈ 3.7,
    /// rare draws up to ~10. Multiplied by 1_000_000 to land in
    /// "1.0 SOL = 1_000_000 base units" territory.
    size_dist: LogNormal<f64>,
}

impl UniformWorkload {
    pub fn new(oracle_twap: u64, expiry_slot: u64) -> Self {
        use rand::SeedableRng;
        Self {
            // Per-instance fixed seed makes runs reproducible. Real
            // benches that need stochastic variation should
            // construct multiple instances with distinct seeds.
            rng: rand::rngs::StdRng::seed_from_u64(0xC0FFEE),
            oracle_twap,
            expiry_slot,
            size_dist: LogNormal::new(0.0, 0.8).expect("σ=0.8 is valid"),
        }
    }
}

impl Workload for UniformWorkload {
    fn sample(&mut self) -> OrderIntent {
        // Side coin-flip.
        let side = if self.rng.gen_bool(0.5) {
            OrderSide::Bid
        } else {
            OrderSide::Ask
        };

        // Price ± 5% around oracle midpoint. `gen_range` is
        // half-open `[lo, hi)` — fine for our purposes.
        let lo = (self.oracle_twap as f64 * 0.95) as u64;
        let hi = (self.oracle_twap as f64 * 1.05) as u64;
        let price_limit = self.rng.gen_range(lo..=hi);

        // Lognormal size, bounded to keep `amount * price_limit`
        // safely under u64::MAX. With price_limit ≤ ~158M (oracle
        // × 1.05) and amount ≤ 5B, the product is ≤ 7.9 × 10^17,
        // well under u64::MAX = 1.8 × 10^19.
        let size_f = self.size_dist.sample(&mut self.rng);
        let amount = (size_f * 1_000_000.0).clamp(100_000.0, 5_000_000_000.0) as u64;

        OrderIntent {
            side,
            order_type: OrderType::Limit,
            amount,
            price_limit,
            expiry_slot: self.expiry_slot,
            symbol: "SOL-USDC".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_samples_within_price_band() {
        let mut w = UniformWorkload::new(150_000_000, 2_000_000_000);
        for _ in 0..1000 {
            let intent = w.sample();
            let lo = (150_000_000_f64 * 0.95) as u64;
            let hi = (150_000_000_f64 * 1.05) as u64;
            assert!(
                (lo..=hi).contains(&intent.price_limit),
                "price {} outside [{lo}, {hi}]",
                intent.price_limit
            );
            assert!(
                (100_000..=5_000_000_000).contains(&intent.amount),
                "amount {} outside size bounds",
                intent.amount
            );
        }
    }

    #[test]
    fn uniform_balances_bid_ask() {
        let mut w = UniformWorkload::new(150_000_000, 2_000_000_000);
        let mut bids = 0u32;
        let mut asks = 0u32;
        for _ in 0..1000 {
            match w.sample().side {
                OrderSide::Bid => bids += 1,
                OrderSide::Ask => asks += 1,
            }
        }
        // 50/50 ± ~5% in 1000 samples; loose bounds catch
        // outrageous bias.
        assert!((400..=600).contains(&bids), "bids={bids}/1000");
        assert!((400..=600).contains(&asks), "asks={asks}/1000");
    }
}
