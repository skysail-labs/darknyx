//! Order generators — one [`OrderIntent`] per `sample()`.
//!
//! A single [`ScenarioWorkload`] branches on the chosen [`Scenario`] so all
//! shapes share the RNG + price/size machinery:
//!
//! - `uniform` — side coin-flip; price uniform in `twap × [0.95,1.05]`;
//!   lognormal size. Broad intake load; crosses by chance.
//! - `exact-match` — alternating bid/ask at the midpoint, equal size → every
//!   consecutive pair fully matches.
//! - `partial-fill` — `exact-match` but bids are 2× the ask size → each match
//!   leaves a residual that relocks onto an anchor.
//! - `ioc-fok` — `exact-match` shape with order_type cycling limit/ioc/fok.
//! - `over-collateral` — `exact-match` shape; each order declares collateral
//!   `over_collateral_bps` above the minimum.
//!
//! Note: synthetic orders carry stub VALID_INPUT proofs, so a *match* attempts
//! to settle but the on-chain lock fails — the scenarios stress intake + the
//! matcher (batching, paging, anchor rotation, execution policy), NOT settle.
//! Real on-chain settle is the `--real-settle` mode (see BENCHMARK.md).

use darkpool_matcher::book::{OrderSide, OrderType};
use rand::Rng;
use rand_distr::{Distribution, LogNormal};

use crate::config::Scenario;

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
    /// Over-collateralization, in bps of the required collateral. `0` ⇒ the
    /// order declares no explicit `collateral_amount` (intake uses the derived
    /// minimum). `> 0` ⇒ auth derives `required`, adds this surplus, and sends
    /// it as `collateral_amount`.
    pub collateral_surplus_bps: u16,
}

/// Workload generator trait — `sample()` produces one intent per call. Holds its
/// own RNG so traders run in parallel without contention.
pub trait Workload: Send + 'static {
    fn sample(&mut self) -> OrderIntent;
}

/// Build a per-trader workload. `seed` distinguishes traders so they don't all
/// emit byte-identical streams (which would collide on the same crossing book).
pub fn make_workload(
    scenario: Scenario,
    oracle_twap: u64,
    expiry_slot: u64,
    symbol: String,
    over_collateral_bps: u16,
    seed: u64,
) -> Box<dyn Workload> {
    Box::new(ScenarioWorkload::new(
        scenario,
        oracle_twap,
        expiry_slot,
        symbol,
        over_collateral_bps,
        seed,
    ))
}

/// Base order size for the crossing scenarios (1.0 "SOL" in base units).
const MATCH_SIZE: u64 = 1_000_000;

pub struct ScenarioWorkload {
    scenario: Scenario,
    rng: rand::rngs::StdRng,
    oracle_twap: u64,
    expiry_slot: u64,
    symbol: String,
    over_collateral_bps: u16,
    /// Lognormal size sampler (uniform scenario). μ=0, σ=0.8 → median 1.0.
    size_dist: LogNormal<f64>,
    /// Alternates bid/ask for the crossing scenarios so consecutive samples
    /// form a matchable pair.
    next_is_bid: bool,
    /// Cycles limit/ioc/fok for the `ioc-fok` scenario.
    type_cycle: u8,
}

impl ScenarioWorkload {
    pub fn new(
        scenario: Scenario,
        oracle_twap: u64,
        expiry_slot: u64,
        symbol: String,
        over_collateral_bps: u16,
        seed: u64,
    ) -> Self {
        use rand::SeedableRng;
        Self {
            scenario,
            rng: rand::rngs::StdRng::seed_from_u64(0xC0FFEE ^ seed),
            oracle_twap,
            expiry_slot,
            symbol,
            over_collateral_bps,
            size_dist: LogNormal::new(0.0, 0.8).expect("σ=0.8 is valid"),
            next_is_bid: true,
            type_cycle: 0,
        }
    }

    fn uniform(&mut self) -> OrderIntent {
        let side = if self.rng.gen_bool(0.5) {
            OrderSide::Bid
        } else {
            OrderSide::Ask
        };
        let lo = (self.oracle_twap as f64 * 0.95) as u64;
        let hi = (self.oracle_twap as f64 * 1.05) as u64;
        let price_limit = self.rng.gen_range(lo..=hi);
        let size_f = self.size_dist.sample(&mut self.rng);
        let amount = (size_f * 1_000_000.0).clamp(100_000.0, 5_000_000_000.0) as u64;
        OrderIntent {
            side,
            order_type: OrderType::Limit,
            amount,
            price_limit,
            expiry_slot: self.expiry_slot,
            symbol: self.symbol.clone(),
            collateral_surplus_bps: 0,
        }
    }

    /// Crossing pair: alternating side at the midpoint. `bid_mult` scales the
    /// bid's size (2 ⇒ partial fills). `order_type` + `surplus_bps` vary by
    /// scenario.
    fn crossing(&mut self, bid_mult: u64, order_type: OrderType, surplus_bps: u16) -> OrderIntent {
        let side = if self.next_is_bid {
            OrderSide::Bid
        } else {
            OrderSide::Ask
        };
        self.next_is_bid = !self.next_is_bid;
        // Both sides at the midpoint → bid_price == ask_price → they cross.
        let price_limit = self.oracle_twap.max(1);
        let amount = match side {
            OrderSide::Bid => MATCH_SIZE.saturating_mul(bid_mult),
            OrderSide::Ask => MATCH_SIZE,
        };
        OrderIntent {
            side,
            order_type,
            amount,
            price_limit,
            expiry_slot: self.expiry_slot,
            symbol: self.symbol.clone(),
            collateral_surplus_bps: surplus_bps,
        }
    }

    fn next_ioc_fok_type(&mut self) -> OrderType {
        let t = match self.type_cycle % 3 {
            0 => OrderType::Limit,
            1 => OrderType::Ioc,
            _ => OrderType::Fok,
        };
        self.type_cycle = self.type_cycle.wrapping_add(1);
        t
    }
}

impl Workload for ScenarioWorkload {
    fn sample(&mut self) -> OrderIntent {
        match self.scenario {
            Scenario::Uniform => self.uniform(),
            Scenario::ExactMatch => self.crossing(1, OrderType::Limit, 0),
            Scenario::PartialFill => self.crossing(2, OrderType::Limit, 0),
            Scenario::IocFok => {
                let ot = self.next_ioc_fok_type();
                self.crossing(1, ot, 0)
            }
            Scenario::OverCollateral => {
                self.crossing(1, OrderType::Limit, self.over_collateral_bps)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(scenario: Scenario) -> ScenarioWorkload {
        ScenarioWorkload::new(
            scenario,
            150_000_000,
            2_000_000_000,
            "SOL-USDC".into(),
            2000,
            0,
        )
    }

    #[test]
    fn uniform_samples_within_price_band() {
        let mut w = w(Scenario::Uniform);
        for _ in 0..1000 {
            let intent = w.sample();
            let lo = (150_000_000_f64 * 0.95) as u64;
            let hi = (150_000_000_f64 * 1.05) as u64;
            assert!((lo..=hi).contains(&intent.price_limit));
            assert!((100_000..=5_000_000_000).contains(&intent.amount));
        }
    }

    #[test]
    fn exact_match_alternates_sides_at_midpoint() {
        let mut w = w(Scenario::ExactMatch);
        let a = w.sample();
        let b = w.sample();
        assert_ne!(
            a.side as u8 == OrderSide::Bid as u8,
            b.side as u8 == OrderSide::Bid as u8
        );
        assert_eq!(a.price_limit, 150_000_000);
        assert_eq!(b.price_limit, 150_000_000);
        assert_eq!(a.amount, MATCH_SIZE);
        assert_eq!(b.amount, MATCH_SIZE);
    }

    #[test]
    fn partial_fill_bid_is_double_the_ask() {
        let mut w = w(Scenario::PartialFill);
        // First sample is a bid (next_is_bid starts true).
        let bid = w.sample();
        let ask = w.sample();
        assert_eq!(bid.side as u8, OrderSide::Bid as u8);
        assert_eq!(ask.side as u8, OrderSide::Ask as u8);
        assert_eq!(bid.amount, 2 * MATCH_SIZE);
        assert_eq!(ask.amount, MATCH_SIZE);
    }

    #[test]
    fn ioc_fok_cycles_order_types() {
        let mut w = w(Scenario::IocFok);
        let types: Vec<OrderType> = (0..3).map(|_| w.sample().order_type).collect();
        assert!(types.contains(&OrderType::Limit));
        assert!(types.contains(&OrderType::Ioc));
        assert!(types.contains(&OrderType::Fok));
    }

    #[test]
    fn over_collateral_carries_surplus_bps() {
        let mut w = w(Scenario::OverCollateral);
        assert_eq!(w.sample().collateral_surplus_bps, 2000);
    }
}
