//! Priority-fee bidding from `getRecentPrioritizationFees` samples.
//!
//! A background poller (main.rs) periodically pulls the recent per-slot
//! prioritization fees and folds them into a single compute-unit price
//! (micro-lamports / CU) via [`priority_fee_bid`], stored in a shared atomic.
//! Each settle-path tx then prepends a `ComputeBudget::SetComputeUnitPrice`
//! ix at the cached price. Because the CU limits are right-sized
//! (see [`super::pipeline`]), the absolute fee (`price × cu_limit`) is bid on a
//! tight footprint.
//!
//! The bid is the Nth percentile of the recent fees — high enough to land
//! ahead of the median bidder, capped so a fee spike can't drain the signer.
//! A quiet network (all-zero samples, e.g. devnet) bids 0: no priority needed.

/// Percentile (0..=100) of the recent per-slot fees to bid. 75th lands ahead of
/// the median without chasing the single-slot peak.
const PRIORITY_FEE_PERCENTILE: usize = 75;

/// Default cap on the compute-unit price (micro-lamports / CU) so a congestion
/// spike can't drain the TEE signer. 1_000_000 µlamports/CU = 1 lamport/CU →
/// at the 187k-CU settle that's ~0.000187 SOL max priority per settle.
/// Overridable via `NYX_TEE_PRIORITY_FEE_CAP` (read in main.rs).
pub const DEFAULT_PRIORITY_FEE_CAP_MICRO_LAMPORTS: u64 = 1_000_000;

/// Fold recent per-slot prioritization fees into a single compute-unit price
/// (micro-lamports / CU): the [`PRIORITY_FEE_PERCENTILE`]th percentile, clamped
/// to `cap`. Empty input → 0.
pub fn priority_fee_bid(samples: &[u64], cap: u64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut v: Vec<u64> = samples.to_vec();
    v.sort_unstable();
    // Nearest-rank percentile on a 0-indexed sorted vec.
    let idx = ((v.len() - 1) * PRIORITY_FEE_PERCENTILE) / 100;
    v[idx].min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bids_zero() {
        assert_eq!(priority_fee_bid(&[], 1_000_000), 0);
    }

    #[test]
    fn all_zero_quiet_network_bids_zero() {
        assert_eq!(priority_fee_bid(&[0, 0, 0, 0], 1_000_000), 0);
    }

    #[test]
    fn picks_75th_percentile() {
        // 0..=100 step 10 → 11 samples; idx = (10 * 75)/100 = 7 → value 70.
        let s: Vec<u64> = (0..=10).map(|i| i * 10).collect();
        assert_eq!(priority_fee_bid(&s, 1_000_000), 70);
    }

    #[test]
    fn caps_the_bid() {
        let s = vec![5_000_000, 6_000_000, 7_000_000, 8_000_000];
        // 75th percentile would be high; cap pulls it down.
        assert_eq!(priority_fee_bid(&s, 1_000_000), 1_000_000);
    }

    #[test]
    fn unsorted_input_is_handled() {
        assert_eq!(priority_fee_bid(&[100, 1, 50, 2, 200], 1_000_000), 100);
    }
}
