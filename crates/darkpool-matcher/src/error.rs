use thiserror::Error;

#[derive(Debug, Error)]
pub enum MatchError {
    #[error("circuit breaker tripped: clearing_price {clearing} outside band of oracle {oracle} (bps={bps})")]
    CircuitBreakerTripped {
        clearing: u64,
        oracle: i64,
        bps: u16,
    },

    #[error("oracle stale: publish_time_ms={publish_ms} observed_at_ms={observed_ms}")]
    OracleStale { publish_ms: u64, observed_ms: u64 },

    #[error("min_fill_size violation on order {order_id}: filled={filled} min={min}")]
    MinFillViolation {
        order_id: u64,
        filled: u64,
        min: u64,
    },

    #[error("conservation broken on slot {slot}: in={in_amt} out={out_amt}")]
    Conservation {
        slot: usize,
        in_amt: u64,
        out_amt: u64,
    },

    #[error("internal invariant: {0}")]
    Internal(&'static str),
}
