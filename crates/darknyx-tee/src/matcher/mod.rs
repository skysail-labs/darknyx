//! In-TEE matching.
//!
//! The matching algorithm itself lives in `crates/darkpool-matcher` and is the
//! single source of truth; this module is the integration surface around it — the
//! order book, and the tokio interval driver that ties oracle, book, and algorithm
//! together on each tick. See `docs/tee-architecture.md` §5.
//!
//! ```text
//!   book.rs       the resting order book and its indices
//!   interval.rs   the tick driver: oracle read → match → emit RunBatchOutput
//!   gate.rs       admission checks an order must pass before it rests
//!   openings.rs   input-note openings captured and verified at intake
//!   lifecycle.rs  order state transitions
//!   fills.rs      fill records emitted to the fills channel
//!   selftrade.rs  self-trade prevention
//! ```
//!
//! **The driver calls `PreparedMatchTick::next_page` with
//! `single_fill_per_order: true`, not `run_batch`.** `run_batch` chains partial
//! fills within one batch and exists for tests and legacy callers; production does
//! not use it. A change made against `run_batch`'s behaviour will not show up here.
//!
//! Matching is uniform-clearing-price, and a batch carries at most N=16 matches
//! because that is what the VALID_MATCH_BATCH circuit is instantiated for — paging
//! past 16 is the driver's job, not the algorithm's.

pub mod book;
pub mod fills;
pub mod gate;
pub mod interval;
pub mod lifecycle;
pub mod openings;
pub mod selftrade;

pub use book::{BookError, OrderBook};
pub use fills::FillMemo;
pub use gate::{TradingGate, TradingPauseReason};
pub use interval::{
    DriverConfig, MatcherDriver, MatcherState, DEFAULT_MAX_ORACLE_AGE_MS,
    DEFAULT_MAX_ORACLE_FUTURE_SKEW_MS,
};
pub use lifecycle::{OrderLifecycleEvent, OrderLifecycleKind};
pub use openings::{NoteOpening, OpeningError, OpeningStore, OrderOpening};
