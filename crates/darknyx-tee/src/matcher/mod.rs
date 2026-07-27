//! In-TEE matching layer. The pure algorithm lives in
//! `crates/darkpool-matcher`; this module is the integration
//! surface — the order book + the tokio interval driver that
//! ties oracle, book, and algorithm together. See
//! `docs/tee-architecture.md` §5.

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
