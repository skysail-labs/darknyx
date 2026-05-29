//! In-TEE matching layer. The pure algorithm lives in
//! `crates/darkpool-matcher`; this module is the integration
//! surface — the order book + the tokio interval driver that
//! ties oracle, book, and algorithm together. See
//! `docs/tee-architecture.md` §5.

pub mod book;
pub mod interval;
pub mod openings;
pub mod selftrade;

pub use book::{BookError, OrderBook};
pub use interval::{DriverConfig, MatcherDriver, MatcherState, DEFAULT_MAX_ORACLE_AGE_MS};
pub use openings::{NoteOpening, OpeningError, OpeningStore};
