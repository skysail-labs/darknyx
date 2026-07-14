//! Pyth pull-pattern oracle. Background `sync` task pulls fresh
//! prices from `hermes.pyth.network` over HTTPS, verifies the
//! Wormhole guardian signatures in-process, and writes the result
//! into a shared `OracleCache`. The matcher tick (§5.4) reads from
//! the cache at every batch fire.
//!
//! See `docs/tee-architecture.md` §5.6 for the full design + the
//! v2-vs-v3 trust trade-off discussion.

pub mod accumulator;
pub mod cache;
pub mod hermes;
pub mod sync;
pub mod vaa;

pub use accumulator::{AccumulatorError, AccumulatorUpdate, PriceFeedMessage, PriceUpdate};
pub use cache::{CachedPrice, OracleCache, OracleSnapshot};
pub use hermes::{HermesClient, HermesError, HermesPriceUpdate};
pub use sync::{spawn_oracle_sync, SyncConfig};
pub use vaa::{verify as verify_vaa, ParsedVaa, VaaError};
