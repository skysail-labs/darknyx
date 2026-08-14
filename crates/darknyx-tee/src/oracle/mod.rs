//! Pyth oracle boundary. Exactly one boot-selected producer writes the shared
//! cache: either the authenticated upgraded router service (verified 3-of-5 in
//! process) or finalized upgraded Pyth Core push accounts on Solana. The
//! matcher reads only the cache and therefore never waits on oracle I/O.
//!
//! See `docs/tee-architecture.md` §6 for the source and freshness model.

pub mod accumulator;
pub mod cache;
pub mod hermes;
pub mod push;
pub mod source;
pub mod sync;
pub mod vaa;

pub use accumulator::{AccumulatorError, AccumulatorUpdate, PriceFeedMessage, PriceUpdate};
pub use cache::{
    BatchApplyReport, CachedPrice, FreshnessPolicy, OracleCache, OracleCacheError, OracleSnapshot,
    OracleUnits, UnitConversionError,
};
pub use hermes::{
    HermesBatchUpdate, HermesClient, HermesError, HermesPriceUpdate, DEFAULT_HERMES_ENDPOINT,
    UPGRADED_HERMES_ENDPOINT,
};
pub use push::{derive_push_feed_address, spawn_push_oracle_sync, PushSyncConfig};
pub use source::{OracleMode, OracleSourceKind};
pub use sync::{spawn_oracle_sync, MarketOracleBinding, SyncConfig};
pub use vaa::{verify as verify_vaa, verify_for_profile, ParsedVaa, TrustProfile, VaaError};
