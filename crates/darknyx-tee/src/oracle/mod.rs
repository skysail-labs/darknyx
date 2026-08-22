//! Pyth oracle boundary.
//!
//! Exactly one boot-selected producer writes the shared cache: either the
//! authenticated Pyth router service (verified 3-of-5 in process) or finalized Pyth
//! Core push accounts on Solana. **The matcher reads only the cache**, so a match
//! tick never waits on oracle I/O and a slow or unreachable oracle degrades price
//! freshness rather than stalling matching.
//!
//! ```text
//!   source.rs       the boot selection between producers
//!   sync.rs         the producer loop that refreshes the cache
//!   cache.rs        the shared cache the matcher reads, and its freshness state
//!   push.rs         Pyth Core push accounts on Solana
//!   hermes.rs       the Pyth router service client
//!   vaa.rs          VAA parsing and signature verification
//!   accumulator.rs  accumulator-proof handling — see docs/oracle-accumulator-notes.md
//! ```
//!
//! Freshness is enforced at read time, not at write time: a stale cache entry is
//! visible to the matcher as stale rather than being silently withheld, so the
//! admission gate decides what to do about it. See `docs/tee-architecture.md` §6.

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
