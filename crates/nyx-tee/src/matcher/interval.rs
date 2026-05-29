//! The matching tick. Pulled together from:
//!
//!   - `OrderBook` (this crate, `matcher/book.rs`) — the in-memory
//!     state the daemon writes to as orders arrive.
//!   - `OracleCache` (this crate, `oracle/cache.rs`) — populated
//!     by the `oracle_sync` background task.
//!   - `darkpool_matcher::run_batch(...)` — the pure algorithm,
//!     same crate the on-chain ix calls.
//!
//! Every `BATCH_MS` (default 2 s, per D5), the driver:
//!   1. Sweeps the book of expired orders (cheap range-scan on
//!      the per-expiry-slot index).
//!   2. Snapshots the book + the oracle cache.
//!   3. Calls `darkpool_matcher::run_batch(...)`.
//!   4. Applies the emitted `OrderUpdate`s back to the book.
//!   5. If any real matches landed, ships the `RunBatchOutput`
//!      down an mpsc channel — the settle scheduler picks it up
//!      from there in PR 4d.
//!
//! Conceptual shift documented in `docs/tee-architecture.md`
//! §5.4: nobody outside the TEE can trigger a match. The driver
//! is wholly internal to the long-running daemon.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use darkpool_matcher::{
    config::{MatchConfig, OracleSnapshot},
    match_result::RunBatchOutput,
    run_batch as matcher_run_batch,
};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time;

use crate::oracle::cache::OracleCache;

use super::book::OrderBook;

/// Maximum age of an oracle cache entry the matcher will accept.
/// Default 5 seconds — same order as the batch tick. If the
/// `oracle_sync` task is healthy this is comfortably stale;
/// during a Hermes outage matching ticks no-op and orders queue
/// in the book.
pub const DEFAULT_MAX_ORACLE_AGE_MS: u64 = 5_000;

/// Shared mutable state the driver and order submitters touch.
///
/// `RwLock` not `Mutex`: the matcher tick takes a write lock for
/// microseconds; submitters take a write lock for microseconds.
/// Read queries (future `/tree/inclusion` etc.) take the read
/// lock so they don't contend.
#[derive(Default)]
pub struct MatcherState {
    book: OrderBook,
    next_match_id: u64,
    /// Per-order input-note openings (4g.7a). Populated at intake
    /// after the opening verifies against the signed commitment;
    /// read by the settle assembler; pruned on cancel / settle.
    openings: super::openings::OpeningStore,
    /// This market's base + quote SPL mints. The order intake needs
    /// them to pick the collateral mint (bid → quote, ask → base)
    /// when re-deriving + verifying the note commitment. Zero until
    /// set via [`Self::with_market`]; `new()` leaves them zeroed for
    /// tests that don't exercise the opening path.
    base_mint: [u8; 32],
    quote_mint: [u8; 32],
}

impl MatcherState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set this market's mints. Called once at startup from the same
    /// `MatchConfig` the driver uses, so intake-time commitment
    /// verification hashes against the real mints.
    pub fn with_market(mut self, base_mint: [u8; 32], quote_mint: [u8; 32]) -> Self {
        self.base_mint = base_mint;
        self.quote_mint = quote_mint;
        self
    }

    pub fn book(&self) -> &OrderBook {
        &self.book
    }

    pub fn book_mut(&mut self) -> &mut OrderBook {
        &mut self.book
    }

    pub fn next_match_id(&self) -> u64 {
        self.next_match_id
    }

    /// `(base_mint, quote_mint)` for this market.
    pub fn market_mints(&self) -> ([u8; 32], [u8; 32]) {
        (self.base_mint, self.quote_mint)
    }

    pub fn openings(&self) -> &super::openings::OpeningStore {
        &self.openings
    }

    pub fn openings_mut(&mut self) -> &mut super::openings::OpeningStore {
        &mut self.openings
    }
}

/// Configuration for one matching tick loop. One driver per market
/// in production — for v2 we run a single market while we shake
/// the design down.
pub struct DriverConfig {
    /// `MatchConfig` passed to `darkpool_matcher::run_batch(...)`.
    /// Constructed from the on-chain `MatchingConfig` + the v2
    /// `VaultConfig.fee_rate_bps` + `protocol_owner_commitment`
    /// snapshot at startup. Bumping this requires a daemon
    /// restart (later PR: hot-reload from on-chain).
    pub match_config: MatchConfig,
    /// Pyth feed id for this market — the matcher reads
    /// `oracle_cache.snapshot(feed_id, ...)` at each tick.
    pub feed_id: String,
    /// Tick cadence. D5 default is 2000 ms; the test uses a
    /// shorter interval + `tokio::time::pause`.
    pub batch_ms: u64,
    /// Maximum age for a cached oracle entry to be used.
    pub max_oracle_age_ms: u64,
}

/// Drives matching for a single market. Each driver owns:
///   - an `Arc<RwLock<MatcherState>>` (the book + match-id counter)
///   - a reference to the shared `OracleCache`
///   - an `Arc<AtomicU64>` slot source (driven by a separate
///     Solana-RPC poller in production; advanced manually in tests)
///   - an `mpsc::Sender<RunBatchOutput>` to forward matches to
///     the settle scheduler / sink
pub struct MatcherDriver {
    pub state: Arc<RwLock<MatcherState>>,
    pub oracle: OracleCache,
    pub current_slot: Arc<AtomicU64>,
    pub matches_tx: mpsc::Sender<RunBatchOutput>,
    pub cfg: DriverConfig,
}

impl MatcherDriver {
    /// Spawn the driver as a background tokio task. Returns the
    /// `JoinHandle` so the caller can `.abort()` on shutdown.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Tick loop. Returns only on abort or unrecoverable error
    /// (the only "unrecoverable" path today is the matches_tx
    /// channel closing — meaning the receiver was dropped).
    async fn run(self) {
        let mut ticker = time::interval(Duration::from_millis(self.cfg.batch_ms));
        // Don't fire missed ticks back-to-back if we lag.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            if let Err(channel_closed) = self.tick().await {
                // The settle channel is closed: there's nothing to
                // do with future matches, so exit. Anything else is
                // logged inside `tick()` and we keep going.
                tracing::warn!("matcher tick stopped: {channel_closed}");
                return;
            }
        }
    }

    /// Run one matching cycle. Public for tests that want to drive
    /// the ticker manually instead of advancing tokio time.
    pub async fn tick(&self) -> Result<(), anyhow::Error> {
        let now_slot = self.current_slot.load(Ordering::Relaxed);

        // Read the oracle. If it's missing or too stale, log + skip
        // this tick — we don't want to clear against a price that
        // may have drifted in the meantime.
        let oracle = match self
            .oracle
            .snapshot(&self.cfg.feed_id, self.cfg.max_oracle_age_ms, now_slot)
            .await
        {
            Some(s) => MatcherOracleSnapshot::from(s).0,
            None => {
                tracing::debug!(
                    feed_id = self.cfg.feed_id,
                    "oracle stale or missing — skipping matching tick"
                );
                return Ok(());
            }
        };

        // Sweep expired orders under a brief write lock; we emit
        // their order_ids as `Expired` updates the future API
        // layer will publish on the `orders` WS channel.
        let expired_ids = {
            let mut state = self.state.write().await;
            state.book_mut().sweep_expired(now_slot)
        };
        if !expired_ids.is_empty() {
            tracing::info!(
                count = expired_ids.len(),
                "matcher tick: swept expired orders"
            );
        }

        // Snapshot the book outside the matcher call — we don't
        // want to hold the read lock across `run_batch` (could
        // block submitters for tens of microseconds).
        let (book_snap, start_match_id) = {
            let state = self.state.read().await;
            (state.book().snapshot(), state.next_match_id())
        };

        if book_snap.orders.is_empty() {
            // Nothing to match; just return.
            return Ok(());
        }

        let output = match matcher_run_batch(
            &book_snap,
            &oracle,
            &self.cfg.match_config,
            now_slot,
            start_match_id,
        ) {
            Ok(out) => out,
            Err(e) => {
                // Production behaviour: log + continue — one bad
                // order shouldn't kill the daemon. The most common
                // failure today is `MatchError::Internal("Poseidon
                // failed for ... change note")` — usually means an
                // order with a non-BN254-Fr-safe `user_commitment`
                // slipped past intake validation. Future PR adds an
                // intake-time check; for now this is the catch-all.
                tracing::warn!(
                    error = %e,
                    orders_in_snapshot = book_snap.orders.len(),
                    "matcher run_batch failed; skipping tick"
                );
                return Ok(());
            }
        };

        // Apply the matcher's emitted updates + bump next_match_id
        // under a brief write lock.
        {
            let mut state = self.state.write().await;
            state.book_mut().apply_updates(&output.order_updates);
            state.next_match_id = state
                .next_match_id
                .saturating_add(output.matches.len() as u64);
        }

        if !output.matches.is_empty() {
            tracing::info!(
                clearing_price = output.clearing_price,
                count = output.matches.len(),
                "matcher tick: produced matches"
            );
            // Forward to the settle scheduler. Returns Err if the
            // receiver dropped — meaning we should shut down.
            self.matches_tx
                .send(output)
                .await
                .map_err(|_| anyhow::anyhow!("matches channel closed"))?;
        }
        Ok(())
    }
}

// ─────── Type conversion: oracle::CachedPrice → matcher::OracleSnapshot ─────
//
// The `oracle::OracleSnapshot` shape (in oracle/cache.rs) and the
// `darkpool_matcher::OracleSnapshot` shape (in matcher/config.rs)
// are mirrors of each other but live in separate crates so we need
// an explicit conversion at the boundary. Local newtype wrapper
// because we can't `impl From` across two foreign types.

struct MatcherOracleSnapshot(OracleSnapshot);

impl From<crate::oracle::cache::OracleSnapshot> for MatcherOracleSnapshot {
    fn from(value: crate::oracle::cache::OracleSnapshot) -> Self {
        Self(OracleSnapshot {
            twap: value.twap,
            confidence: value.confidence,
            exponent: value.exponent,
            publish_slot: value.publish_slot,
        })
    }
}
