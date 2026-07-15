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

use darkpool_crypto::match_output_inner_hash;
use darkpool_crypto::note::commitment_from_fields_v2;
use darkpool_matcher::change_note::{CHANGE_ROLE_BUYER, CHANGE_ROLE_SELLER};
use darkpool_matcher::{
    book::{OrderUpdate, OrderUpdateKind},
    config::{MatchConfig, OracleSnapshot},
    match_result::{RunBatchOutput, RELOCK_ORDER_ID_NONE},
    run_batch_capped as matcher_run_batch,
};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time;

use crate::oracle::cache::OracleCache;

use super::book::OrderBook;
use super::fills::FillMemo;
use super::openings::{NoteOpening, OrderOpening};

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
    /// Fixed-point denominator for bid collateral and match pricing.
    price_scale: u64,
    /// Protocol fee rate (bps) — mirrors the driver's
    /// `MatchConfig.fee_rate_bps`. Intake uses it to derive the
    /// *fee-inclusive* collateral each order must lock (nominal +
    /// own fee) so a filled order can pay its own protocol fee out of
    /// its own collateral. 0 (default) → fee-free, collateral = nominal.
    fee_rate_bps: u16,
    /// Legacy fill-memo broadcast retained until canonical order v2 removes
    /// anchor/top-up transport. Derived continuations no longer depend on this
    /// channel for output safety; chain recovery is the durable source.
    fills_tx: tokio::sync::broadcast::Sender<FillMemo>,
    /// Broadcast of [`OrderUpdate`]s — the order-lifecycle events the tick
    /// produces (fully-filled / partially-filled / cancelled / expired). The
    /// `/v1/stream` orders channel subscribes (via `api::order_router`) and fans
    /// each to the owning account. Kept alive with no subscribers (the tick
    /// ignores the send `Err`). Account-agnostic here — keyed by `order_id`;
    /// the API layer maps `order_id → account` (same bridge fills use).
    order_updates_tx: tokio::sync::broadcast::Sender<OrderUpdate>,
}

impl Default for MatcherState {
    fn default() -> Self {
        // 1024 buffered memos is ample — a slow WS client lags (loses old
        // memos) rather than back-pressuring the matcher tick.
        let (fills_tx, _rx) = tokio::sync::broadcast::channel(1024);
        let (order_updates_tx, _rx2) = tokio::sync::broadcast::channel(1024);
        Self {
            book: OrderBook::default(),
            next_match_id: 0,
            openings: super::openings::OpeningStore::default(),
            base_mint: [0u8; 32],
            quote_mint: [0u8; 32],
            price_scale: 1,
            fee_rate_bps: 0,
            fills_tx,
            order_updates_tx,
        }
    }
}

impl MatcherState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to the fill-memo broadcast (the WS `fills` channel).
    pub fn subscribe_fills(&self) -> tokio::sync::broadcast::Receiver<FillMemo> {
        self.fills_tx.subscribe()
    }

    /// Subscribe to the order-lifecycle broadcast (the WS `orders` channel).
    pub fn subscribe_order_updates(&self) -> tokio::sync::broadcast::Receiver<OrderUpdate> {
        self.order_updates_tx.subscribe()
    }

    /// Set this market's mints. Called once at startup from the same
    /// `MatchConfig` the driver uses, so intake-time commitment
    /// verification hashes against the real mints.
    pub fn with_market(mut self, base_mint: [u8; 32], quote_mint: [u8; 32]) -> Self {
        self.base_mint = base_mint;
        self.quote_mint = quote_mint;
        self
    }

    /// Set the protocol fee rate (bps) intake uses to derive the
    /// fee-inclusive collateral. Call at startup with the same
    /// `MatchConfig.fee_rate_bps` the driver matches against.
    pub fn with_fee_rate_bps(mut self, fee_rate_bps: u16) -> Self {
        self.fee_rate_bps = fee_rate_bps;
        self
    }

    pub fn with_price_scale(mut self, price_scale: u64) -> Self {
        self.price_scale = price_scale.max(1);
        self
    }

    pub fn price_scale(&self) -> u64 {
        self.price_scale
    }

    /// Protocol fee rate (bps) for this market.
    pub fn fee_rate_bps(&self) -> u16 {
        self.fee_rate_bps
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

/// Build deterministic continuation outputs for relocking sides of a freshly
/// matched batch. Each change inner is `Poseidon3(24, input_inner, role)`, so
/// no client-supplied anchor or process-local settlement id can influence it.
/// The rotated opening remains inside the enclave because Tx D creates its
/// relock atomically; the next page consumes that locked commitment directly.
///
/// A missing input opening downgrades the residual to cancelled rather than
/// emitting an output whose circuit opening the scheduler cannot reconstruct.
///
/// Must run under the matcher write lock, BEFORE `apply_updates`.
fn assign_derived_continuations(state: &mut MatcherState, output: &mut RunBatchOutput) {
    let (base_mint, quote_mint) = state.market_mints();
    // Collected post-loop edits to `order_updates` (can't borrow it while
    // `matches` is borrowed mut): order_id -> Some(new_collateral_note) to
    // rewrite the PartiallyFilled, or None to downgrade to Cancelled.
    let mut update_edits: Vec<([u8; 16], Option<[u8; 32]>)> = Vec::new();

    for m in output.matches.iter_mut() {
        // ── buyer side → note_e (QUOTE collateral) ──
        if m.buyer_relock_order_id != RELOCK_ORDER_ID_NONE && m.buyer_change_amt > 0 {
            let oid = m.buyer_relock_order_id;
            let prior = state.openings().get(&m.note_buyer);
            match prior {
                Some(prior) => {
                    let owner = prior.opening.owner_commitment;
                    let inner =
                        match_output_inner_hash(&prior.opening.inner_hash, CHANGE_ROLE_BUYER);
                    if let Ok(inner) = inner {
                        if let Ok(note_e) = commitment_from_fields_v2(
                            &quote_mint,
                            m.buyer_change_amt,
                            &owner,
                            &inner,
                        ) {
                            m.note_e_commitment = note_e;
                            let opening = OrderOpening {
                                opening: NoteOpening {
                                    token_mint: quote_mint,
                                    amount: m.buyer_change_amt,
                                    owner_commitment: owner,
                                    inner_hash: inner,
                                    // Settlement replay protection is commitment-
                                    // keyed. The user's spending key derives the
                                    // real nullifier when it later withdraws.
                                    nullifier: [0u8; 32],
                                },
                                order_id: oid,
                                expiry_slot: prior.expiry_slot,
                                // The relock (created when THIS batch settles)
                                // pins note_e on-chain, so the continuation
                                // re-consumes it without a fresh VALID_INPUT
                                // proof; these carry forward the prior values.
                                merkle_root: prior.merkle_root,
                                // Carried forward; unused — `from_relock` skips lock_note.
                                tree_id: prior.tree_id,
                                valid_input_proof: prior.valid_input_proof.clone(),
                                // note_e is locked by THIS batch's re-lock — the
                                // NEXT batch that consumes it must skip lock_note.
                                from_relock: true,
                                // The continuation note returns to the same owner —
                                // carry the viewing key so the residual stays
                                // recoverable across re-locks (Proposal B).
                                viewing_pubkey: prior.viewing_pubkey,
                            };
                            state.openings_mut().insert(note_e, opening);
                            update_edits.push((oid, Some(note_e)));
                        } else {
                            m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                            update_edits.push((oid, None));
                        }
                    } else {
                        m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((oid, None));
                    }
                }
                None => {
                    m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                    update_edits.push((oid, None));
                }
            }
        }

        // ── seller side → note_f (BASE collateral) ──
        if m.seller_relock_order_id != RELOCK_ORDER_ID_NONE && m.seller_change_amt > 0 {
            let oid = m.seller_relock_order_id;
            let prior = state.openings().get(&m.note_seller);
            match prior {
                Some(prior) => {
                    let owner = prior.opening.owner_commitment;
                    let inner =
                        match_output_inner_hash(&prior.opening.inner_hash, CHANGE_ROLE_SELLER);
                    if let Ok(inner) = inner {
                        if let Ok(note_f) = commitment_from_fields_v2(
                            &base_mint,
                            m.seller_change_amt,
                            &owner,
                            &inner,
                        ) {
                            m.note_f_commitment = note_f;
                            let opening = OrderOpening {
                                opening: NoteOpening {
                                    token_mint: base_mint,
                                    amount: m.seller_change_amt,
                                    owner_commitment: owner,
                                    inner_hash: inner,
                                    nullifier: [0u8; 32],
                                },
                                order_id: oid,
                                expiry_slot: prior.expiry_slot,
                                merkle_root: prior.merkle_root,
                                // Carried forward; unused — `from_relock` skips lock_note.
                                tree_id: prior.tree_id,
                                valid_input_proof: prior.valid_input_proof.clone(),
                                // note_f is locked by THIS batch's re-lock.
                                from_relock: true,
                                // Carry the viewing key forward (Proposal B) so the
                                // seller's continuation residual stays recoverable.
                                viewing_pubkey: prior.viewing_pubkey,
                            };
                            state.openings_mut().insert(note_f, opening);
                            update_edits.push((oid, Some(note_f)));
                        } else {
                            m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                            update_edits.push((oid, None));
                        }
                    } else {
                        m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((oid, None));
                    }
                }
                None => {
                    m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                    update_edits.push((oid, None));
                }
            }
        }
    }

    // Apply the collected edits to the order updates.
    for (oid, edit) in update_edits {
        for u in output.order_updates.iter_mut() {
            if u.order_id != oid {
                continue;
            }
            match edit {
                Some(new_note) => {
                    if let OrderUpdateKind::PartiallyFilled {
                        new_collateral_note,
                        ..
                    } = &mut u.kind
                    {
                        *new_collateral_note = new_note;
                    }
                }
                None => {
                    // Downgrade the residual to Cancelled (leaves the book).
                    u.kind = OrderUpdateKind::Cancelled;
                }
            }
        }
    }
}

/// Configuration for one matching tick loop. One driver per market
/// in production — for v2 we run a single market while we shake
/// the design down.
pub struct DriverConfig {
    /// `MatchConfig` passed to `darkpool_matcher::run_batch(...)`.
    /// Constructed from the on-chain `MarketConfig` + the v2
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
    /// Max matches the matcher emits per settle batch — the N of the
    /// VALID_MATCH_BATCH circuit (production: `PRODUCTION_BATCH_N` = 16).
    /// A tick that clears more than this is paged into multiple ≤N
    /// batches (see `tick`). The settle circuit can't absorb a larger
    /// batch, so emitting more would be dropped by the settle assembler.
    pub max_matches_per_batch: usize,
}

/// Safety bound on paging iterations per tick — caps work/latency per
/// tick and guarantees the paging loop terminates even if a logic bug
/// stops the book from draining. At N=16 this allows up to 4096
/// matches/tick, far beyond any realistic crossing book.
const MAX_PAGES_PER_TICK: usize = 256;

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

        // ── Paged matching ──────────────────────────────────────────
        // The matcher can clear far more crossing pairs than the N=16
        // settle circuit absorbs in one batch (the loadgen saw 23-50
        // matches/tick, all dropped by the settle assembler). Page the
        // book: each iteration matches up to `max_matches_per_batch`
        // fills (run_batch_capped), emits that ≤N RunBatchOutput as its
        // own settle batch, applies the fills to the in-memory book,
        // and loops until the book stops crossing. Batches settle
        // SEQUENTIALLY downstream (the scheduler awaits each), so a
        // relock / change note produced by one page is on-chain before
        // a later page that consumes it as collateral settles.
        let max_per_batch = self.cfg.max_matches_per_batch.max(1);
        for page in 0..MAX_PAGES_PER_TICK {
            // Re-snapshot each page so the previous page's fills (applied
            // below) are reflected. Read lock is released before the
            // match so submitters aren't blocked across it.
            let (book_snap, start_match_id) = {
                let state = self.state.read().await;
                let snap = state.book().snapshot();
                (snap, state.next_match_id())
            };
            if book_snap.orders.is_empty() {
                break;
            }

            let mut output = match matcher_run_batch(
                &book_snap,
                &oracle,
                &self.cfg.match_config,
                now_slot,
                start_match_id,
                max_per_batch,
                // single_fill_per_order: each order fills at most once
                // per batch. A partially-filled order's residual relocks
                // on-chain and is dropped from the book (apply_updates) —
                // re-matching it would consume a change note the TEE
                // can't nullify (no spending key). Until the client
                // re-submission relayer lands, residuals await re-submit.
                true,
            ) {
                Ok(out) => out,
                Err(e) => {
                    // Production behaviour: log + stop paging — one bad
                    // order shouldn't kill the daemon. The most common
                    // failure today is `MatchError::Internal("Poseidon
                    // failed for ... change note")` — usually an order
                    // with a non-BN254-Fr-safe `user_commitment` that
                    // slipped past intake. Future PR adds an intake-time
                    // check; for now this is the catch-all.
                    tracing::warn!(
                        error = %e,
                        orders_in_snapshot = book_snap.orders.len(),
                        page,
                        "matcher run_batch failed; ending tick"
                    );
                    break;
                }
            };

            // Apply this page's updates + advance the match-id counter
            // under a brief write lock. `assign_derived_continuations` first
            // rebuilds note_e/note_f from the consumed input inner and inserts
            // the rotated opening, so the circuit and next relock agree.
            {
                let mut state = self.state.write().await;
                assign_derived_continuations(&mut state, &mut output);
                state.book_mut().apply_updates(&output.order_updates);
                // Evict the anchor pool of any order that left the book
                // (full fill / cancel / IOC-or-exhaustion residual / expiry);
                // a continuing PartiallyFilled keeps its pool. Also publish
                // every update on the order-lifecycle broadcast so `orders` subscribers
                // can stream it (best-effort; no subscriber → send `Err`, ignored).
                for u in &output.order_updates {
                    let _ = state.order_updates_tx.send(u.clone());
                    if matches!(
                        u.kind,
                        OrderUpdateKind::FullyFilled { .. }
                            | OrderUpdateKind::Cancelled
                            | OrderUpdateKind::Expired
                    ) {
                        state.openings_mut().remove_anchor_pool(&u.order_id);
                    }
                }
                state.next_match_id = state
                    .next_match_id
                    .saturating_add(output.matches.len() as u64);
            }

            if output.matches.is_empty() {
                // Book no longer crosses (circuit breaker, or no eligible
                // pairs left) — nothing more to page this tick.
                break;
            }

            tracing::info!(
                count = output.matches.len(),
                page,
                "matcher tick: produced matches (page)"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::openings::{NoteOpening, OrderOpening};
    use crate::settle::lock_note::Groth16ProofBytes;
    use darkpool_matcher::match_result::{MatchPair, MatchStatus};

    fn fr_safe(tag: u8) -> [u8; 32] {
        // Top byte zero ⇒ < BN254 modulus (safe to Poseidon-hash).
        let mut a = [0u8; 32];
        a[31] = tag;
        a
    }

    /// Proposal B: the viewing-encryption pubkey on a partially-filled order's
    /// input opening must carry verbatim onto the rotated continuation opening,
    /// so a multi-fill residual's change stays recoverable. Guards the
    /// `viewing_pubkey: prior.viewing_pubkey` carry in
    /// `assign_derived_continuations`.
    #[test]
    fn viewing_pubkey_survives_continuation_relock() {
        let base_mint = [0xb1u8; 32];
        let quote_mint = [0x9eu8; 32];
        let mut state = MatcherState::new().with_market(base_mint, quote_mint);

        let bid_id = [0x42u8; 16];
        let note_buyer = [0x55u8; 32];
        let owner = fr_safe(0x11);
        let viewing = [0xABu8; 32];

        // Input-note opening for the buyer, carrying a viewing pubkey.
        state.openings_mut().insert(
            note_buyer,
            OrderOpening {
                opening: NoteOpening {
                    token_mint: quote_mint,
                    amount: 2_000,
                    owner_commitment: owner,
                    inner_hash: fr_safe(0x33),
                    nullifier: [0x77u8; 32],
                },
                order_id: bid_id,
                expiry_slot: 1_000_000,
                merkle_root: [0xDDu8; 32],
                tree_id: 3,
                valid_input_proof: Groth16ProofBytes {
                    pi_a: [1u8; 64],
                    pi_b: [2u8; 128],
                    pi_c: [3u8; 64],
                },
                from_relock: false,
                viewing_pubkey: Some(viewing),
            },
        );
        // A partial fill that relocks the buyer's residual (note_e).
        let m = MatchPair {
            note_buyer,
            note_seller: [0x66u8; 32],
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            owner_buyer: [0x01u8; 32],
            owner_seller: [0x02u8; 32],
            user_commitment_buyer: fr_safe(0x44),
            user_commitment_seller: fr_safe(0x45),
            buyer_note_value: 2_000,
            seller_note_value: 1_000,
            base_amt: 5,
            quote_amt: 1_500,
            buyer_change_amt: 500,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            buyer_relock_order_id: bid_id,
            buyer_relock_expiry: 1_000_000,
            seller_relock_order_id: RELOCK_ORDER_ID_NONE,
            seller_relock_expiry: 0,
            price: 100,
            pyth_at_match: 100,
            batch_slot: 10,
            match_id: 0,
            status: MatchStatus::Filled,
        };
        let mut output = RunBatchOutput::empty(10, 100, 0);
        output.matches = vec![m];

        assign_derived_continuations(&mut state, &mut output);

        // The rotated opening is keyed by the freshly-computed note_e.
        let note_e = output.matches[0].note_e_commitment;
        assert_ne!(note_e, [0u8; 32], "note_e should have been rebuilt");
        let rotated = state
            .openings()
            .get(&note_e)
            .expect("rotated continuation opening present");
        assert!(rotated.from_relock, "continuation is a relock");
        assert_eq!(
            rotated.viewing_pubkey,
            Some(viewing),
            "viewing pubkey carried onto the continuation opening"
        );
    }
}
