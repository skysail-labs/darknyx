//! The matching tick. Pulled together from:
//!
//!   - `OrderBook` (this crate, `matcher/book.rs`) — the in-memory
//!     state the daemon writes to as orders arrive.
//!   - `OracleCache` (this crate, `oracle/cache.rs`) — populated
//!     by the `oracle_sync` background task.
//!   - `darkpool_matcher::PreparedMatchTick::next_page(...)` — the pure
//!     algorithm, same crate the on-chain ix calls.
//!
//!     NOT `run_batch`, which these lines used to name (SW-28). The two differ
//!     in `single_fill_per_order`: `next_page` passes `true`, so a
//!     partially-filled order is relocked and NOT re-matched within the batch,
//!     while `run_batch` chains. A reader auditing the matcher from the enclave
//!     inward landed on the wrong function and reasoned about chaining
//!     semantics the enclave never uses.
//!
//! Every `BATCH_MS` (default 2 s, per D5), the driver:
//!   1. Sweeps the book of expired orders (cheap range-scan on
//!      the per-expiry-slot index).
//!   2. Snapshots the book + the oracle cache.
//!   3. Calls `darkpool_matcher::PreparedMatchTick::next_page(...)`.
//!   4. Reserves matched orders as `pending_settlement` without changing
//!      quantities or publishing fills.
//!   5. Ships the `RunBatchOutput` to the settle scheduler. Each order update
//!      is applied only after that match's Tx D confirms; rejected matches are
//!      terminal and ambiguous matches stay reserved.
//!
//! Conceptual shift documented in `docs/tee-architecture.md`
//! §5.4: nobody outside the TEE can trigger a match. The driver
//! is wholly internal to the long-running daemon.

use std::collections::{HashMap, HashSet};
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
    PreparedMatchTick,
};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time;

use crate::oracle::cache::{FreshnessPolicy, OracleCache, OracleUnits};
use crate::settle::vault::market_config_pda;

use super::book::OrderBook;
use super::fills::FillMemo;
use super::gate::TradingGate;
use super::lifecycle::{OrderLifecycleEvent, OrderLifecycleKind};
use super::openings::{NoteOpening, OrderOpening};

/// Maximum age of an oracle cache entry the matcher will accept.
/// Default 5 seconds — same order as the batch tick. If the `oracle_sync` task
/// is healthy this is comfortably stale; during an outage the independent
/// oracle reason pauses new intake and matching while cancellation and
/// reconciliation remain available.
pub const DEFAULT_MAX_ORACLE_AGE_MS: u64 = 5_000;
pub const DEFAULT_MAX_ORACLE_FUTURE_SKEW_MS: u64 = 1_000;

/// Shared mutable state the driver and order submitters touch.
///
/// `RwLock` not `Mutex`: the matcher tick takes a write lock for
/// microseconds; submitters take a write lock for microseconds.
/// Read queries (future `/tree/inclusion` etc.) take the read
/// lock so they don't contend.
pub struct MatcherState {
    book: OrderBook,
    next_match_id: u64,
    /// Per-order input-note openings. Populated at intake
    /// after the opening verifies against the signed commitment;
    /// read by the settle assembler; pruned on cancel / settle.
    openings: super::openings::OpeningStore,
    /// Input openings retained after a definitive settlement failure. Their
    /// orders are terminal, but the same collateral must not back a fresh
    /// signed order until its NoteLock expires.
    failed_reservations: HashMap<[u8; 32], u64>,
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
    /// Live, per-fill recovery records. Each memo binds the derived change
    /// output to its consumed input commitment and circuit role.
    fills_tx: tokio::sync::broadcast::Sender<FillMemo>,
    /// Broadcast of [`OrderUpdate`]s — the order-lifecycle events the tick
    /// produces (fully-filled / partially-filled / cancelled / expired). The
    /// `/v1/stream` orders channel subscribes (via `api::order_router`) and fans
    /// each to the owning account. Kept alive with no subscribers (the tick
    /// ignores the send `Err`). Account-agnostic here — keyed by `order_id`;
    /// the API layer maps `order_id → account` (same bridge fills use).
    order_updates_tx: tokio::sync::broadcast::Sender<OrderLifecycleEvent>,
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
            failed_reservations: HashMap::new(),
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
    pub fn subscribe_order_updates(&self) -> tokio::sync::broadcast::Receiver<OrderLifecycleEvent> {
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

    /// Canonical base58 market identity, derived from the on-chain
    /// `MarketConfig` PDA rather than a display symbol.
    pub fn market_id(&self) -> String {
        market_config_pda(&self.base_mint, &self.quote_mint)
            .0
            .to_string()
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
/// The rotated opening is inserted only after that match's Tx D confirms.
///
/// A missing input opening downgrades the residual to cancelled rather than
/// emitting an output whose circuit opening the scheduler cannot reconstruct.
///
/// Must run before orders are reserved and the batch is sent to settlement.
fn prepare_derived_continuations(state: &MatcherState, output: &mut RunBatchOutput) {
    let (base_mint, quote_mint) = state.market_mints();
    // Collected post-loop edits to `order_updates` (can't borrow it while
    // `matches` is borrowed mut): order_id -> Some(new_collateral_note) to
    // rewrite the PartiallyFilled, or None to downgrade to Cancelled.
    let mut update_edits: Vec<([u8; 16], Option<[u8; 32]>)> = Vec::new();

    for m in output.matches.iter_mut() {
        // ── buyer side → note_e (QUOTE collateral) ──
        if m.buyer_change_amt > 0 {
            let relock_oid = m.buyer_relock_order_id;
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
                            if relock_oid != RELOCK_ORDER_ID_NONE {
                                update_edits.push((relock_oid, Some(note_e)));
                            }
                        } else if relock_oid != RELOCK_ORDER_ID_NONE {
                            m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                            update_edits.push((relock_oid, None));
                        }
                    } else if relock_oid != RELOCK_ORDER_ID_NONE {
                        m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((relock_oid, None));
                    }
                }
                None => {
                    if relock_oid != RELOCK_ORDER_ID_NONE {
                        m.buyer_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((relock_oid, None));
                    }
                }
            }
        }

        // ── seller side → note_f (BASE collateral) ──
        if m.seller_change_amt > 0 {
            let relock_oid = m.seller_relock_order_id;
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
                            if relock_oid != RELOCK_ORDER_ID_NONE {
                                update_edits.push((relock_oid, Some(note_f)));
                            }
                        } else if relock_oid != RELOCK_ORDER_ID_NONE {
                            m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                            update_edits.push((relock_oid, None));
                        }
                    } else if relock_oid != RELOCK_ORDER_ID_NONE {
                        m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((relock_oid, None));
                    }
                }
                None => {
                    if relock_oid != RELOCK_ORDER_ID_NONE {
                        m.seller_relock_order_id = RELOCK_ORDER_ID_NONE;
                        update_edits.push((relock_oid, None));
                    }
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

impl MatcherState {
    /// Reserve every matched order without applying quantities or publishing a
    /// fill. `OrderStatus::Matched` is exposed as `pending_settlement` and is
    /// skipped by subsequent matcher snapshots.
    pub(crate) fn reserve_batch(&mut self, output: &RunBatchOutput) -> Result<(), String> {
        let mut ids = Vec::with_capacity(output.matches.len() * 2);
        let mut pending_events = Vec::with_capacity(output.matches.len() * 2);
        let market_id = self.market_id();
        for m in &output.matches {
            let buyer = self
                .openings
                .get(&m.note_buyer)
                .ok_or_else(|| format!("missing buyer opening {}", hex::encode(m.note_buyer)))?;
            let seller = self
                .openings
                .get(&m.note_seller)
                .ok_or_else(|| format!("missing seller opening {}", hex::encode(m.note_seller)))?;
            ids.push(buyer.order_id);
            ids.push(seller.order_id);
            pending_events.push(OrderLifecycleEvent {
                trading_key: m.owner_buyer,
                order_id: buyer.order_id,
                market_id: market_id.clone(),
                match_id: Some(m.match_id),
                kind: OrderLifecycleKind::PendingSettlement {
                    lock_expiry_slot: buyer.expiry_slot,
                },
            });
            pending_events.push(OrderLifecycleEvent {
                trading_key: m.owner_seller,
                order_id: seller.order_id,
                market_id: market_id.clone(),
                match_id: Some(m.match_id),
                kind: OrderLifecycleKind::PendingSettlement {
                    lock_expiry_slot: seller.expiry_slot,
                },
            });
        }
        let unique: HashSet<_> = ids.iter().copied().collect();
        if unique.len() != ids.len() {
            return Err("a settlement batch references one order more than once".to_string());
        }
        self.book
            .reserve_for_settlement(&ids)
            .map_err(|error| error.to_string())?;
        for event in pending_events {
            let _ = self.order_updates_tx.send(event);
        }
        Ok(())
    }

    fn continuation_opening(
        prior: &OrderOpening,
        token_mint: [u8; 32],
        amount: u64,
        inner_hash: [u8; 32],
        order_id: [u8; 16],
        tree_id: u8,
    ) -> OrderOpening {
        OrderOpening {
            opening: NoteOpening {
                token_mint,
                amount,
                owner_commitment: prior.opening.owner_commitment,
                inner_hash,
            },
            order_id,
            expiry_slot: prior.expiry_slot,
            merkle_root: prior.merkle_root,
            tree_id,
            valid_input_proof: prior.valid_input_proof.clone(),
            from_relock: true,
            viewing_pubkey: prior.viewing_pubkey,
        }
    }

    /// Apply one confirmed match. This is the only path that mutates filled
    /// quantities, rotates continuation collateral, or publishes fill memos.
    pub(crate) fn commit_confirmed_match(
        &mut self,
        output: &RunBatchOutput,
        match_index: usize,
        settle_tree_id: u8,
    ) -> Result<(), String> {
        let m = output
            .matches
            .get(match_index)
            .ok_or_else(|| format!("match index {match_index} out of range"))?;
        let buyer = self
            .openings
            .get(&m.note_buyer)
            .ok_or_else(|| format!("missing buyer opening {}", hex::encode(m.note_buyer)))?;
        let seller = self
            .openings
            .get(&m.note_seller)
            .ok_or_else(|| format!("missing seller opening {}", hex::encode(m.note_seller)))?;
        let updates: Vec<OrderUpdate> = output
            .order_updates
            .iter()
            .filter(|update| {
                update.order_id == buyer.order_id || update.order_id == seller.order_id
            })
            .cloned()
            .collect();
        if updates.len() != 2 {
            return Err(format!(
                "confirmed match {match_index} has {} participant updates, expected 2",
                updates.len()
            ));
        }

        self.openings.remove(&m.note_buyer);
        self.openings.remove(&m.note_seller);
        self.failed_reservations.remove(&m.note_buyer);
        self.failed_reservations.remove(&m.note_seller);

        let (base_mint, quote_mint) = self.market_mints();
        if m.buyer_change_amt > 0 {
            let inner = match_output_inner_hash(&buyer.opening.inner_hash, CHANGE_ROLE_BUYER)
                .map_err(|error| error.to_string())?;
            let _ = self.fills_tx.send(FillMemo::new(
                buyer.order_id,
                m.note_buyer,
                CHANGE_ROLE_BUYER,
                m.buyer_change_amt,
                m.note_e_commitment,
                quote_mint,
                inner,
            ));
            if m.buyer_relock_order_id != RELOCK_ORDER_ID_NONE {
                self.openings.insert(
                    m.note_e_commitment,
                    Self::continuation_opening(
                        &buyer,
                        quote_mint,
                        m.buyer_change_amt,
                        inner,
                        m.buyer_relock_order_id,
                        settle_tree_id,
                    ),
                );
            }
        }
        if m.seller_change_amt > 0 {
            let inner = match_output_inner_hash(&seller.opening.inner_hash, CHANGE_ROLE_SELLER)
                .map_err(|error| error.to_string())?;
            let _ = self.fills_tx.send(FillMemo::new(
                seller.order_id,
                m.note_seller,
                CHANGE_ROLE_SELLER,
                m.seller_change_amt,
                m.note_f_commitment,
                base_mint,
                inner,
            ));
            if m.seller_relock_order_id != RELOCK_ORDER_ID_NONE {
                self.openings.insert(
                    m.note_f_commitment,
                    Self::continuation_opening(
                        &seller,
                        base_mint,
                        m.seller_change_amt,
                        inner,
                        m.seller_relock_order_id,
                        settle_tree_id,
                    ),
                );
            }
        }

        self.book.apply_updates(&updates);
        let market_id = self.market_id();
        for update in updates {
            let _ = self.order_updates_tx.send(OrderLifecycleEvent::settled(
                update,
                market_id.clone(),
                Some(m.match_id),
            ));
        }
        Ok(())
    }

    /// Make a definitive settlement failure terminal without applying its
    /// proposed fill. The input openings stay reserved until their NoteLocks
    /// expire, preventing an immediately resubmitted order from reusing locked
    /// collateral.
    pub(crate) fn reject_match(
        &mut self,
        output: &RunBatchOutput,
        match_index: usize,
        reason: &str,
    ) -> Result<(), String> {
        let m = output
            .matches
            .get(match_index)
            .ok_or_else(|| format!("match index {match_index} out of range"))?;
        let buyer = self
            .openings
            .get(&m.note_buyer)
            .ok_or_else(|| format!("missing buyer opening {}", hex::encode(m.note_buyer)))?;
        let seller = self
            .openings
            .get(&m.note_seller)
            .ok_or_else(|| format!("missing seller opening {}", hex::encode(m.note_seller)))?;

        let _ = self.book.remove_pending_settlement(&buyer.order_id);
        let _ = self.book.remove_pending_settlement(&seller.order_id);
        self.failed_reservations
            .insert(m.note_buyer, buyer.expiry_slot);
        self.failed_reservations
            .insert(m.note_seller, seller.expiry_slot);
        for (trading_key, order_id, lock_expiry_slot) in [
            (m.owner_buyer, buyer.order_id, buyer.expiry_slot),
            (m.owner_seller, seller.order_id, seller.expiry_slot),
        ] {
            let _ = self.order_updates_tx.send(OrderLifecycleEvent {
                trading_key,
                order_id,
                market_id: self.market_id(),
                match_id: Some(m.match_id),
                kind: OrderLifecycleKind::SettlementFailed {
                    reason: reason.to_string(),
                    lock_expiry_slot,
                },
            });
        }
        Ok(())
    }

    pub(crate) fn reject_batch(&mut self, output: &RunBatchOutput, reason: &str) {
        for idx in 0..output.matches.len() {
            let m = &output.matches[idx];
            if !self.openings.is_reserved(&m.note_buyer)
                && !self.openings.is_reserved(&m.note_seller)
            {
                // This sibling already confirmed and its consumed openings
                // were replaced/removed by `commit_confirmed_match`.
                continue;
            }
            if let Err(error) = self.reject_match(output, idx, reason) {
                tracing::error!(match_idx = idx, %error, "failed to reject settlement match");
            }
        }
    }

    /// Release only terminal failed reservations whose lock expiry has passed.
    /// Ambiguous matches remain in the book as `Matched` and are never swept by
    /// this path.
    pub(crate) fn release_failed_reservations(&mut self, now_slot: u64) {
        let expired: Vec<[u8; 32]> = self
            .failed_reservations
            .iter()
            .filter_map(|(commitment, expiry)| (*expiry <= now_slot).then_some(*commitment))
            .collect();
        for commitment in expired {
            self.failed_reservations.remove(&commitment);
            self.openings.remove(&commitment);
        }
    }
}

/// Configuration for one matching tick loop. Production creates one driver per
/// configured market and shares only the venue-wide settlement resources.
pub struct DriverConfig {
    /// `MatchConfig` passed to `darkpool_matcher::PreparedMatchTick::new(...)`.
    /// Constructed from the on-chain `MarketConfig` + the v2
    /// `VaultConfig.fee_rate_bps` + `protocol_owner_commitment`
    /// snapshot at startup. The finalized governance monitor pauses trading on
    /// drift; a process restart atomically adopts a changed parameter set.
    pub match_config: MatchConfig,
    /// Pyth feed id for this market — the matcher reads
    /// `oracle_cache.snapshot(feed_id, ...)` at each tick.
    pub feed_id: String,
    /// Tick cadence. D5 default is 2000 ms; the test uses a
    /// shorter interval + `tokio::time::pause`.
    pub batch_ms: u64,
    /// Maximum age for a cached oracle entry to be used.
    pub max_oracle_age_ms: u64,
    /// Maximum accepted signed timestamp lead over the TEE wall clock.
    pub max_oracle_future_skew_ms: u64,
    /// Governed atomic-unit conversion for this market.
    pub oracle_units: OracleUnits,
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
    /// Layered fail-closed gate for this market. Governance/drain state is
    /// venue-wide; oracle state is market-local. A paused tick is a no-op;
    /// existing settlement jobs continue in the independent scheduler.
    pub trading_gate: TradingGate,
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
        if !self.trading_gate.is_open() {
            tracing::debug!("trading paused — skipping matching tick");
            return Ok(());
        }
        let now_slot = self.current_slot.load(Ordering::Relaxed);

        // Read the oracle. If it's missing or too stale, log + skip
        // this tick — we don't want to clear against a price that
        // may have drifted in the meantime.
        let freshness = FreshnessPolicy {
            max_age_ms: self.cfg.max_oracle_age_ms,
            max_future_skew_ms: self.cfg.max_oracle_future_skew_ms,
        };
        let oracle = match self
            .oracle
            .snapshot(&self.cfg.feed_id, freshness, self.cfg.oracle_units)
            .await
        {
            Ok(s) => MatcherOracleSnapshot::from(s).0,
            Err(error) => {
                self.trading_gate
                    .pause_for(super::gate::TradingPauseReason::Oracle);
                tracing::warn!(
                    feed_id = self.cfg.feed_id,
                    error = %error,
                    "oracle invalid, stale, or missing — trading PAUSED"
                );
                return Ok(());
            }
        };

        // Sweep expired orders under a brief write lock; we emit
        // their order_ids as `Expired` updates the future API
        // layer will publish on the `orders` WS channel.
        let expired_ids = {
            let mut state = self.state.write().await;
            state.release_failed_reservations(now_slot);
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
        // book: prepare one sorted snapshot + price-level demand/supply curves,
        // then each iteration matches up to `max_matches_per_batch` fills,
        // reserves those orders, emits that ≤N RunBatchOutput as its own settle
        // batch, and removes the touched levels from later pages. New orders
        // arriving while this tick is paging wait for the next deterministic
        // snapshot. Batches settle sequentially downstream; a continuation can
        // re-enter a later tick only after its Tx D confirms.
        let max_per_batch = self.cfg.max_matches_per_batch.max(1);
        let (book_snap, mut next_match_id) = {
            let state = self.state.read().await;
            (state.book().snapshot(), state.next_match_id())
        };
        if book_snap.orders.is_empty() {
            return Ok(());
        }
        let mut prepared =
            PreparedMatchTick::new(book_snap, self.cfg.match_config.clone(), now_slot);

        for page in 0..MAX_PAGES_PER_TICK {
            let mut output = match prepared.next_page(&oracle, next_match_id, max_per_batch) {
                Ok(out) => out,
                Err(e) => {
                    // Production behaviour: log + stop paging — one bad
                    // order shouldn't kill the daemon. The most common
                    // failure today is `MatchError::Internal("Poseidon
                    // failed for ... change note")` — usually corrupted
                    // internal state or an order that bypassed intake. Intake
                    // already rejects non-BN254-Fr-safe commitments; this is the
                    // defense-in-depth catch-all.
                    tracing::warn!(
                        error = %e,
                        orders_in_snapshot = prepared.snapshot_len(),
                        page,
                        "matcher next_page failed; ending tick"
                    );
                    break;
                }
            };

            // Governance may have paused while the pure page calculation was
            // running. Recheck immediately before reserving/mutating the book so
            // a detected config transition cannot create a new settle batch.
            if !self.trading_gate.is_open() {
                tracing::warn!("trading paused during matcher tick; discarding computed page");
                break;
            }

            // Prepare proof-bound continuation commitments, apply only updates
            // unrelated to a real match (for example FOK cancellation), and
            // reserve every matched order. Fill quantities, rotated openings,
            // and fill broadcasts wait for each match's Tx D outcome.
            {
                let mut state = self.state.write().await;
                prepare_derived_continuations(&state, &mut output);
                let participant_ids: HashSet<[u8; 16]> = output
                    .matches
                    .iter()
                    .flat_map(|m| {
                        [
                            state.openings().get(&m.note_buyer).map(|o| o.order_id),
                            state.openings().get(&m.note_seller).map(|o| o.order_id),
                        ]
                    })
                    .flatten()
                    .collect();
                let immediate: Vec<OrderUpdate> = output
                    .order_updates
                    .iter()
                    .filter(|update| !participant_ids.contains(&update.order_id))
                    .cloned()
                    .collect();
                state.book_mut().apply_updates(&immediate);
                let market_id = state.market_id();
                for update in immediate {
                    let _ = state.order_updates_tx.send(OrderLifecycleEvent::settled(
                        update,
                        market_id.clone(),
                        None,
                    ));
                }
                if !output.matches.is_empty() {
                    state
                        .reserve_batch(&output)
                        .map_err(|error| anyhow::anyhow!("reserve settlement batch: {error}"))?;
                }
                state.next_match_id = state
                    .next_match_id
                    .saturating_add(output.matches.len() as u64);
            }
            next_match_id = next_match_id.saturating_add(output.matches.len() as u64);

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
            if let Err(send_error) = self.matches_tx.send(output).await {
                let output = send_error.0;
                let mut state = self.state.write().await;
                state.reject_batch(&output, "settlement scheduler unavailable");
                return Err(anyhow::anyhow!("matches channel closed"));
            }
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
            publish_time_ms: value.publish_time_ms,
            observed_at_ms: value.observed_at_ms,
            max_age_ms: value.max_age_ms,
            max_future_skew_ms: value.max_future_skew_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::openings::{NoteOpening, OrderOpening};
    use crate::settle::lock_note::Groth16ProofBytes;
    use darkpool_matcher::book::{
        Order, OrderSide, OrderStatus, OrderType, OrderUpdate, OrderUpdateKind,
    };
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
    /// finality-gated continuation constructor.
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

        prepare_derived_continuations(&state, &mut output);

        // Preparation derives the proof-bound commitment but does not insert or
        // broadcast it before Tx D confirmation.
        let note_e = output.matches[0].note_e_commitment;
        assert_ne!(note_e, [0u8; 32], "note_e should have been rebuilt");
        assert!(state.openings().get(&note_e).is_none());
        let prior = state.openings().get(&note_buyer).unwrap();
        let inner = match_output_inner_hash(&prior.opening.inner_hash, CHANGE_ROLE_BUYER).unwrap();
        let rotated = MatcherState::continuation_opening(
            &prior,
            quote_mint,
            output.matches[0].buyer_change_amt,
            inner,
            bid_id,
            3,
        );
        assert!(rotated.from_relock, "continuation is a relock");
        assert_eq!(
            rotated.viewing_pubkey,
            Some(viewing),
            "viewing pubkey carried onto the continuation opening"
        );
        assert_eq!(inner, rotated.opening.inner_hash);
        assert_eq!(rotated.tree_id, 3, "continuation follows the settle shard");
    }

    #[test]
    fn reservation_is_non_mutating_and_rejection_is_terminal_until_unlock() {
        let base_mint = [0xb1u8; 32];
        let quote_mint = [0x9eu8; 32];
        let mut state = MatcherState::new().with_market(base_mint, quote_mint);
        let buyer_id = [0x01; 16];
        let seller_id = [0x02; 16];
        let expiry = 5_000;
        let proof = Groth16ProofBytes {
            pi_a: [1; 64],
            pi_b: [2; 128],
            pi_c: [3; 64],
        };
        let buyer_opening = NoteOpening {
            token_mint: quote_mint,
            amount: 1_000,
            owner_commitment: fr_safe(0x11),
            inner_hash: fr_safe(0x12),
        };
        let seller_opening = NoteOpening {
            token_mint: base_mint,
            amount: 10,
            owner_commitment: fr_safe(0x21),
            inner_hash: fr_safe(0x22),
        };
        let note_buyer = buyer_opening.commitment().unwrap();
        let note_seller = seller_opening.commitment().unwrap();
        for (note, opening, order_id) in [
            (note_buyer, buyer_opening.clone(), buyer_id),
            (note_seller, seller_opening.clone(), seller_id),
        ] {
            state.openings_mut().insert(
                note,
                OrderOpening {
                    opening,
                    order_id,
                    expiry_slot: expiry,
                    merkle_root: [0x44; 32],
                    tree_id: 0,
                    valid_input_proof: proof.clone(),
                    from_relock: false,
                    viewing_pubkey: Some([0x55; 32]),
                },
            );
        }
        for order in [
            Order {
                trading_key: [0x31; 32],
                side: OrderSide::Bid,
                order_type: OrderType::Limit,
                status: OrderStatus::Pending,
                arrival_slot: 1,
                expiry_slot: expiry,
                price_limit: 100,
                amount: 10,
                total_quantity: 10,
                filled_quantity: 0,
                min_fill_qty: 0,
                note_amount: 1_000,
                collateral_note: note_buyer,
                owner_commitment: buyer_opening.owner_commitment,
                order_id: buyer_id,
                order_inclusion_commitment: [0x61; 32],
            },
            Order {
                trading_key: [0x32; 32],
                side: OrderSide::Ask,
                order_type: OrderType::Limit,
                status: OrderStatus::Pending,
                arrival_slot: 2,
                expiry_slot: expiry,
                price_limit: 100,
                amount: 10,
                total_quantity: 10,
                filled_quantity: 0,
                min_fill_qty: 0,
                note_amount: 10,
                collateral_note: note_seller,
                owner_commitment: seller_opening.owner_commitment,
                order_id: seller_id,
                order_inclusion_commitment: [0x62; 32],
            },
        ] {
            state.book_mut().submit(order).unwrap();
        }

        let m = MatchPair {
            note_buyer,
            note_seller,
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            owner_buyer: [0x31; 32],
            owner_seller: [0x32; 32],
            buyer_note_value: 1_000,
            seller_note_value: 10,
            base_amt: 10,
            quote_amt: 1_000,
            buyer_change_amt: 0,
            seller_change_amt: 0,
            buyer_fee_amt: 0,
            seller_fee_amt: 0,
            buyer_relock_order_id: RELOCK_ORDER_ID_NONE,
            buyer_relock_expiry: 0,
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
        output.order_updates = vec![
            OrderUpdate {
                trading_key: [0x31; 32],
                order_id: buyer_id,
                kind: OrderUpdateKind::FullyFilled {
                    filled_quantity: 10,
                },
            },
            OrderUpdate {
                trading_key: [0x32; 32],
                order_id: seller_id,
                kind: OrderUpdateKind::FullyFilled {
                    filled_quantity: 10,
                },
            },
        ];

        let mut lifecycle = state.subscribe_order_updates();
        let mut fills = state.subscribe_fills();
        state.reserve_batch(&output).unwrap();
        for id in [buyer_id, seller_id] {
            let order = state.book().get(&id).unwrap();
            assert_eq!(order.status, OrderStatus::Matched);
            assert_eq!(order.amount, 10, "reservation mutated quantity");
            assert_eq!(order.filled_quantity, 0, "reservation published fill");
        }
        assert!(state.book().snapshot().orders.is_empty());
        for _ in 0..2 {
            assert!(matches!(
                lifecycle.try_recv().unwrap().kind,
                OrderLifecycleKind::PendingSettlement {
                    lock_expiry_slot: 5_000
                }
            ));
        }
        assert!(fills.try_recv().is_err(), "fill emitted before finality");

        state.reject_match(&output, 0, "Tx D reverted").unwrap();
        assert!(state.book().get(&buyer_id).is_none());
        assert!(state.book().get(&seller_id).is_none());
        assert!(state.openings().is_reserved(&note_buyer));
        assert!(state.openings().is_reserved(&note_seller));
        for _ in 0..2 {
            match lifecycle.try_recv().unwrap().kind {
                OrderLifecycleKind::SettlementFailed {
                    reason,
                    lock_expiry_slot,
                } => {
                    assert_eq!(reason, "Tx D reverted");
                    assert_eq!(lock_expiry_slot, expiry);
                }
                other => panic!("unexpected lifecycle event: {other:?}"),
            }
        }
        assert!(fills.try_recv().is_err(), "rejected match emitted a fill");
        state.release_failed_reservations(expiry - 1);
        assert!(state.openings().is_reserved(&note_buyer));
        state.release_failed_reservations(expiry);
        assert!(!state.openings().is_reserved(&note_buyer));
        assert!(!state.openings().is_reserved(&note_seller));
    }
}
