//! End-to-end test of the in-TEE matching tick.
//!
//! Wires up everything PR 4c builds:
//!   - The `MatcherDriver`
//!   - The `OrderBook` (in-memory book)
//!   - The `OracleCache` — pre-populated with a synthetic price;
//!     no Hermes in the loop.
//!
//! We don't use `tokio::time::pause` + `advance` because that
//! combined with `mpsc::recv().await` is a known deadlock
//! pattern: under `pause()` virtual time only progresses when
//! explicitly advanced, but `recv().await` blocks the test task
//! and prevents further advances → driver task never wakes. The
//! cleanest equivalent: call `driver.tick()` directly. That's
//! what the matching cycle does on every interval anyway —
//! testing it directly proves the same wiring without
//! adversarial tokio-time mechanics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use darkpool_matcher::{
    book::{Order, OrderSide, OrderStatus, OrderType},
    config::MatchConfig,
};
use nyx_tee::matcher::{DriverConfig, MatcherDriver, MatcherState};
use nyx_tee::oracle::{cache::CachedPrice, OracleCache};
use tokio::sync::{mpsc, RwLock};

const FEED_ID: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

fn mk_order(side: OrderSide, idx: u8, price: u64, amount: u64) -> Order {
    let mut tk = [0u8; 32];
    tk[0] = idx;
    let mut oid = [0u8; 16];
    oid[0] = idx;
    oid[15] = 1;
    // user_commitment must be BN254-Fr-safe (top byte < 0x30) because
    // the matcher's change-note construction Poseidon-hashes it. The
    // on-chain `make_pending_seed` enforces this by zeroing byte 0;
    // we do the same here.
    let user_commitment = {
        let mut u = [idx ^ 0xab; 32];
        u[0] = 0;
        u
    };
    Order {
        trading_key: tk,
        side,
        order_type: OrderType::Limit,
        status: OrderStatus::Pending,
        arrival_slot: 1,
        expiry_slot: 1_000_000,
        price_limit: price,
        amount,
        total_quantity: amount,
        filled_quantity: 0,
        min_fill_qty: 0,
        note_amount: amount.saturating_mul(price).max(amount).max(1),
        collateral_note: [idx; 32],
        user_commitment,
        order_id: oid,
        order_inclusion_commitment: [idx ^ 0xcd; 32],
    }
}

fn mk_config() -> MatchConfig {
    let mut base_mint = [0u8; 32];
    base_mint[0] = 1;
    base_mint[31] = 0xb1;
    let mut quote_mint = [0u8; 32];
    quote_mint[0] = 1;
    quote_mint[31] = 0x9e;
    MatchConfig {
        base_mint,
        quote_mint,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 100_000, // effectively disabled for the test
        batch_ms: 2000,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}

async fn seed_oracle(cache: &OracleCache, twap: u64) {
    cache
        .upsert(
            FEED_ID.to_string(),
            CachedPrice {
                twap,
                confidence: 0,
                exponent: -8,
                publish_time_ms: 0,
                last_updated_ms: 0, // upsert stamps it
                vaa: Vec::new(),
            },
        )
        .await;
}

fn mk_driver(
    state: Arc<RwLock<MatcherState>>,
    oracle: OracleCache,
    current_slot: Arc<AtomicU64>,
    tx: mpsc::Sender<darkpool_matcher::match_result::RunBatchOutput>,
) -> MatcherDriver {
    MatcherDriver {
        state,
        oracle,
        current_slot,
        matches_tx: tx,
        cfg: DriverConfig {
            match_config: mk_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: nyx_tee::matcher::DEFAULT_MAX_ORACLE_AGE_MS,
            max_matches_per_batch: 16,
        },
    }
}

// ─────── Tests ──────────────────────────────────────────────────────────────

/// The load-bearing case: book has a crossing pair, oracle is
/// fresh, tick fires once, mpsc receiver gets the matches, book
/// drains.
///
/// Uses `try_recv` (not `recv().await`) so the test fails fast
/// if `tick()` returns Ok but didn't push a match — the
/// historical failure mode was a silent matcher error (e.g.
/// non-Fr-safe `user_commitment`) that `tick()` swallowed as a
/// `warn!` log. Asserting synchronous channel state surfaces
/// that immediately.
#[tokio::test]
async fn tick_produces_matches_for_crossing_book() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Bid, 1, 100, 10))
        .expect("submit bid");
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Ask, 2, 100, 10))
        .expect("submit ask");

    seed_oracle(&oracle, 100).await;

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    let output = rx
        .try_recv()
        .expect("driver should have sent a RunBatchOutput synchronously");
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.clearing_price, 100);
    assert_eq!(output.matches[0].base_amt, 10);

    let final_state = state.read().await;
    assert!(final_state.book().is_empty(), "book should be drained");
    assert_eq!(final_state.next_match_id(), 1);
}

/// Paged matching (C): a tick that clears more than
/// `max_matches_per_batch` pairs must emit MULTIPLE ≤N RunBatchOutputs
/// (one settle batch each) rather than a single oversized batch the
/// N=16 settle circuit can't absorb — the gap the Phala loadgen caught
/// (23-50-match ticks dropped at settle assembly). 5 crossing pairs
/// with a cap of 2 → 3 batches (2 + 2 + 1), 5 matches total, book
/// drained across the pages, match-id counter at 5.
#[tokio::test]
async fn tick_pages_oversized_match_set_into_capped_batches() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(16);

    // 5 bids + 5 asks, all crossing at 100 (amount 10) → 5 fills.
    for i in 0..5u8 {
        state
            .write()
            .await
            .book_mut()
            .submit(mk_order(OrderSide::Bid, 1 + 2 * i, 100, 10))
            .expect("submit bid");
        state
            .write()
            .await
            .book_mut()
            .submit(mk_order(OrderSide::Ask, 2 + 2 * i, 100, 10))
            .expect("submit ask");
    }
    seed_oracle(&oracle, 100).await;

    // Driver with a small per-batch cap to force paging within one tick.
    let driver = MatcherDriver {
        state: state.clone(),
        oracle,
        current_slot,
        matches_tx: tx,
        cfg: DriverConfig {
            match_config: mk_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: nyx_tee::matcher::DEFAULT_MAX_ORACLE_AGE_MS,
            max_matches_per_batch: 2,
        },
    };
    driver.tick().await.expect("tick");

    // Drain the channel: 3 batches (2 + 2 + 1), each non-empty and ≤ N.
    let mut batches = Vec::new();
    while let Ok(o) = rx.try_recv() {
        batches.push(o);
    }
    assert_eq!(batches.len(), 3, "5 fills / cap 2 → 3 paged batches");
    assert!(
        batches
            .iter()
            .all(|b| !b.matches.is_empty() && b.matches.len() <= 2),
        "each emitted batch is non-empty and within the N cap"
    );
    let total: usize = batches.iter().map(|b| b.matches.len()).sum();
    assert_eq!(total, 5, "every crossing pair matched across the pages");

    let final_state = state.read().await;
    assert!(
        final_state.book().is_empty(),
        "book drained across all pages of the tick"
    );
    assert_eq!(final_state.next_match_id(), 5);
}

/// When the oracle is missing the tick no-ops; nothing should
/// land on the channel.
#[tokio::test]
async fn tick_skips_when_oracle_missing() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new(); // <-- no entry seeded
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Bid, 1, 100, 10))
        .unwrap();
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Ask, 2, 100, 10))
        .unwrap();

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(state.read().await.book().len(), 2, "book unchanged");
}

/// Empty book → no tick output.
#[tokio::test]
async fn tick_skips_when_book_empty() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    let driver = mk_driver(state, oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

/// Partial fill (option A): bid 20, ask 5 → 1 match of 5. The bid's
/// 15-residual relocks on-chain and LEAVES the in-TEE book — the TEE
/// can't re-match the change note (no spending key for its nullifier),
/// so the residual awaits client re-submission. (Pre-option-A the bid
/// stayed in the book with new_amount=15.)
#[tokio::test]
async fn tick_handles_partial_fill() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    let bid = mk_order(OrderSide::Bid, 1, 100, 20);
    let bid_id = bid.order_id;
    let ask = mk_order(OrderSide::Ask, 2, 100, 5);

    state.write().await.book_mut().submit(bid).unwrap();
    state.write().await.book_mut().submit(ask).unwrap();

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    let output = rx.try_recv().expect("one tick");
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].base_amt, 5);

    let final_state = state.read().await;
    assert!(
        final_state.book().get(&bid_id).is_none(),
        "partially-filled bid's residual relocked and left the in-TEE book"
    );
    assert!(
        final_state.book().is_empty(),
        "ask fully filled + bid residual relocked — book drained"
    );
}

/// Two ticks in sequence, each a distinct full-fill pair. next_match_id
/// advances 0 → 1 → 2 and the book drains each tick. (Pre-option-A this
/// finished a single partially-filled bid across two ticks; under
/// option A a partial fill relocks + leaves the book, so the counter is
/// exercised with two independent full fills instead.)
#[tokio::test]
async fn two_consecutive_ticks_advance_state() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    // Tick 1: bid(10) vs ask(10) — exact full fill, no relock.
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Bid, 1, 100, 10))
        .unwrap();
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Ask, 2, 100, 10))
        .unwrap();

    let driver = mk_driver(state.clone(), oracle.clone(), current_slot.clone(), tx);
    driver.tick().await.expect("first tick");
    let out1 = rx.try_recv().expect("first output");
    assert_eq!(out1.matches.len(), 1);
    assert_eq!(out1.matches[0].base_amt, 10);
    assert_eq!(out1.matches[0].match_id, 0, "first match gets id 0");
    assert!(
        state.read().await.book().is_empty(),
        "first pair fully drained"
    );

    // Tick 2: a fresh full-fill pair — the match-id counter continues.
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Bid, 3, 100, 10))
        .unwrap();
    state
        .write()
        .await
        .book_mut()
        .submit(mk_order(OrderSide::Ask, 4, 100, 10))
        .unwrap();

    driver.tick().await.expect("second tick");
    let out2 = rx.try_recv().expect("second output");
    assert_eq!(out2.matches.len(), 1);
    assert_eq!(out2.matches[0].base_amt, 10);
    assert_eq!(out2.matches[0].match_id, 1, "second match gets id 1");

    assert!(state.read().await.book().is_empty());
    assert_eq!(state.read().await.next_match_id(), 2);
}

/// Sanity: tick sweeps expired orders before matching.
#[tokio::test]
async fn tick_sweeps_expired_orders() {
    let state = Arc::new(RwLock::new(MatcherState::new()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1000));
    let (tx, _rx) = mpsc::channel(8);

    let mut order = mk_order(OrderSide::Bid, 1, 100, 10);
    order.expiry_slot = 50;
    state.write().await.book_mut().submit(order).unwrap();

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");
    assert!(state.read().await.book().is_empty(), "expired order purged");
}

/// AtomicU64 read smoke — useful for catching a downstream
/// breakage in the slot-source abstraction when PR 4d adds a
/// Solana RPC poller.
#[test]
fn slot_source_compiles() {
    let s = AtomicU64::new(42);
    assert_eq!(s.load(Ordering::Relaxed), 42);
}
