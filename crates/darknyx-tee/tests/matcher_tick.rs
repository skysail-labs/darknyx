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

use darknyx_tee::matcher::{
    DriverConfig, MatcherDriver, MatcherState, NoteOpening, OrderOpening, TradingGate,
    TradingPauseReason, DEFAULT_MAX_ORACLE_FUTURE_SKEW_MS,
};
use darknyx_tee::oracle::{CachedPrice, OracleCache, OracleUnits, TrustProfile};
use darknyx_tee::settle::Groth16ProofBytes;
use darkpool_matcher::{
    book::{Order, OrderSide, OrderStatus, OrderType},
    config::MatchConfig,
};
use tokio::sync::{mpsc, RwLock};

const FEED_ID: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const OTHER_FEED_ID: &str = "aa0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

fn mk_order(side: OrderSide, idx: u8, price: u64, amount: u64) -> Order {
    let mut tk = [0u8; 32];
    tk[0] = idx;
    let mut oid = [0u8; 16];
    oid[0] = idx;
    oid[15] = 1;
    // `owner_commitment` must be BN254-Fr-safe (top byte <= 0x30) because the
    // matcher's change-note construction Poseidon-hashes it. Zeroing byte 0 is
    // the cheap way to guarantee that for a synthetic value.
    let owner_commitment = {
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
        owner_commitment, // keyed on idx, so distinct traders differ
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
        // price_scale must be consistent with these toy prices/amounts: with
        // clearing_price=100 and base amounts of 5–10, a price_scale of 1e8
        // floored `quote = base*price/price_scale` to ZERO — a degenerate clear
        // that mints an unspendable zero-amount quote note. The matcher now
        // skips zero-quote clears (U-06) and the circuit rejects them (U-03), so
        // the config must yield a positive quote. price_scale=100 → quote=base.
        price_scale: 100,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 100_000, // effectively disabled for the test
        batch_ms: 2000,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}

fn mk_state() -> MatcherState {
    let cfg = mk_config();
    MatcherState::new().with_market(cfg.base_mint, cfg.quote_mint)
}

fn submit_with_opening(state: &mut tokio::sync::RwLockWriteGuard<'_, MatcherState>, order: Order) {
    let cfg = mk_config();
    let mint = match order.side {
        OrderSide::Bid => cfg.quote_mint,
        OrderSide::Ask => cfg.base_mint,
    };
    let mut inner_hash = [order.order_id[0].wrapping_add(1); 32];
    inner_hash[0] = 0;
    state.openings_mut().insert(
        order.collateral_note,
        OrderOpening {
            opening: NoteOpening {
                token_mint: mint,
                amount: order.note_amount,
                owner_commitment: order.owner_commitment,
                inner_hash,
            },
            order_id: order.order_id,
            expiry_slot: order.expiry_slot,
            merkle_root: [0x44; 32],
            tree_id: 0,
            valid_input_proof: Groth16ProofBytes {
                pi_a: [1; 64],
                pi_b: [2; 128],
                pi_c: [3; 64],
            },
            from_relock: false,
            viewing_pubkey: Some([0x55; 32]),
        },
    );
    state.book_mut().submit(order).unwrap();
}

async fn seed_oracle(cache: &OracleCache, twap: u64) {
    cache
        .seed_unverified(
            FEED_ID.to_string(),
            CachedPrice {
                twap,
                confidence: 0,
                // With equal token decimals and price_scale=100 this preserves
                // the toy matcher prices exactly.
                exponent: -2,
                publish_time_ms: 0,
                vaa_sequence: 1,
                trust_profile: TrustProfile::RouterQuorumV1,
                last_updated_ms: 0, // seed_unverified stamps it
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
        trading_gate: TradingGate::default(),
        cfg: DriverConfig {
            match_config: mk_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: darknyx_tee::matcher::DEFAULT_MAX_ORACLE_AGE_MS,
            max_oracle_future_skew_ms: DEFAULT_MAX_ORACLE_FUTURE_SKEW_MS,
            oracle_units: OracleUnits {
                base_decimals: 6,
                quote_decimals: 6,
                price_scale: 100,
            },
            max_matches_per_batch: 16,
        },
    }
}

// ─────── Tests ──────────────────────────────────────────────────────────────

/// The load-bearing case: book has a crossing pair, oracle is
/// fresh, tick fires once, mpsc receiver gets the matches, and both orders are
/// reserved without applying the fill.
///
/// Uses `try_recv` (not `recv().await`) so the test fails fast
/// if `tick()` returns Ok but didn't push a match — the
/// historical failure mode was a silent matcher error (e.g.
/// a non-Fr-safe `owner_commitment`) that `tick()` swallowed as a
/// `warn!` log. Asserting synchronous channel state surfaces
/// that immediately.
#[tokio::test]
async fn tick_produces_matches_for_crossing_book() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Bid, 1, 100, 10),
    );
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Ask, 2, 100, 10),
    );

    seed_oracle(&oracle, 100).await;

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    let output = rx
        .try_recv()
        .expect("driver should have sent a RunBatchOutput synchronously");
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.clearing_price, 100);
    assert_eq!(output.matches[0].base_amt, 10);
    // Pin a POSITIVE quote (base*price/price_scale = 10*100/100 = 10). Guards
    // against a config that floors quote to zero — the degenerate clear U-06
    // now skips and U-03 rejects in-circuit.
    assert_eq!(output.matches[0].quote_amt, 10);

    let final_state = state.read().await;
    assert!(
        final_state.book().snapshot().orders.is_empty(),
        "reserved orders must not be matchable"
    );
    assert_eq!(final_state.book().len(), 2, "orders await Tx D finality");
    assert_eq!(final_state.next_match_id(), 1);
}

#[tokio::test]
async fn governance_pause_makes_matcher_tick_a_no_op() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Bid, 1, 100, 10),
    );
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Ask, 2, 100, 10),
    );
    seed_oracle(&oracle, 100).await;

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    assert!(driver.trading_gate.pause());
    driver.tick().await.expect("paused tick");

    assert!(rx.try_recv().is_err());
    assert_eq!(state.read().await.book().len(), 2);
}

/// Paged matching (C): a tick that clears more than
/// `max_matches_per_batch` pairs must emit MULTIPLE ≤N RunBatchOutputs
/// (one settle batch each) rather than a single oversized batch the
/// N=16 settle circuit can't absorb — the gap the Phala loadgen caught
/// (23-50-match ticks dropped at settle assembly). 5 crossing pairs
/// with a cap of 2 → 3 batches (2 + 2 + 1), 5 matches total, book
/// reserved across the pages, match-id counter at 5.
#[tokio::test]
async fn tick_pages_oversized_match_set_into_capped_batches() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(16);

    // 5 bids + 5 asks, all crossing at 100 (amount 10) → 5 fills.
    for i in 0..5u8 {
        submit_with_opening(
            &mut state.write().await,
            mk_order(OrderSide::Bid, 1 + 2 * i, 100, 10),
        );
        submit_with_opening(
            &mut state.write().await,
            mk_order(OrderSide::Ask, 2 + 2 * i, 100, 10),
        );
    }
    seed_oracle(&oracle, 100).await;

    // Driver with a small per-batch cap to force paging within one tick.
    let driver = MatcherDriver {
        state: state.clone(),
        oracle,
        current_slot,
        matches_tx: tx,
        trading_gate: TradingGate::default(),
        cfg: DriverConfig {
            match_config: mk_config(),
            feed_id: FEED_ID.to_string(),
            batch_ms: 1000,
            max_oracle_age_ms: darknyx_tee::matcher::DEFAULT_MAX_ORACLE_AGE_MS,
            max_oracle_future_skew_ms: DEFAULT_MAX_ORACLE_FUTURE_SKEW_MS,
            oracle_units: OracleUnits {
                base_decimals: 6,
                quote_decimals: 6,
                price_scale: 100,
            },
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
    // Every paged match carries a positive quote (no zero-quote clears survive
    // U-06); base*price/price_scale = 10*100/100 = 10 for each pair.
    assert!(
        batches
            .iter()
            .all(|b| b.matches.iter().all(|m| m.quote_amt == 10)),
        "every paged match has a positive quote"
    );
    let total: usize = batches.iter().map(|b| b.matches.len()).sum();
    assert_eq!(total, 5, "every crossing pair matched across the pages");

    let final_state = state.read().await;
    assert!(final_state.book().snapshot().orders.is_empty());
    assert_eq!(final_state.book().len(), 10, "all orders await settlement");
    assert_eq!(final_state.next_match_id(), 5);
}

/// When the oracle is missing the tick no-ops; nothing should
/// land on the channel.
#[tokio::test]
async fn tick_skips_when_oracle_missing() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new(); // <-- no entry seeded
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Bid, 1, 100, 10),
    );
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Ask, 2, 100, 10),
    );

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    let gate = driver.trading_gate.clone();
    driver.tick().await.expect("tick");

    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(state.read().await.book().len(), 2, "book unchanged");
    assert!(gate.is_paused_for(TradingPauseReason::Oracle));
}

#[tokio::test]
async fn healthy_market_tick_cannot_clear_another_markets_oracle_pause() {
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let sol_gate = TradingGate::default();
    let btc_gate = sol_gate.fork_market();

    let (sol_tx, _sol_rx) = mpsc::channel(1);
    let mut stale_sol = mk_driver(
        Arc::new(RwLock::new(mk_state())),
        oracle.clone(),
        current_slot.clone(),
        sol_tx,
    );
    stale_sol.trading_gate = sol_gate.clone();
    stale_sol.cfg.feed_id = OTHER_FEED_ID.to_string();
    stale_sol.tick().await.expect("stale SOL tick");
    assert!(sol_gate.is_paused_for(TradingPauseReason::Oracle));
    assert!(btc_gate.is_open());

    let (btc_tx, _btc_rx) = mpsc::channel(1);
    let mut healthy_btc = mk_driver(
        Arc::new(RwLock::new(mk_state())),
        oracle,
        current_slot,
        btc_tx,
    );
    healthy_btc.trading_gate = btc_gate.clone();
    healthy_btc.tick().await.expect("healthy BTC tick");

    assert!(btc_gate.is_open());
    assert!(
        sol_gate.is_paused_for(TradingPauseReason::Oracle),
        "a healthy market tick has no authority over another market's gate"
    );
}

/// Empty book → no tick output.
#[tokio::test]
async fn tick_skips_when_book_empty() {
    let state = Arc::new(RwLock::new(mk_state()));
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

/// Partial fill: bid 20, ask 5 → 1 match of 5. Before Tx D finality both
/// original orders remain unchanged and reserved.
#[tokio::test]
async fn tick_handles_partial_fill() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    let bid = mk_order(OrderSide::Bid, 1, 100, 20);
    let bid_id = bid.order_id;
    let ask = mk_order(OrderSide::Ask, 2, 100, 5);

    submit_with_opening(&mut state.write().await, bid);
    submit_with_opening(&mut state.write().await, ask);

    let driver = mk_driver(state.clone(), oracle, current_slot, tx);
    driver.tick().await.expect("tick");

    let output = rx.try_recv().expect("one tick");
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].base_amt, 5);
    // Positive quote: 5*100/100 = 5 (the partial fill still clears a real notional).
    assert_eq!(output.matches[0].quote_amt, 5);

    let final_state = state.read().await;
    let pending_bid = final_state.book().get(&bid_id).unwrap();
    assert_eq!(pending_bid.status, OrderStatus::Matched);
    assert_eq!(pending_bid.amount, 20);
    assert_eq!(pending_bid.filled_quantity, 0);
    assert!(final_state.book().snapshot().orders.is_empty());
}

/// Two ticks in sequence, each a distinct full-fill pair. next_match_id
/// advances 0 → 1 → 2. The first pair stays reserved while the second fresh
/// pair remains eligible on the next tick.
#[tokio::test]
async fn two_consecutive_ticks_advance_state() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1));
    let (tx, mut rx) = mpsc::channel(8);

    // Tick 1: bid(10) vs ask(10) — exact full fill, no relock.
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Bid, 1, 100, 10),
    );
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Ask, 2, 100, 10),
    );

    let driver = mk_driver(state.clone(), oracle.clone(), current_slot.clone(), tx);
    driver.tick().await.expect("first tick");
    let out1 = rx.try_recv().expect("first output");
    assert_eq!(out1.matches.len(), 1);
    assert_eq!(out1.matches[0].base_amt, 10);
    assert_eq!(out1.matches[0].quote_amt, 10);
    assert_eq!(out1.matches[0].match_id, 0, "first match gets id 0");
    assert!(state.read().await.book().snapshot().orders.is_empty());
    assert_eq!(state.read().await.book().len(), 2);

    // Tick 2: a fresh full-fill pair — the match-id counter continues.
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Bid, 3, 100, 10),
    );
    submit_with_opening(
        &mut state.write().await,
        mk_order(OrderSide::Ask, 4, 100, 10),
    );

    driver.tick().await.expect("second tick");
    let out2 = rx.try_recv().expect("second output");
    assert_eq!(out2.matches.len(), 1);
    assert_eq!(out2.matches[0].base_amt, 10);
    assert_eq!(out2.matches[0].quote_amt, 10);
    assert_eq!(out2.matches[0].match_id, 1, "second match gets id 1");

    assert!(state.read().await.book().snapshot().orders.is_empty());
    assert_eq!(state.read().await.book().len(), 4);
    assert_eq!(state.read().await.next_match_id(), 2);
}

/// Sanity: tick sweeps expired orders before matching.
#[tokio::test]
async fn tick_sweeps_expired_orders() {
    let state = Arc::new(RwLock::new(mk_state()));
    let oracle = OracleCache::new();
    seed_oracle(&oracle, 100).await;
    let current_slot = Arc::new(AtomicU64::new(1000));
    let (tx, _rx) = mpsc::channel(8);

    let mut order = mk_order(OrderSide::Bid, 1, 100, 10);
    order.expiry_slot = 50;
    submit_with_opening(&mut state.write().await, order);

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
