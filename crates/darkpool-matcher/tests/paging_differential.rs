//! Differential coverage for the P-03 prepared matcher pager.
//!
//! The reference path deliberately repeats `run_batch_capped` over a book with
//! every prior page's touched orders removed. That is the pre-P-03 production
//! behavior. The prepared path must produce byte-identical Borsh outputs while
//! sorting and aggregating only once.

use std::collections::HashSet;
use std::time::Instant;

use darkpool_matcher::{
    run_batch_capped, MatchConfig, OracleSnapshot, Order, OrderBook, OrderSide, OrderStatus,
    OrderType, PreparedMatchTick, RunBatchOutput,
};
use proptest::prelude::*;

const CURRENT_SLOT: u64 = 100;
type OrderSpec = (bool, u8, u8, u8, u8, u8, u8, u8, u8);

fn fr_safe(tag: u8, index: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[23] = tag;
    value[24..].copy_from_slice(&(index as u64).to_be_bytes());
    value
}

#[allow(clippy::too_many_arguments)]
fn order(
    index: usize,
    side: OrderSide,
    order_type: OrderType,
    status: OrderStatus,
    price: u64,
    amount: u64,
    min_fill_qty: u64,
    arrival_slot: u64,
    expiry_slot: u64,
    filled_quantity: u64,
) -> Order {
    let trading_key = fr_safe(1, index);
    let owner_commitment = fr_safe(2, index);
    let mut order_id = [0u8; 16];
    order_id[8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());

    // Prices are bounded to <= 150 with price_scale=100 below. This generous
    // over-collateralization keeps every generated randomized fill inside the
    // conservation checks, including 30-bps fees.
    let note_amount = match side {
        OrderSide::Bid => amount.saturating_mul(2).saturating_add(1_000),
        OrderSide::Ask => amount.saturating_add(1_000),
    };

    Order {
        trading_key,
        side,
        order_type,
        status,
        arrival_slot,
        expiry_slot,
        price_limit: price,
        amount,
        total_quantity: amount.saturating_add(filled_quantity),
        filled_quantity,
        min_fill_qty,
        note_amount,
        collateral_note: fr_safe(3, index),
        user_commitment: fr_safe(4, index),
        owner_commitment,
        order_id,
        order_inclusion_commitment: fr_safe(5, index),
    }
}

fn config() -> MatchConfig {
    MatchConfig {
        base_mint: [0xb1; 32],
        quote_mint: [0x9e; 32],
        price_scale: 100,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 10_000,
        batch_ms: 2_000,
        fee_rate_bps: 30,
        protocol_owner_commitment: fr_safe(6, 0),
    }
}

fn oracle() -> OracleSnapshot {
    OracleSnapshot {
        twap: 100,
        confidence: 1,
        exponent: -2,
        publish_slot: CURRENT_SLOT,
    }
}

fn legacy_pages(
    mut book: OrderBook,
    config: &MatchConfig,
    oracle: &OracleSnapshot,
    cap: usize,
) -> Vec<RunBatchOutput> {
    let mut pages = Vec::new();
    let mut next_match_id = 7u64;

    for _ in 0..256 {
        let output = run_batch_capped(
            &book,
            oracle,
            config,
            CURRENT_SLOT,
            next_match_id,
            cap,
            true,
        )
        .expect("reference page");
        next_match_id = next_match_id.saturating_add(output.matches.len() as u64);

        let touched: HashSet<_> = output
            .order_updates
            .iter()
            .map(|update| (update.trading_key, update.order_id))
            .collect();
        book.orders
            .retain(|order| !touched.contains(&(order.trading_key, order.order_id)));

        let done = output.matches.is_empty();
        pages.push(output);
        if done {
            break;
        }
    }
    pages
}

fn prepared_pages(
    book: OrderBook,
    config: &MatchConfig,
    oracle: &OracleSnapshot,
    cap: usize,
) -> Vec<RunBatchOutput> {
    let mut prepared = PreparedMatchTick::new(book, config.clone(), CURRENT_SLOT);
    let mut pages = Vec::new();
    let mut next_match_id = 7u64;

    for _ in 0..256 {
        let output = prepared
            .next_page(oracle, next_match_id, cap)
            .expect("prepared page");
        next_match_id = next_match_id.saturating_add(output.matches.len() as u64);
        let done = output.matches.is_empty();
        pages.push(output);
        if done {
            break;
        }
    }
    pages
}

fn assert_pages_equal(expected: &[RunBatchOutput], actual: &[RunBatchOutput]) {
    assert_eq!(actual.len(), expected.len(), "page count changed");
    for (page, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        assert_eq!(
            borsh::to_vec(actual).expect("serialize prepared output"),
            borsh::to_vec(expected).expect("serialize reference output"),
            "page {page} changed"
        );
    }
}

fn book_from_specs(specs: &[OrderSpec]) -> OrderBook {
    let orders = specs
        .iter()
        .enumerate()
        .map(
            |(
                index,
                &(is_bid, order_type, status, price, amount, min_fill, arrival, expiry, filled),
            )| {
                let side = if is_bid {
                    OrderSide::Bid
                } else {
                    OrderSide::Ask
                };
                let order_type = match order_type % 3 {
                    0 => OrderType::Limit,
                    1 => OrderType::Ioc,
                    _ => OrderType::Fok,
                };
                let status = match status % 4 {
                    0 | 1 => OrderStatus::Pending,
                    2 => OrderStatus::Matched,
                    _ => OrderStatus::Cancelled,
                };
                let amount = u64::from(amount % 40 + 1);
                let min_fill_qty = u64::from(min_fill) % (amount + 1);
                let price = u64::from(price % 151);
                let expiry_slot = if expiry % 5 == 0 {
                    CURRENT_SLOT + 10
                } else {
                    CURRENT_SLOT + 1_000
                };
                order(
                    index,
                    side,
                    order_type,
                    status,
                    price,
                    amount,
                    min_fill_qty,
                    u64::from(arrival),
                    expiry_slot,
                    u64::from(filled % 20),
                )
            },
        )
        .collect();
    OrderBook { orders }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    #[test]
    fn prepared_paging_is_byte_exact_with_legacy_resnapshotting(
        specs in prop::collection::vec(
            (any::<bool>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(),
             any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()),
            0..48,
        ),
        cap in 1usize..9,
    ) {
        let book = book_from_specs(&specs);
        let config = config();
        let oracle = oracle();
        let expected = legacy_pages(book.clone(), &config, &oracle, cap);
        let actual = prepared_pages(book, &config, &oracle, cap);

        prop_assert_eq!(actual.len(), expected.len());
        for (page, (expected, actual)) in expected.iter().zip(&actual).enumerate() {
            prop_assert_eq!(
                borsh::to_vec(actual).expect("serialize prepared output"),
                borsh::to_vec(expected).expect("serialize reference output"),
                "page {} changed",
                page,
            );
        }
    }
}

#[test]
fn prepared_paging_drains_many_pages_without_semantic_drift() {
    let specs: Vec<_> = (0..128)
        .map(|index| {
            let is_bid = index < 64;
            (
                is_bid,
                (index % 3) as u8,
                0,
                if is_bid { 110 } else { 90 },
                10,
                (index % 5) as u8,
                index as u8,
                1,
                0,
            )
        })
        .collect();
    let book = book_from_specs(&specs);
    let config = config();
    let oracle = oracle();

    let expected = legacy_pages(book.clone(), &config, &oracle, 4);
    let actual = prepared_pages(book, &config, &oracle, 4);
    assert_pages_equal(&expected, &actual);
    assert!(actual.len() > 2, "fixture must exercise repeated paging");
}

/// Manual release-mode evidence for the avoided per-page clone/sort. Ignored
/// in the normal gate because wall-clock assertions are not portable; the PR
/// records the measured result from an explicit local run.
#[test]
#[ignore = "manual matcher performance measurement"]
fn benchmark_prepared_paging_against_repeated_preparation() {
    let mut orders = Vec::with_capacity(8_192);
    for index in 0..4_096 {
        orders.push(order(
            index,
            OrderSide::Bid,
            OrderType::Limit,
            OrderStatus::Pending,
            100 + (index % 64) as u64,
            10,
            0,
            index as u64,
            CURRENT_SLOT + 10_000,
            0,
        ));
        orders.push(order(
            index + 4_096,
            OrderSide::Ask,
            OrderType::Limit,
            OrderStatus::Pending,
            90 + (index % 64) as u64,
            10,
            0,
            index as u64,
            CURRENT_SLOT + 10_000,
            0,
        ));
    }
    let book = OrderBook { orders };
    let config = config();
    let oracle = oracle();

    let legacy_started = Instant::now();
    let expected = legacy_pages(book.clone(), &config, &oracle, 16);
    let legacy_elapsed = legacy_started.elapsed();

    let prepared_started = Instant::now();
    let actual = prepared_pages(book, &config, &oracle, 16);
    let prepared_elapsed = prepared_started.elapsed();

    assert_pages_equal(&expected, &actual);
    eprintln!(
        "matcher paging benchmark: pages={} repeated_prepare_ms={:.3} prepared_ms={:.3} speedup={:.2}x",
        actual.len(),
        legacy_elapsed.as_secs_f64() * 1_000.0,
        prepared_elapsed.as_secs_f64() * 1_000.0,
        legacy_elapsed.as_secs_f64() / prepared_elapsed.as_secs_f64(),
    );
}
