//! SW-28 — `run_batch`'s chaining path must not re-match on the zero sentinel.
//!
//! After a partial fill the matcher writes the ZERO SENTINEL into the
//! snapshot's collateral note: the real change-note commitment is not derivable
//! in the matcher (the settle assembler computes it), and zeroes make "not yet
//! derived" explicit and unusable rather than plausible-looking.
//!
//! `run_batch` passes `single_fill_per_order: false`, so a partially-filled
//! order STAYS at its index to match the next counterparty. Combined, the next
//! `MatchPair` took `note_buyer`/`note_seller = [0u8; 32]` — a commitment no
//! opening exists for and the tree can never contain. The value deliberately
//! made unusable was then consumed as a match input.
//!
//! The enclave never reaches this: it goes through
//! `PreparedMatchTick::next_page` (`single_fill_per_order: true`). Two comments
//! in `darknyx-tee/src/matcher/interval.rs` and one line in CLAUDE.md said
//! otherwise, which is what set the trap for whoever wired up the "simple"
//! wrapper next. Those are corrected; this pins the behaviour.
//!
//! Run with: `cargo test -p darkpool-matcher --test chaining_sentinel`

use darkpool_matcher::{
    run_batch, MatchConfig, OracleSnapshot, Order, OrderBook, OrderSide, OrderStatus, OrderType,
};

const CURRENT_SLOT: u64 = 100;
const ZERO_COMMITMENT: [u8; 32] = [0u8; 32];

fn fr_safe(tag: u8, index: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[23] = tag;
    value[24..].copy_from_slice(&(index as u64).to_be_bytes());
    value
}

#[allow(clippy::too_many_arguments)]
fn order(index: usize, side: OrderSide, price: u64, amount: u64) -> Order {
    let mut order_id = [0u8; 16];
    order_id[8..].copy_from_slice(&((index + 1) as u64).to_be_bytes());
    // Generous collateral so every fill clears the conservation checks,
    // including the 30-bps fee.
    let note_amount = match side {
        OrderSide::Bid => amount.saturating_mul(2).saturating_add(1_000),
        OrderSide::Ask => amount.saturating_add(1_000),
    };
    Order {
        order_id,
        trading_key: fr_safe(1, index),
        owner_commitment: fr_safe(2, index),
        collateral_note: fr_safe(3, index),
        order_inclusion_commitment: fr_safe(5, index),
        side,
        order_type: OrderType::Limit,
        status: OrderStatus::Pending,
        price_limit: price,
        amount,
        total_quantity: amount,
        filled_quantity: 0,
        min_fill_qty: 0,
        note_amount,
        arrival_slot: 1,
        expiry_slot: CURRENT_SLOT + 100,
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
        publish_time_ms: 1_000,
        observed_at_ms: 1_000,
        max_age_ms: 5_000,
        max_future_skew_ms: 1_000,
    }
}

#[test]
fn chaining_never_emits_a_zero_sentinel_collateral_note() {
    // One large bid that two smaller asks can each partially fill at P*. The
    // bid is partially filled by the first ask, is relocked onto the sentinel,
    // and under the old code stayed in play for the second.
    let book = OrderBook {
        orders: vec![
            order(0, OrderSide::Bid, 100, 30),
            order(1, OrderSide::Ask, 100, 10),
            order(2, OrderSide::Ask, 100, 10),
        ],
    };

    let out = run_batch(&book, &oracle(), &config(), CURRENT_SLOT, 0).expect("batch should run");

    for (i, m) in out.matches.iter().enumerate() {
        assert_ne!(
            m.note_buyer, ZERO_COMMITMENT,
            "match {i} consumed the zero-sentinel collateral note as note_buyer"
        );
        assert_ne!(
            m.note_seller, ZERO_COMMITMENT,
            "match {i} consumed the zero-sentinel collateral note as note_seller"
        );
    }
}
