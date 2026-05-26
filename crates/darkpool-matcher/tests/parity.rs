//! Parity tests gating the run_batch lift.
//!
//! Each scenario below mirrors one in
//! `programs/matching_engine/tests/run_batch.rs` — input book +
//! oracle + config constructed the same way, expected outputs
//! asserted the same way. If the matcher's `run_batch` produces a
//! different `RunBatchOutput` than the on-chain handler would
//! produce on the equivalent PendingOrder PDAs, exactly one of
//! these tests fails.
//!
//! We intentionally skip three scenarios from the litesvm file:
//!   - test_cancel_flips_pending_to_cancelled
//!   - test_cancel_unauthorized_caller_rejected
//!   - test_run_batch_rejects_non_tee_signer
//!
//! All three test instruction-level concerns (cancel ix auth, TEE
//! signer gate) that don't exist at the algorithm layer.
//!
//! `cargo test -p darkpool-matcher --test parity`

use darkpool_matcher::book::{
    Order, OrderBook, OrderSide, OrderStatus, OrderType, OrderUpdateKind,
};
use darkpool_matcher::config::{MatchConfig, OracleSnapshot};
use darkpool_matcher::run_batch;

// ─────── Fixture helpers (mirror PendingSeed construction) ──────────────────
//
// The litesvm harness builds PendingSeeds via `make_pending_seed`
// and then sets a few fields directly. We replicate the same
// derivation here so the inputs are byte-identical: same
// collateral_note layout, same user_commitment (with byte 0
// zeroed for Fr safety), same order_id, same
// order_inclusion_commitment.

/// Mirrors `programs/matching_engine/tests/run_batch.rs::pseed`.
/// Returns an `Order` with the same field-by-field bytes the
/// litesvm test would seed into a PendingOrder PDA.
fn pseed(idx: u8, side_u8: u8, price: u64, amount: u64, expiry: u64) -> Order {
    let mut tk = [0u8; 32];
    tk[1..9].copy_from_slice(&(idx as u64).to_le_bytes());

    let mut collateral_note = [0u8; 32];
    collateral_note[0] = side_u8;
    collateral_note[1..9].copy_from_slice(&(0u64).to_le_bytes()); // slot_idx
    collateral_note[9..17].copy_from_slice(&price.to_le_bytes());
    collateral_note[10] = idx; // overriden in pseed() helper

    let mut user_commitment = tk;
    user_commitment[0] = 0; // Fr safety

    let mut order_id = [0u8; 16];
    order_id[0] = side_u8.wrapping_add(1);
    order_id[1] = 0; // slot_idx
    order_id[2..10].copy_from_slice(&price.to_le_bytes());
    order_id[15] = idx.wrapping_add(1); // distinctness

    let mut oic = [0u8; 32];
    oic[0] = side_u8;
    oic[1] = 0; // slot_idx
    oic[2..10].copy_from_slice(&price.to_le_bytes());
    oic[10] = idx; // distinctness

    let side = if side_u8 == 0 {
        OrderSide::Bid
    } else {
        OrderSide::Ask
    };

    Order {
        trading_key: tk,
        side,
        order_type: OrderType::Limit,
        status: OrderStatus::Pending,
        arrival_slot: 1,
        expiry_slot: expiry,
        price_limit: price,
        amount,
        total_quantity: amount,
        filled_quantity: 0,
        min_fill_qty: 0,
        note_amount: amount.saturating_mul(price).max(amount).max(1),
        collateral_note,
        user_commitment,
        order_id,
        order_inclusion_commitment: oic,
    }
}

/// Default MatchConfig matching the litesvm `init_market_full` call:
/// random mints, `tick_size = 1`, `fee_rate_bps = 0` (no fees in
/// any of the litesvm scenarios), `protocol_owner_commitment =
/// [0; 32]` (no fee flush — gated by the same condition the
/// on-chain code checks), `batch_ms = 2000`.
fn config(circuit_breaker_bps: u64, min_order_size: u64) -> MatchConfig {
    // The litesvm harness uses fresh random Pubkeys for the mints.
    // Their actual bytes don't affect the algorithm outputs except
    // by feeding into Poseidon during change-note construction —
    // and the parity scenarios that exercise change-note math
    // (none of them do; all 8 use `fee_rate_bps = 0`) would need
    // deterministic mints. For these scenarios, any fixed bytes
    // work.
    let base_mint = {
        let mut m = [0u8; 32];
        m[0] = 1;
        m[31] = 0xb1;
        m
    };
    let quote_mint = {
        let mut m = [0u8; 32];
        m[0] = 1;
        m[31] = 0x9e;
        m
    };
    MatchConfig {
        base_mint,
        quote_mint,
        tick_size: 1,
        min_order_size,
        circuit_breaker_bps,
        batch_ms: 2000,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}

fn oracle(twap: u64) -> OracleSnapshot {
    OracleSnapshot {
        twap,
        confidence: 0,
        exponent: 0,
        publish_slot: 1,
    }
}

fn book_of(orders: Vec<Order>) -> OrderBook {
    OrderBook { orders }
}

// ─────── Scenario 1: uniform clearing price ─────────────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_uniform_clearing_price
//   5 bids @ 150..146 + 3 asks @ 144..146, amount = 10 each.
//   At P=146: demand=50, supply=30 → matched=30.
//   At P=145: demand=40, supply=20 → matched=20.
//   Highest-matched price wins: (146, 30) → 3 matches.

#[test]
fn parity_1_uniform_clearing_price() {
    let book = book_of(vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 0, 149, 10, 1_000_000),
        pseed(2, 0, 148, 10, 1_000_000),
        pseed(3, 0, 147, 10, 1_000_000),
        pseed(4, 0, 146, 10, 1_000_000),
        pseed(5, 1, 144, 10, 1_000_000),
        pseed(6, 1, 145, 10, 1_000_000),
        pseed(7, 1, 146, 10, 1_000_000),
    ]);
    let out = run_batch(&book, &oracle(146), &config(100_000, 0), 1, 0).expect("matcher");

    assert_eq!(out.circuit_breaker_tripped, 0);
    assert_eq!(out.clearing_price, 146);
    assert_eq!(
        out.matches.len(),
        3,
        "expected 3 fills (supply=30 base units / 10 per ask)"
    );
    assert!(out.matches.iter().all(|m| m.price == 146));
}

// ─────── Scenario 2: intra-batch ordering irrelevant ────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_intra_batch_ordering_irrelevant
//   2 bids @ 105/100, 2 asks @ 95/100, amount = 5.
//   Run twice — once with default arrival_slots, once with two of
//   them swapped — and assert (clearing_price, match_count) is
//   identical.

#[test]
fn parity_2_intra_batch_ordering_irrelevant() {
    let seeds_a = vec![
        pseed(0, 0, 105, 5, 1_000_000),
        pseed(1, 0, 100, 5, 1_000_000),
        pseed(2, 1, 95, 5, 1_000_000),
        pseed(3, 1, 100, 5, 1_000_000),
    ];
    let mut seeds_b = seeds_a.clone();
    seeds_b[0].arrival_slot = 99;
    seeds_b[3].arrival_slot = 1;

    let a = run_batch(&book_of(seeds_a), &oracle(100), &config(100_000, 0), 1, 0).expect("a");
    let b = run_batch(&book_of(seeds_b), &oracle(100), &config(100_000, 0), 1, 0).expect("b");

    assert_eq!(
        (a.clearing_price, a.matches.len(), a.circuit_breaker_tripped),
        (b.clearing_price, b.matches.len(), b.circuit_breaker_tripped),
        "outcome must be order-invariant"
    );
}

// ─────── Scenario 3: circuit breaker trips ──────────────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_circuit_breaker_pauses_batch
//   Oracle=100, circuit_breaker_bps=300 (3%).
//   Bid @ 150, Ask @ 140 → P* ~ 145, deviation 45% → trip.
//   Expected: cb_tripped=1, match_count=0, clearing_price=0.
//   Both orders stay Pending (no OrderUpdates emitted).

#[test]
fn parity_3_circuit_breaker_pauses_batch() {
    let book = book_of(vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 1, 140, 10, 1_000_000),
    ]);
    let out = run_batch(&book, &oracle(100), &config(300, 0), 1, 0).expect("matcher");

    assert_eq!(out.circuit_breaker_tripped, 1);
    assert_eq!(out.matches.len(), 0);
    assert_eq!(out.clearing_price, 0);
    // No order updates — both stay Pending.
    assert!(
        out.order_updates.is_empty(),
        "circuit breaker tripped → orders untouched, got {:?}",
        out.order_updates
    );
}

// ─────── Scenario 4: per-market isolation (CB tripping in A) ────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_circuit_breaker_does_not_affect_other_pairs
//   Two markets, two run_batch calls. The matcher is pure so
//   "isolation" reduces to "two independent run_batch calls with
//   different inputs produce different outputs". Both halves
//   asserted here.

#[test]
fn parity_4_per_market_isolation() {
    // Market A — tripping setup. Same as scenario 3.
    let book_a = book_of(vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 1, 140, 10, 1_000_000),
    ]);
    let out_a = run_batch(&book_a, &oracle(100), &config(300, 0), 1, 0).expect("market A");
    assert_eq!(out_a.circuit_breaker_tripped, 1);
    assert_eq!(out_a.matches.len(), 0);

    // Market B — healthy setup. Bid/ask both @ 145, oracle=145,
    // circuit_breaker_bps=300 → deviation 0%, no trip.
    let book_b = book_of(vec![
        pseed(0, 0, 145, 10, 1_000_000),
        pseed(1, 1, 145, 10, 1_000_000),
    ]);
    let out_b = run_batch(&book_b, &oracle(145), &config(300, 0), 1, 0).expect("market B");
    assert_eq!(out_b.circuit_breaker_tripped, 0);
    assert!(!out_b.matches.is_empty(), "market B should fill");
}

// ─────── Scenario 5: expired orders drained ─────────────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_expired_orders_drained
//   Bid expires at slot 5, ask at 1M. now_slot = 100 (warped).
//   The bid is drained (Expired); the ask stays Pending; no
//   matches (no counterparty).

#[test]
fn parity_5_expired_orders_drained() {
    let book = book_of(vec![
        pseed(0, 0, 100, 5, 5), // expires at slot 5
        pseed(1, 1, 100, 5, 1_000_000),
    ]);
    let out = run_batch(&book, &oracle(100), &config(100_000, 0), 100, 0).expect("matcher");

    assert_eq!(out.matches.len(), 0);
    // One OrderUpdate: the bid is Expired. The ask is untouched
    // (still Pending — no counterparty after the expiry sweep).
    assert_eq!(out.order_updates.len(), 1);
    let upd = &out.order_updates[0];
    assert!(matches!(upd.kind, OrderUpdateKind::Expired));
    // Identity bytes must match the expired bid (idx=0).
    let expected_oid = {
        let mut o = [0u8; 16];
        o[0] = 1; // side_u8 + 1 (bid)
        o[2..10].copy_from_slice(&100u64.to_le_bytes());
        o[15] = 1; // idx + 1
        o
    };
    assert_eq!(upd.order_id, expected_oid);
}

// ─────── Scenario 6: min_fill_qty enforced ──────────────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_min_fill_qty_enforced
//   Bid amount=20 with min_fill_qty=10. Ask amount=5.
//   crossable = min(20, 5) = 5, but 5 < 10 → skip.
//   Expected: match_count=0, both stay Pending.

#[test]
fn parity_6_min_fill_qty_enforced() {
    let mut bid = pseed(0, 0, 100, 20, 1_000_000);
    bid.min_fill_qty = 10;
    let ask = pseed(1, 1, 100, 5, 1_000_000);
    let book = book_of(vec![bid, ask]);
    let out = run_batch(&book, &oracle(100), &config(100_000, 0), 1, 0).expect("matcher");

    assert_eq!(out.matches.len(), 0);
    assert!(
        out.order_updates.is_empty(),
        "no fill → no updates, got {:?}",
        out.order_updates
    );
}

// ─────── Scenario 7: inclusion root published ───────────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_inclusion_root_published
//   3 orders (s0 bid @105, s1 bid @100, s2 ask @95). After
//   matching, the matcher publishes a SHA-256 binary Merkle root
//   over the 3 order_inclusion_commitments (padded to 4 by
//   duplicating the last leaf). We re-derive the expected root
//   inline using `sha2::Sha256` (byte-equal to the on-chain
//   `solana_program::hash::hashv` per the merkle_root_sha256
//   parity test).

#[test]
fn parity_7_inclusion_root_published() {
    use sha2::{Digest, Sha256};

    let s0 = pseed(0, 0, 105, 5, 1_000_000);
    let s1 = pseed(1, 0, 100, 5, 1_000_000);
    let s2 = pseed(2, 1, 95, 5, 1_000_000);
    let book = book_of(vec![s0.clone(), s1.clone(), s2.clone()]);
    let out = run_batch(&book, &oracle(100), &config(100_000, 0), 1, 0).expect("matcher");

    assert_ne!(out.inclusion_root, [0u8; 32]);

    // Expected: SHA-256 Merkle root over [s0.oic, s1.oic, s2.oic, s2.oic].
    let leaves = [
        s0.order_inclusion_commitment,
        s1.order_inclusion_commitment,
        s2.order_inclusion_commitment,
        s2.order_inclusion_commitment,
    ];
    let h01: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(leaves[0]);
        h.update(leaves[1]);
        h.finalize().into()
    };
    let h23: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(leaves[2]);
        h.update(leaves[3]);
        h.finalize().into()
    };
    let expected: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(h01);
        h.update(h23);
        h.finalize().into()
    };
    assert_eq!(out.inclusion_root, expected);
}

// ─────── Scenario 8: partial fill keeps slot pending ────────────────────────
//
// programs/matching_engine/tests/run_batch.rs::test_partial_fill_keeps_slot_pending
//   Bid amount=20, ask amount=5, both @ 100.
//   crossable = 5 → one fill of 5. Bid residual=15 (Pending),
//   ask filled (Matched).

#[test]
fn parity_8_partial_fill_keeps_slot_pending() {
    let bid = pseed(0, 0, 100, 20, 1_000_000);
    let ask = pseed(1, 1, 100, 5, 1_000_000);
    let book = book_of(vec![bid, ask]);
    let out = run_batch(&book, &oracle(100), &config(100_000, 0), 1, 0).expect("matcher");

    assert_eq!(out.matches.len(), 1);
    assert_eq!(out.matches[0].base_amt, 5);
    assert_eq!(out.matches[0].quote_amt, 500);

    // Two OrderUpdates: ask FullyFilled, bid PartiallyFilled with
    // new_amount=15.
    assert_eq!(out.order_updates.len(), 2);

    // Locate each by its order_id (idx=0 → bid, idx=1 → ask).
    let bid_oid = {
        let mut o = [0u8; 16];
        o[0] = 1; // side_u8 + 1
        o[2..10].copy_from_slice(&100u64.to_le_bytes());
        o[15] = 1;
        o
    };
    let ask_oid = {
        let mut o = [0u8; 16];
        o[0] = 2; // side_u8 + 1
        o[2..10].copy_from_slice(&100u64.to_le_bytes());
        o[15] = 2;
        o
    };
    let bid_upd = out
        .order_updates
        .iter()
        .find(|u| u.order_id == bid_oid)
        .expect("bid update");
    let ask_upd = out
        .order_updates
        .iter()
        .find(|u| u.order_id == ask_oid)
        .expect("ask update");

    match &bid_upd.kind {
        OrderUpdateKind::PartiallyFilled { new_amount, .. } => {
            assert_eq!(*new_amount, 15);
        }
        other => panic!("expected bid PartiallyFilled, got {other:?}"),
    }
    assert!(
        matches!(ask_upd.kind, OrderUpdateKind::FullyFilled { .. }),
        "expected ask FullyFilled, got {:?}",
        ask_upd.kind
    );
}
