//! `run_batch` integration tests against the privacy-fix PendingOrder model.
//!
//! Each test seeds a fresh market + a set of PendingOrder PDAs (one per
//! pseudo-trader since each (market, trading_key, slot_idx) maps to a
//! unique PDA), then drives `run_batch` with those PDAs supplied as
//! `remaining_accounts`.

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Seed N pending orders. Each gets its own synthetic trading_key
/// (`tk[0..8] = idx`) so the PDAs are distinct.
fn seed_pendings(
    h: &mut Harness,
    market: &solana_address::Address,
    seeds: &[PendingSeed],
) -> Vec<solana_address::Address> {
    seeds
        .iter()
        .map(|s| seed_pending_order(h, market, s))
        .collect()
}

/// Build a PendingSeed with auto-incremented synthetic trading_key.
fn pseed(idx: u8, side: u8, price: u64, amount: u64, expiry: u64) -> PendingSeed {
    let mut tk = [0u8; 32];
    tk[1..9].copy_from_slice(&(idx as u64).to_le_bytes());
    let mut s = make_pending_seed(tk, 0, side, price, amount, expiry);
    // Distinct collateral_note + order_id per seed.
    s.collateral_note[10] = idx;
    s.order_id[15] = idx.wrapping_add(1);
    s.order_inclusion_commitment[10] = idx;
    s
}

// ============================================================================
// 1. Uniform clearing price
// ============================================================================
#[test]
fn test_uniform_clearing_price() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(146);

    let seeds = vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 0, 149, 10, 1_000_000),
        pseed(2, 0, 148, 10, 1_000_000),
        pseed(3, 0, 147, 10, 1_000_000),
        pseed(4, 0, 146, 10, 1_000_000),
        pseed(5, 1, 144, 10, 1_000_000),
        pseed(6, 1, 145, 10, 1_000_000),
        pseed(7, 1, 146, 10, 1_000_000),
    ];
    let pdas = seed_pendings(&mut h, &market, &seeds);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_circuit_breaker_tripped, 0);
    // P=146: demand=50, supply=30 → 30. P=145: demand=40 supply=20 → 20.
    assert_eq!(br.last_clearing_price, 146);
    assert_eq!(br.last_match_count, 3);
}

// ============================================================================
// 2. Intra-batch ordering invariance
// ============================================================================
#[test]
fn test_intra_batch_ordering_irrelevant() {
    let run = |seeds: Vec<PendingSeed>| -> (u64, u64) {
        let mut h = Harness::setup();
        let market = Keypair::new().pubkey();
        h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
        h.update_mock_oracle(100);
        let pdas = seed_pendings(&mut h, &market, &seeds);
        let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
        let tx = Transaction::new(
            &[&h.tee],
            Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
            h.svm.latest_blockhash(),
        );
        h.svm.send_transaction(tx).expect("run_batch");
        let br = read_batch_results(&h, &market);
        (br.last_clearing_price, br.last_match_count)
    };

    let a = vec![
        pseed(0, 0, 105, 5, 1_000_000),
        pseed(1, 0, 100, 5, 1_000_000),
        pseed(2, 1, 95, 5, 1_000_000),
        pseed(3, 1, 100, 5, 1_000_000),
    ];
    let mut b = a.clone();
    // Swap arrival_slots so seq order changes but content is identical.
    b[0].arrival_slot = 99;
    b[3].arrival_slot = 1;
    let r1 = run(a);
    let r2 = run(b);
    assert_eq!(r1, r2, "outcome must be order-invariant");
}

// ============================================================================
// 3. Circuit breaker trips when P* deviates from TWAP
// ============================================================================
#[test]
fn test_circuit_breaker_pauses_batch() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 300, 1, 0);
    h.update_mock_oracle(100); // 50% deviation vs P*~150 → trip

    let seeds = vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 1, 140, 10, 1_000_000),
    ];
    let pdas = seed_pendings(&mut h, &market, &seeds);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_circuit_breaker_tripped, 1);
    assert_eq!(br.last_match_count, 0);
    assert_eq!(br.last_clearing_price, 0);
    // Both slots stay Pending.
    for pda in &pdas {
        assert_eq!(read_pending_status(&h, pda), 1);
    }
}

// ============================================================================
// 4. Circuit breakers are per-market
// ============================================================================
#[test]
fn test_circuit_breaker_does_not_affect_other_pairs() {
    let mut h = Harness::setup();
    let oracle_a = Keypair::new().pubkey();
    Harness::write_mock_oracle(&mut h.svm, &oracle_a, 100);
    let oracle_b = Keypair::new().pubkey();
    Harness::write_mock_oracle(&mut h.svm, &oracle_b, 145);

    let market_a = Keypair::new().pubkey();
    let market_b = Keypair::new().pubkey();
    h.init_market_full(&market_a, 2, oracle_a, 300, 1, 0);
    h.init_market_full(&market_b, 2, oracle_b, 300, 1, 0);

    let seeds_a = vec![
        pseed(0, 0, 150, 10, 1_000_000),
        pseed(1, 1, 140, 10, 1_000_000),
    ];
    let seeds_b = vec![
        pseed(0, 0, 145, 10, 1_000_000),
        pseed(1, 1, 145, 10, 1_000_000),
    ];
    let pdas_a = seed_pendings(&mut h, &market_a, &seeds_a);
    let pdas_b = seed_pendings(&mut h, &market_b, &seeds_b);

    let mut ix_a = build_run_batch_ix(&h, &market_a, &h.tee, &pdas_a);
    ix_a.accounts[4].pubkey = oracle_a;
    let tx_a = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_a], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_a).expect("run_batch A");

    h.svm.expire_blockhash();
    let mut ix_b = build_run_batch_ix(&h, &market_b, &h.tee, &pdas_b);
    ix_b.accounts[4].pubkey = oracle_b;
    let tx_b = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_b], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_b).expect("run_batch B");

    let br_a = read_batch_results(&h, &market_a);
    let br_b = read_batch_results(&h, &market_b);
    assert_eq!(br_a.last_circuit_breaker_tripped, 1);
    assert_eq!(br_a.last_match_count, 0);
    assert_eq!(br_b.last_circuit_breaker_tripped, 0);
    assert!(br_b.last_match_count > 0);
}

// ============================================================================
// 5. Expired orders are drained
// ============================================================================
#[test]
fn test_expired_orders_drained() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let seeds = vec![
        pseed(0, 0, 100, 5, 5), // expires at slot 5
        pseed(1, 1, 100, 5, 1_000_000),
    ];
    let pdas = seed_pendings(&mut h, &market, &seeds);

    h.svm.warp_to_slot(100);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    // Slot 0 expired (status = 3); slot 1 still pending.
    assert_eq!(read_pending_status(&h, &pdas[0]), 3);
    assert_eq!(read_pending_status(&h, &pdas[1]), 1);
    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_match_count, 0);
}

// ============================================================================
// 6. min_fill_qty enforced
// ============================================================================
#[test]
fn test_min_fill_qty_enforced() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let mut bid = pseed(0, 0, 100, 20, 1_000_000);
    bid.min_fill_qty = 10;
    let ask = pseed(1, 1, 100, 5, 1_000_000);
    let pdas = seed_pendings(&mut h, &market, &[bid, ask]);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_match_count, 0);
    for pda in &pdas {
        assert_eq!(read_pending_status(&h, pda), 1);
    }
}

// ============================================================================
// 7. Inclusion root published
// ============================================================================
#[test]
fn test_inclusion_root_published() {
    use solana_program::hash::hashv;

    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let s0 = pseed(0, 0, 105, 5, 1_000_000);
    let s1 = pseed(1, 0, 100, 5, 1_000_000);
    let s2 = pseed(2, 1, 95, 5, 1_000_000);
    let pdas = seed_pendings(&mut h, &market, &[s0, s1, s2]);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_ne!(br.last_inclusion_root, [0u8; 32]);

    let leaves = [
        s0.order_inclusion_commitment,
        s1.order_inclusion_commitment,
        s2.order_inclusion_commitment,
        s2.order_inclusion_commitment,
    ];
    let h01 = hashv(&[&leaves[0], &leaves[1]]).to_bytes();
    let h23 = hashv(&[&leaves[2], &leaves[3]]).to_bytes();
    let expected = hashv(&[&h01, &h23]).to_bytes();
    assert_eq!(br.last_inclusion_root, expected);
}

// ============================================================================
// 8. Per-market state isolation
// ============================================================================
#[test]
fn test_market_state_isolated() {
    let mut h = Harness::setup();
    let market_a = Keypair::new().pubkey();
    let market_b = Keypair::new().pubkey();
    h.init_market_full(&market_a, 2, h.pyth_account, 100_000, 1, 0);
    h.init_market_full(&market_b, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let pdas_a = seed_pendings(
        &mut h,
        &market_a,
        &[
            pseed(0, 0, 100, 5, 1_000_000),
            pseed(1, 1, 100, 5, 1_000_000),
        ],
    );
    let pdas_b = seed_pendings(
        &mut h,
        &market_b,
        &[
            pseed(0, 0, 100, 5, 1_000_000),
            pseed(1, 0, 100, 5, 1_000_000),
        ],
    );

    let ix_a = build_run_batch_ix(&h, &market_a, &h.tee, &pdas_a);
    let tx_a = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix_a], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx_a).expect("run_batch A");

    // B untouched.
    for pda in &pdas_b {
        assert_eq!(read_pending_status(&h, pda), 1);
    }
    let br_b = read_batch_results(&h, &market_b);
    assert_eq!(br_b.last_batch_slot, 0);

    let br_a = read_batch_results(&h, &market_a);
    assert!(br_a.last_match_count > 0);
}

// ============================================================================
// 9. Cancel flips a Pending slot to Cancelled
// ============================================================================
#[test]
fn test_cancel_flips_pending_to_cancelled() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    // Allocate a real slot owned by `h.trader` so cancel passes the
    // trading_key signer check.
    let trader_pk = h.trader.pubkey();
    let init_ix = h.build_init_pending_order_slot_ix(&market, 0, &h.trader);
    let init_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[init_ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(init_tx).expect("init slot");

    // Submit an order so the slot is Pending.
    let mut order_id = [0u8; 16];
    order_id[15] = 0xab;
    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        slot_idx: 0,
        side: 0,
        order_type: 0,
        _padding: [0u8; 5],
        amount: 50,
        min_fill_qty: 0,
        price_limit: 100,
        note_amount: 50 * 100,
        expiry_slot: 1_000_000,
        order_id,
        note_commitment: [9u8; 32],
        user_commitment: [7u8; 32],
    };
    h.svm.expire_blockhash();
    let submit_ix = h.build_submit_order_ix(args);
    let submit_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[submit_ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(submit_tx).expect("submit ok");
    let (slot_pda, _) = pending_order_pda(&h.me_id, &market, &trader_pk, 0);
    assert_eq!(read_pending_status(&h, &slot_pda), 1);

    // Cancel.
    h.svm.expire_blockhash();
    let cancel_ix = build_cancel_order_ix(&h, &market, 0, &h.trader);
    let cancel_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[cancel_ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(cancel_tx).expect("cancel ok");
    assert_eq!(read_pending_status(&h, &slot_pda), 4);
}

// ============================================================================
// 10. Cancelling someone else's slot is rejected (PDA seed enforcement)
// ============================================================================
#[test]
fn test_cancel_unauthorized_caller_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    // Allocate a slot for trader, populate it.
    let trader_pk = h.trader.pubkey();
    let init_ix = h.build_init_pending_order_slot_ix(&market, 0, &h.trader);
    let init_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[init_ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(init_tx).expect("init slot");

    let mut order_id = [0u8; 16];
    order_id[15] = 0xcd;
    let args = SubmitOrderArgs {
        market: market.to_bytes(),
        slot_idx: 0,
        side: 0,
        order_type: 0,
        _padding: [0u8; 5],
        amount: 5,
        min_fill_qty: 0,
        price_limit: 10,
        note_amount: 50,
        expiry_slot: 1_000_000,
        order_id,
        note_commitment: [9u8; 32],
        user_commitment: [7u8; 32],
    };
    h.svm.expire_blockhash();
    let submit_ix = h.build_submit_order_ix(args);
    let submit_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[submit_ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(submit_tx).expect("submit ok");

    // Intruder tries to cancel using their own key — PDA seed mismatches.
    let intruder = Keypair::new();
    h.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    h.svm.expire_blockhash();
    let cancel_ix = build_cancel_order_ix(&h, &market, 0, &intruder);
    let cancel_tx = Transaction::new(
        &[&intruder],
        Message::new(&[cancel_ix], Some(&intruder.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(cancel_tx)
        .expect_err("intruder cancel must fail");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("accountnotinitialized")
            || logs.to_lowercase().contains("constraintseeds")
            || logs.to_lowercase().contains("accountownedbywrongprogram"),
        "expected slot-not-allocated error, got:\n{logs}"
    );

    // Original slot still Pending.
    let (slot_pda, _) = pending_order_pda(&h.me_id, &market, &trader_pk, 0);
    assert_eq!(read_pending_status(&h, &slot_pda), 1);
}

// ============================================================================
// 11. TEE authority gate on run_batch
// ============================================================================
#[test]
fn test_run_batch_rejects_non_tee_signer() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    let pdas = seed_pendings(
        &mut h,
        &market,
        &[
            pseed(0, 0, 100, 5, 1_000_000),
            pseed(1, 1, 100, 5, 1_000_000),
        ],
    );

    let intruder = Keypair::new();
    h.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();
    let ix = build_run_batch_ix(&h, &market, &intruder, &pdas);
    let tx = Transaction::new(
        &[&intruder],
        Message::new(
            &[compute_budget_ix(1_400_000), ix],
            Some(&intruder.pubkey()),
        ),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("non-TEE signer must be rejected");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("notrootkey")
            || logs.to_lowercase().contains("not the configured")
            || logs.to_lowercase().contains("teeauthority"),
        "expected NotRootKey, got:\n{logs}"
    );
}

// ============================================================================
// 12. Partial fill rotates collateral_note + leaves Pending residual
// ============================================================================
#[test]
fn test_partial_fill_keeps_slot_pending() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market_full(&market, 2, h.pyth_account, 100_000, 1, 0);
    h.update_mock_oracle(100);

    // Bid wants 20, ask only has 5 → partial fill of 5.
    let bid = pseed(0, 0, 100, 20, 1_000_000);
    let ask = pseed(1, 1, 100, 5, 1_000_000);
    let pdas = seed_pendings(&mut h, &market, &[bid, ask]);

    let ix = build_run_batch_ix(&h, &market, &h.tee, &pdas);
    let tx = Transaction::new(
        &[&h.tee],
        Message::new(&[compute_budget_ix(1_400_000), ix], Some(&h.tee.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("run_batch");

    let br = read_batch_results(&h, &market);
    assert_eq!(br.last_match_count, 1);
    // Bid: status still Pending, amount = 15.
    assert_eq!(read_pending_status(&h, &pdas[0]), 1);
    assert_eq!(read_pending_amount(&h, &pdas[0]), 15);
    // Ask: full fill → Matched.
    assert_eq!(read_pending_status(&h, &pdas[1]), 2);
}
