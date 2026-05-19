//! Privacy-fix submit_order litesvm integration tests.
//!
//! Submit_order is now a single-account write into a pre-allocated
//! `PendingOrder` slot PDA. In production the PDA is delegated to the
//! ER and `submit_order` runs inside the rollup; in litesvm we drive
//! the program directly on the L1-equivalent runtime — the privacy
//! property is achieved at the network layer, the on-chain logic is
//! the same in both environments.

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

#[allow(clippy::result_large_err)]
fn run_submit(
    h: &mut Harness,
    args: SubmitOrderArgs,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let ix = h.build_submit_order_ix(args);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).map(|_| ())
}

fn ensure_slot(h: &mut Harness, market: &solana_address::Address, slot_idx: u8) {
    let trader_pk = h.trader.pubkey();
    let ix = h.build_init_pending_order_slot_ix(market, slot_idx, &h.trader);
    let tx = Transaction::new(
        &[&h.trader],
        Message::new(&[ix], Some(&trader_pk)),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("init_pending_order_slot");
}

fn happy_args(
    market: &solana_address::Address,
    slot_idx: u8,
    user_commitment: [u8; 32],
) -> SubmitOrderArgs {
    let mut order_id = [0u8; 16];
    order_id[15] = 0xab;
    SubmitOrderArgs {
        market: market.to_bytes(),
        slot_idx,
        side: 0,
        order_type: 0,
        _padding: [0u8; 5],
        amount: 100,
        min_fill_qty: 0,
        price_limit: 200,
        note_amount: 100 * 200,
        expiry_slot: 1_000_000,
        order_id,
        note_commitment: [9u8; 32],
        user_commitment,
    }
}

#[test]
fn test_submit_writes_pending_slot() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);

    ensure_slot(&mut h, &market, 0);

    // Pre-submit: status = Empty (0).
    let (slot_pda, _) = pending_order_pda(&h.me_id, &market, &h.trader.pubkey(), 0);
    assert_eq!(read_pending_status(&h, &slot_pda), 0);

    let args = happy_args(&market, 0, [7u8; 32]);
    run_submit(&mut h, args).expect("happy submit_order");

    // Post-submit: status = Pending (1) and amount written.
    assert_eq!(read_pending_status(&h, &slot_pda), 1);
    assert_eq!(read_pending_amount(&h, &slot_pda), 100);
}

#[test]
fn test_zero_amount_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.amount = 0;
    let err = run_submit(&mut h, args).expect_err("zero amount must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("zeroamount"),
        "expected ZeroAmount, got:\n{logs}"
    );
}

#[test]
fn test_zero_price_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.price_limit = 0;
    let err = run_submit(&mut h, args).expect_err("zero price must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("zeroprice"),
        "expected ZeroPrice, got:\n{logs}"
    );
}

#[test]
fn test_invalid_side_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.side = 7;
    let err = run_submit(&mut h, args).expect_err("invalid side must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("invalidside"),
        "expected InvalidSide, got:\n{logs}"
    );
}

#[test]
fn test_zero_order_id_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.order_id = [0u8; 16];
    let err = run_submit(&mut h, args).expect_err("zero order_id must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("invalidorderid"),
        "expected InvalidOrderId, got:\n{logs}"
    );
}

#[test]
fn test_notional_exceeds_note_value_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.note_amount = args.amount * args.price_limit - 1; // notional > note
    let err = run_submit(&mut h, args).expect_err("over-notional must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("notionalexceeds") || logs.to_lowercase().contains("notional"),
        "expected NotionalExceedsNoteValue, got:\n{logs}"
    );
}

#[test]
fn test_expiry_in_past_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    h.svm.warp_to_slot(100);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.expiry_slot = 50;
    let err = run_submit(&mut h, args).expect_err("past expiry must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("expiryinpast") || logs.to_lowercase().contains("expiry"),
        "expected ExpiryInPast, got:\n{logs}"
    );
}

#[test]
fn test_min_fill_too_large_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);
    let mut args = happy_args(&market, 0, [7u8; 32]);
    args.min_fill_qty = args.amount + 1;
    let err = run_submit(&mut h, args).expect_err("min_fill > amount must reject");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("amountbelowminordersize")
            || logs.to_lowercase().contains("min"),
        "expected AmountBelowMinOrderSize, got:\n{logs}"
    );
}

#[test]
fn test_slot_already_occupied_rejected() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);

    let args = happy_args(&market, 0, [7u8; 32]);
    run_submit(&mut h, args).expect("first submit ok");

    h.svm.expire_blockhash();
    // Second submit (different order_id) without cancelling first must fail.
    let mut args2 = args;
    args2.order_id[14] = 0xfe;
    let err = run_submit(&mut h, args2).expect_err("must reject occupied slot");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("slotalreadyoccupied")
            || logs.to_lowercase().contains("occupied"),
        "expected SlotAlreadyOccupied, got:\n{logs}"
    );
}

#[test]
fn test_cancel_then_resubmit_works() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);

    // Submit, cancel, resubmit different params.
    run_submit(&mut h, happy_args(&market, 0, [7u8; 32])).expect("submit 1");

    h.svm.expire_blockhash();
    let cancel_ix = build_cancel_order_ix(&h, &market, 0, &h.trader);
    let cancel_tx = Transaction::new(
        &[&h.trader],
        Message::new(&[cancel_ix], Some(&h.trader.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(cancel_tx).expect("cancel ok");

    let (slot_pda, _) = pending_order_pda(&h.me_id, &market, &h.trader.pubkey(), 0);
    assert_eq!(read_pending_status(&h, &slot_pda), 4); // Cancelled

    h.svm.expire_blockhash();
    let mut args2 = happy_args(&market, 0, [7u8; 32]);
    args2.order_id[14] = 0xfe;
    args2.amount = 250;
    args2.note_amount = 250 * 200;
    run_submit(&mut h, args2).expect("submit after cancel ok");
    assert_eq!(read_pending_status(&h, &slot_pda), 1);
    assert_eq!(read_pending_amount(&h, &slot_pda), 250);
}

#[test]
fn test_stranger_cannot_write_others_slot() {
    let mut h = Harness::setup();
    let market = Keypair::new().pubkey();
    h.init_market(&market, 2);
    ensure_slot(&mut h, &market, 0);

    // Spawn an intruder.
    let intruder = Keypair::new();
    h.svm.airdrop(&intruder.pubkey(), 1_000_000_000).unwrap();

    // Build a submit_order ix with the intruder as signer + intruder's own
    // PendingOrder PDA seed (which doesn't exist). Anchor's seeds check
    // will fail because the intruder does not have a slot for this market.
    let args = happy_args(&market, 0, [7u8; 32]);
    let ix = h.build_submit_order_ix_for(args, &intruder);
    let tx = Transaction::new(
        &[&intruder],
        Message::new(&[ix], Some(&intruder.pubkey())),
        h.svm.latest_blockhash(),
    );
    let err = h
        .svm
        .send_transaction(tx)
        .expect_err("intruder must not be able to write any slot");
    let logs = err.meta.logs.join("\n");
    assert!(
        logs.to_lowercase().contains("accountnotinitialized")
            || logs.to_lowercase().contains("constraintseeds")
            || logs.to_lowercase().contains("accountdiscriminatormismatch")
            || logs.to_lowercase().contains("accountownedbywrongprogram"),
        "expected slot-not-allocated error, got:\n{logs}"
    );
}
