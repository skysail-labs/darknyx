//! `submit_order` — JWT-authenticated order submission INSIDE the ER.
//!
//! Privacy property: this instruction is sent to the MagicBlock ER's
//! authenticated PER RPC (NOT L1). The PendingOrder slot it writes was
//! already delegated to the ER on L1 in an earlier setup tx, which
//! itself contained no order details. Therefore the `side`, `amount`,
//! `price_limit`, `note_commitment`, `user_commitment`, `order_id`
//! never appear in any L1 transaction log — they live and die inside
//! the TEE unless the order matches in `run_batch`.
//!
//! Validation:
//!   1. The slot's seed enforces that `trading_key` is the slot's owner.
//!   2. Slot must be Empty (or Cancelled / Expired / Matched, which are
//!      treated as reusable Empties).
//!   3. Order parameters are well-formed (side ∈ {0,1},
//!      order_type ∈ {0,1,2}, amount > 0, price > 0, expiry > now).
//!   4. Notional (amount × price_limit) does not exceed the supplied
//!      `note_amount` — same conservation law `run_batch` enforces.
//!   5. Min-fill is plausible (`min_fill_qty <= amount`).
//!
//! NO vault CPI. NO NoteLock allocation. The TEE will create the
//! NoteLock atomically with `tee_forced_settle` on L1 only for matched
//! pairs — unmatched orders never produce any L1 trace.
//!
//! Notes on `MatchingConfig` access from inside the ER:
//!   We DO NOT require MatchingConfig as an account here. Two reasons:
//!     a) MatchingConfig is delegated to the ER as a separate PDA;
//!        requiring it would make `submit_order` accept it from the
//!        caller, which is fine but adds one more account to the tx.
//!     b) We do the cheap-side checks (amount > 0, expiry > now) here
//!        and defer the `min_order_size` gate to `run_batch` — orders
//!        below the floor will simply be skipped at match time. That
//!        keeps `submit_order` as a single-account write and lets us
//!        change market params without invalidating in-flight orders.

use anchor_lang::prelude::*;
use solana_program::hash::hashv;

use crate::errors::MatchingError;
use crate::state::{
    PendingOrder, PENDING_SIDE_ASK, PENDING_SIDE_BID, PENDING_STATUS_CANCELLED,
    PENDING_STATUS_EMPTY, PENDING_STATUS_EXPIRED, PENDING_STATUS_MATCHED, PENDING_STATUS_PENDING,
    PENDING_TYPE_FOK, PENDING_TYPE_IOC, PENDING_TYPE_LIMIT,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct SubmitOrderArgs {
    /// Market this slot is bound to (seed component for slot PDA).
    pub market: Pubkey,
    /// 0..MAX_PENDING_SLOTS_PER_USER — which of the user's pre-delegated
    /// slots to write into.
    pub slot_idx: u8,
    /// 0 = bid (buy), 1 = ask (sell).
    pub side: u8,
    /// 0 = LIMIT, 1 = IOC, 2 = FOK.
    pub order_type: u8,
    pub _padding: [u8; 5],
    /// Order size (base units).
    pub amount: u64,
    /// Min fill qty — 0 = any partial allowed.
    pub min_fill_qty: u64,
    /// Limit price in tick units (base per quote unit).
    pub price_limit: u64,
    /// Full note value collateralising the order (BUY: QUOTE; SELL: BASE).
    pub note_amount: u64,
    /// Slot at which the order auto-expires.
    pub expiry_slot: u64,
    /// Caller-supplied 16-byte client id.
    pub order_id: [u8; 16],
    /// Poseidon commitment of the note collateralising this order.
    pub note_commitment: [u8; 32],
    /// Owner commitment (= Poseidon(spending_key, r_owner)). The TEE
    /// derives change-note commitments back to this owner at match time.
    pub user_commitment: [u8; 32],
}

#[derive(Accounts)]
#[instruction(args: SubmitOrderArgs)]
pub struct SubmitOrder<'info> {
    /// Trading Key — owner of the slot, signs the order intent.
    #[account(mut)]
    pub trading_key: Signer<'info>,

    /// The pre-delegated PendingOrder slot. Seeds-checked: only the
    /// owner trading_key can possibly resolve to this PDA, so a
    /// stranger CANNOT write into someone else's slot.
    #[account(
        mut,
        seeds = [
            PendingOrder::SEED,
            args.market.as_ref(),
            trading_key.key().as_ref(),
            core::slice::from_ref(&args.slot_idx),
        ],
        bump = pending_order.load()?.bump,
    )]
    pub pending_order: AccountLoader<'info, PendingOrder>,
}

pub fn submit_order_handler(ctx: Context<SubmitOrder>, args: SubmitOrderArgs) -> Result<()> {
    // --- Parameter validation ---
    require!(
        args.side == PENDING_SIDE_BID || args.side == PENDING_SIDE_ASK,
        MatchingError::InvalidSide
    );
    require!(
        args.order_type == PENDING_TYPE_LIMIT
            || args.order_type == PENDING_TYPE_IOC
            || args.order_type == PENDING_TYPE_FOK,
        MatchingError::InvalidOrderType
    );
    require!(args.amount > 0, MatchingError::ZeroAmount);
    require!(args.price_limit > 0, MatchingError::ZeroPrice);
    require!(args.order_id != [0u8; 16], MatchingError::InvalidOrderId);
    require!(
        args.min_fill_qty <= args.amount,
        MatchingError::AmountBelowMinOrderSize
    );

    // Notional / collateral sufficiency check — same conservation law as
    // run_batch's settlement (note.amount == trade_leg + change + fee).
    let required = if args.side == PENDING_SIDE_BID {
        (args.amount as u128)
            .checked_mul(args.price_limit as u128)
            .ok_or(MatchingError::NotionalOverflow)?
    } else {
        args.amount as u128
    };
    require!(
        required <= args.note_amount as u128,
        MatchingError::NotionalExceedsNoteValue
    );

    let now = Clock::get()?.slot;
    require!(args.expiry_slot > now, MatchingError::ExpiryInPast);

    // --- Slot identity + reusability check ---
    let bump = {
        let slot = ctx.accounts.pending_order.load()?;
        require!(
            slot.trading_key == ctx.accounts.trading_key.key(),
            MatchingError::UnauthorizedTradingKey
        );
        require!(slot.market == args.market, MatchingError::MarketMismatch);
        require!(
            slot.slot_idx == args.slot_idx,
            MatchingError::InvalidPendingSlot
        );
        // Slot must be reusable: Empty / Matched / Expired / Cancelled all OK.
        // Pending = currently-resting order, must be cancelled first.
        require!(
            matches!(
                slot.status,
                PENDING_STATUS_EMPTY
                    | PENDING_STATUS_MATCHED
                    | PENDING_STATUS_EXPIRED
                    | PENDING_STATUS_CANCELLED
            ),
            MatchingError::SlotAlreadyOccupied
        );
        slot.bump
    };

    // --- Inclusion commitment (anchored at submit time) ---
    let inclusion_commitment =
        compute_inclusion_commitment(now, &args.note_commitment, &ctx.accounts.trading_key.key());

    // --- Write the order intent into the delegated slot ---
    {
        let mut slot = ctx.accounts.pending_order.load_mut()?;
        slot.status = PENDING_STATUS_PENDING;
        slot.side = args.side;
        slot.order_type = args.order_type;
        slot.bump = bump;
        slot.arrival_slot = now;
        slot.expiry_slot = args.expiry_slot;
        slot.price_limit = args.price_limit;
        slot.amount = args.amount;
        slot.total_quantity = args.amount;
        slot.filled_quantity = 0;
        slot.min_fill_qty = args.min_fill_qty;
        slot.note_amount = args.note_amount;
        slot.collateral_note = args.note_commitment;
        slot.user_commitment = args.user_commitment;
        slot.order_id = args.order_id;
        slot.order_inclusion_commitment = inclusion_commitment;
        slot._padding_a = [0u8; 3];
        slot._padding_b = [0u8; 8];
    }

    emit!(OrderSubmitted {
        market: args.market,
        trading_key: ctx.accounts.trading_key.key(),
        slot_idx: args.slot_idx,
        order_inclusion_commitment: inclusion_commitment,
        arrival_slot: now,
    });
    Ok(())
}

/// `SHA-256(arrival_slot || note_commitment || trading_key)` — anchored
/// at submit time. Surfaced back to the user for censorship audits and
/// the inclusion root that `run_batch` publishes for each batch.
pub fn compute_inclusion_commitment(
    arrival_slot: u64,
    note_commitment: &[u8; 32],
    trading_key: &Pubkey,
) -> [u8; 32] {
    let slot_bytes = arrival_slot.to_le_bytes();
    hashv(&[&slot_bytes[..], &note_commitment[..], trading_key.as_ref()]).to_bytes()
}

#[event]
pub struct OrderSubmitted {
    pub market: Pubkey,
    pub trading_key: Pubkey,
    pub slot_idx: u8,
    pub order_inclusion_commitment: [u8; 32],
    pub arrival_slot: u64,
}
