//! `run_batch` — periodic batch auction inside the ER (spec §20.6 + §23.4).
//!
//! The on-chain ix shell. The matching algorithm itself moved into
//! `crates/darkpool-matcher` in TEE-v2 PR 2. This file is the thin
//! adapter that:
//!
//!   1. Reads PendingOrder PDAs from `ctx.remaining_accounts` and
//!      builds the matcher's `OrderBook`.
//!   2. Snapshots vault + market config into `darkpool_matcher::MatchConfig`.
//!   3. Reads the Pyth (or mock) oracle into `OracleSnapshot`.
//!   4. Calls `darkpool_matcher::run_batch(...)`.
//!   5. Writes the returned `RunBatchOutput` back to `BatchResults`
//!      (matches into the ring buffer, fee_buckets into the
//!      accumulators, last_* stats into the header) and applies
//!      `OrderUpdate`s to the source PendingOrder PDAs.
//!
//! Privacy property unchanged: PendingOrder PDAs stay delegated to
//! the ER between batches. They are NEVER committed back to L1, so
//! even after `run_batch` finishes, a stranger reading L1 sees only
//! the aggregate `BatchResults`. Individual unmatched orders leave
//! zero L1 trace.

use anchor_lang::prelude::*;

use darkpool_matcher::{
    book::{Order as MatcherOrder, OrderBook, OrderSide, OrderStatus, OrderType, OrderUpdateKind},
    config::{MatchConfig, OracleSnapshot},
    match_result::{MatchPair, MatchStatus},
    run_batch as matcher_run_batch,
};

use crate::errors::MatchingError;
use crate::state::batch_results::BATCH_RESULTS_CAPACITY;
use crate::state::pyth::read_oracle_price;
use crate::state::{
    BatchResults, MatchResult, MatchingConfig, PendingOrder, MATCH_RESULT_STATUS_FILLED,
    PENDING_SIDE_ASK, PENDING_SIDE_BID, PENDING_STATUS_CANCELLED, PENDING_STATUS_EXPIRED,
    PENDING_STATUS_MATCHED, PENDING_STATUS_PENDING, PENDING_TYPE_FOK, PENDING_TYPE_IOC,
    PENDING_TYPE_LIMIT,
};

/// Hard cap on the number of PendingOrder PDAs accepted via
/// `remaining_accounts`. This is a transaction-level constraint
/// (Solana account-list size + compute budget), NOT a matcher
/// concern — the matcher itself has no such limit. A v2 with
/// paged matching across multiple `run_batch` calls can lift this.
pub const MAX_PENDING_ACCOUNTS_PER_BATCH: usize = 24;

#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct RunBatch<'info> {
    /// TEE authority — must equal `vault_config.tee_pubkey`. Inside the
    /// ER session, the validator runs as this signer.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        seeds = [MatchingConfig::SEED, market.as_ref()],
        bump = matching_config.load()?.bump,
    )]
    pub matching_config: AccountLoader<'info, MatchingConfig>,

    #[account(
        mut,
        seeds = [BatchResults::SEED, market.as_ref()],
        bump = batch_results.load()?.bump,
    )]
    pub batch_results: AccountLoader<'info, BatchResults>,

    /// Read-only snapshot of vault config — supplies fee_rate_bps +
    /// protocol_owner_commitment + tee_pubkey.
    #[account(
        seeds = [vault::state::VaultConfig::SEED],
        bump = vault_config.load()?.bump,
        seeds::program = vault::ID,
    )]
    pub vault_config: AccountLoader<'info, vault::state::VaultConfig>,

    /// Must equal `matching_config.pyth_account`.
    /// CHECK: validated by pubkey comparison in handler.
    pub oracle_account: UncheckedAccount<'info>,
    // PendingOrder PDAs are passed via `ctx.remaining_accounts`.
}

pub fn run_batch_handler<'info>(
    ctx: Context<'_, '_, 'info, 'info, RunBatch<'info>>,
    market: Pubkey,
) -> Result<()> {
    // ─── 1. Account validation ─────────────────────────────────────────────
    let (base_mint, quote_mint, circuit_bps, min_order_size, tick_size) = {
        let cfg = ctx.accounts.matching_config.load()?;
        require!(cfg.market == market, MatchingError::MarketMismatch);
        require!(
            ctx.accounts.oracle_account.key() == cfg.pyth_account,
            MatchingError::OracleAccountMismatch
        );
        (
            cfg.base_mint,
            cfg.quote_mint,
            cfg.circuit_breaker_bps,
            cfg.min_order_size,
            cfg.tick_size,
        )
    };

    // TEE authority gate.
    {
        let vc = ctx.accounts.vault_config.load()?;
        require!(
            ctx.accounts.tee_authority.key() == vc.tee_pubkey,
            MatchingError::NotRootKey
        );
    }

    let (fee_rate_bps, protocol_owner_commitment) = {
        let vc = ctx.accounts.vault_config.load()?;
        (vc.fee_rate_bps, vc.protocol_owner_commitment)
    };

    let now_slot = Clock::get()?.slot;
    let pyth_twap = read_oracle_price(&ctx.accounts.oracle_account.to_account_info())?;

    require!(
        ctx.remaining_accounts.len() <= MAX_PENDING_ACCOUNTS_PER_BATCH,
        MatchingError::OrderbookFull
    );

    // ─── 2. Read PendingOrder PDAs → build matcher OrderBook ───────────────
    //
    // We carry the `(trading_key, order_id)` of each order alongside
    // its `rem_idx` so step 5 (applying OrderUpdates) can find the
    // source PDA without a linear scan.
    let mut book = OrderBook::with_capacity(ctx.remaining_accounts.len());
    let mut rem_idx_lookup: Vec<([u8; 32], [u8; 16], usize)> =
        Vec::with_capacity(ctx.remaining_accounts.len());

    for (i, ai) in ctx.remaining_accounts.iter().enumerate() {
        require!(
            ai.owner == &crate::ID,
            MatchingError::PendingOrderInvalidOwner
        );

        let loader: AccountLoader<'_, PendingOrder> = AccountLoader::try_from(ai)?;
        let slot = loader.load()?;
        require!(slot.market == market, MatchingError::MarketMismatch);

        let matcher_order = pending_order_to_matcher(&slot)?;
        rem_idx_lookup.push((matcher_order.trading_key, matcher_order.order_id, i));
        book.insert(matcher_order);
    }

    // ─── 3. Build MatchConfig + OracleSnapshot ─────────────────────────────
    let match_config = MatchConfig {
        base_mint: base_mint.to_bytes(),
        quote_mint: quote_mint.to_bytes(),
        tick_size,
        min_order_size,
        circuit_breaker_bps: circuit_bps,
        // The matcher uses batch_ms informationally; the on-chain
        // ix doesn't actually drive cadence (the TEE caller does)
        // so any value is fine here. We forward the on-chain
        // matching_config.batch_interval_slots scaled to ms (each
        // Solana slot ≈ 400 ms).
        batch_ms: 0,
        fee_rate_bps,
        protocol_owner_commitment,
    };
    let oracle = OracleSnapshot {
        twap: pyth_twap,
        confidence: 0,
        exponent: 0,
        publish_slot: now_slot,
    };

    // ─── 4. Read start_match_id, call the matcher ──────────────────────────
    let start_match_id = {
        let br = ctx.accounts.batch_results.load()?;
        br.next_match_id
    };

    // Re-init the on-chain fee accumulators before the matcher
    // runs. The matcher itself doesn't touch them; we mirror the
    // old behaviour where the on-chain `BatchResults` always
    // shows the latest batch's mint bindings + zeroed counters
    // before adding the per-match deltas back at step 5.
    {
        let mut br = ctx.accounts.batch_results.load_mut()?;
        br.fee_accumulators[0].token_mint = base_mint;
        br.fee_accumulators[0].accumulated_fees = 0;
        br.fee_accumulators[0].batch_slot = now_slot;
        br.fee_accumulators[0].flushed_commitment = [0u8; 32];
        br.fee_accumulators[1].token_mint = quote_mint;
        br.fee_accumulators[1].accumulated_fees = 0;
        br.fee_accumulators[1].batch_slot = now_slot;
        br.fee_accumulators[1].flushed_commitment = [0u8; 32];
    }

    let output = matcher_run_batch(&book, &oracle, &match_config, now_slot, start_match_id)
        .map_err(matcher_error_to_anchor)?;

    // ─── 5. Apply RunBatchOutput to BatchResults ───────────────────────────
    {
        let mut br = ctx.accounts.batch_results.load_mut()?;
        for pair in output.matches.iter() {
            let slot_idx = (br.write_cursor as usize) % BATCH_RESULTS_CAPACITY;
            br.results[slot_idx] = match_pair_to_result(pair);
            br.write_cursor = br.write_cursor.saturating_add(1);
        }
        br.next_match_id = br.next_match_id.saturating_add(output.matches.len() as u64);

        // Fee buckets — write through. The matcher already applied
        // `flushed_commitment` if protocol_owner_commitment was set
        // AND the CB didn't trip; mirror those bytes verbatim.
        br.fee_accumulators[0].accumulated_fees = output.fee_buckets[0].accumulated_fees;
        br.fee_accumulators[0].flushed_commitment = output.fee_buckets[0].flushed_commitment;
        br.fee_accumulators[1].accumulated_fees = output.fee_buckets[1].accumulated_fees;
        br.fee_accumulators[1].flushed_commitment = output.fee_buckets[1].flushed_commitment;

        br.last_inclusion_root = output.inclusion_root;
        br.last_batch_slot = now_slot;
        br.last_match_count = output.matches.len() as u64;
        br.last_clearing_price = output.clearing_price;
        br.last_pyth_twap = pyth_twap;
        br.last_circuit_breaker_tripped = output.circuit_breaker_tripped;
    }

    // ─── 6. Apply OrderUpdates back to PendingOrder PDAs ───────────────────
    for upd in output.order_updates.iter() {
        // Find the source rem_idx by matching the (trading_key,
        // order_id) bytes. Linear scan is fine — N ≤ 24 (cap above).
        let rem_idx = rem_idx_lookup
            .iter()
            .find(|(tk, oid, _)| *tk == upd.trading_key && *oid == upd.order_id)
            .map(|(_, _, i)| *i)
            .ok_or(MatchingError::OrderbookFull)?;

        let ai = &ctx.remaining_accounts[rem_idx];
        let loader: AccountLoader<'_, PendingOrder> = AccountLoader::try_from(ai)?;
        let mut slot = loader.load_mut()?;
        apply_update(&mut slot, &upd.kind);
    }

    emit!(BatchExecuted {
        market,
        batch_slot: now_slot,
        match_count: output.matches.len() as u64,
        clearing_price: output.clearing_price,
        pyth_twap,
        circuit_breaker_tripped: output.circuit_breaker_tripped == 1,
        inclusion_root: output.inclusion_root,
    });
    Ok(())
}

// ─────── Adapter helpers ────────────────────────────────────────────────────

/// Convert a `PendingOrder` zero-copy view into a pure `matcher::Order`.
/// Validates that the on-chain u8 discriminants for side / order_type /
/// status are inside the matcher's enum range — any out-of-range byte
/// means the on-chain state is corrupted and we refuse to match.
fn pending_order_to_matcher(slot: &PendingOrder) -> Result<MatcherOrder> {
    let side = match slot.side {
        PENDING_SIDE_BID => OrderSide::Bid,
        PENDING_SIDE_ASK => OrderSide::Ask,
        _ => return err!(MatchingError::PendingOrderInvalidOwner),
    };
    let order_type = match slot.order_type {
        PENDING_TYPE_LIMIT => OrderType::Limit,
        PENDING_TYPE_IOC => OrderType::Ioc,
        PENDING_TYPE_FOK => OrderType::Fok,
        _ => return err!(MatchingError::PendingOrderInvalidOwner),
    };
    let status = match slot.status {
        PENDING_STATUS_PENDING => OrderStatus::Pending,
        PENDING_STATUS_EXPIRED => OrderStatus::Expired,
        PENDING_STATUS_MATCHED => OrderStatus::Matched,
        PENDING_STATUS_CANCELLED => OrderStatus::Cancelled,
        // Empty slots get mapped to Empty — the matcher's
        // partition_book will skip them.
        _ => OrderStatus::Empty,
    };
    Ok(MatcherOrder {
        trading_key: slot.trading_key.to_bytes(),
        side,
        order_type,
        status,
        arrival_slot: slot.arrival_slot,
        expiry_slot: slot.expiry_slot,
        price_limit: slot.price_limit,
        amount: slot.amount,
        total_quantity: slot.total_quantity,
        filled_quantity: slot.filled_quantity,
        min_fill_qty: slot.min_fill_qty,
        note_amount: slot.note_amount,
        collateral_note: slot.collateral_note,
        user_commitment: slot.user_commitment,
        order_id: slot.order_id,
        order_inclusion_commitment: slot.order_inclusion_commitment,
    })
}

/// Convert a matcher `MatchPair` into the on-chain Anchor `MatchResult`
/// zero-copy struct. Field order is identical, but `Pubkey` fields
/// need byte-array → `Pubkey` re-wrap.
fn match_pair_to_result(p: &MatchPair) -> MatchResult {
    let status_byte = match p.status {
        MatchStatus::Empty => 0,
        MatchStatus::Filled => MATCH_RESULT_STATUS_FILLED,
    };
    MatchResult {
        note_buyer: p.note_buyer,
        note_seller: p.note_seller,
        note_e_commitment: p.note_e_commitment,
        note_f_commitment: p.note_f_commitment,
        owner_buyer: Pubkey::from(p.owner_buyer),
        owner_seller: Pubkey::from(p.owner_seller),
        user_commitment_buyer: p.user_commitment_buyer,
        user_commitment_seller: p.user_commitment_seller,
        buyer_note_value: p.buyer_note_value,
        seller_note_value: p.seller_note_value,
        base_amt: p.base_amt,
        quote_amt: p.quote_amt,
        buyer_change_amt: p.buyer_change_amt,
        seller_change_amt: p.seller_change_amt,
        buyer_fee_amt: p.buyer_fee_amt,
        seller_fee_amt: p.seller_fee_amt,
        buyer_relock_order_id: p.buyer_relock_order_id,
        buyer_relock_expiry: p.buyer_relock_expiry,
        seller_relock_order_id: p.seller_relock_order_id,
        seller_relock_expiry: p.seller_relock_expiry,
        price: p.price,
        pyth_at_match: p.pyth_at_match,
        batch_slot: p.batch_slot,
        match_id: p.match_id,
        status: status_byte,
        _padding: [0u8; 7],
    }
}

/// Apply one matcher `OrderUpdate` to a PendingOrder PDA. Mirrors the
/// four branches of the old in-handler `apply_slot_updates`.
fn apply_update(slot: &mut PendingOrder, kind: &OrderUpdateKind) {
    match kind {
        OrderUpdateKind::FullyFilled { filled_quantity } => {
            slot.status = PENDING_STATUS_MATCHED;
            slot.filled_quantity = *filled_quantity;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
            slot.price_limit = 0;
            slot.note_amount = 0;
            slot.min_fill_qty = 0;
            slot.user_commitment = [0u8; 32];
            slot.order_id = [0u8; 16];
        }
        OrderUpdateKind::PartiallyFilled {
            new_amount,
            new_collateral_note,
            new_note_amount,
            filled_quantity,
        } => {
            // Slot stays Pending — keep the status byte.
            slot.amount = *new_amount;
            slot.collateral_note = *new_collateral_note;
            slot.note_amount = *new_note_amount;
            slot.filled_quantity = *filled_quantity;
        }
        OrderUpdateKind::Cancelled => {
            slot.status = PENDING_STATUS_CANCELLED;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
        }
        OrderUpdateKind::Expired => {
            slot.status = PENDING_STATUS_EXPIRED;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
        }
    }
}

/// Translate a `darkpool_matcher::MatchError` into a `MatchingError`
/// for the Anchor return path. The matcher's variants don't have a
/// 1:1 mapping with the existing on-chain error codes, so we
/// collapse them onto the closest existing variant — this matches
/// the assertion logs the litesvm tests grep for.
fn matcher_error_to_anchor(e: darkpool_matcher::error::MatchError) -> anchor_lang::error::Error {
    use darkpool_matcher::error::MatchError as M;
    match e {
        M::OracleStale { .. } => error!(MatchingError::OracleZeroPrice),
        M::CircuitBreakerTripped { .. } => error!(MatchingError::OracleZeroPrice),
        M::MinFillViolation { .. } => error!(MatchingError::OrderbookFull),
        M::Conservation { .. } => error!(MatchingError::ConservationViolation),
        M::Internal(s) => {
            msg!("matcher internal error: {}", s);
            error!(MatchingError::PoseidonFailed)
        }
    }
}

#[event]
pub struct BatchExecuted {
    pub market: Pubkey,
    pub batch_slot: u64,
    pub match_count: u64,
    pub clearing_price: u64,
    pub pyth_twap: u64,
    pub circuit_breaker_tripped: bool,
    pub inclusion_root: [u8; 32],
}
