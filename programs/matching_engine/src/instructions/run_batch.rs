//! `run_batch` — periodic batch auction inside the ER (spec §20.6 + §23.4).
//!
//! New shape (post-privacy-fix): the order book has no on-chain
//! aggregate store. Each pending order lives in its own delegated
//! `PendingOrder` PDA. `run_batch` receives ALL `PendingOrder` PDAs
//! that should participate in this auction via `remaining_accounts`,
//! reads them inside the ER (so the order intents stay inside the
//! TEE), runs the same uniform-clearing-price algorithm, and writes
//! match results to `BatchResults` (the only account that ever
//! commits back to L1).
//!
//! Slots that match (fully or partially) are mutated in place:
//!   - Full fill → status = Matched, fields cleared, slot reusable.
//!   - Partial fill → status stays Pending, `amount` decremented,
//!     `collateral_note` rotated to the change-note commitment so
//!     the next batch operates on the change note.
//!   - Expired → status = Expired, fields cleared.
//!   - IOC unmatched → status = Cancelled.
//!
//! Privacy property: PendingOrder PDAs stay delegated to the ER
//! between batches. They are NEVER committed back to L1, so even
//! after `run_batch` finishes, a stranger reading L1 sees only the
//! aggregate `BatchResults` (clearing price + match results +
//! inclusion root). Individual unmatched orders leave zero L1 trace.

use anchor_lang::prelude::*;
use core::cell::Ref;

use crate::errors::MatchingError;
use crate::state::batch_results::BATCH_RESULTS_CAPACITY;
use crate::state::pyth::read_oracle_price;
use crate::state::{
    change_note, BatchResults, MatchResult, MatchingConfig, PendingOrder,
    MATCH_RESULT_STATUS_FILLED, PENDING_SIDE_ASK, PENDING_SIDE_BID, PENDING_STATUS_CANCELLED,
    PENDING_STATUS_EXPIRED, PENDING_STATUS_MATCHED, PENDING_STATUS_PENDING, PENDING_TYPE_FOK,
    PENDING_TYPE_IOC, RELOCK_ORDER_ID_NONE,
};
use darkpool_crypto::note::commitment_from_fields;

/// Orders whose `expiry_slot` is within this many slots of `now_slot` are
/// drained before the matching pass, not included in any match. This
/// guarantees that the follow-up `tee_forced_settle` transaction has
/// enough runway to land on L1 before the implicit settle deadline.
pub const SETTLEMENT_BUFFER_SLOTS: u64 = 20;

/// Hard cap on the number of PendingOrder PDAs accepted via
/// `remaining_accounts`. Keeps the matching loop within compute budget
/// and the call within Solana's per-tx account limits. A v2 with paged
/// matching across multiple `run_batch` calls can lift this.
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

/// Local in-memory copy of a PendingOrder slot used during matching.
/// Holds the index back into `remaining_accounts` so we can write
/// updates to the source PDA after match decisions are made.
#[derive(Clone, Copy, Debug)]
struct OrderSnapshot {
    rem_idx: usize,
    side: u8,
    order_type: u8,
    arrival_slot: u64,
    expiry_slot: u64,
    price_limit: u64,
    amount: u64,
    min_fill_qty: u64,
    note_amount: u64,
    collateral_note: [u8; 32],
    user_commitment: [u8; 32],
    trading_key: Pubkey,
    order_id: [u8; 16],
    inclusion: [u8; 32],
}

fn deviates_by_more_than_bps(p: u64, reference: u64, bps: u64) -> bool {
    if reference == 0 {
        return true;
    }
    let diff = p.abs_diff(reference);
    (diff as u128).saturating_mul(10_000) > (reference as u128).saturating_mul(bps as u128)
}

fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    use solana_program::hash::hashv;
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut target = 1usize;
    while target < level.len() {
        target *= 2;
    }
    while level.len() < target {
        level.push(*level.last().unwrap());
    }
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hashv(&[&pair[0], &pair[1]]).to_bytes());
        }
        level = next;
    }
    level[0]
}

/// Compute uniform clearing price + matched volume across the live
/// snapshot vectors. Same algorithm as the legacy DarkCLOB-driven
/// version: candidate prices = union of distinct `price_limit`s, pick
/// the price maximising `min(demand, supply)`. Ties broken by lowest
/// price (deterministic).
fn compute_clearing_price(bids: &[OrderSnapshot], asks: &[OrderSnapshot]) -> Option<(u64, u64)> {
    if bids.is_empty() || asks.is_empty() {
        return None;
    }
    let mut candidates: Vec<u64> = Vec::with_capacity(bids.len() + asks.len());
    for b in bids.iter() {
        candidates.push(b.price_limit);
    }
    for a in asks.iter() {
        candidates.push(a.price_limit);
    }
    candidates.sort();
    candidates.dedup();

    let mut best_p: Option<u64> = None;
    let mut best_matched: u64 = 0;
    for &p in candidates.iter() {
        let demand: u64 = bids
            .iter()
            .filter(|b| b.price_limit >= p)
            .fold(0u64, |a, b| a.saturating_add(b.amount));
        let supply: u64 = asks
            .iter()
            .filter(|a_| a_.price_limit <= p)
            .fold(0u64, |a, b| a.saturating_add(b.amount));
        let matched = demand.min(supply);
        if matched > best_matched {
            best_matched = matched;
            best_p = Some(p);
        }
    }
    best_p.map(|p| (p, best_matched))
}

pub fn run_batch_handler<'info>(
    ctx: Context<'_, '_, 'info, 'info, RunBatch<'info>>,
    market: Pubkey,
) -> Result<()> {
    // --- Market + oracle sanity ---
    let (base_mint, quote_mint, circuit_bps, min_order_size) = {
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

    // --- Phase-5 fee inputs ---
    let (fee_rate_bps, protocol_owner_commitment) = {
        let vc = ctx.accounts.vault_config.load()?;
        (vc.fee_rate_bps as u64, vc.protocol_owner_commitment)
    };

    let now_slot = Clock::get()?.slot;
    let pyth_twap = read_oracle_price(&ctx.accounts.oracle_account.to_account_info())?;
    require!(pyth_twap > 0, MatchingError::OracleZeroPrice);

    // --- Load PendingOrder snapshots from remaining_accounts ---
    require!(
        ctx.remaining_accounts.len() <= MAX_PENDING_ACCOUNTS_PER_BATCH,
        MatchingError::OrderbookFull
    );

    let mut bids: Vec<OrderSnapshot> = Vec::new();
    let mut asks: Vec<OrderSnapshot> = Vec::new();
    let mut inclusion_leaves: Vec<[u8; 32]> = Vec::new();

    // Pass 1: read each PendingOrder; mark expired in-place; collect Pending.
    for (i, ai) in ctx.remaining_accounts.iter().enumerate() {
        // Slot must be owned by us.
        require!(
            ai.owner == &crate::ID,
            MatchingError::PendingOrderInvalidOwner
        );

        let loader: AccountLoader<PendingOrder> = AccountLoader::try_from(ai)?;
        // Validate the slot's market binding.
        {
            let slot = loader.load()?;
            require!(slot.market == market, MatchingError::MarketMismatch);
        }

        // Snapshot under read borrow first; mutate (mark Expired etc.) under
        // a separate write borrow so we don't hold both at once.
        let snap = {
            let slot = loader.load()?;
            if slot.status != PENDING_STATUS_PENDING {
                None
            } else if slot.expiry_slot <= now_slot.saturating_add(SETTLEMENT_BUFFER_SLOTS) {
                Some((true, snapshot_from_slot(&slot, i)))
            } else if slot.amount < min_order_size && min_order_size > 0 {
                // Below min_order_size — skip (don't expire; client may
                // resubmit or admin may lower the floor).
                None
            } else {
                Some((false, snapshot_from_slot(&slot, i)))
            }
        };

        match snap {
            None => {}
            Some((expired, s)) => {
                if expired {
                    let mut slot = loader.load_mut()?;
                    slot.status = PENDING_STATUS_EXPIRED;
                    slot.amount = 0;
                    slot.collateral_note = [0u8; 32];
                } else {
                    inclusion_leaves.push(s.inclusion);
                    match s.side {
                        PENDING_SIDE_BID => bids.push(s),
                        PENDING_SIDE_ASK => asks.push(s),
                        _ => {}
                    }
                }
            }
        }
    }

    // Sort by (price, arrival_slot). Bids: descending price; asks: ascending.
    bids.sort_by(|a, b| {
        b.price_limit
            .cmp(&a.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });
    asks.sort_by(|a, b| {
        a.price_limit
            .cmp(&b.price_limit)
            .then(a.arrival_slot.cmp(&b.arrival_slot))
    });

    // --- Reset per-batch FeeAccumulators ---
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

    // --- Compute clearing price ---
    let mut cb_tripped: u8 = 0;
    let mut match_count: u64 = 0;
    let clearing_price: u64;

    if let Some((p_star, _matched)) = compute_clearing_price(&bids, &asks) {
        if deviates_by_more_than_bps(p_star, pyth_twap, circuit_bps) {
            cb_tripped = 1;
            clearing_price = 0;
        } else {
            clearing_price = p_star;
            match_count = generate_matches(
                &ctx,
                p_star,
                pyth_twap,
                now_slot,
                &mut bids,
                &mut asks,
                &base_mint,
                &quote_mint,
                fee_rate_bps,
            )? as u64;
        }
    } else {
        clearing_price = 0;
    }

    // --- Compute inclusion root ---
    let inclusion_root = merkle_root_sha256(&inclusion_leaves);

    // --- Persist updated PendingOrder slots: full-fill clears slot;
    //     partial-fill rotates collateral; IOC residual cancels. ---
    apply_slot_updates(&ctx, &bids, &asks, now_slot)?;

    // --- Flush fee notes (only when CB did not trip and a protocol
    //     owner_commitment is configured). ---
    if protocol_owner_commitment != [0u8; 32] && cb_tripped == 0 {
        const FEE_ROLE_BASE: u8 = 0xFB;
        const FEE_ROLE_QUOTE: u8 = 0xFC;
        let mut br = ctx.accounts.batch_results.load_mut()?;
        let base_fees = br.fee_accumulators[0].accumulated_fees;
        if base_fees > 0 {
            let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_BASE);
            let r = change_note::derive_blinding(now_slot, FEE_ROLE_BASE);
            let c = commitment_from_fields(
                &base_mint.to_bytes(),
                base_fees,
                &protocol_owner_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?;
            br.fee_accumulators[0].flushed_commitment = c;
        }
        let quote_fees = br.fee_accumulators[1].accumulated_fees;
        if quote_fees > 0 {
            let nonce = change_note::derive_nonce(now_slot, FEE_ROLE_QUOTE);
            let r = change_note::derive_blinding(now_slot, FEE_ROLE_QUOTE);
            let c = commitment_from_fields(
                &quote_mint.to_bytes(),
                quote_fees,
                &protocol_owner_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?;
            br.fee_accumulators[1].flushed_commitment = c;
        }
    }

    // --- Publish batch summary ---
    {
        let mut br = ctx.accounts.batch_results.load_mut()?;
        br.last_inclusion_root = inclusion_root;
        br.last_batch_slot = now_slot;
        br.last_match_count = match_count;
        br.last_clearing_price = clearing_price;
        br.last_pyth_twap = pyth_twap;
        br.last_circuit_breaker_tripped = cb_tripped;
    }

    emit!(BatchExecuted {
        market,
        batch_slot: now_slot,
        match_count,
        clearing_price,
        pyth_twap,
        circuit_breaker_tripped: cb_tripped == 1,
        inclusion_root,
    });
    Ok(())
}

fn snapshot_from_slot(slot: &Ref<PendingOrder>, rem_idx: usize) -> OrderSnapshot {
    OrderSnapshot {
        rem_idx,
        side: slot.side,
        order_type: slot.order_type,
        arrival_slot: slot.arrival_slot,
        expiry_slot: slot.expiry_slot,
        price_limit: slot.price_limit,
        amount: slot.amount,
        min_fill_qty: slot.min_fill_qty,
        note_amount: slot.note_amount,
        collateral_note: slot.collateral_note,
        user_commitment: slot.user_commitment,
        trading_key: slot.trading_key,
        order_id: slot.order_id,
        inclusion: slot.order_inclusion_commitment,
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_matches<'info>(
    ctx: &Context<'_, '_, 'info, 'info, RunBatch<'info>>,
    p_star: u64,
    pyth_twap: u64,
    now_slot: u64,
    bids: &mut [OrderSnapshot],
    asks: &mut [OrderSnapshot],
    base_mint: &Pubkey,
    quote_mint: &Pubkey,
    fee_rate_bps: u64,
) -> Result<usize> {
    let mut produced: usize = 0;
    let mut bi = 0usize;
    let mut ai = 0usize;

    while bi < bids.len() && ai < asks.len() {
        // Price-limit crossing must hold at P*.
        if bids[bi].price_limit < p_star || asks[ai].price_limit > p_star {
            if bids[bi].price_limit < p_star {
                bi += 1;
            }
            if ai < asks.len() && asks[ai].price_limit > p_star {
                ai += 1;
            }
            continue;
        }

        let crossable = bids[bi].amount.min(asks[ai].amount);

        // FOK enforcement.
        if bids[bi].order_type == PENDING_TYPE_FOK && crossable < bids[bi].amount {
            bids[bi].amount = 0; // mark as cancelled — handled by apply_slot_updates
            bids[bi].order_type = u8::MAX; // sentinel: cancel-not-fill
            bi += 1;
            continue;
        }
        if asks[ai].order_type == PENDING_TYPE_FOK && crossable < asks[ai].amount {
            asks[ai].amount = 0;
            asks[ai].order_type = u8::MAX;
            ai += 1;
            continue;
        }

        // min_fill_qty.
        if crossable < bids[bi].min_fill_qty || crossable < asks[ai].min_fill_qty {
            if bids[bi].amount <= asks[ai].amount {
                bi += 1;
            } else {
                ai += 1;
            }
            continue;
        }

        // Trade legs.
        let quote_amt_u128 = (crossable as u128)
            .checked_mul(p_star as u128)
            .ok_or(MatchingError::NotionalOverflow)?;
        require!(
            quote_amt_u128 <= u64::MAX as u128,
            MatchingError::NotionalOverflow
        );
        let quote_amt = quote_amt_u128 as u64;

        let buyer_fee_amt = ((quote_amt as u128) * fee_rate_bps as u128 / 10_000u128) as u64;
        let seller_fee_amt = ((crossable as u128) * fee_rate_bps as u128 / 10_000u128) as u64;

        let buyer_charge = quote_amt
            .checked_add(buyer_fee_amt)
            .ok_or(MatchingError::FeeOverflow)?;
        let seller_charge = crossable
            .checked_add(seller_fee_amt)
            .ok_or(MatchingError::FeeOverflow)?;
        let buyer_change_amt = bids[bi]
            .note_amount
            .checked_sub(buyer_charge)
            .ok_or(MatchingError::ConservationViolation)?;
        let seller_change_amt = asks[ai]
            .note_amount
            .checked_sub(seller_charge)
            .ok_or(MatchingError::ConservationViolation)?;

        let match_id = {
            let br = ctx.accounts.batch_results.load()?;
            br.next_match_id
        };

        let note_e_commitment = if buyer_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_BUYER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_BUYER);
            commitment_from_fields(
                &quote_mint.to_bytes(),
                buyer_change_amt,
                &bids[bi].user_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?
        } else {
            [0u8; 32]
        };
        let note_f_commitment = if seller_change_amt > 0 {
            let nonce = change_note::derive_nonce(match_id, change_note::CHANGE_ROLE_SELLER);
            let r = change_note::derive_blinding(match_id, change_note::CHANGE_ROLE_SELLER);
            commitment_from_fields(
                &base_mint.to_bytes(),
                seller_change_amt,
                &asks[ai].user_commitment,
                &nonce,
                &r,
            )
            .map_err(|_| error!(MatchingError::PoseidonFailed))?
        } else {
            [0u8; 32]
        };

        let b_remaining_after = bids[bi].amount.saturating_sub(crossable);
        let a_remaining_after = asks[ai].amount.saturating_sub(crossable);
        let buyer_relock =
            b_remaining_after > 0 && bids[bi].order_type == 0 && buyer_change_amt > 0;
        let seller_relock =
            a_remaining_after > 0 && asks[ai].order_type == 0 && seller_change_amt > 0;

        let (buyer_relock_order_id, buyer_relock_expiry) = if buyer_relock {
            (bids[bi].order_id, bids[bi].expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };
        let (seller_relock_order_id, seller_relock_expiry) = if seller_relock {
            (asks[ai].order_id, asks[ai].expiry_slot)
        } else {
            (RELOCK_ORDER_ID_NONE, 0)
        };

        // Snapshot copies for write phase.
        let b_note = bids[bi].collateral_note;
        let a_note = asks[ai].collateral_note;
        let b_tk = bids[bi].trading_key;
        let a_tk = asks[ai].trading_key;
        let b_uc = bids[bi].user_commitment;
        let a_uc = asks[ai].user_commitment;
        let b_nval = bids[bi].note_amount;
        let a_nval = asks[ai].note_amount;

        {
            let mut br = ctx.accounts.batch_results.load_mut()?;
            let slot_idx = (br.write_cursor as usize) % BATCH_RESULTS_CAPACITY;
            let mr = MatchResult {
                note_buyer: b_note,
                note_seller: a_note,
                note_e_commitment,
                note_f_commitment,
                owner_buyer: b_tk,
                owner_seller: a_tk,
                user_commitment_buyer: b_uc,
                user_commitment_seller: a_uc,
                buyer_note_value: b_nval,
                seller_note_value: a_nval,
                base_amt: crossable,
                quote_amt,
                buyer_change_amt,
                seller_change_amt,
                buyer_fee_amt,
                seller_fee_amt,
                buyer_relock_order_id,
                buyer_relock_expiry,
                seller_relock_order_id,
                seller_relock_expiry,
                price: p_star,
                pyth_at_match: pyth_twap,
                batch_slot: now_slot,
                match_id,
                status: MATCH_RESULT_STATUS_FILLED,
                _padding: [0u8; 7],
            };
            br.results[slot_idx] = mr;
            br.write_cursor = br.write_cursor.saturating_add(1);
            br.next_match_id = br.next_match_id.saturating_add(1);

            br.fee_accumulators[0].accumulated_fees = br.fee_accumulators[0]
                .accumulated_fees
                .saturating_add(seller_fee_amt);
            br.fee_accumulators[1].accumulated_fees = br.fee_accumulators[1]
                .accumulated_fees
                .saturating_add(buyer_fee_amt);
        }

        // Update local snapshots — write to PDAs in apply_slot_updates.
        bids[bi].amount = b_remaining_after;
        if buyer_relock {
            bids[bi].collateral_note = note_e_commitment;
            bids[bi].note_amount = buyer_change_amt;
        }
        asks[ai].amount = a_remaining_after;
        if seller_relock {
            asks[ai].collateral_note = note_f_commitment;
            asks[ai].note_amount = seller_change_amt;
        }

        produced += 1;

        // Advance whichever side filled entirely.
        if b_remaining_after == 0 {
            bi += 1;
        }
        if a_remaining_after == 0 {
            ai += 1;
        }
    }

    Ok(produced)
}

/// Walk the (post-match) snapshot vectors and write the resulting state
/// back into the PendingOrder PDAs. Slots not visited here keep their
/// pre-batch state (Pending with full amount).
fn apply_slot_updates<'info>(
    ctx: &Context<'_, '_, 'info, 'info, RunBatch<'info>>,
    bids: &[OrderSnapshot],
    asks: &[OrderSnapshot],
    _now_slot: u64,
) -> Result<()> {
    for s in bids.iter().chain(asks.iter()) {
        let ai = &ctx.remaining_accounts[s.rem_idx];
        let loader: AccountLoader<PendingOrder> = AccountLoader::try_from(ai)?;
        let mut slot = loader.load_mut()?;

        if s.order_type == u8::MAX {
            // Sentinel: FOK / similar — wipe to Cancelled.
            slot.status = PENDING_STATUS_CANCELLED;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
            continue;
        }

        if s.amount == 0 && s.note_amount > 0 {
            // Partial-fill but residual fully consumed — actually a full fill.
            // Mark Matched and wipe.
            slot.status = PENDING_STATUS_MATCHED;
            slot.filled_quantity = slot.total_quantity;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
            slot.price_limit = 0;
            slot.note_amount = 0;
            slot.min_fill_qty = 0;
            slot.user_commitment = [0u8; 32];
            slot.order_id = [0u8; 16];
        } else if s.amount == 0 {
            // Full fill (possibly after multiple partials in same batch).
            slot.status = PENDING_STATUS_MATCHED;
            slot.filled_quantity = slot.total_quantity;
            slot.amount = 0;
            slot.collateral_note = [0u8; 32];
            slot.price_limit = 0;
            slot.note_amount = 0;
            slot.min_fill_qty = 0;
            slot.user_commitment = [0u8; 32];
            slot.order_id = [0u8; 16];
        } else if s.amount < slot.amount {
            // Partial fill — keep Pending, rotate collateral, decrement amount.
            slot.filled_quantity = slot
                .filled_quantity
                .saturating_add(slot.amount.saturating_sub(s.amount));
            slot.amount = s.amount;
            slot.collateral_note = s.collateral_note;
            slot.note_amount = s.note_amount;

            // IOC residual: cancel rather than re-rest.
            if s.order_type == PENDING_TYPE_IOC {
                slot.status = PENDING_STATUS_CANCELLED;
                slot.amount = 0;
                slot.collateral_note = [0u8; 32];
            }
        }
        // else: untouched — slot.amount unchanged.
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviation_check_within_bounds_is_false() {
        assert!(!deviates_by_more_than_bps(1005, 1000, 50));
    }

    #[test]
    fn deviation_check_outside_bounds_is_true() {
        assert!(deviates_by_more_than_bps(1100, 1000, 50));
    }

    #[test]
    fn deviation_check_exact_300bps_boundary() {
        assert!(!deviates_by_more_than_bps(1030, 1000, 300));
        assert!(deviates_by_more_than_bps(1031, 1000, 300));
    }

    #[test]
    fn merkle_root_empty_is_zero() {
        assert_eq!(merkle_root_sha256(&[]), [0u8; 32]);
    }

    #[test]
    fn merkle_root_single_leaf_is_itself() {
        let leaf = [42u8; 32];
        assert_eq!(merkle_root_sha256(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_three_leaves_pads_last() {
        use solana_program::hash::hashv;
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        let h01 = hashv(&[&l0, &l1]).to_bytes();
        let h23 = hashv(&[&l2, &l2]).to_bytes();
        let expected = hashv(&[&h01, &h23]).to_bytes();
        assert_eq!(merkle_root_sha256(&[l0, l1, l2]), expected);
    }
}
