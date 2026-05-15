//! Nyx dark pool — matching engine program.
//!
//! Privacy architecture (post privacy-fix):
//!
//!   L1 setup (per user, per market, one-time):
//!     - `init_pending_order_slot(market, slot_idx)` → empty PendingOrder PDA.
//!     - `delegate_pending_order(market, slot_idx)` → hand it to the ER.
//!
//!   L1 setup (per market, one-time):
//!     - `init_market` + `init_mock_oracle` (or real Pyth feed).
//!     - `delegate_matching_config` + `delegate_batch_results`.
//!
//!   ER session (authenticated PER RPC, JWT-gated):
//!     - `submit_order(args)` writes order intent into the user's
//!       delegated PendingOrder slot. Never on L1.
//!     - `cancel_order(market, slot_idx)` resets a slot to Cancelled.
//!     - `run_batch(market)` matches all PendingOrder PDAs supplied as
//!       remaining_accounts, writes MatchResults to BatchResults,
//!       rotates partially-filled slots' collateral.
//!     - `commit_market_state` / `undelegate_market` push BatchResults
//!       (and optionally MatchingConfig) back to L1.
//!
//!   L1 settlement (TEE-driven, post-commit):
//!     - `[ComputeBudget, Ed25519, vault::lock_note(buyer),
//!        vault::lock_note(seller), vault::tee_forced_settle]` —
//!       atomic. The order intents that produced this match never
//!       appear on L1 outside of the aggregate `BatchResults` snapshot.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::ephemeral;

pub mod errors;
pub mod instructions;
pub mod state;

pub use instructions::cancel_order;
pub use instructions::commit_market_state;
pub use instructions::configure_access;
pub use instructions::delegate_batch_results;
pub use instructions::delegate_dark_clob;
pub use instructions::delegate_matching_config;
pub use instructions::delegate_pending_order;
pub use instructions::init_market;
pub use instructions::init_mock_oracle;
pub use instructions::init_pending_order_slot;
pub use instructions::run_batch;
pub use instructions::submit_order;
pub use instructions::undelegate_market;

use instructions::*;

declare_id!("6EasFxo6RCWrK4KAwcdUJqL4KjReLC3rtah8EtHgHSqe");

#[ephemeral]
#[program]
pub mod matching_engine {
    use super::*;

    pub fn init_market(
        ctx: Context<InitMarket>,
        args: init_market::InitMarketArgs,
    ) -> Result<()> {
        init_market::init_market_handler(ctx, args)
    }

    pub fn configure_access(
        ctx: Context<ConfigureAccess>,
        market: Pubkey,
        members: Vec<configure_access::MemberArg>,
        is_update: bool,
    ) -> Result<()> {
        configure_access::configure_access_handler(ctx, market, members, is_update)
    }

    pub fn init_pending_order_slot(
        ctx: Context<InitPendingOrderSlot>,
        market: Pubkey,
        slot_idx: u8,
    ) -> Result<()> {
        init_pending_order_slot::init_pending_order_slot_handler(ctx, market, slot_idx)
    }

    pub fn delegate_pending_order(
        ctx: Context<DelegatePendingOrder>,
        market: Pubkey,
        slot_idx: u8,
    ) -> Result<()> {
        delegate_pending_order::delegate_pending_order_handler(ctx, market, slot_idx)
    }

    pub fn delegate_dark_clob(ctx: Context<DelegateDarkClob>, market: Pubkey) -> Result<()> {
        delegate_dark_clob::delegate_dark_clob_handler(ctx, market)
    }

    pub fn submit_order(
        ctx: Context<SubmitOrder>,
        args: submit_order::SubmitOrderArgs,
    ) -> Result<()> {
        submit_order::submit_order_handler(ctx, args)
    }

    pub fn cancel_order(
        ctx: Context<CancelOrder>,
        market: Pubkey,
        slot_idx: u8,
    ) -> Result<()> {
        cancel_order::cancel_order_handler(ctx, market, slot_idx)
    }

    pub fn run_batch<'info>(
        ctx: Context<'_, '_, 'info, 'info, RunBatch<'info>>,
        market: Pubkey,
    ) -> Result<()> {
        run_batch::run_batch_handler(ctx, market)
    }

    pub fn init_mock_oracle(ctx: Context<InitMockOracle>, twap: u64) -> Result<()> {
        init_mock_oracle::init_mock_oracle_handler(ctx, twap)
    }

    pub fn delegate_matching_config(
        ctx: Context<DelegateMatchingConfig>,
        market: Pubkey,
    ) -> Result<()> {
        delegate_matching_config::delegate_matching_config_handler(ctx, market)
    }

    pub fn delegate_batch_results(
        ctx: Context<DelegateBatchResults>,
        market: Pubkey,
    ) -> Result<()> {
        delegate_batch_results::delegate_batch_results_handler(ctx, market)
    }

    pub fn commit_market_state(ctx: Context<CommitMarketState>) -> Result<()> {
        commit_market_state::commit_market_state_handler(ctx)
    }

    pub fn undelegate_market(ctx: Context<UndelegateMarket>) -> Result<()> {
        undelegate_market::undelegate_market_handler(ctx)
    }
}
