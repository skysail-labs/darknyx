//! `delegate_matching_config` — hand the MatchingConfig PDA to the MagicBlock
//! ER validator so `run_batch` can read+cache it alongside the delegated
//! DarkCLOB/BatchResults.
//!
//! MatchingConfig is immutable after `init_market`, so it's technically OK to
//! serve it via an ER read-only clone. We delegate it anyway — the MagicBlock
//! scheduler keeps delegated accounts hot in the ER session without fallback
//! RPC round-trips, and the `#[ephemeral]` macro's account-loader expects
//! every ix-passed account to be present in the session (writable or not).

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::delegate;
use ephemeral_rollups_sdk::cpi::DelegateConfig;

#[delegate]
#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct DelegateMatchingConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Delegated to the ER validator via the #[delegate] macro.
    #[account(mut, del)]
    pub pda: AccountInfo<'info>,
}

pub fn delegate_matching_config_handler(
    ctx: Context<DelegateMatchingConfig>,
    market: Pubkey,
) -> Result<()> {
    let seed_refs: &[&[u8]] = &[crate::state::MatchingConfig::SEED, market.as_ref()];
    ctx.accounts
        .delegate_pda(&ctx.accounts.payer, seed_refs, DelegateConfig::default())?;
    Ok(())
}
