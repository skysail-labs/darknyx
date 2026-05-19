//! `delegate_batch_results` — hand the BatchResults PDA to the MagicBlock ER
//! validator. Required because `run_batch` mutates BatchResults (writing the
//! MatchResult ring + FeeAccumulators) and the validator must own it
//! writably inside the ER session.
//!
//! When the ER session commits state back to L1 (see `commit_market_state`
//! and `undelegate_market`), settlement can read the freshly-published
//! MatchResult by the usual L1 RPC path.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::delegate;
use ephemeral_rollups_sdk::cpi::DelegateConfig;

#[delegate]
#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct DelegateBatchResults<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Delegated to the ER validator via the #[delegate] macro.
    #[account(mut, del)]
    pub pda: AccountInfo<'info>,
}

pub fn delegate_batch_results_handler(
    ctx: Context<DelegateBatchResults>,
    market: Pubkey,
) -> Result<()> {
    let seed_refs: &[&[u8]] = &[crate::state::BatchResults::SEED, market.as_ref()];
    ctx.accounts
        .delegate_pda(&ctx.accounts.payer, seed_refs, DelegateConfig::default())?;
    Ok(())
}
