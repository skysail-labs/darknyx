//! `delegate_dark_clob` — hand the DarkCLOB PDA to the MagicBlock ER validator.
//!
//! Once delegated, the DarkCLOB lives in the PER and all further writes to it
//! (notably `submit_order`) execute inside the TEE. The delegation is not
//! per-order — the DarkCLOB stays delegated across batches for the lifetime
//! of the market.

use anchor_lang::prelude::*;
use ephemeral_rollups_sdk::anchor::delegate;
use ephemeral_rollups_sdk::cpi::DelegateConfig;

#[delegate]
#[derive(Accounts)]
#[instruction(market: Pubkey)]
pub struct DelegateDarkClob<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Delegated to the ER validator via the #[delegate] macro.
    #[account(mut, del)]
    pub pda: AccountInfo<'info>,
}

pub fn delegate_dark_clob_handler(ctx: Context<DelegateDarkClob>, market: Pubkey) -> Result<()> {
    let seed_refs: &[&[u8]] = &[crate::state::DarkCLOB::SEED, market.as_ref()];
    // MagicBlock default-picks a validator. For production we'll want the
    // admin to pass a preferred validator; plumb it through the args when
    // the governance story lands.
    ctx.accounts
        .delegate_pda(&ctx.accounts.payer, seed_refs, DelegateConfig::default())?;
    Ok(())
}
