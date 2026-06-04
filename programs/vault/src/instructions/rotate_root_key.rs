//! Rotate the protocol root key.
//!
//! Root-key rotation uses a self-signature model: only the current root key
//! can sign to install a new one. Admin cannot override — the root key is an
//! independent governance authority by design.

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(new_root_key: Pubkey)]
pub struct RotateRootKey<'info> {
    /// Must equal `vault_config.root_key`. Verified in the handler.
    pub current_root_key: Signer<'info>,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,
}

pub fn rotate_root_key_handler(ctx: Context<RotateRootKey>, new_root_key: Pubkey) -> Result<()> {
    let mut cfg = ctx.accounts.vault_config.load_mut()?;
    require!(
        ctx.accounts.current_root_key.key() == cfg.root_key,
        VaultError::Unauthorized
    );
    require!(new_root_key != Pubkey::default(), VaultError::Unauthorized);
    cfg.root_key = new_root_key;

    emit!(RootKeyRotated {
        old_root_key: ctx.accounts.current_root_key.key(),
        new_root_key,
    });
    Ok(())
}

#[event]
pub struct RootKeyRotated {
    pub old_root_key: Pubkey,
    pub new_root_key: Pubkey,
}
