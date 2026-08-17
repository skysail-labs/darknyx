//! Rotate the protocol root key.
//!
//! Root-key rotation uses a self-signature model: only the current root key
//! can sign to install a new one. Admin cannot override — the root key is an
//! independent governance authority by design.

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;

#[derive(Accounts)]
#[instruction(new_root_key: Address)]
pub struct RotateRootKey {
    /// Must equal `vault_config.root_key`. Verified in the handler.
    pub current_root_key: Signer,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,
}

pub fn rotate_root_key_handler(ctx: &mut Context<RotateRootKey>, new_root_key: Address) -> Result<()> {
    let mut cfg = ctx.accounts.vault_config;
    require!(
        ctx.accounts.current_root_key.address() == cfg.root_key,
        VaultError::Unauthorized
    );
    require!(
        new_root_key != Address::default()
            && new_root_key != cfg.root_key
            && new_root_key != cfg.admin
            && !cfg.is_authorized_tee(&new_root_key),
        VaultError::InvalidRootKey
    );
    cfg.root_key = new_root_key;

    emit!(RootKeyRotated {
        old_root_key: ctx.accounts.current_root_key.address(),
        new_root_key,
    });
    Ok(())
}

#[event]
pub struct RootKeyRotated {
    pub old_root_key: Address,
    pub new_root_key: Address,
}
