//! DEVNET-ONLY: close the `VaultConfig` PDA so it can be re-`initialize`d
//! under a NEW layout. Admin-gated.
//!
//! The `VaultConfig` zero-copy layout changes across versions (e.g. the
//! tree-sharding split moved the Merkle state out + replaced `tee_pubkey`
//! with `tee_pubkeys[16]`). A program upgrade does NOT touch the existing
//! PDA's bytes, so after a layout change the on-chain account is the wrong
//! size + has fields at stale offsets — every ix that does
//! `bump = vault_config.bump` then fails `ConstraintSeeds`, and
//! `initialize` (which uses `init`) can't recreate it because the PDA still
//! exists. This ix drains + zeroes the account so the runtime reclaims it,
//! letting `initialize` rebuild it fresh under the current layout.
//!
//! Deliberately layout-AGNOSTIC: it does NOT deserialize `VaultConfig` (the
//! bytes may be an old layout). It reads only the program ownership + the
//! `admin` pubkey, which sits at byte offset 8 (right after the 8-byte Anchor
//! discriminator) in EVERY version of the struct.
//!
//! Production note: a real mainnet layout change needs a proper migration
//! (preserving state), not a wipe. This is the devnet/staging reset path,
//! alongside `reset_merkle_tree`.

use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;

use crate::errors::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct CloseVaultConfig {
    #[account(mut)]
    pub admin: Signer,
    /// CHECK: validated manually in the handler (program-owned + `admin` field
    /// at offset 8). NOT loaded as `VaultConfig` — the bytes may be a stale
    /// layout, so an `AccountLoader` deref would read garbage / wrong offsets.
    #[account(mut, seeds = [VaultConfig::SEED], bump)]
    pub vault_config: UncheckedAccount,
}

pub fn close_vault_config_handler(ctx: &mut Context<CloseVaultConfig>) -> Result<()> {
    let info = ctx.accounts.vault_config.to_account_info();
    require!(info.owner == &crate::ID, VaultError::Unauthorized);

    // `admin` is the first field after the 8-byte discriminator in every
    // VaultConfig layout version → byte offset 8..40.
    {
        let data = info.try_borrow_data()?;
        require!(data.len() >= 40, VaultError::Unauthorized);
        let mut stored_admin = [0u8; 32];
        stored_admin.copy_from_slice(&data[8..40]);
        require!(
            stored_admin == ctx.accounts.admin.address().to_bytes(),
            VaultError::Unauthorized
        );
    }

    // Drain lamports to admin + zero the data → the runtime reclaims the
    // 0-lamport account at tx end, so a follow-up `initialize` can recreate it.
    let admin_info = ctx.accounts.admin.to_account_info();
    let reclaimed = info.lamports();
    **admin_info.try_borrow_mut_lamports()? = admin_info
        .lamports()
        .checked_add(reclaimed)
        .ok_or(Error::from(VaultError::ArithmeticOverflow))?;
    **info.try_borrow_mut_lamports()? = 0;
    let mut data = info.try_borrow_mut_data()?;
    for b in data.iter_mut() {
        *b = 0;
    }
    Ok(())
}
