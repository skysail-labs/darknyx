use crate::errors::VaultError;
use crate::merkle::compute_zero_subtree_roots;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(tee_pubkey: Pubkey, root_key: Pubkey, num_trees: u8)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + size_of::<VaultConfig>(),
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

/// Initialize the GLOBAL vault config. The per-shard Merkle trees are created
/// separately (`initialize_tree`, one per shard id). `tee_pubkey` seeds the
/// authorized-key set as its first entry; the full K-key set is installed via
/// `set_tee_pubkeys` at the rotation ceremony. `num_trees` is the shard count.
pub fn initialize_handler(
    ctx: Context<Initialize>,
    tee_pubkey: Pubkey,
    root_key: Pubkey,
    num_trees: u8,
) -> Result<()> {
    require!(
        (1..=MAX_TREES).contains(&num_trees),
        VaultError::InvalidTreeCount
    );
    let cfg = &mut ctx.accounts.vault_config.load_init()?;

    cfg.admin = ctx.accounts.admin.key();
    cfg.tee_pubkeys = [Pubkey::default(); MAX_TEE_KEYS];
    cfg.tee_pubkeys[0] = tee_pubkey;
    cfg.num_tee_keys = 1;
    cfg.root_key = root_key;
    cfg.num_trees = num_trees;
    cfg.zero_subtree_roots = compute_zero_subtree_roots()?;
    cfg.bump = ctx.bumps.vault_config;
    cfg.protocol_owner_commitment = [0u8; 32];
    cfg.fee_rate_bps = 0;
    cfg._padding = [0u8; 3];
    let _ = VaultError::ZeroAmount; // keep errors linked in
    Ok(())
}
