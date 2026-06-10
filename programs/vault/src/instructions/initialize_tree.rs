use crate::errors::VaultError;
use crate::merkle::empty_root;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

#[derive(Accounts)]
#[instruction(tree_id: u8)]
pub struct InitializeTree<'info> {
    #[account(mut, address = vault_config.load()?.admin @ VaultError::Unauthorized)]
    pub admin: Signer<'info>,

    #[account(seeds = [VaultConfig::SEED], bump = vault_config.load()?.bump)]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    #[account(
        init,
        payer = admin,
        space = 8 + size_of::<MerkleTree>(),
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    pub system_program: Program<'info, System>,
}

/// Create one Merkle-tree shard account (`tree_id < num_trees`). Empty root is
/// derived from the global `zero_subtree_roots` in `VaultConfig`. Admin-gated.
pub fn initialize_tree_handler(ctx: Context<InitializeTree>, tree_id: u8) -> Result<()> {
    let cfg = ctx.accounts.vault_config.load()?;
    require!(tree_id < cfg.num_trees, VaultError::InvalidProof);
    let empty = empty_root(&cfg.zero_subtree_roots)?;
    drop(cfg);

    let tree = &mut ctx.accounts.merkle_tree.load_init()?;
    tree.leaf_count = 0;
    tree.current_root = empty;
    tree.roots = [[0u8; 32]; ROOT_HISTORY_SIZE];
    tree.right_path = [[0u8; 32]; MERKLE_DEPTH as usize];
    tree.roots_head = 0;
    tree.tree_id = tree_id;
    tree.bump = ctx.bumps.merkle_tree;
    tree._padding = [0u8; 5];
    Ok(())
}
