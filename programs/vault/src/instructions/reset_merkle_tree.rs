//! DEVNET-ONLY: reset the vault's Merkle tree back to its empty initial
//! state. Admin-gated so production multisigs can choose never to call it.
//!
//! Intended use: end-to-end tests that run on a shared devnet vault
//! singleton need a clean tree to reason about inclusion proofs. Without
//! this ix every test run would inherit the accumulated leaves of prior
//! runs and off-chain shadow trees would diverge from on-chain.
//!
//! Side-effects:
//!   * leaf_count := 0
//!   * right_path[..] := [0u8; 32]
//!   * roots[..]      := [0u8; 32]
//!   * roots_head     := 0
//!   * current_root   := empty_root(zero_subtree_roots)
//!
//! Wallet registrations, deposit/consume guards, locks, validity markers, and
//! mint liabilities are NOT wiped; they're separate PDAs. The tree reset only
//! affects the set of accepted inclusion roots going forward. A future
//! VALID_SPEND whose witness pre-dates the reset simply fails `contains_root`,
//! which is the correct behaviour.

use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::merkle::empty_root;
use crate::state::{MerkleTree, VaultConfig, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

#[derive(Accounts)]
#[instruction(tree_id: u8)]
pub struct ResetMerkleTree {
    #[account(address = vault_config.admin @ VaultError::Unauthorized)]
    pub admin: Signer,
    #[account(seeds = [VaultConfig::SEED], bump = vault_config.bump)]
    pub vault_config: Account<VaultConfig>,
    #[account(
        mut,
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.bump,
    )]
    pub merkle_tree: Account<MerkleTree>,
}

pub fn reset_merkle_tree_handler(ctx: &mut Context<ResetMerkleTree>, _tree_id: u8) -> Result<()> {
    let empty = empty_root(&ctx.accounts.vault_config.zero_subtree_roots)?;
    let tree = &mut ctx.accounts.merkle_tree;
    tree.leaf_count = 0;
    tree.right_path = [[0u8; 32]; MERKLE_DEPTH as usize];
    tree.roots = [[0u8; 32]; ROOT_HISTORY_SIZE];
    tree.roots_head = 0;
    tree.current_root = empty;
    Ok(())
}
