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
//! Nullifiers, wallets, deposits-in-flight, and fee accumulators are
//! NOT wiped; they're separate PDAs. That's intentional: already-minted
//! WalletEntry / NullifierEntry PDAs remain valid records, and the
//! tree-reset only affects the set of ACCEPTED inclusion roots going
//! forward. A future VALID_SPEND whose witness pre-dates the reset will
//! simply fail `contains_root`, which is the correct behaviour.

use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::merkle::empty_root;
use crate::state::{VaultConfig, MERKLE_DEPTH, ROOT_HISTORY_SIZE};

#[derive(Accounts)]
pub struct ResetMerkleTree<'info> {
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,
}

pub fn reset_merkle_tree_handler(ctx: Context<ResetMerkleTree>) -> Result<()> {
    let cfg = &mut ctx.accounts.vault_config.load_mut()?;
    require_keys_eq!(
        ctx.accounts.admin.key(),
        cfg.admin,
        VaultError::Unauthorized
    );

    cfg.leaf_count = 0;
    cfg.right_path = [[0u8; 32]; MERKLE_DEPTH as usize];
    cfg.roots = [[0u8; 32]; ROOT_HISTORY_SIZE];
    cfg.roots_head = 0;
    cfg.current_root = empty_root(&cfg.zero_subtree_roots)?;
    Ok(())
}
