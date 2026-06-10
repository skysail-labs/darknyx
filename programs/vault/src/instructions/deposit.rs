use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};
use darkpool_crypto::note::commitment_from_fields_v2;

#[derive(Accounts)]
#[instruction(tree_id: u8, amount: u64, owner_commitment: [u8; 32], inner_hash: [u8; 32])]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Global config — read-only (provides `zero_subtree_roots` + is the SPL
    /// token authority); the leaf append goes to `merkle_tree` below.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// The Merkle-tree shard this deposit's note is appended to.
    #[account(
        mut,
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.load()?.bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    pub token_mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = depositor_token_account.mint == token_mint.key() @ VaultError::Unauthorized,
        constraint = depositor_token_account.owner == depositor.key() @ VaultError::Unauthorized,
    )]
    pub depositor_token_account: Account<'info, TokenAccount>,

    /// Per-mint vault token account (PDA).
    /// Initialized lazily via `init_if_needed` on first deposit of each mint.
    #[account(
        init_if_needed,
        payer = depositor,
        token::mint = token_mint,
        token::authority = vault_config,
        seeds = [b"vault_token", token_mint.key().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// v2 — per-mint outstanding-notes counter. Lazy-init on first deposit
    /// of each mint, mirrors the lifecycle of `vault_token_account`.
    #[account(
        init_if_needed,
        payer = depositor,
        space = OutstandingMint::SPACE,
        seeds = [OutstandingMint::SEED, token_mint.key().as_ref()],
        bump,
    )]
    pub outstanding_mint: Account<'info, OutstandingMint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

pub fn deposit_handler(
    ctx: Context<Deposit>,
    _tree_id: u8,
    amount: u64,
    owner_commitment: [u8; 32],
    inner_hash: [u8; 32],
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);

    // Transfer tokens in.
    let cpi_accounts = TransferChecked {
        from: ctx.accounts.depositor_token_account.to_account_info(),
        to: ctx.accounts.vault_token_account.to_account_info(),
        mint: ctx.accounts.token_mint.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };
    transfer_checked(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
        amount,
        ctx.accounts.token_mint.decimals,
    )?;

    // Compute note commitment using the shared crypto crate (v2: single
    // inner_hash replaces the old nonce + blinding_r pair; mint stays bound).
    let token_mint_bytes: [u8; 32] = ctx.accounts.token_mint.key().to_bytes();
    let commitment =
        commitment_from_fields_v2(&token_mint_bytes, amount, &owner_commitment, &inner_hash)
            .map_err(|_| error!(VaultError::MalformedPublicInputs))?;

    // Append into the shard's Merkle tree (zero_subtree_roots come from the
    // global config). Scoped so the borrows release before the accounts below.
    let (leaf_index, new_root) = {
        let cfg = ctx.accounts.vault_config.load()?;
        let zsr = cfg.zero_subtree_roots;
        drop(cfg);
        let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
        let leaf_index = tree.leaf_count;
        let new_root = append_leaf(tree, &zsr, commitment)?;
        (leaf_index, new_root)
    };

    // v2 — bump the per-mint outstanding counter. `init_if_needed` may have
    // just freshly created the account (mint == Pubkey::default()), so set
    // the descriptor fields idempotently before incrementing.
    let om = &mut ctx.accounts.outstanding_mint;
    om.mint = ctx.accounts.token_mint.key();
    om.bump = ctx.bumps.outstanding_mint;
    om.outstanding = om
        .outstanding
        .checked_add(amount)
        .ok_or(error!(VaultError::ArithmeticOverflow))?;

    // Solvency invariant: outstanding can never exceed the SPL pool. After
    // a deposit, both sides incremented by `amount`, so this is tight.
    // Re-read the SPL account because the `transfer_checked` CPI mutated it.
    ctx.accounts.vault_token_account.reload()?;
    require!(
        om.outstanding <= ctx.accounts.vault_token_account.amount,
        VaultError::SolvencyInvariantViolated
    );

    emit!(NoteCreated {
        tree_id: _tree_id,
        leaf_index,
        commitment,
        token_mint: ctx.accounts.token_mint.key(),
        amount,
        new_root,
    });

    Ok(())
}

#[event]
pub struct NoteCreated {
    pub tree_id: u8,
    pub leaf_index: u64,
    pub commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub amount: u64,
    pub new_root: [u8; 32],
}
