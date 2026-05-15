use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};
use darkpool_crypto::note::commitment_from_fields;

#[derive(Accounts)]
#[instruction(amount: u64, owner_commitment: [u8; 32], nonce: [u8; 32], blinding_r: [u8; 32])]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

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
    amount: u64,
    owner_commitment: [u8; 32],
    nonce: [u8; 32],
    blinding_r: [u8; 32],
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

    // Compute note commitment using the shared crypto crate.
    let token_mint_bytes: [u8; 32] = ctx.accounts.token_mint.key().to_bytes();
    let commitment = commitment_from_fields(
        &token_mint_bytes,
        amount,
        &owner_commitment,
        &nonce,
        &blinding_r,
    )
    .map_err(|_| error!(VaultError::MalformedPublicInputs))?;

    // Append into Merkle tree. Scoped so the RefMut on vault_config is
    // released before we touch the other ctx.accounts borrows below.
    let (leaf_index, new_root) = {
        let cfg = &mut ctx.accounts.vault_config.load_mut()?;
        let leaf_index = cfg.leaf_count;
        let new_root = append_leaf(cfg, commitment)?;
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
    pub leaf_index: u64,
    pub commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub amount: u64,
    pub new_root: [u8; 32],
}
