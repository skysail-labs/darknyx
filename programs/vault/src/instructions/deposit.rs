use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_deposit::*, Groth16Proof};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};
use std::mem::size_of;

#[derive(Accounts)]
#[instruction(tree_id: u8, amount: u64, note_commitment: [u8; 32], recovery_nonce: [u8; 32], proof: Groth16Proof)]
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

    /// S-05 deposit-once guard, commitment-keyed. `init` makes a duplicate
    /// commitment structurally impossible and fails LOUDLY at the point of the
    /// mistake, rather than silently accepting tokens for a note that can never
    /// be withdrawn.
    ///
    /// Rent- and CPI-neutral in aggregate: `withdraw` stopped allocating its
    /// redundant nullifier-keyed guard (PF-04) in the same change, and the two
    /// accounts are the same size.
    #[account(
        init,
        payer = depositor,
        space = 8 + size_of::<DepositedNoteEntry>(),
        seeds = [DepositedNoteEntry::SEED, note_commitment.as_ref()],
        bump,
    )]
    pub deposited_note: AccountLoader<'info, DepositedNoteEntry>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

pub fn deposit_handler(
    ctx: Context<Deposit>,
    _tree_id: u8,
    amount: u64,
    note_commitment: [u8; 32],
    recovery_nonce: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);

    // VALID_DEPOSIT public inputs, in circuit declaration order. The mint is
    // split into two u128 field elements; amount is the instruction's u64.
    let mint_bytes = ctx.accounts.token_mint.key().to_bytes();
    let [mint_lo, mint_hi] = pubkey_pair_be32(&mint_bytes);
    let public_inputs: [[u8; 32]; 5] = [
        note_commitment,
        mint_lo,
        mint_hi,
        u64_be32(amount),
        recovery_nonce,
    ];
    let vk = make_vk(
        &VALID_DEPOSIT_ALPHA_G1,
        &VALID_DEPOSIT_BETA_G2,
        &VALID_DEPOSIT_GAMMA_G2,
        &VALID_DEPOSIT_DELTA_G2,
        &VALID_DEPOSIT_IC,
    );

    // Verify before the SPL transfer or any state mutation. An invalid proof
    // therefore cannot move custody, increment outstanding, or append a leaf.
    verify_groth16_proof::<5>(&vk, &proof, &public_inputs)?;

    // Transfer tokens in.
    let cpi_accounts = TransferChecked {
        from: ctx.accounts.depositor_token_account.to_account_info(),
        to: ctx.accounts.vault_token_account.to_account_info(),
        mint: ctx.accounts.token_mint.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };
    transfer_checked(
        CpiContext::new(ctx.accounts.token_program.key(), cpi_accounts),
        amount,
        ctx.accounts.token_mint.decimals,
    )?;

    // Append into the shard's Merkle tree (zero_subtree_roots come from the
    // global config). Scoped so the borrows release before the accounts below.
    let (leaf_index, new_root) = {
        let cfg = ctx.accounts.vault_config.load()?;
        let zsr = cfg.zero_subtree_roots;
        drop(cfg);
        let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
        let leaf_index = tree.leaf_count;
        let new_root = append_leaf(tree, &zsr, note_commitment)?;
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
        commitment: note_commitment,
        token_mint: ctx.accounts.token_mint.key(),
        amount,
        new_root,
    });

    Ok(())
}

/// Split a Solana pubkey into the exact two u128 public inputs used by Circom.
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&pk[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&pk[..16]);
    [lo, hi]
}

fn u64_be32(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
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
