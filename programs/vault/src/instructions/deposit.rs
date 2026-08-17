use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_deposit::*, Groth16Proof};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};
use std::mem::size_of;

#[derive(Accounts)]
#[instruction(tree_id: u8, amount: u64, note_commitment: [u8; 32], recovery_nonce: [u8; 32], proof: Groth16Proof)]
pub struct Deposit {
    #[account(mut)]
    pub depositor: Signer,

    /// Global config — read-only (provides `zero_subtree_roots` + is the SPL
    /// token authority); the leaf append goes to `merkle_tree` below.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,

    /// The Merkle-tree shard this deposit's note is appended to.
    #[account(
        mut,
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.bump,
    )]
    pub merkle_tree: Account<MerkleTree>,

    pub token_mint: Account<Mint>,

    #[account(
        mut,
        constraint = depositor_token_account.mint == token_mint.address() @ VaultError::Unauthorized,
        constraint = depositor_token_account.owner == depositor.address() @ VaultError::Unauthorized,
    )]
    pub depositor_token_account: Account<TokenAccount>,

    /// Per-mint vault token account (PDA).
    /// Initialized lazily via `init_if_needed` on first deposit of each mint.
    #[account(
        init_if_needed,
        payer = depositor,
        token::mint = token_mint,
        token::authority = vault_config,
        seeds = [b"vault_token", token_mint.address().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<TokenAccount>,

    /// v2 — per-mint outstanding-notes counter. Lazy-init on first deposit
    /// of each mint, mirrors the lifecycle of `vault_token_account`.
    #[account(
        init_if_needed,
        payer = depositor,
        space = OutstandingMint::SPACE,
        seeds = [OutstandingMint::SEED, token_mint.address().as_ref()],
        bump,
    )]
    pub outstanding_mint: Account<OutstandingMint>,

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
    pub deposited_note: Account<DepositedNoteEntry>,

    pub token_program: Program<Token>,
    pub system_program: Program<System>,
    pub rent: Sysvar<Rent>,
}

pub fn deposit_handler(
    ctx: &mut Context<Deposit>,
    _tree_id: u8,
    amount: u64,
    note_commitment: [u8; 32],
    recovery_nonce: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);

    // VALID_DEPOSIT public inputs, in circuit declaration order. The mint is
    // split into two u128 field elements; amount is the instruction's u64.
    let mint_bytes = ctx.accounts.token_mint.address().to_bytes();
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
    // v2 CPI handles: `cpi_handle_mut()` for the accounts the transfer debits
    // and credits (both are `mut` in the Accounts struct, which the mut handle
    // requires), `cpi_handle()` for the read-only mint and authority.
    let cpi_accounts = TransferChecked {
        from: ctx.accounts.depositor_token_account.cpi_handle_mut(),
        to: ctx.accounts.vault_token_account.cpi_handle_mut(),
        mint: ctx.accounts.token_mint.cpi_handle(),
        authority: ctx.accounts.depositor.cpi_handle(),
    };
    transfer_checked(
        CpiContext::new(ctx.accounts.token_program.address(), cpi_accounts),
        amount,
        // v2: SPL wrapper fields are private; read through the accessor.
        ctx.accounts.token_mint.decimals(),
    )?;

    // Append into the shard's Merkle tree (zero_subtree_roots come from the
    // global config). Scoped so the borrows release before the accounts below.
    let (leaf_index, new_root) = {
        let cfg = ctx.accounts.vault_config;
        let zsr = cfg.zero_subtree_roots;
        drop(cfg);
        let tree = &mut ctx.accounts.merkle_tree;
        let leaf_index = tree.leaf_count.get();
        let new_root = append_leaf(tree, &zsr, note_commitment)?;
        (leaf_index, new_root)
    };

    // v2 — bump the per-mint outstanding counter. `init_if_needed` may have
    // just freshly created the account (mint == Address::default()), so set
    // the descriptor fields idempotently before incrementing.
    let om = &mut ctx.accounts.outstanding_mint;
    om.mint = ctx.accounts.token_mint.address();
    om.bump = ctx.bumps.outstanding_mint;
    // Arithmetic goes through the native type so the v1 CHECKED overflow
    // semantics are preserved exactly (guide §5.2 warns against silently
    // switching to wrapping while Pod-ifying).
    om.outstanding = om
        .outstanding
        .get()
        .checked_add(amount)
        .ok_or(Error::from(VaultError::ArithmeticOverflow))?
        .into();

    // Solvency invariant: outstanding can never exceed the SPL pool. After
    // a deposit, both sides incremented by `amount`, so this is tight.
    //
    // v1 needed a `reload()` here because the `transfer_checked` CPI mutated
    // the account after borsh had already deserialized it. v2 `Account<T>` is
    // zero-copy over the live account buffer, so the post-CPI value is read
    // directly and the reload is not just unnecessary but meaningless.
    require!(
        om.outstanding.get() <= ctx.accounts.vault_token_account.amount(),
        VaultError::SolvencyInvariantViolated
    );

    emit!(NoteCreated {
        tree_id: _tree_id,
        leaf_index,
        commitment: note_commitment,
        token_mint: ctx.accounts.token_mint.address(),
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
    pub token_mint: Address,
    pub amount: u64,
    pub new_root: [u8; 32],
}
