use crate::errors::VaultError;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_spend::*, Groth16Proof};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};
use core::mem::size_of;

/// Split a 32-byte Solana pubkey into [lo_u128_be32, hi_u128_be32] — each
/// encoded as 32 BE bytes (left-padded). Matches `darkpool-crypto`'s
/// `pubkey_to_fr_pair`, which is what the VALID_SPEND circuit expects.
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    [lo, hi]
}

fn u64_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

#[derive(Accounts)]
#[instruction(tree_id: u8, note_commitment: [u8; 32], nullifier: [u8; 32], merkle_root: [u8; 32], amount: u64, proof: Groth16Proof)]
pub struct Withdraw<'info> {
    /// Any signer may pay the rent. Authorization is via ZK proof.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Global config — the SPL token authority (read-only; no tree state here).
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// The Merkle-tree shard the spent note lives in (read-only recency check).
    #[account(
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.load()?.bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    pub token_mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [b"vault_token", token_mint.key().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = destination_token_account.mint == token_mint.key() @ VaultError::Unauthorized,
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    /// If the note has been consumed, this account must exist; we assert
    /// `consumed_note` is NOT found on the *alternate* path, but because Anchor
    /// requires all accounts up-front, we use `AccountInfo` + manual deref to
    /// reject only if it is initialized.
    /// (Layer-3 guard before ZK verification — Section 19.4 of the spec.)
    #[account(
        seeds = [ConsumedNoteEntry::SEED, note_commitment.as_ref()],
        bump,
    )]
    /// CHECK: validated manually in the handler.
    pub consumed_note_slot: AccountInfo<'info>,

    /// Same pattern for note lock — must not be initialized.
    #[account(
        seeds = [NoteLock::SEED, note_commitment.as_ref()],
        bump,
    )]
    /// CHECK: validated manually in the handler.
    pub note_lock_slot: AccountInfo<'info>,

    /// Nullifier PDA. If already initialized, the withdrawal is a double-spend.
    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<NullifierEntry>(),
        seeds = [NullifierEntry::SEED, nullifier.as_ref()],
        bump,
    )]
    pub nullifier_entry: AccountLoader<'info, NullifierEntry>,

    /// v2 — per-mint outstanding-notes counter for this token. MUST exist
    /// (i.e. deposit() must have been called for this mint at least once,
    /// or there's nothing to withdraw).
    #[account(
        mut,
        seeds = [OutstandingMint::SEED, token_mint.key().as_ref()],
        bump = outstanding_mint.bump,
    )]
    pub outstanding_mint: Account<'info, OutstandingMint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn withdraw_handler(
    ctx: Context<Withdraw>,
    _tree_id: u8,
    note_commitment: [u8; 32],
    nullifier: [u8; 32],
    merkle_root: [u8; 32],
    amount: u64,
    proof: Groth16Proof,
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);

    // ----- Layer 3: consumed-notes guard -----
    // If the slot is already initialized (owner == program_id, has data), reject.
    {
        let info = &ctx.accounts.consumed_note_slot;
        // Uninitialized PDA: owner = system_program, data empty.
        if info.owner == ctx.program_id {
            return err!(VaultError::NoteAlreadyConsumed);
        }
    }

    // ----- Layer 1: note-lock guard -----
    {
        let info = &ctx.accounts.note_lock_slot;
        if info.owner == ctx.program_id {
            // Check expiry — lock is effective only until expiry_slot.
            let data = info.try_borrow_data()?;
            // Anchor prefixes 8-byte discriminator; then fields laid out by `#[account]`.
            // For the guard we only need the expiry_slot — it's safer to reject any
            // initialized lock and require the user to call `release_lock` first.
            let _ = data;
            return err!(VaultError::NoteAlreadyLocked);
        }
    }

    // ----- Merkle root must be recent (in THIS shard's ring) -----
    require!(
        ctx.accounts.merkle_tree.load()?.contains_root(&merkle_root),
        VaultError::StaleMerkleRoot
    );

    // ----- Verify ZK proof -----
    // VALID_SPEND public signals (in circuit declaration order):
    //   [merkleRoot, nullifier, tokenMint[0], tokenMint[1], amount, noteCommitment]
    //
    // Wire order matches circuit.sym (circom places outputs before inputs):
    //   wire 1: noteCommitment (signal output — first in IC sum)
    //   wire 2: merkleRoot
    //   wire 3: nullifier
    //   wire 4: tokenMint[0]
    //   wire 5: tokenMint[1]
    //   wire 6: amount
    // Binding noteCommitment as wire 1 prevents the "arbitrary note_commitment
    // bypass" attack where a caller supplies an un-nullified commitment while
    // submitting a proof for a different, already-nullified note.
    let mint_bytes = ctx.accounts.token_mint.key().to_bytes();
    let [mint_lo, mint_hi] = pubkey_pair_be32(&mint_bytes);
    let public_inputs: [[u8; 32]; 6] = [
        note_commitment,
        merkle_root,
        nullifier,
        mint_lo,
        mint_hi,
        u64_be32(amount),
    ];

    let vk = make_vk(
        &VALID_SPEND_ALPHA_G1,
        &VALID_SPEND_BETA_G2,
        &VALID_SPEND_GAMMA_G2,
        &VALID_SPEND_DELTA_G2,
        &VALID_SPEND_IC,
    );
    verify_groth16_proof::<6>(&vk, &proof, &public_inputs)?;

    // ----- v2 solvency check (must come BEFORE state mutation) -----
    require!(
        ctx.accounts.outstanding_mint.outstanding >= amount,
        VaultError::InsufficientOutstanding
    );

    // ----- Mark nullifier as spent -----
    let n = &mut ctx.accounts.nullifier_entry.load_init()?;
    n.nullifier = nullifier;
    n.spent_slot = Clock::get()?.slot;
    n.bump = ctx.bumps.nullifier_entry;
    n._padding = [0u8; 7];

    // ----- Decrement outstanding counter -----
    // Subtract is safe because of the InsufficientOutstanding check above.
    ctx.accounts.outstanding_mint.outstanding -= amount;

    // ----- Transfer tokens out -----
    let bump = ctx.accounts.vault_config.load()?.bump;
    let cfg_seeds: &[&[u8]] = &[VaultConfig::SEED, &[bump]];
    let signer_seeds: &[&[&[u8]]] = &[cfg_seeds];

    let cpi_accounts = TransferChecked {
        from: ctx.accounts.vault_token_account.to_account_info(),
        to: ctx.accounts.destination_token_account.to_account_info(),
        mint: ctx.accounts.token_mint.to_account_info(),
        authority: ctx.accounts.vault_config.to_account_info(),
    };
    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        ),
        amount,
        ctx.accounts.token_mint.decimals,
    )?;

    // Solvency invariant check (both counters dropped by `amount`).
    ctx.accounts.vault_token_account.reload()?;
    require!(
        ctx.accounts.outstanding_mint.outstanding <= ctx.accounts.vault_token_account.amount,
        VaultError::SolvencyInvariantViolated
    );

    emit!(Withdrawn {
        nullifier,
        note_commitment,
        token_mint: ctx.accounts.token_mint.key(),
        amount,
    });

    Ok(())
}

#[event]
pub struct Withdrawn {
    pub nullifier: [u8; 32],
    pub note_commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub amount: u64,
}
