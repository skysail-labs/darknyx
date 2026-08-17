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
#[instruction(tree_id: u8, note_use_tag: [u8; 32])]
pub struct Withdraw {
    /// Any signer may pay the rent. Authorization is via ZK proof.
    #[account(mut)]
    pub payer: Signer,

    /// Global config — the SPL token authority (read-only; no tree state here).
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,

    /// The Merkle-tree shard the spent note lives in (read-only recency check).
    #[account(
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.bump,
    )]
    pub merkle_tree: Account<MerkleTree>,

    pub token_mint: Account<Mint>,

    #[account(
        mut,
        seeds = [b"vault_token", token_mint.address().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<TokenAccount>,

    #[account(
        mut,
        constraint = destination_token_account.mint() == token_mint.address() @ VaultError::Unauthorized,
    )]
    pub destination_token_account: Account<TokenAccount>,

    /// Consume-once guard. `init` makes the tag-keyed `ConsumedNoteEntry`
    /// the single trustless double-spend guard SHARED with TEE settle
    /// (`tee_forced_settle_batched::consumed_a/b`): a note withdrawn here can no
    /// longer be consumed by a later settle (that settle's `consumed_a` init
    /// collides on this PDA), and a settle-consumed note can no longer be
    /// withdrawn (this init collides). The tag is circuit-bound to the private
    /// opening and its Merkle-leaf commitment, while not republishing that leaf.
    /// This closes the former nullifier-keyed cross-path gap: the settle's
    /// nullifier was TEE-supplied + unconstrained and could not serve as a
    /// shared consume-once handle.
    #[account(
        init,
        payer = payer,
        space = 8 + size_of::<ConsumedNoteEntry>(),
        seeds = [ConsumedNoteEntry::SEED, note_use_tag.as_ref()],
        bump,
    )]
    pub consumed_note: Account<ConsumedNoteEntry>,

    /// Same pattern for note lock — must not be initialized.
    #[account(
        seeds = [NoteLock::SEED, note_use_tag.as_ref()],
        bump,
    )]
    /// CHECK: validated manually in the handler.
    pub note_lock_slot: UncheckedAccount,

    /// v2 — per-mint outstanding-notes counter for this token. MUST exist
    /// (i.e. deposit() must have been called for this mint at least once,
    /// or there's nothing to withdraw).
    #[account(
        mut,
        seeds = [OutstandingMint::SEED, token_mint.address().as_ref()],
        bump = outstanding_mint.bump,
    )]
    pub outstanding_mint: Account<OutstandingMint>,

    pub token_program: Program<Token>,
    pub system_program: Program<System>,
}

#[allow(clippy::too_many_arguments)]
pub fn withdraw_handler(
    ctx: &mut Context<Withdraw>,
    _tree_id: u8,
    note_use_tag: [u8; 32],
    nullifier: [u8; 32],
    merkle_root: [u8; 32],
    amount: u64,
    proof: Groth16Proof,
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);

    // ----- Layer 3: consumed-notes guard -----
    // Enforced by the `consumed_note` `init` constraint (a second withdraw OR a
    // prior settle-consume of this tag makes the init fail). The entry is
    // written near the bottom of the handler, alongside the nullifier.

    // ----- Layer 1: note-lock guard -----
    //
    // S-03: rejects only a LIVE lock. This used to reject any initialized lock
    // account, expired or not, while nothing shipped could call `release_lock`
    // — so one failed settle made a note permanently unwithdrawable.
    require!(
        !crate::state::note_lock_is_live(
            ctx.accounts.note_lock_slot.account(),
            Clock::get()?.slot
        )?,
        VaultError::NoteAlreadyLocked
    );

    // ----- Merkle root must be recent (in THIS shard's ring) -----
    require!(
        ctx.accounts.merkle_tree.contains_root(&merkle_root),
        VaultError::StaleMerkleRoot
    );

    // ----- Verify ZK proof -----
    // VALID_SPEND public signals (in circuit declaration order):
    //   [merkleRoot, nullifier, tokenMint[0], tokenMint[1], amount, recipient[0],
    //    recipient[1]] plus the noteUseTag OUTPUT
    //
    // Wire order matches circuit.sym (circom places outputs before inputs):
    //   wire 1: noteUseTag (signal output — first in IC sum)
    //   wire 2: merkleRoot
    //   wire 3: nullifier
    //   wire 4: tokenMint[0]
    //   wire 5: tokenMint[1]
    //   wire 6: amount
    //   wire 7: recipient[0]  (dest_lo — low 128 bits of the destination ATA)
    //   wire 8: recipient[1]  (dest_hi — high 128 bits)
    // Binding noteUseTag as wire 1 prevents the "arbitrary handle bypass" attack
    // where a caller supplies an un-consumed handle while submitting a proof for
    // a different, already-consumed note. The TAG rather than the commitment:
    // publishing the commitment here would relink this withdrawal to the note's
    // Merkle leaf, and thus to its deposit and every trade it passed through.
    let mint_bytes = ctx.accounts.token_mint.address().to_bytes();
    let [mint_lo, mint_hi] = pubkey_pair_be32(&mint_bytes);
    // S-01: bind the DESTINATION into the proof. Without this the tuple
    // (note_use_tag, nullifier, merkle_root, amount, proof) was a bearer
    // instrument — the proof authorised destroying the note but said nothing
    // about where the money went, so whoever held those bytes first decided
    // the destination. Exploitable by front-running, and (needing no
    // privileged position at all) by replaying any withdraw that LANDS AND
    // REVERTS: a reverted tx publishes the proof in the ledger permanently
    // while creating neither guard PDA, leaving the note spendable.
    //
    // A 256-bit pubkey does not fit one BN254 Fr element, so it splits into
    // lo/hi halves exactly like the mint — hence 8 public inputs, not 7.
    let dest_bytes = ctx.accounts.destination_token_account.address().to_bytes();
    let [dest_lo, dest_hi] = pubkey_pair_be32(&dest_bytes);
    let public_inputs: [[u8; 32]; 8] = [
        note_use_tag,
        merkle_root,
        nullifier,
        mint_lo,
        mint_hi,
        u64_be32(amount),
        dest_lo,
        dest_hi,
    ];

    let vk = make_vk(
        &VALID_SPEND_ALPHA_G1,
        &VALID_SPEND_BETA_G2,
        &VALID_SPEND_GAMMA_G2,
        &VALID_SPEND_DELTA_G2,
        &VALID_SPEND_IC,
    );
    verify_groth16_proof::<8>(&vk, &proof, &public_inputs)?;

    // ----- v2 solvency check (must come BEFORE state mutation) -----
    require!(
        ctx.accounts.outstanding_mint.outstanding >= amount,
        VaultError::InsufficientOutstanding
    );

    // ----- Mark the note consumed (tag-keyed) -----
    //
    // PF-04: this is now the ONLY guard withdraw allocates. The second,
    // nullifier-keyed guard was removed — it had zero readers anywhere (no
    // instruction, SDK query, indexer table, daemon logic), and it was worse
    // than redundant: `nullifier = Poseidon3(3, sk, inner)` is
    // amount- AND mint-independent, so two distinct notes of one owner sharing
    // an `inner_hash` collide on it and the second legitimate withdraw is
    // bricked. `note_use_tag` is a circuit-bound public OUTPUT of
    // VALID_SPEND, so the tag-keyed guard is complete on its own.
    let slot = Clock::get()?.slot;
    // The shared consume-once guard with TEE settle. `match_id` is the all-zero
    // sentinel — there is no match on the withdraw path.
    let c = &mut ctx.accounts.consumed_note;
    c.note_use_tag = note_use_tag;
    c.match_id = [0u8; 16];
    c.consumed_slot = (slot).into();
    c.bump = ctx.bumps.consumed_note;
    c._padding = [0u8; 7];

    // ----- Decrement outstanding counter -----
    // The InsufficientOutstanding check above already guarantees no underflow;
    // `checked_sub` makes that defense-in-depth explicit (and mirrors deposit's
    // `checked_add`) so a future reorder of the guard can't silently wrap.
    ctx.accounts.outstanding_mint.outstanding = ctx
        .accounts
        .outstanding_mint
        .outstanding
        .checked_sub(amount)
        .ok_or(Error::from(VaultError::InsufficientOutstanding))?;

    // ----- Transfer tokens out -----
    let bump = ctx.accounts.vault_config.bump;
    let cfg_seeds: &[&[u8]] = &[VaultConfig::SEED, &[bump]];
    let signer_seeds: &[&[&[u8]]] = &[cfg_seeds];

    let cpi_accounts = TransferChecked {
        from: ctx.accounts.vault_token_account.to_cpi_handle_mut(),
        to: ctx.accounts.destination_token_account.to_cpi_handle_mut(),
        mint: ctx.accounts.token_mint.to_cpi_handle(),
        authority: ctx.accounts.vault_config.to_cpi_handle(),
    };
    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.address(),
            cpi_accounts,
            signer_seeds,
        ),
        amount,
        ctx.accounts.token_mint.decimals(),
    )?;

    // Solvency invariant check (both counters dropped by `amount`). No
    // `reload()`: v2 `Account<T>` reads the live account buffer, so the
    // post-CPI balance is already visible.
    require!(
        ctx.accounts.outstanding_mint.outstanding.get()
            <= ctx.accounts.vault_token_account.amount(),
        VaultError::SolvencyInvariantViolated
    );

    emit!(Withdrawn {
        nullifier,
        note_use_tag,
        token_mint: *ctx.accounts.token_mint.address(),
        amount,
    });

    Ok(())
}

#[event]
pub struct Withdrawn {
    pub nullifier: [u8; 32],
    pub note_use_tag: [u8; 32],
    pub token_mint: Address,
    pub amount: u64,
}
