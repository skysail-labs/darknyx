use crate::errors::VaultError;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_input::*, Groth16Proof};
use anchor_lang::prelude::*;
use core::mem::size_of;

/// Split a 32-byte Solana pubkey into [lo_u128_be32, hi_u128_be32] — each
/// encoded as 32 BE bytes (left-padded). Matches `darkpool-crypto`'s
/// `pubkey_to_fr_pair`, which is what the VALID_INPUT circuit expects.
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    [lo, hi]
}

#[derive(Accounts)]
#[instruction(
    tree_id: u8,
    note_commitment: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
    token_mint: Pubkey,
    merkle_root: [u8; 32],
    proof: Groth16Proof,
)]
pub struct LockNote<'info> {
    /// The TEE-operated relayer. We enforce that `tee_authority.key()` is one of
    /// `vault_config.tee_pubkeys` (the authorized shard fee-payer/signer set) so
    /// only a registered TEE key can lock notes.
    ///
    /// NOTE: even with the registered key gate, the TEE could previously
    /// "lock" any 32-byte commitment whether or not it actually existed in
    /// the Merkle tree, with any amount it wanted (see §4.1 of the v2
    /// migration brief). The VALID_INPUT proof closes that hole — the TEE
    /// now must relay a user-generated ZK proof attesting that the
    /// commitment exists in the tree with the declared mint and a private,
    /// positive, range-constrained amount.
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    #[account(
        seeds = [VaultConfig::SEED],
        bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// The Merkle-tree shard the input note lives in. Read-only — we only check
    /// its recent-root ring.
    #[account(
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.load()?.bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NoteLock>(),
        seeds = [NoteLock::SEED, note_commitment.as_ref()],
        bump,
    )]
    pub note_lock: AccountLoader<'info, NoteLock>,

    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn lock_note_handler(
    ctx: Context<LockNote>,
    _tree_id: u8,
    note_commitment: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
    token_mint: Pubkey,
    merkle_root: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    let clock = Clock::get()?;

    // TEE-authority gate + Merkle-root recency check (against THIS shard).
    {
        let cfg = ctx.accounts.vault_config.load()?;
        require!(
            cfg.is_authorized_tee(&ctx.accounts.tee_authority.key()),
            VaultError::Unauthorized
        );
        // The proof was generated against `merkle_root`; that root must still
        // be in this shard's recent-root ring. Same recency policy as `withdraw`.
        require!(
            ctx.accounts.merkle_tree.load()?.contains_root(&merkle_root),
            VaultError::StaleMerkleRoot
        );
    }

    require!(expiry_slot > clock.slot, VaultError::InvalidExpirySlot);
    // v2 hardening: cap how far in the future the lock can sit. The vault's
    // `withdraw` rejects while a NoteLock exists, even an expired one, so the
    // lock window is also the censorship window. See `MAX_LOCK_TTL_SLOTS`.
    require!(
        expiry_slot <= clock.slot.saturating_add(MAX_LOCK_TTL_SLOTS),
        VaultError::InvalidExpirySlot
    );
    // VALID_INPUT public inputs, in the order declared by the circom
    // `component main { public [merkleRoot, noteCommitment, tokenMint] }`.
    // `tokenMint[2]` expands as two entries (`lo`, `hi`) — four total. Amount
    // remains a private positive u64 witness constrained inside the proof.
    let mint_bytes = token_mint.to_bytes();
    let [mint_lo, mint_hi] = pubkey_pair_be32(&mint_bytes);
    let public_inputs: [[u8; 32]; 4] = [merkle_root, note_commitment, mint_lo, mint_hi];

    let vk = make_vk(
        &VALID_INPUT_ALPHA_G1,
        &VALID_INPUT_BETA_G2,
        &VALID_INPUT_GAMMA_G2,
        &VALID_INPUT_DELTA_G2,
        &VALID_INPUT_IC,
    );
    verify_groth16_proof::<4>(&vk, &proof, &public_inputs)?;

    // Proof verified — every field of the lock is now cryptographically bound
    // to a real Merkle leaf owned by the proof generator. Write the lock.
    let lock = &mut ctx.accounts.note_lock.load_init()?;
    lock.note_commitment = note_commitment;
    lock.token_mint = token_mint;
    lock.order_id = order_id;
    lock.expiry_slot = expiry_slot;
    lock.locked_by = ctx.accounts.tee_authority.key();
    lock.bump = ctx.bumps.note_lock;
    lock._padding = [0u8; 7];

    emit!(NoteLocked {
        note_commitment,
        token_mint,
        order_id,
        expiry_slot,
    });
    Ok(())
}

#[event]
pub struct NoteLocked {
    pub note_commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
}
