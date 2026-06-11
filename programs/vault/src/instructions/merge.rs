//! In-pool note merge (VALID_MERGE K=2/4).
//!
//! Consumes K input notes (all the same owner + mint, each in the Merkle tree)
//! and mints ONE output note whose amount is their sum — no external transfer.
//! Used to consolidate fragmented notes so a user can place an order larger than
//! any single note (then over-collateralization returns the surplus as change).
//!
//! Conservation: K notes consumed + 1 minted, same mint, same total ⇒ the
//! per-mint `OutstandingMint` counter is UNCHANGED (the pool owes the user the
//! same total). Replay is guarded by the per-input `NullifierEntry` PDA — created
//! manually here (fails if it already exists), the same guard `withdraw` uses via
//! `init`. Dummy padding slots carry a public nullifier of 0 (the circuit binds
//! them inactive), so they create no PDA and can't smuggle a spend.

use crate::errors::VaultError;
use crate::merkle::append_leaf;
use crate::state::*;
use crate::zk::{
    verifier::make_vk, verify_groth16_proof, vk_valid_merge_k2::*, vk_valid_merge_k4::*,
    Groth16Proof,
};
use anchor_lang::prelude::*;
use anchor_lang::system_program;
use core::mem::size_of;

/// Split a 32-byte pubkey into [lo_u128_be32, hi_u128_be32] — matches
/// `darkpool-crypto::pubkey_to_fr_pair` (what the circuit's `tokenMint[2]` is).
fn pubkey_pair_be32(pk: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    [lo, hi]
}

#[derive(Accounts)]
#[instruction(tree_id: u8)]
pub struct Merge<'info> {
    /// Any signer pays rent for the new nullifier PDAs + output leaf. Authority
    /// is the ZK proof.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Global config — read-only (provides `zero_subtree_roots`).
    #[account(seeds = [VaultConfig::SEED], bump = vault_config.load()?.bump)]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// The Merkle-tree shard the inputs live in + the merged output is appended to.
    #[account(mut, seeds = [MerkleTree::SEED, &[tree_id]], bump = merkle_tree.load()?.bump)]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    pub system_program: Program<'info, System>,
    // The NullifierEntry PDAs for the NON-ZERO input nullifiers are passed as
    // `remaining_accounts` (writable, uninitialised), in nullifier order.
}

#[allow(clippy::too_many_arguments)]
pub fn merge_handler<'info>(
    ctx: Context<'_, '_, '_, 'info, Merge<'info>>,
    tree_id: u8,
    nullifiers: Vec<[u8; 32]>,
    output_commitment: [u8; 32],
    token_mint: Pubkey,
    merkle_root: [u8; 32],
    k: u8,
    proof: Groth16Proof,
) -> Result<()> {
    require!(
        (k == 2 || k == 4) && nullifiers.len() == k as usize,
        VaultError::InvalidMergeK
    );

    // Merkle root must be recent in THIS shard (membership proofs built against it).
    require!(
        ctx.accounts.merkle_tree.load()?.contains_root(&merkle_root),
        VaultError::StaleMerkleRoot
    );

    // ----- Verify the VALID_MERGE proof (VK chosen by K) -----
    // Public signals (circom output-first order):
    //   [outputCommitment, merkleRoot, mint_lo, mint_hi, nullifiers[0..K-1]]
    let [mint_lo, mint_hi] = pubkey_pair_be32(&token_mint.to_bytes());
    match k {
        2 => {
            let pi: [[u8; 32]; 6] = [
                output_commitment,
                merkle_root,
                mint_lo,
                mint_hi,
                nullifiers[0],
                nullifiers[1],
            ];
            let vk = make_vk(
                &VALID_MERGE_K2_ALPHA_G1,
                &VALID_MERGE_K2_BETA_G2,
                &VALID_MERGE_K2_GAMMA_G2,
                &VALID_MERGE_K2_DELTA_G2,
                &VALID_MERGE_K2_IC,
            );
            verify_groth16_proof::<6>(&vk, &proof, &pi)?;
        }
        4 => {
            let pi: [[u8; 32]; 8] = [
                output_commitment,
                merkle_root,
                mint_lo,
                mint_hi,
                nullifiers[0],
                nullifiers[1],
                nullifiers[2],
                nullifiers[3],
            ];
            let vk = make_vk(
                &VALID_MERGE_K4_ALPHA_G1,
                &VALID_MERGE_K4_BETA_G2,
                &VALID_MERGE_K4_GAMMA_G2,
                &VALID_MERGE_K4_DELTA_G2,
                &VALID_MERGE_K4_IC,
            );
            verify_groth16_proof::<8>(&vk, &proof, &pi)?;
        }
        _ => return err!(VaultError::InvalidMergeK),
    }

    // ----- Consume each non-zero (active) input by creating its nullifier PDA -----
    // The proof binds zero-nullifier slots to inactive, so a padded slot creates
    // no PDA. `remaining_accounts` holds exactly one PDA per non-zero nullifier,
    // in order.
    let zero = [0u8; 32];
    let spent_slot = Clock::get()?.slot;
    let mut accts = ctx.remaining_accounts.iter();
    for nf in nullifiers.iter() {
        if *nf == zero {
            continue;
        }
        let ai = accts
            .next()
            .ok_or(error!(VaultError::MergeAccountMismatch))?;
        create_nullifier_pda(
            ai,
            &ctx.accounts.payer,
            &ctx.accounts.system_program,
            nf,
            spent_slot,
        )?;
    }
    // No extra accounts should remain.
    require!(accts.next().is_none(), VaultError::MergeAccountMismatch);

    // ----- Mint the output note: append its commitment as a new leaf -----
    // Capture the leaf_index the same way `deposit` does (the slot the leaf
    // lands at, BEFORE append_leaf bumps leaf_count) so `NoteMerged` can carry
    // it — the off-chain mirror + the client both need the EXACT index, which a
    // post-hoc leaf_count read can't give under concurrent appends.
    let (leaf_index, new_root) = {
        let zsr = ctx.accounts.vault_config.load()?.zero_subtree_roots;
        let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
        let leaf_index = tree.leaf_count;
        let new_root = append_leaf(tree, &zsr, output_commitment)?;
        (leaf_index, new_root)
    };

    // NOTE: OutstandingMint is intentionally UNCHANGED — value in == value out.

    emit!(NoteMerged {
        tree_id,
        output_commitment,
        token_mint,
        k,
        leaf_index,
        new_root,
    });
    Ok(())
}

/// Manually create + populate a `NullifierEntry` PDA (zero-copy). Mirrors
/// `tee_forced_settle::create_relock_pda`. Fails if the PDA already exists
/// (double-spend / double-merge guard).
fn create_nullifier_pda<'info>(
    ai: &AccountInfo<'info>,
    payer: &Signer<'info>,
    system_program: &Program<'info, System>,
    nullifier: &[u8; 32],
    spent_slot: u64,
) -> Result<()> {
    let (expected, bump) =
        Pubkey::find_program_address(&[NullifierEntry::SEED, nullifier.as_ref()], &crate::ID);
    require_keys_eq!(ai.key(), expected, VaultError::MergeAccountMismatch);
    require!(
        ai.data_is_empty() && ai.lamports() == 0,
        VaultError::NoteAlreadyConsumed
    );

    let space = 8 + size_of::<NullifierEntry>();
    let lamports = Rent::get()?.minimum_balance(space);
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[NullifierEntry::SEED, nullifier.as_ref(), &bump_arr];
    let signer_seeds = &[seeds];

    system_program::create_account(
        CpiContext::new_with_signer(
            system_program.to_account_info(),
            system_program::CreateAccount {
                from: payer.to_account_info(),
                to: ai.to_account_info(),
            },
            signer_seeds,
        ),
        lamports,
        space as u64,
        &crate::ID,
    )?;

    let mut data = ai.try_borrow_mut_data()?;
    data[..8].copy_from_slice(NullifierEntry::DISCRIMINATOR);
    let (_head, body) = data.split_at_mut(8);
    let n: &mut NullifierEntry = bytemuck::from_bytes_mut(body);
    n.nullifier = *nullifier;
    n.spent_slot = spent_slot;
    n.bump = bump;
    n._padding = [0u8; 7];
    Ok(())
}

#[event]
pub struct NoteMerged {
    /// Shard the merged output leaf was appended to (routes the off-chain mirror).
    pub tree_id: u8,
    pub output_commitment: [u8; 32],
    pub token_mint: Pubkey,
    pub k: u8,
    /// Tree position the merged output leaf landed at (its inclusion index).
    pub leaf_index: u64,
    pub new_root: [u8; 32],
}
