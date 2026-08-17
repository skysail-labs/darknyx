//! In-pool note merge (VALID_MERGE K=2/4).
//!
//! Consumes K input notes (all the same owner + mint, each in the Merkle tree)
//! and mints ONE output note whose amount is their sum — no external transfer.
//! Used to consolidate fragmented notes so a user can place an order larger than
//! any single note (then over-collateralization returns the surplus as change).
//!
//! Conservation: K notes consumed + 1 minted, same mint, same total ⇒ the
//! per-mint `OutstandingMint` counter is UNCHANGED (the pool owes the user the
//! same total). Replay is guarded by the per-input `ConsumedNoteEntry` PDA
//! (tag-keyed) — created manually here (fails if it already exists), the
//! SAME consume-once guard `withdraw` + TEE settle use. This closes C-01 (audit):
//! merge previously keyed a separate nullifier-based guard, disjoint from
//! settle's old commitment-keyed `ConsumedNoteEntry`, so the same note could be
//! consumed once by merge and once by settle (double-spend). Dummy padding
//! slots emit a public input use tag of 0 (the circuit binds them inactive),
//! so they create no PDA and can't smuggle a spend.

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
pub struct Merge {
    /// Any signer pays rent for the new consumed-note PDAs + output leaf. Authority
    /// is the ZK proof.
    #[account(mut)]
    pub payer: Signer,

    /// Global config — read-only (provides `zero_subtree_roots`).
    #[account(seeds = [VaultConfig::SEED], bump = vault_config.bump)]
    pub vault_config: Account<VaultConfig>,

    /// The Merkle-tree shard the inputs live in + the merged output is appended to.
    #[account(mut, seeds = [MerkleTree::SEED, &[tree_id]], bump = merkle_tree.bump)]
    pub merkle_tree: Account<MerkleTree>,

    pub system_program: Program<System>,
    // `remaining_accounts` contains two same-length runs, each in active
    // input-use-tag order: first the writable, uninitialised
    // ConsumedNoteEntry PDAs; then the read-only NoteLock PDAs, which may be
    // absent OR present-but-expired — only a LIVE lock blocks the merge, as
    // decided by `note_lock_is_live` (S-03). Dummy zero tags contribute
    // no accounts.
}

#[allow(clippy::too_many_arguments)]
pub fn merge_handler<'info>(
    ctx: &mut Context<Merge>,
    tree_id: u8,
    input_use_tags: Vec<[u8; 32]>,
    output_commitment: [u8; 32],
    token_mint: Address,
    merkle_root: [u8; 32],
    k: u8,
    proof: Groth16Proof,
) -> Result<()> {
    require!(
        (k == 2 || k == 4) && input_use_tags.len() == k as usize,
        VaultError::InvalidMergeK
    );

    // N-04: merge and settlement share the TAG-keyed consume guard, but
    // merge must also respect the order pin. Otherwise an owner can merge a
    // live order's input, making its later settle fail and griefing the
    // counterparty until lock expiry. Require exactly one absent NoteLock PDA
    // for every active input before proof verification or state mutation.
    let active_tags: Vec<&[u8; 32]> = input_use_tags
        .iter()
        .filter(|tag| **tag != [0u8; 32])
        .collect();
    let active_len = active_tags.len();
    // N-14 defense-in-depth: reject the all-dummy transport before proof work
    // or a tree append. The circuit independently requires at least one active,
    // positive input and a positive output amount.
    require!(active_len > 0, VaultError::EmptyMerge);
    // v2: `remaining_accounts` is a method returning an owned
    // `Vec<AccountView>`, not a borrowed slice field. It must be bound before
    // splitting — splitting a temporary would leave the halves dangling.
    let remaining = ctx.remaining_accounts()?;
    require!(
        remaining.len() == active_len.saturating_mul(2),
        VaultError::MergeAccountMismatch
    );
    let (consumed_accounts, note_lock_accounts) = remaining.split_at(active_len);
    // S-11: active inputs must be pairwise DISTINCT. Two identical active
    // tags would make the circuit's `outputAmount` double-count one
    // note. That is currently unreachable — the second
    // `create_consumed_note_pda` sees the account already created, and the
    // System Program independently rejects a duplicate `create_account` — but
    // the whole guarantee resting on one runtime behaviour, with no in-circuit
    // backstop and no negative test, is not a place to leave value
    // conservation. K <= 4, so the O(K^2) scan is free.
    for (i, a) in active_tags.iter().enumerate() {
        for b in active_tags.iter().skip(i + 1) {
            require!(a != b, VaultError::DuplicateMergeInput);
        }
    }
    let now_slot = Clock::get()?.slot;
    for (tag, note_lock) in active_tags.iter().zip(note_lock_accounts) {
        let (expected, _) =
            Address::find_program_address(&[NoteLock::SEED, tag.as_ref()], &crate::ID);
        require_keys_eq!(note_lock.address(), expected, VaultError::MergeAccountMismatch);
        // S-03: only a LIVE lock blocks the merge (N-04's intent — stop an
        // owner merging a live order's collateral and griefing the
        // counterparty — is preserved; an EXPIRED lock no longer bricks it).
        require!(
            !crate::state::note_lock_is_live(note_lock, now_slot)?,
            VaultError::NoteAlreadyLocked
        );
    }

    // Merkle root must be recent in THIS shard (membership proofs built against it).
    require!(
        ctx.accounts.merkle_tree.contains_root(&merkle_root),
        VaultError::StaleMerkleRoot
    );

    // ----- Verify the VALID_MERGE proof (VK chosen by K) -----
    // Public signals (snarkjs order: outputs first, then public inputs):
    //   [outputCommitment, inputUseTags[0..K-1], merkleRoot, mint_lo, mint_hi]
    // (C-01: the input tags are PUBLIC outputs, right after
    // outputCommitment, replacing the trailing nullifiers.)
    let [mint_lo, mint_hi] = pubkey_pair_be32(&token_mint.to_bytes());
    match k {
        2 => {
            let pi: [[u8; 32]; 6] = [
                output_commitment,
                input_use_tags[0],
                input_use_tags[1],
                merkle_root,
                mint_lo,
                mint_hi,
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
                input_use_tags[0],
                input_use_tags[1],
                input_use_tags[2],
                input_use_tags[3],
                merkle_root,
                mint_lo,
                mint_hi,
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
        _ => return Err(Error::from(VaultError::InvalidMergeK)),
    }

    // ----- Consume each non-zero (active) input by creating its ConsumedNoteEntry -----
    // The proof binds inactive slots to a zero input-commitment, so a padded slot
    // creates no PDA. `remaining_accounts` holds exactly one PDA per non-zero
    // input commitment, in order.
    // Reuse the slot already read for the lock-liveness check — same
    // transaction, therefore the same slot, and one fewer sysvar read.
    let spent_slot = now_slot;
    for (commitment, ai) in active_tags.iter().zip(consumed_accounts) {
        create_consumed_note_pda(
            ai,
            &ctx.accounts.payer,
            &ctx.accounts.system_program,
            commitment,
            spent_slot,
        )?;
    }

    // ----- Mint the output note: append its commitment as a new leaf -----
    // Capture the leaf_index the same way `deposit` does (the slot the leaf
    // lands at, BEFORE append_leaf bumps leaf_count) so `NoteMerged` can carry
    // it — the off-chain mirror + the client both need the EXACT index, which a
    // post-hoc leaf_count read can't give under concurrent appends.
    let (leaf_index, new_root) = {
        let zsr = ctx.accounts.vault_config.zero_subtree_roots;
        let tree = &mut ctx.accounts.merkle_tree;
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
        leaf_index: leaf_index.get(),
        new_root,
    });
    Ok(())
}

/// Manually create + populate a `ConsumedNoteEntry` PDA (zero-copy), keyed on
/// the note COMMITMENT — the SAME consume-once guard `withdraw` inits and TEE
/// settle inits (`consumed_a/b`). Mirrors `tee_forced_settle::create_relock_pda`.
/// Fails if the PDA already exists (a prior withdraw / settle / merge already
/// consumed this note → double-spend). `match_id` is the all-zero sentinel
/// (merge is not a match), matching `withdraw`'s `ConsumedNoteEntry`.
fn create_consumed_note_pda<'info>(
    ai: &AccountView,
    payer: &Signer,
    system_program: &Program<System>,
    note_use_tag: &[u8; 32],
    consumed_slot: u64,
) -> Result<()> {
    let (expected, bump) = Address::find_program_address(
        &[ConsumedNoteEntry::SEED, note_use_tag.as_ref()],
        &crate::ID,
    );
    require_keys_eq!(ai.address(), expected, VaultError::MergeAccountMismatch);
    require!(
        ai.data_is_empty() && ai.lamports() == 0,
        VaultError::NoteAlreadyConsumed
    );

    let space = 8 + size_of::<ConsumedNoteEntry>();
    let lamports = Rent::get()?.minimum_balance(space);
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[ConsumedNoteEntry::SEED, note_use_tag.as_ref(), &bump_arr];
    let signer_seeds = &[seeds];

    system_program::create_account(
        CpiContext::new_with_signer(
            system_program.address(),
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
    data[..8].copy_from_slice(ConsumedNoteEntry::DISCRIMINATOR);
    let (_head, body) = data.split_at_mut(8);
    let c: &mut ConsumedNoteEntry = bytemuck::from_bytes_mut(body);
    c.note_use_tag = *note_use_tag;
    c.match_id = [0u8; 16];
    c.consumed_slot = (consumed_slot).into();
    c.bump = bump;
    c._padding = [0u8; 7];
    Ok(())
}

#[event]
pub struct NoteMerged {
    /// Shard the merged output leaf was appended to (routes the off-chain mirror).
    pub tree_id: u8,
    pub output_commitment: [u8; 32],
    pub token_mint: Address,
    pub k: u8,
    /// Tree position the merged output leaf landed at (its inclusion index).
    pub leaf_index: u64,
    pub new_root: [u8; 32],
}
