use crate::errors::VaultError;
use crate::state::*;
use crate::zk::{verifier::make_vk, verify_groth16_proof, vk_valid_input::*, Groth16Proof};
use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;
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
    note_use_tag: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
    token_mint: Address,
    merkle_root: [u8; 32],
    proof: Groth16Proof,
)]
pub struct LockNote {
    /// The TEE-operated relayer. We enforce that `tee_authority.address()` is one of
    /// `vault_config.tee_pubkeys` (the authorized shard fee-payer/signer set) so
    /// only a registered TEE key can lock notes.
    ///
    /// NOTE: even with the registered key gate, the TEE could previously
    /// "lock" any 32-byte handle whether or not it actually existed in
    /// the Merkle tree, with any amount it wanted (see §4.1 of the v2
    /// migration brief). The VALID_INPUT proof closes that hole — the TEE
    /// now must relay a user-generated ZK proof attesting that the
    /// tag is derived from a commitment that exists in the tree with the
    /// declared mint and a private, positive, range-constrained amount.
    #[account(mut)]
    pub tee_authority: Signer,

    // PF-02: read the stored bump instead of re-deriving it. A bare `bump`
    // makes Anchor run `find_program_address`, which averages ~1.4 hash
    // attempts; every other handler (withdraw, deposit, merge, settle) already
    // uses the stored value. This path runs 2N times per batch, so it was the
    // single cheapest CU win in the audit.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,

    /// The Merkle-tree shard the input note lives in. Read-only — we only check
    /// its recent-root ring.
    #[account(
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.bump,
    )]
    pub merkle_tree: Account<MerkleTree>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NoteLock>(),
        seeds = [NoteLock::SEED, note_use_tag.as_ref()],
        bump,
    )]
    pub note_lock: Account<NoteLock>,

    /// U-02 consume-once guard. The tag-keyed `ConsumedNoteEntry` for
    /// this note MUST be ABSENT: a note already settled
    /// (`tee_forced_settle_batched::consumed_a/b`) or withdrawn
    /// (`withdraw::consumed_note`) has this PDA initialized, and a retained
    /// VALID_INPUT proof would otherwise let an authorized TEE re-lock it (rent
    /// waste + stuck state). NOT `init` — this handler must not create it (the
    /// real settle/withdraw own that lifecycle); the address is pinned by seeds
    /// and existence is checked in the handler.
    /// CHECK: seeds pin the address; the handler rejects a already-initialized
    /// (program-owned) account.
    #[account(
        seeds = [ConsumedNoteEntry::SEED, note_use_tag.as_ref()],
        bump,
    )]
    pub consumed_note: UncheckedAccount,

    pub system_program: Program<System>,
}

#[allow(clippy::too_many_arguments)]
pub fn lock_note_handler(
    ctx: &mut Context<LockNote>,
    _tree_id: u8,
    note_use_tag: [u8; 32],
    order_id: [u8; 16],
    expiry_slot: u64,
    token_mint: Address,
    merkle_root: [u8; 32],
    proof: Groth16Proof,
) -> Result<()> {
    let clock = Clock::get()?;

    // TEE-authority gate + Merkle-root recency check (against THIS shard).
    {
        let cfg = ctx.accounts.vault_config;
        require!(
            cfg.is_authorized_tee(&ctx.accounts.tee_authority.address()),
            VaultError::Unauthorized
        );
        // The proof was generated against `merkle_root`; that root must still
        // be in this shard's recent-root ring. Same recency policy as `withdraw`.
        require!(
            ctx.accounts.merkle_tree.contains_root(&merkle_root),
            VaultError::StaleMerkleRoot
        );
    }

    // U-02: reject re-locking an already-consumed note. If the tag-keyed
    // `ConsumedNoteEntry` exists (program-owned), the note was settled or
    // withdrawn; the Merkle leaf survives, so a still-valid VALID_INPUT proof
    // would otherwise pass below. Cheap check first — mirror of the inverted
    // `withdraw` note-lock guard. A non-existent PDA is system-owned → allowed.
    require!(
        ctx.accounts.consumed_note.owner != ctx.program_id,
        VaultError::NoteAlreadyConsumed
    );

    require!(expiry_slot > clock.slot, VaultError::InvalidExpirySlot);
    // v2 hardening: cap how far in the future the lock can sit. The vault's
    // `withdraw` rejects while a NoteLock exists, even an expired one, so the
    // lock window is also the censorship window. See `MAX_LOCK_TTL_SLOTS`.
    require!(
        expiry_slot <= clock.slot.saturating_add(MAX_LOCK_TTL_SLOTS),
        VaultError::InvalidExpirySlot
    );
    // VALID_INPUT public inputs, in the order declared by the circom
    // `component main { public [merkleRoot, noteUseTag, tokenMint] }`.
    // `tokenMint[2]` expands as two entries (`lo`, `hi`) — four total. Amount
    // remains a private positive u64 witness constrained inside the proof.
    let mint_bytes = token_mint.to_bytes();
    let [mint_lo, mint_hi] = pubkey_pair_be32(&mint_bytes);
    let public_inputs: [[u8; 32]; 4] = [merkle_root, note_use_tag, mint_lo, mint_hi];

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
    let lock = &mut ctx.accounts.note_lock;
    lock.note_use_tag = note_use_tag;
    lock.token_mint = token_mint;
    lock.order_id = order_id;
    lock.expiry_slot = expiry_slot;
    lock.locked_by = ctx.accounts.tee_authority.address();
    lock.bump = ctx.bumps.note_lock;
    lock._padding = [0u8; 7];

    emit!(NoteLocked {
        note_use_tag,
        token_mint,
        order_id,
        expiry_slot,
    });
    Ok(())
}

/// A note was locked. Carries the TAG, not the commitment — publishing the
/// commitment in an event would relink the lock to the note's Merkle leaf and
/// undo the point of the tag.
#[event]
pub struct NoteLocked {
    pub note_use_tag: [u8; 32],
    pub token_mint: Address,
    pub order_id: [u8; 16],
    pub expiry_slot: u64,
}
