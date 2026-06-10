//! v3.5 — TEE-forced atomic settlement, batched-marker variant.
//!
//! Mirror of `tee_forced_settle` (per-match `ValidCreateMarker` +
//! `ValidPriceMarker` flow) except the two markers are collapsed into
//! ONE `BatchValidityMarker`. The marker is written by the upstream
//! `verify_match_batch` ix and seeded by the Merkle root over up-to-16
//! per-slot leaves.
//!
//! The handler:
//!   1. Verifies the TEE Ed25519 signature over canonical_payload_hash
//!      (identical to the per-match flow).
//!   2. Recomputes the per-slot leaf from the payload + the input
//!      locks' mints (Poseidon12 + Poseidon9 — must byte-match the
//!      circuit's `MatchSlot` template).
//!   3. Walks a fixed-depth-4 Merkle inclusion path (N=16) using the
//!      provided sibling hashes + match_index.
//!   4. Asserts the BatchValidityMarker PDA exists at the
//!      [b"batch_validity", root]-derived address + non-expired.
//!   5. Applies the same conservation laws + state mutations as the
//!      per-match handler. (Lock + consumed-note + nullifier writes +
//!      Merkle-tree appends + optional re-locks.)
//!   6. Closes the marker, refunding rent to `tee_authority`.
//!
//! Coexists with `tee_forced_settle` during the cutover window. The
//! matcher chooses which path to use; once the batched path proves
//! out on devnet, the per-match ix + its two markers can be deleted
//! in a follow-up vault upgrade.
//!
//! Hardcoded N=16: the proof's Merkle tree is depth 4. Smaller batch
//! sizes (N=2 / N=4) are for circuit-side scaling validation; the
//! on-chain handler accepts N=16 only.

use crate::errors::VaultError;
use crate::instructions::tee_forced_settle::{
    canonical_payload_hash, verify_tee_signature, MatchResultPayload, TradeSettled,
};
use crate::merkle::append_leaf;
use crate::state::*;
use anchor_lang::prelude::*;
use core::mem::size_of;

// Target-gated Poseidon imports — `programs/vault/Cargo.toml` makes
// `light-poseidon` available only on host builds and `solana-poseidon`
// only on the SBF (`target_os = "solana"`) build. Same pattern as
// `merkle.rs::poseidon2`.
#[cfg(not(target_os = "solana"))]
use ark_bn254::Fr;
#[cfg(not(target_os = "solana"))]
use light_poseidon::{Poseidon, PoseidonBytesHasher};
#[cfg(target_os = "solana")]
use solana_poseidon::{hashv as solana_poseidon_hashv, Endianness, Parameters};

/// Generic Poseidon-BN254X5 over `inputs.len()` field elements. Inputs
/// are 32-byte big-endian field-element encodings.
///
/// On SBF (`target_os = "solana"`) this routes through the
/// `solana_poseidon` syscall wrapper — fast, supports widths up to 13
/// (= nInputs ≤ 12, matching `light_poseidon`'s MAX_X5_LEN).
/// On host this uses the pure-Rust `light_poseidon` path. Both produce
/// byte-identical outputs.
fn poseidon_n(inputs: &[&[u8]]) -> Result<[u8; 32]> {
    #[cfg(target_os = "solana")]
    {
        return solana_poseidon_hashv(Parameters::Bn254X5, Endianness::BigEndian, inputs)
            .map(|h| h.to_bytes())
            .map_err(|_| error!(VaultError::InvalidBatchBinding));
    }
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
            .map_err(|_| error!(VaultError::InvalidBatchBinding))?;
        hasher
            .hash_bytes_be(inputs)
            .map_err(|_| error!(VaultError::InvalidBatchBinding))
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Pad a u64 to a 32-byte big-endian field-element encoding.
fn u64_be32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Split a 32-byte pubkey into [lo_u128_be32, hi_u128_be32]. Matches the
/// `pubkey_pair_be32` helper used by VALID_CREATE / VALID_SPEND and the
/// `pubkeyToFrPair` helper in the TS prover.
///
/// hi = the FIRST 16 bytes of the pubkey, viewed as a u128.
/// lo = the LAST 16 bytes.
fn pubkey_be32_pair(pk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&pk[16..32]);
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&pk[0..16]);
    (lo, hi)
}

/// Compute the per-slot leaf hash. MUST byte-match `template MatchSlot()` in
/// `circuits/templates/match_batch.circom`:
///
///   h1   = Poseidon12(DOMAIN_LEAF_INNER=20,
///                     note_a, note_b, note_c, note_d, note_e, note_f,
///                     qm_lo, qm_hi, bm_lo, bm_hi,
///                     base_amount)
///   leaf = Poseidon9 (DOMAIN_LEAF_TOP=21, h1,
///                     quote_amount,
///                     buyer_change_amt, seller_change_amt,
///                     buyer_fee_amt, seller_fee_amt,
///                     clearing_price, batch_slot)
// Exposed for integration tests that need to fabricate a Merkle root
// without running the full `verify_match_batch` Groth16 verifier (see
// `programs/matching_engine/tests/tee_forced_settle_batched.rs`).
pub fn compute_match_leaf(
    payload: &MatchResultPayload,
    quote_mint: &Pubkey,
    base_mint: &Pubkey,
) -> Result<[u8; 32]> {
    let (qm_lo, qm_hi) = pubkey_be32_pair(&quote_mint.to_bytes());
    let (bm_lo, bm_hi) = pubkey_be32_pair(&base_mint.to_bytes());
    let domain_inner = u64_be32(20); // DOMAIN_LEAF_INNER
    let base_amount = u64_be32(payload.base_amount);

    let h1 = poseidon_n(&[
        &domain_inner,
        payload.note_a_commitment.as_ref(),
        payload.note_b_commitment.as_ref(),
        payload.note_c_commitment.as_ref(),
        payload.note_d_commitment.as_ref(),
        payload.note_e_commitment.as_ref(),
        payload.note_f_commitment.as_ref(),
        &qm_lo,
        &qm_hi,
        &bm_lo,
        &bm_hi,
        &base_amount,
    ])?;

    let domain_top = u64_be32(21); // DOMAIN_LEAF_TOP
    let quote_amount = u64_be32(payload.quote_amount);
    let buyer_change = u64_be32(payload.buyer_change_amt);
    let seller_change = u64_be32(payload.seller_change_amt);
    let buyer_fee = u64_be32(payload.buyer_fee_amt);
    let seller_fee = u64_be32(payload.seller_fee_amt);
    let clearing_price = u64_be32(payload.clearing_price);
    let batch_slot = u64_be32(payload.batch_slot);

    let leaf = poseidon_n(&[
        &domain_top,
        &h1,
        &quote_amount,
        &buyer_change,
        &seller_change,
        &buyer_fee,
        &seller_fee,
        &clearing_price,
        &batch_slot,
    ])?;

    Ok(leaf)
}

/// Walk a depth-4 Merkle inclusion path from `leaf` up to the root, hashing
/// at each level with the supplied sibling. `match_index` bits select
/// left/right at each level (bit 0 = level 0; 0 = current is left child,
/// 1 = current is right child). MUST match the circuit's `MerkleRoot(16)`
/// template and the TS-side `merkleInclusionPath()` helper.
// Exposed alongside `compute_match_leaf` for the same test-only
// reason — see the comment above that fn.
pub fn walk_merkle_path_n16(
    leaf: &[u8; 32],
    match_index: u8,
    proof: &[[u8; 32]; 4],
) -> Result<[u8; 32]> {
    if match_index >= 16 {
        return err!(VaultError::InvalidBatchBinding);
    }
    let domain = u64_be32(22); // DOMAIN_BATCH_ROOT
    let mut current = *leaf;
    // iter().enumerate() avoids clippy::needless_range_loop while still
    // letting us read the level index `i` for the left/right selector.
    for (i, sibling) in proof.iter().enumerate() {
        let going_right = ((match_index >> i) & 1) == 1;
        let (left, right): (&[u8; 32], &[u8; 32]) = if going_right {
            (sibling, &current)
        } else {
            (&current, sibling)
        };
        current = poseidon_n(&[&domain, left, right])?;
    }
    Ok(current)
}

// ----------------------------------------------------------------------------
// Accounts + handler
// ----------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(tree_id: u8, payload: MatchResultPayload, match_index: u8, merkle_proof: [[u8; 32]; 4])]
pub struct TeeForcedSettleBatched<'info> {
    #[account(mut)]
    pub tee_authority: Signer<'info>,

    /// Global config — READ-ONLY on the settle hot path (authorized-key check +
    /// protocol_owner_commitment + zero_subtree_roots). Read-only is the whole
    /// point of sharding: the output append goes to `merkle_tree` below, so two
    /// settles on different shards share no writable account.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    /// The Merkle-tree shard this settle appends its output notes to. Different
    /// matches round-robin across shards → no write-conflict → the leader can
    /// co-include + parallelize them.
    #[account(
        mut,
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.load()?.bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTree>,

    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_a_commitment.as_ref()],
        bump,
        close = tee_authority,
    )]
    pub note_lock_a: AccountLoader<'info, NoteLock>,

    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_b_commitment.as_ref()],
        bump,
        close = tee_authority,
    )]
    pub note_lock_b: AccountLoader<'info, NoteLock>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<ConsumedNoteEntry>(),
        seeds = [ConsumedNoteEntry::SEED, payload.note_a_commitment.as_ref()],
        bump,
    )]
    pub consumed_a: AccountLoader<'info, ConsumedNoteEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<ConsumedNoteEntry>(),
        seeds = [ConsumedNoteEntry::SEED, payload.note_b_commitment.as_ref()],
        bump,
    )]
    pub consumed_b: AccountLoader<'info, ConsumedNoteEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NullifierEntry>(),
        seeds = [NullifierEntry::SEED, payload.nullifier_a.as_ref()],
        bump,
    )]
    pub nullifier_a_entry: AccountLoader<'info, NullifierEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = 8 + size_of::<NullifierEntry>(),
        seeds = [NullifierEntry::SEED, payload.nullifier_b.as_ref()],
        bump,
    )]
    pub nullifier_b_entry: AccountLoader<'info, NullifierEntry>,

    /// CHECK: Seeds validated in handler when re-lock is requested.
    #[account(mut)]
    pub note_lock_e: UncheckedAccount<'info>,

    /// CHECK: Seeds validated in handler when re-lock is requested.
    #[account(mut)]
    pub note_lock_f: UncheckedAccount<'info>,

    /// Instructions sysvar — for Ed25519 precompile inspection.
    /// CHECK: Address validated via `address = sysvar_id()`.
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    /// v3.5 — single batch-validity marker. PDA seed = the Merkle root
    /// computed in the handler from (leaf, merkle_proof, match_index).
    /// Marker must already exist (written by an upstream
    /// `verify_match_batch` ix) and be unexpired.
    ///
    /// One marker covers ALL matches in the batch (it's keyed by the
    /// batch's Merkle root, which is identical across every match
    /// position), so this handler does NOT close it — closing here
    /// would brick every subsequent match in the same batch. The
    /// marker is left open and may be reclaimed by a follow-up
    /// cleanup ix once the batch is fully settled.
    ///
    /// CHECK: Validated via the binding check in the handler (PDA
    /// address recomputed from `[SEED, merkle_root]`; existence +
    /// expiry asserted before any state mutation).
    #[account(mut)]
    pub batch_validity_marker: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn tee_forced_settle_batched_handler(
    ctx: Context<TeeForcedSettleBatched>,
    _tree_id: u8,
    payload: MatchResultPayload,
    match_index: u8,
    merkle_proof: [[u8; 32]; 4],
) -> Result<()> {
    let clock = Clock::get()?;
    // The signer must be one of the authorized TEE keys (the shard
    // fee-payer/authority set); the ed25519 sig is bound to THAT key.
    let tee_pubkey = ctx.accounts.tee_authority.key();
    require!(
        ctx.accounts
            .vault_config
            .load()?
            .is_authorized_tee(&tee_pubkey),
        VaultError::Unauthorized
    );

    // Ed25519 precompile binds the TEE signature to the canonical hash
    // of the payload. Identical to the per-match flow.
    verify_tee_signature(
        &ctx.accounts.instructions_sysvar,
        &tee_pubkey,
        &canonical_payload_hash(&payload),
    )?;

    // ────────────────────────────────────────────────────────────────────
    // v3.5 batch-marker check. Replaces the two per-match marker checks.
    //
    // Recompute the leaf hash from payload + lock mints, walk the depth-4
    // Merkle path with the provided siblings + match_index, derive the
    // expected `BatchValidityMarker` PDA address, and assert this account
    // is at that address + owned by us + non-expired.
    // ────────────────────────────────────────────────────────────────────
    // Quote mint is lock_a's mint (buyer pays quote → note_a is quote); base
    // mint is lock_b's. Cache the two MINTS here (a single load of each lock):
    // the batch-binding leaf needs them, AND the re-locks below stamp them onto
    // the continuation NoteLock (note_e is quote, note_f is base) so the NEXT
    // batch that consumes the continuation reads back a correct mint. The locks
    // themselves are re-loaded further below for the order_id/amount validation.
    let (lock_a_mint, lock_b_mint) = {
        let la = ctx.accounts.note_lock_a.load()?;
        let lb = ctx.accounts.note_lock_b.load()?;
        (la.token_mint, lb.token_mint)
    };
    {
        let leaf = compute_match_leaf(&payload, &lock_a_mint, &lock_b_mint)?;
        let computed_root = walk_merkle_path_n16(&leaf, match_index, &merkle_proof)?;

        let (expected_marker_pda, _) = Pubkey::find_program_address(
            &[BatchValidityMarker::SEED, computed_root.as_ref()],
            &crate::ID,
        );
        require_keys_eq!(
            ctx.accounts.batch_validity_marker.key(),
            expected_marker_pda,
            VaultError::InvalidBatchBinding
        );

        let marker_info = ctx.accounts.batch_validity_marker.to_account_info();
        require!(
            marker_info.owner == &crate::ID,
            VaultError::InvalidBatchBinding
        );
        let marker_data = marker_info.try_borrow_data()?;
        require!(
            marker_data.len() >= 8 + 32 + 8,
            VaultError::InvalidBatchBinding
        );
        let expiry_slot = u64::from_le_bytes(marker_data[8 + 32..8 + 32 + 8].try_into().unwrap());
        drop(marker_data);
        require!(
            clock.slot < expiry_slot,
            VaultError::BatchValidityMarkerExpired
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // From here down, IDENTICAL to `tee_forced_settle_handler` — lock
    // checks, conservation laws, consumed-note / nullifier writes,
    // Merkle-tree appends, optional re-locks. We duplicate rather than
    // share via a helper because the parent Context<T> types differ
    // (TeeForcedSettle vs TeeForcedSettleBatched); a refactor into a
    // shared inner function can wait until the old ix is retired.
    // ────────────────────────────────────────────────────────────────────
    {
        let lock_a = ctx.accounts.note_lock_a.load()?;
        let lock_b = ctx.accounts.note_lock_b.load()?;
        require!(
            lock_a.order_id == payload.order_id_a,
            VaultError::NoteNotLockedForOrder
        );
        require!(
            lock_b.order_id == payload.order_id_b,
            VaultError::NoteNotLockedForOrder
        );

        let expected_a = payload
            .quote_amount
            .checked_add(payload.buyer_change_amt)
            .and_then(|v| v.checked_add(payload.buyer_fee_amt))
            .ok_or(error!(VaultError::ArithmeticOverflow))?;
        require!(
            lock_a.amount == expected_a,
            VaultError::ConservationViolation
        );
        let expected_b = payload
            .base_amount
            .checked_add(payload.seller_change_amt)
            .and_then(|v| v.checked_add(payload.seller_fee_amt))
            .ok_or(error!(VaultError::ArithmeticOverflow))?;
        require!(
            lock_b.amount == expected_b,
            VaultError::ConservationViolation
        );

        let has_e = payload.note_e_commitment != [0u8; 32];
        let has_f = payload.note_f_commitment != [0u8; 32];
        require!(
            has_e == (payload.buyer_change_amt > 0),
            VaultError::ChangeNoteInconsistent
        );
        require!(
            has_f == (payload.seller_change_amt > 0),
            VaultError::ChangeNoteInconsistent
        );

        if payload.buyer_relock_order_id != [0u8; 16] {
            require!(has_e, VaultError::RelockRequiresChangeNote);
        }
        if payload.seller_relock_order_id != [0u8; 16] {
            require!(has_f, VaultError::RelockRequiresChangeNote);
        }
    }

    // Mark consumed notes.
    let ca = &mut ctx.accounts.consumed_a.load_init()?;
    ca.note_commitment = payload.note_a_commitment;
    ca.match_id = payload.match_id;
    ca.consumed_slot = clock.slot;
    ca.bump = ctx.bumps.consumed_a;
    ca._padding = [0u8; 7];

    let cb = &mut ctx.accounts.consumed_b.load_init()?;
    cb.note_commitment = payload.note_b_commitment;
    cb.match_id = payload.match_id;
    cb.consumed_slot = clock.slot;
    cb.bump = ctx.bumps.consumed_b;
    cb._padding = [0u8; 7];

    // Mark nullifiers spent.
    let na = &mut ctx.accounts.nullifier_a_entry.load_init()?;
    na.nullifier = payload.nullifier_a;
    na.spent_slot = clock.slot;
    na.bump = ctx.bumps.nullifier_a_entry;
    na._padding = [0u8; 7];

    let nb = &mut ctx.accounts.nullifier_b_entry.load_init()?;
    nb.nullifier = payload.nullifier_b;
    nb.spent_slot = clock.slot;
    nb.bump = ctx.bumps.nullifier_b_entry;
    nb._padding = [0u8; 7];

    // Append output leaves to THIS shard: note_c, note_d, note_e (if any),
    // note_f (if any), then the two batch fee notes (base, quote) if any.
    // `zero_subtree_roots` + the protocol-owner gate come from the read-only
    // global config; the appends mutate only `merkle_tree`.
    let (zsr, protocol_owner_set) = {
        let cfg = ctx.accounts.vault_config.load()?;
        (
            cfg.zero_subtree_roots,
            cfg.protocol_owner_commitment != [0u8; 32],
        )
    };
    let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
    let leaf_c = tree.leaf_count;
    let _ = append_leaf(tree, &zsr, payload.note_c_commitment)?;
    let leaf_d = tree.leaf_count;
    let mut new_root = append_leaf(tree, &zsr, payload.note_d_commitment)?;

    let leaf_e = if payload.note_e_commitment != [0u8; 32] {
        let idx = tree.leaf_count;
        new_root = append_leaf(tree, &zsr, payload.note_e_commitment)?;
        idx
    } else {
        u64::MAX
    };
    let leaf_f = if payload.note_f_commitment != [0u8; 32] {
        let idx = tree.leaf_count;
        new_root = append_leaf(tree, &zsr, payload.note_f_commitment)?;
        idx
    } else {
        u64::MAX
    };

    // Two batch-level protocol fee notes, one per mint: base (seller-side
    // fees) + quote (buyer-side fees). Only the first settlement in a batch
    // carries them; both `[0;32]` otherwise. Symmetric to the per-match
    // output leaves above — settle never touches `outstanding` (value is
    // conserved out of the consumed note_a/b; the fee note just lets the
    // protocol claim its share via the normal VALID_SPEND path).
    let leaf_fee_base = if payload.note_fee_base_commitment != [0u8; 32] {
        require!(protocol_owner_set, VaultError::ProtocolOwnerUnset);
        let idx = tree.leaf_count;
        new_root = append_leaf(tree, &zsr, payload.note_fee_base_commitment)?;
        idx
    } else {
        u64::MAX
    };
    let leaf_fee_quote = if payload.note_fee_quote_commitment != [0u8; 32] {
        require!(protocol_owner_set, VaultError::ProtocolOwnerUnset);
        let idx = tree.leaf_count;
        new_root = append_leaf(tree, &zsr, payload.note_fee_quote_commitment)?;
        idx
    } else {
        u64::MAX
    };

    // Re-locks LAST so a re-lock failure rolls back every preceding
    // state change.
    if payload.buyer_relock_order_id != [0u8; 16] {
        super::tee_forced_settle::create_relock_pda(
            &ctx.accounts.note_lock_e,
            &ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            &payload.note_e_commitment,
            &lock_a_mint, // note_e is the buyer's change → QUOTE
            &payload.buyer_relock_order_id,
            payload.buyer_relock_expiry,
            payload.buyer_change_amt,
        )?;
    }
    if payload.seller_relock_order_id != [0u8; 16] {
        super::tee_forced_settle::create_relock_pda(
            &ctx.accounts.note_lock_f,
            &ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            &payload.note_f_commitment,
            &lock_b_mint, // note_f is the seller's change → BASE
            &payload.seller_relock_order_id,
            payload.seller_relock_expiry,
            payload.seller_change_amt,
        )?;
    }

    // DO NOT close `batch_validity_marker` here. It's a single PDA
    // keyed by the batch's Merkle root and shared across every match
    // in the batch — closing it after match 0 would brick matches
    // 1..N-1 because the existence check at the top of the handler
    // would see `lamports() == 0`. The marker carries an
    // `expiry_slot` so an unclosed-but-expired marker can't be
    // reused; the small rent (~49 bytes) is reclaimable by the
    // `close_batch_validity_marker` ix once the matcher knows the
    // batch is fully settled.

    emit!(TradeSettled {
        tree_id: _tree_id,
        match_id: payload.match_id,
        clearing_price: payload.clearing_price,
        base_amount: payload.base_amount,
        quote_amount: payload.quote_amount,
        buyer_change_amt: payload.buyer_change_amt,
        seller_change_amt: payload.seller_change_amt,
        buyer_fee_amt: payload.buyer_fee_amt,
        seller_fee_amt: payload.seller_fee_amt,
        note_c_leaf: leaf_c,
        note_d_leaf: leaf_d,
        note_e_leaf: leaf_e,
        note_f_leaf: leaf_f,
        note_fee_base_leaf: leaf_fee_base,
        note_fee_quote_leaf: leaf_fee_quote,
        buyer_relock_active: payload.buyer_relock_order_id != [0u8; 16],
        seller_relock_active: payload.seller_relock_order_id != [0u8; 16],
        new_root,
    });
    Ok(())
}
