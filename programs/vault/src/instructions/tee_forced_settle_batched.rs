//! v3 — TEE-forced atomic settlement, batched-marker variant.
//!
//! One `BatchValidityMarker` covers the whole batch, written by the upstream
//! `verify_match_batch` ix and seeded by the Merkle root over up-to-16
//! per-slot leaves.
//!
//! The handler:
//!   1. Verifies the TEE Ed25519 signature over canonical_payload_hash.
//!   2. Recomputes the per-slot leaf from consumed/relock note-use tags plus
//!      created commitments (arity-12 — must byte-match the circuit's
//!      `MatchSlot` template).
//!   3. Walks a fixed-depth-4 Merkle inclusion path (N=16) using the
//!      provided sibling hashes + match_index.
//!   4. Asserts the BatchValidityMarker PDA exists at the
//!      [b"batch_validity", root]-derived address + non-expired.
//!   5. Applies the conservation laws + state mutations: lock +
//!      consumed-note writes, Merkle-tree appends, optional re-locks.
//!   6. Leaves the marker OPEN — one `BatchValidityMarker` covers all N
//!      matches in the batch, so a separate `close_batch_validity_marker`
//!      ix reclaims its rent exactly once, after every match settles.
//!      (Closing it here would brick every match after the first — see §8.2.)
//!
//! This is the ONLY settle entrypoint. Its shared helpers — the payload, the
//! canonical hash, the signature check, the relock allocator — live in
//! `settlement_shared.rs`.
//!
//! Hardcoded N=16: the proof's Merkle tree is depth 4. Smaller batch
//! sizes (N=2 / N=4) are for circuit-side scaling validation; the
//! on-chain handler accepts N=16 only.

use crate::errors::VaultError;
use crate::instructions::settlement_shared::{
    canonical_payload_hash, verify_tee_signature, MatchResultPayload, TradeSettled,
};
use crate::merkle::append_leaves;
use crate::state::*;
use anchor_lang::prelude::*;

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
            .map_err(|_| Error::from(VaultError::InvalidBatchBinding));
    }
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
            .map_err(|_| Error::from(VaultError::InvalidBatchBinding))?;
        hasher
            .hash_bytes_be(inputs)
            .map_err(|_| Error::from(VaultError::InvalidBatchBinding))
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

/// Compute the per-slot leaf hash. MUST byte-match `template MatchSlot()` in
/// `circuits/templates/match_batch.circom`:
///
///   relock_digest = Poseidon3(DOMAIN_RELOCK_DIGEST=30, tag_e, tag_f)
///   leaf = Poseidon12(DOMAIN_LEAF_V3=31, active=1,
///                     tag_a, tag_b, note_c, note_d, note_e, note_f,
///                     note_fee_base, note_fee_quote, batch_slot, relock_digest)
///
/// Amount-private: the leaf binds consumed identities through their tags and
/// created identities through their commitments, so it no longer hashes — and
/// the payload no longer needs to carry — plaintext amounts. The two fee-note
/// commitments are bound here so THIS match's fee-note append is proof-backed:
/// fees are PER-MATCH (each active MatchSlot derives its own
/// `note_fee_base/quote` from that match's consumed commitments), so every
/// settle carries its own match's fee notes — not a batch-aggregate flushed by
/// one slot.
// Exposed for integration tests that need to fabricate a Merkle root
// without running the full `verify_match_batch` Groth16 verifier (see
// `programs/vault/tests/tee_forced_settle_batched.rs`).
pub fn compute_match_leaf(payload: &MatchResultPayload) -> Result<[u8; 32]> {
    let domain = u64_be32(31); // DOMAIN_LEAF_V3
    let batch_slot = u64_be32(payload.batch_slot);

    // The two relock tags are folded into ONE field. Binding them separately
    // would make the leaf 13 inputs against light-poseidon's cap of 12
    // (MAX_X5_LEN = 13) and force the retired two-stage Poseidon12+Poseidon9
    // split back. They must be bound at all because the in-settle relock takes
    // no proof of its own — an unconstrained tag would let an authorized TEE
    // lock an arbitrary note, bounded only by MAX_LOCK_TTL_SLOTS.
    let relock_digest = poseidon_n(&[
        &u64_be32(30), // DOMAIN_RELOCK_DIGEST
        payload.note_e_use_tag.as_ref(),
        payload.note_f_use_tag.as_ref(),
    ])?;

    // TWELVE inputs — EXACTLY at the cap. Adding any further field forces the
    // two-stage split; `leaf_arity_is_at_the_poseidon_cap` pins this.
    let leaf = poseidon_n(&[
        &domain,
        &u64_be32(1), // Tx D can only settle an active proof slot.
        payload.note_a_use_tag.as_ref(),
        payload.note_b_use_tag.as_ref(),
        payload.note_c_commitment.as_ref(),
        payload.note_d_commitment.as_ref(),
        payload.note_e_commitment.as_ref(),
        payload.note_f_commitment.as_ref(),
        payload.note_fee_base_commitment.as_ref(),
        payload.note_fee_quote_commitment.as_ref(),
        &batch_slot,
        relock_digest.as_ref(),
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
        return Err(Error::from(VaultError::InvalidBatchBinding));
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
#[instruction(tree_id: u8, payload: MatchResultPayload)]
pub struct TeeForcedSettleBatched {
    #[account(mut)]
    pub tee_authority: Signer,

    /// Global config — READ-ONLY on the settle hot path (authorized-key check +
    /// protocol_owner_commitment + zero_subtree_roots). Read-only is the whole
    /// point of sharding: the output append goes to `merkle_tree` below, so two
    /// settles on different shards share no writable account.
    #[account(
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,

    /// The Merkle-tree shard this settle appends its output notes to. Different
    /// matches round-robin across shards → no write-conflict → the leader can
    /// co-include + parallelize them.
    #[account(
        mut,
        seeds = [MerkleTree::SEED, &[tree_id]],
        bump = merkle_tree.bump,
    )]
    pub merkle_tree: Account<MerkleTree>,

    // PF-01: both locks store their own bump (`state.rs::NoteLock.bump`,
    // written by `lock_note` and `create_relock_pda`), so read it rather than
    // making Anchor search. `consumed_a`/`consumed_b` below deliberately keep
    // the bare `bump` — they are `init` and store nothing to read back, so
    // the search there is genuine.
    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_a_use_tag.as_ref()],
        bump = note_lock_a.bump,
        close = tee_authority,
    )]
    pub note_lock_a: Account<NoteLock>,

    #[account(
        mut,
        seeds = [NoteLock::SEED, payload.note_b_use_tag.as_ref()],
        bump = note_lock_b.bump,
        close = tee_authority,
    )]
    pub note_lock_b: Account<NoteLock>,

    #[account(
        init,
        payer = tee_authority,
        space = ConsumedNoteEntry::SPACE,
        seeds = [ConsumedNoteEntry::SEED, payload.note_a_use_tag.as_ref()],
        bump,
    )]
    pub consumed_a: Account<ConsumedNoteEntry>,

    #[account(
        init,
        payer = tee_authority,
        space = ConsumedNoteEntry::SPACE,
        seeds = [ConsumedNoteEntry::SEED, payload.note_b_use_tag.as_ref()],
        bump,
    )]
    pub consumed_b: Account<ConsumedNoteEntry>,

    // NOTE: the two per-match nullifier-keyed inits were removed here. The
    // TEE-supplied nullifiers were unconstrained (no nullifier signal in
    // VALID_MATCH_BATCH; `compute_match_leaf` binds the consumed use tags,
    // output commitments + batch_slot), so writing them served no soundness purpose
    // and enabled a griefing freeze (a compromised TEE could pre-claim a
    // victim's future withdraw nullifier) while leaving the real double-spend
    // guard to the tag-keyed `consumed_a/b` above (which `withdraw` now
    // also writes). Dropping them also reclaimed 2 `init` CPIs + 2 accounts off
    // Tx D. Settlement payload v9 removes the now-vestigial nullifier fields
    // from the signed instruction data too, restoring another 64 bytes of
    // transaction headroom.
    /// CHECK: Seeds validated in handler when re-lock is requested. The account
    /// is writable only when the instruction builder sees a non-zero buyer
    /// relock order id; exact-fill/dummy destinations stay read-only.
    pub note_lock_e: UncheckedAccount,

    /// CHECK: Seeds validated in handler when re-lock is requested.
    /// `dup`: on an exact-fill settle, note_lock_e/f both derive from the
    /// `[0;32]` sentinel. Both are read-only in that case; the attribute keeps
    /// the duplicate-account intent explicit.
    ///
    /// NO `dup` attribute under v2, deliberately. v1 carried `#[account(dup)]`
    /// to make the exact-fill aliasing explicit, and v2 demands the
    /// `unsafe(dup)` spelling for it — but `unsafe(dup)` also marks the field
    /// MUTABLE, because its entire purpose is waiving the duplicate-MUTABLE
    /// check (guide §7.3). That has two costs here, neither of them wanted:
    ///
    ///   1. the account becomes required-writable, so every caller must mark it
    ///      writable even on exact-fill paths that never touch it;
    ///   2. on exact-fill `note_lock_e` and `note_lock_f` are both
    ///      `PDA(["note_lock", [0;32]])` — the SAME account — so making it
    ///      writable write-locks one shared PDA across every concurrent settle,
    ///      serialising exactly the settles tree-sharding exists to run in
    ///      parallel.
    ///
    /// Dropping the attribute is safe because the check it waives cannot fire:
    /// neither field carries `mut`, so neither is in the derive's MUT_MASK and
    /// an alias between them ANDs to zero.
    pub note_lock_f: UncheckedAccount,

    /// Instructions sysvar — for Ed25519 precompile inspection.
    /// CHECK: Address validated via `address = sysvar_id()`.
    #[account(address = solana_sdk_ids::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount,

    /// The batch's single validity marker. PDA seed = the Merkle root
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
    pub batch_validity_marker: UncheckedAccount,

    pub system_program: Program<System>,
}

pub fn tee_forced_settle_batched_handler(
    ctx: &mut Context<TeeForcedSettleBatched>,
    _tree_id: u8,
    payload: MatchResultPayload,
    match_index: u8,
    merkle_proof: [[u8; 32]; 4],
) -> Result<()> {
    let clock = Clock::get()?;
    // The signer must be one of the authorized TEE keys (the shard
    // fee-payer/authority set); the ed25519 sig is bound to THAT key.
    let tee_pubkey = *ctx.accounts.tee_authority.address();
    // CU-2: one vault_config load yields everything the handler reads off it —
    // the authorized-key gate, the empty-subtree roots the appends need, and
    // whether a protocol owner is set (the fee-note gate) — instead of loading
    // it again near the appends.
    let (authorized, zsr, protocol_owner_set) = {
        let cfg = &ctx.accounts.vault_config;
        (
            cfg.is_authorized_tee(&tee_pubkey),
            cfg.zero_subtree_roots,
            cfg.protocol_owner_commitment != [0u8; 32],
        )
    };
    require!(authorized, VaultError::Unauthorized);

    // Ed25519 precompile binds the TEE signature to the canonical hash
    // of the payload. Identical to the per-match flow.
    verify_tee_signature(
        &ctx.accounts.instructions_sysvar,
        &tee_pubkey,
        &canonical_payload_hash(&payload),
    )?;

    // ────────────────────────────────────────────────────────────────────
    // Batch-marker check. Replaces the two per-match marker checks.
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
    // CU-2: read every field we need off lock_a/lock_b in ONE load each (the
    // mints for the leaf binding + relock stamping, AND the order_ids for the
    // lock-binding check below), instead of re-loading the locks twice.
    require!(
        ctx.accounts.note_lock_a.account().data_len() == NoteLock::SPACE
            && ctx.accounts.note_lock_b.account().data_len() == NoteLock::SPACE,
        VaultError::InvalidAccountLayout
    );
    let (lock_a_mint, lock_b_mint, lock_a_order_id, lock_b_order_id, lock_a_expiry, lock_b_expiry) = {
        let la = &ctx.accounts.note_lock_a;
        let lb = &ctx.accounts.note_lock_b;
        (
            la.token_mint,
            lb.token_mint,
            la.order_id,
            lb.order_id,
            la.expiry_slot,
            lb.expiry_slot,
        )
    };
    // CS-09: release_lock treats a lock as expired at E, so settlement must be
    // invalid at E too. Check both inputs before any consumed-note allocation,
    // Merkle append, or relock CPI.
    require!(
        clock.slot < lock_a_expiry.get() && clock.slot < lock_b_expiry.get(),
        VaultError::NoteLockExpired
    );
    // C-08: `payload.batch_slot` feeds the leaf hash, and VALID_MATCH_BATCH now
    // binds `batch_slot === slot index`. The leaf is proven included at position
    // `match_index`, so the payload's batch_slot MUST equal match_index — pin it
    // here so a settle can't recompute a valid-looking leaf carrying a different
    // slot value than the position it proves inclusion at.
    require!(
        payload.batch_slot == match_index as u64,
        VaultError::InvalidBatchBinding
    );
    {
        let leaf = compute_match_leaf(&payload)?;
        let computed_root = walk_merkle_path_n16(&leaf, match_index, &merkle_proof)?;

        let (expected_marker_pda, _) = Address::find_program_address(
            &[BatchValidityMarker::SEED, computed_root.as_ref()],
            &crate::ID,
        );
        require_keys_eq!(
            *ctx.accounts.batch_validity_marker.address(),
            expected_marker_pda,
            VaultError::InvalidBatchBinding
        );

        let marker_info = ctx.accounts.batch_validity_marker.account();
        require!(
            marker_info.owner() == &crate::ID,
            VaultError::InvalidBatchBinding
        );
        let marker_data = marker_info.try_borrow()?;
        require!(
            marker_data.len() >= 8 + 32 + 8,
            VaultError::InvalidBatchBinding
        );
        // F-08: this is a RAW read (the marker is an UncheckedAccount so the
        // handler can accept ANY batch's marker by root), so validate the Anchor
        // account discriminator explicitly — owner + length + PDA address are
        // checked above, but the discriminator is what proves the bytes are a
        // `BatchValidityMarker` and not some other program-owned account of the
        // right size.
        require!(
            &marker_data[..8] == BatchValidityMarker::DISCRIMINATOR,
            VaultError::InvalidBatchBinding
        );
        // The length check above guarantees this fixed 8-byte slice exists, so
        // the conversion is infallible; map to a typed error instead of
        // `.unwrap()` to keep panics out of the handler (a panic would fail the
        // tx with an opaque error rather than a program error code).
        let expiry_slot = u64::from_le_bytes(
            marker_data[8 + 32..8 + 32 + 8]
                .try_into()
                .map_err(|_| Error::from(VaultError::InvalidBatchBinding))?,
        );
        drop(marker_data);
        require!(
            clock.slot < expiry_slot,
            VaultError::BatchValidityMarkerExpired
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // From here down, IDENTICAL to `tee_forced_settle_handler` — lock
    // checks, conservation laws, consumed-note writes,
    // Merkle-tree appends, optional re-locks. We duplicate rather than
    // share via a helper because the parent Context<T> types differ
    // (TeeForcedSettle vs TeeForcedSettleBatched); a refactor into a
    // shared inner function can wait until the old ix is retired.
    // ────────────────────────────────────────────────────────────────────
    {
        // order_ids were cached from the single load above (CU-2) — no reload.
        require!(
            lock_a_order_id == payload.order_id_a,
            VaultError::NoteNotLockedForOrder
        );
        require!(
            lock_b_order_id == payload.order_id_b,
            VaultError::NoteNotLockedForOrder
        );

        // Conservation + the exact governed fee are now enforced IN-CIRCUIT
        // (amount-privacy): VALID_MATCH_BATCH range-checks every amount
        // and proves `a_amount === quote+change+fee` (+ the seller leg) and
        // both fee inequalities over PRIVATE amounts, with fee_rate_bps bound to
        // this config as a public input. Together they prove
        // `fee == floor(notional*rate/10000)`. So the chain no longer
        // re-derives or re-checks any of it from plaintext — and the amounts
        // leave the payload entirely. The note commitments + the batch
        // proof bind the values; `NoteLock.amount` is no longer consulted.
        //
        // Change-note PRESENCE is also proven in-circuit
        // (`note_e === (change>0)*hash`), so we only need to know WHETHER a
        // change note exists — to gate the relock below.
        let has_e = payload.note_e_commitment != [0u8; 32];
        let has_f = payload.note_f_commitment != [0u8; 32];

        if payload.buyer_relock_order_id != [0u8; 16] {
            require!(has_e, VaultError::RelockRequiresChangeNote);
        }
        if payload.seller_relock_order_id != [0u8; 16] {
            require!(has_f, VaultError::RelockRequiresChangeNote);
        }
    }

    // Anchor `init` already wrote both typed discriminators. Their tag-keyed
    // PDA existence is the complete consume-once state.

    // (Nullifier writes removed — see the account-struct note above. The
    // tag-keyed `consumed_a/b` are the consume-once guard.)

    // Append output leaves to THIS shard: note_c, note_d, note_e (if any),
    // note_f (if any), then the two batch fee notes (base, quote) if any.
    // `zsr` (empty-subtree roots) + `protocol_owner_set` were read off
    // vault_config at the top (CU-2); the appends mutate only `merkle_tree`.

    // This match's two protocol fee notes, one per mint: base (seller-side
    // fees) + quote (buyer-side fees). Fees are PER-MATCH (amount-privacy):
    // each active MatchSlot derives its own `note_fee_base/quote` from that
    // match's consumed commitments, so every settle in the batch appends its
    // OWN fee notes — not a batch-aggregate that only slot 0 flushes. A leg
    // whose exact fee is zero has a `[0;32]` commitment and is not appended.
    // They mint only once a protocol owner is configured — gate it BEFORE
    // touching the tree so a misconfig fails without leaving partial state.
    // Settle never touches `outstanding` (value is conserved out of the
    // consumed note_a/b; the fee note just lets the protocol claim its share
    // via the normal VALID_SPEND path).
    let has_fee_base = payload.note_fee_base_commitment != [0u8; 32];
    let has_fee_quote = payload.note_fee_quote_commitment != [0u8; 32];
    if has_fee_base || has_fee_quote {
        require!(protocol_owner_set, VaultError::ProtocolOwnerUnset);
    }

    // Gather the output leaves in canonical order and append them in ONE pass.
    // `append_leaves` shares the Merkle-path recomputation across all of them
    // (CU-1): the sequential alternative re-walked all 20 levels per leaf, and
    // for every leaf but the last that walk was provisional work the next leaf
    // overwrote. note_c + note_d always mint; the change + fee notes mint only
    // when non-zero. Each leaf lands at a consecutive index, so its leaf index
    // is `start + its slot in the run`.
    let tree = &mut ctx.accounts.merkle_tree;
    let start = tree.leaf_count.get();
    let mut leaves = [[0u8; 32]; 6];
    let mut n = 0usize;

    let leaf_c = start; // note_c always at slot 0
    leaves[n] = payload.note_c_commitment;
    n += 1;
    let leaf_d = start + 1; // note_d always at slot 1
    leaves[n] = payload.note_d_commitment;
    n += 1;

    let leaf_e = if payload.note_e_commitment != [0u8; 32] {
        let idx = start + n as u64;
        leaves[n] = payload.note_e_commitment;
        n += 1;
        idx
    } else {
        u64::MAX
    };
    let leaf_f = if payload.note_f_commitment != [0u8; 32] {
        let idx = start + n as u64;
        leaves[n] = payload.note_f_commitment;
        n += 1;
        idx
    } else {
        u64::MAX
    };
    let leaf_fee_base = if has_fee_base {
        let idx = start + n as u64;
        leaves[n] = payload.note_fee_base_commitment;
        n += 1;
        idx
    } else {
        u64::MAX
    };
    let leaf_fee_quote = if has_fee_quote {
        let idx = start + n as u64;
        leaves[n] = payload.note_fee_quote_commitment;
        n += 1;
        idx
    } else {
        u64::MAX
    };

    let new_root = append_leaves(tree, &zsr, &leaves[..n])?;

    // Re-locks LAST so a re-lock failure rolls back every preceding
    // state change.
    if payload.buyer_relock_order_id != [0u8; 16] {
        super::settlement_shared::create_relock_pda(
            &mut ctx.accounts.note_lock_e,
            &mut ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            // The TAG, not the commitment. Both are 32 bytes so this compiles
            // either way — passing the commitment would silently create every
            // relock at the wrong address, and the note would then be
            // unspendable because its later consume looks for NoteLock[tag].
            &payload.note_e_use_tag,
            &lock_a_mint, // note_e is the buyer's change → QUOTE
            &payload.buyer_relock_order_id,
            payload.buyer_relock_expiry,
        )?;
    }
    if payload.seller_relock_order_id != [0u8; 16] {
        super::settlement_shared::create_relock_pda(
            &mut ctx.accounts.note_lock_f,
            &mut ctx.accounts.tee_authority,
            &ctx.accounts.system_program,
            &payload.note_f_use_tag,
            &lock_b_mint, // note_f is the seller's change → BASE
            &payload.seller_relock_order_id,
            payload.seller_relock_expiry,
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

#[cfg(test)]
#[cfg(not(target_os = "solana"))]
mod leaf_arity_tests {
    use super::*;

    /// A 32-byte value that is guaranteed < the BN254 modulus.
    ///
    /// `[0xEAu8; 32]` is NOT — it is ~0.91 * 2^256, well above the field, and
    /// `light-poseidon` rejects it as `InvalidBatchBinding` rather than
    /// reducing. That is CLAUDE.md §7.2's documented trap, and the first draft
    /// of these tests walked straight into it. Zeroing the top byte keeps the
    /// value comfortably in range while staying distinguishable.
    fn fr_safe(byte: u8) -> [u8; 32] {
        let mut v = [byte; 32];
        v[0] = 0;
        v
    }

    fn payload_with(tag_e: [u8; 32], tag_f: [u8; 32]) -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11u8; 16],
            note_a_use_tag: fr_safe(0xA1),
            note_b_use_tag: fr_safe(0xB1),
            note_c_commitment: fr_safe(0xC1),
            note_d_commitment: fr_safe(0xD1),
            note_e_commitment: fr_safe(0xE1),
            note_f_commitment: fr_safe(0xF1),
            order_id_a: [0x01u8; 16],
            order_id_b: [0x02u8; 16],
            note_fee_base_commitment: [0u8; 32],
            note_fee_quote_commitment: [0u8; 32],
            buyer_relock_order_id: [0u8; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0u8; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: tag_e,
            note_f_use_tag: tag_f,
            batch_slot: 7,
            fill_recovery: [0u8; 128],
        }
    }

    fn filled<const N: usize>(byte: u8) -> [u8; N] {
        let mut value = [byte; N];
        if N == 32 {
            value[0] = 0;
        }
        value
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut decoded = [0u8; 32];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("fixed vector is valid hex");
        }
        decoded
    }

    /// Cross-language fixed vector shared with
    /// `packages/sdk/tests/batch-binding.test.ts`. This pins not merely the
    /// Poseidon domains, but the exact Rust/TS payload field order and N=16
    /// left/right path convention used by archival fee recovery.
    #[test]
    fn batch_binding_matches_the_sdk_fixed_vector() {
        let payload = MatchResultPayload {
            match_id: filled::<16>(1),
            note_a_use_tag: filled::<32>(2),
            note_b_use_tag: filled::<32>(3),
            note_c_commitment: filled::<32>(4),
            note_d_commitment: filled::<32>(5),
            note_e_commitment: [0u8; 32],
            note_f_commitment: [0u8; 32],
            order_id_a: filled::<16>(6),
            order_id_b: filled::<16>(7),
            note_fee_base_commitment: filled::<32>(8),
            note_fee_quote_commitment: filled::<32>(9),
            buyer_relock_order_id: [0u8; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0u8; 16],
            seller_relock_expiry: 0,
            note_e_use_tag: [0u8; 32],
            note_f_use_tag: [0u8; 32],
            batch_slot: 3,
            fill_recovery: [0u8; 128],
        };
        let siblings = [
            filled::<32>(10),
            filled::<32>(11),
            filled::<32>(12),
            filled::<32>(13),
        ];
        let leaf = compute_match_leaf(&payload).expect("leaf computes");
        assert_eq!(
            leaf,
            decode_hex_32("227bfaf15070d46854c20e13ab209066649c349b6c9ea08b9342b6699623f51a")
        );
        assert_eq!(
            walk_merkle_path_n16(&leaf, 3, &siblings).expect("path computes"),
            decode_hex_32("19ce7fa75f6c9217e42bc2a7659e03583eb481248f2b6fd628bd0495cbcb19c2")
        );
    }

    /// The leaf sits at EXACTLY the `light-poseidon` width cap.
    ///
    /// `MAX_X5_LEN = 13` means at most 12 inputs. The leaf uses all 12, which is
    /// only possible because the two relock tags are folded into one
    /// `relock_digest` field — binding them separately needs 13 and would force
    /// the retired two-stage Poseidon12+Poseidon9 split back.
    ///
    /// This constructs the same 12-input hash `compute_match_leaf` does and
    /// asserts they agree, then shows 13 inputs is rejected outright. Adding a
    /// field to the leaf therefore fails HERE, at the arity, rather than as an
    /// opaque `InvalidBatchBinding` from a devnet settle.
    #[test]
    fn leaf_arity_is_at_the_poseidon_cap() {
        let p = payload_with(fr_safe(0xEA), fr_safe(0xFA));

        let relock_digest = poseidon_n(&[
            &u64_be32(30),
            p.note_e_use_tag.as_ref(),
            p.note_f_use_tag.as_ref(),
        ])
        .expect("relock digest hashes");

        let twelve: [&[u8]; 12] = [
            &u64_be32(31),
            &u64_be32(1),
            p.note_a_use_tag.as_ref(),
            p.note_b_use_tag.as_ref(),
            p.note_c_commitment.as_ref(),
            p.note_d_commitment.as_ref(),
            p.note_e_commitment.as_ref(),
            p.note_f_commitment.as_ref(),
            p.note_fee_base_commitment.as_ref(),
            p.note_fee_quote_commitment.as_ref(),
            &u64_be32(p.batch_slot),
            relock_digest.as_ref(),
        ];
        assert_eq!(twelve.len(), 12, "the leaf must use exactly 12 inputs");
        assert_eq!(
            poseidon_n(&twelve).expect("12 inputs is at the cap"),
            compute_match_leaf(&p).expect("leaf computes"),
            "compute_match_leaf must hash exactly these twelve fields in this order"
        );

        // One more input is over the cap and cannot be hashed at all.
        let mut thirteen: Vec<&[u8]> = twelve.to_vec();
        thirteen.push(p.match_id.as_ref());
        assert!(
            poseidon_n(&thirteen).is_err(),
            "13 inputs must be rejected — adding a leaf field forces the \
             two-stage split back, and this is where that has to be noticed"
        );
    }

    /// The relock tags are BOUND by the leaf.
    ///
    /// They have to be: the in-settle relock takes no proof of its own, so an
    /// unconstrained tag would let an authorized TEE create a `NoteLock` on an
    /// arbitrary note — censorship bounded only by `MAX_LOCK_TTL_SLOTS`.
    /// Changing either tag must change the leaf, which makes the batch Merkle
    /// proof fail against the marker root.
    #[test]
    fn changing_a_relock_tag_changes_the_leaf() {
        let base = compute_match_leaf(&payload_with(fr_safe(0xEA), fr_safe(0xFA))).unwrap();
        assert_ne!(
            base,
            compute_match_leaf(&payload_with(fr_safe(0xEB), fr_safe(0xFA))).unwrap(),
            "note_e_use_tag must be bound by the leaf"
        );
        assert_ne!(
            base,
            compute_match_leaf(&payload_with(fr_safe(0xEA), fr_safe(0xFB))).unwrap(),
            "note_f_use_tag must be bound by the leaf"
        );
    }
}
