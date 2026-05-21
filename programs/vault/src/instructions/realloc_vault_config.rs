//! One-shot migration ix for forward-incompatible `VaultConfig` layout
//! growth. The ZK security-hardening audit bumped `ROOT_HISTORY_SIZE`
//! from 32 to 64, expanding the on-chain `roots` ring buffer by
//! 32 × 32 = 1024 bytes (2488 → 3512 total) AND shifting every field
//! after `roots` by the same 1024 bytes.
//!
//! Anchor's `realloc =` constraint only resizes the buffer; the bytes
//! past `roots` therefore land at the wrong offsets after a naïve
//! realloc, so any subsequent ix that touches `VaultConfig` panics
//! (e.g. `reset_merkle_tree`'s seeds constraint reads the bump byte
//! from the new offset, which is now a hash byte from the old
//! `right_path` slot → `ConstraintSeeds`).
//!
//! Strategy: after Anchor resizes the account, our handler reads the
//! preserved values from their OLD offsets, zero-fills the whole
//! payload, and rewrites them into the NEW offsets. Fields touched:
//!
//! | Field                       | OLD offset | NEW offset | Action          |
//! |-----------------------------|------------|------------|-----------------|
//! | admin / tee_pubkey / rootkey| 8..104     | 8..104     | preserve in place|
//! | leaf_count                  | 104..112   | 104..112   | reset to 0      |
//! | current_root                | 112..144   | 112..144   | recompute empty |
//! | roots [history]             | 144..1168  | 144..2192  | reset to 0      |
//! | zero_subtree_roots          | 1168..1808 | 2192..2832 | move (preserve) |
//! | right_path                  | 1808..2448 | 2832..3472 | reset to 0      |
//! | roots_head                  | 2448       | 3472       | reset to 0      |
//! | bump                        | 2449       | 3473       | set to canonical|
//! | protocol_owner_commitment   | 2450..2482 | 3474..3506 | preserve (move) |
//! | fee_rate_bps                | 2482..2484 | 3506..3508 | preserve (move) |
//! | _padding                    | 2484..2488 | 3508..3512 | zero            |
//!
//! Admin-gated. Idempotent: if the canonical bump byte is already at
//! the NEW offset, the migration ran already and we return Ok without
//! touching state.

use anchor_lang::prelude::*;
use core::mem::size_of;

use crate::errors::VaultError;
use crate::merkle::empty_root;
use crate::state::{VaultConfig, MERKLE_DEPTH};

// Account-data offsets (including the 8-byte Anchor discriminator).
const OLD_ZERO_ROOTS_OFFSET: usize = 1168;
const OLD_BUMP_OFFSET: usize = 2449;
const OLD_PROTOCOL_OWNER_OFFSET: usize = 2450;
const OLD_FEE_RATE_OFFSET: usize = 2482;

const NEW_LEAF_COUNT_OFFSET: usize = 104;
const NEW_CURRENT_ROOT_OFFSET: usize = 112;
const NEW_ZERO_ROOTS_OFFSET: usize = 2192;
const NEW_BUMP_OFFSET: usize = 3473;
const NEW_PROTOCOL_OWNER_OFFSET: usize = 3474;
const NEW_FEE_RATE_OFFSET: usize = 3506;

#[derive(Accounts)]
pub struct ReallocVaultConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// VaultConfig PDA — grown to the current `size_of::<VaultConfig>() + 8`.
    /// The handler does its own admin check by reading the stored admin
    /// from the OLD layout offset (before rewriting), so the seeds
    /// constraint here uses `bump` (no value) — Anchor recomputes via
    /// `find_program_address` rather than trusting the stored bump byte
    /// (which lives at the now-shifted offset).
    ///
    /// Anchor's `realloc` constraint requires a typed account, so we
    /// declare this as `AccountLoader<VaultConfig>`. We intentionally
    /// never call `.load() / .load_mut()` in the handler — those would
    /// bytemuck-cast the pre-migration bytes against the new layout
    /// and produce garbage. Instead the handler reads/writes via
    /// `to_account_info().try_borrow_mut_data()` so layout corrections
    /// happen below the typed layer. The AccountLoader validation
    /// itself only checks disc bytes + size; both are correct after
    /// realloc, so it passes.
    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump,
        realloc = 8 + size_of::<VaultConfig>(),
        realloc::payer = admin,
        realloc::zero = false,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

// `needless_range_loop`: the loops below index into a slice of `data` AND
// into `zero_subtree_roots` simultaneously, so the iterator form would be
// less readable than the explicit index.
#[allow(clippy::needless_range_loop)]
pub fn realloc_vault_config_handler(ctx: Context<ReallocVaultConfig>) -> Result<()> {
    let info = ctx.accounts.vault_config.to_account_info();
    let mut data = info.try_borrow_mut_data()?;

    // Realloc should have brought the buffer up to 3512 bytes.
    require_eq!(
        data.len(),
        8 + size_of::<VaultConfig>(),
        VaultError::Unauthorized
    );

    // Read the admin from the pre-shift offset (same in old + new
    // layouts), then verify the signer matches.
    let mut admin_bytes = [0u8; 32];
    admin_bytes.copy_from_slice(&data[8..40]);
    require_keys_eq!(
        ctx.accounts.admin.key(),
        Pubkey::new_from_array(admin_bytes),
        VaultError::Unauthorized,
    );

    let (_pda, canonical_bump) = Pubkey::find_program_address(&[VaultConfig::SEED], &crate::ID);

    // Idempotency: if the canonical bump byte already sits at the NEW
    // offset, this migration has already run. Doing it again would
    // misinterpret already-correct bytes as the OLD layout and corrupt
    // state. Treat as a no-op success so retries (e.g. dropped tx) are
    // safe.
    if data[NEW_BUMP_OFFSET] == canonical_bump && data[OLD_BUMP_OFFSET] != canonical_bump {
        msg!("realloc_vault_config: already migrated, no-op");
        return Ok(());
    }

    // ----- Snapshot fields from OLD offsets before zero-fill -----
    let mut tee_pubkey = [0u8; 32];
    let mut root_key = [0u8; 32];
    let mut zero_subtree_roots = [[0u8; 32]; MERKLE_DEPTH as usize];
    let mut protocol_owner = [0u8; 32];
    let mut fee_rate = [0u8; 2];

    tee_pubkey.copy_from_slice(&data[40..72]);
    root_key.copy_from_slice(&data[72..104]);
    for i in 0..(MERKLE_DEPTH as usize) {
        let start = OLD_ZERO_ROOTS_OFFSET + i * 32;
        zero_subtree_roots[i].copy_from_slice(&data[start..start + 32]);
    }
    protocol_owner
        .copy_from_slice(&data[OLD_PROTOCOL_OWNER_OFFSET..OLD_PROTOCOL_OWNER_OFFSET + 32]);
    fee_rate.copy_from_slice(&data[OLD_FEE_RATE_OFFSET..OLD_FEE_RATE_OFFSET + 2]);

    // Reset the entire payload, then write fields into NEW offsets.
    data[8..].fill(0);

    // admin / tee_pubkey / root_key — same offsets in old and new layouts.
    data[8..40].copy_from_slice(&admin_bytes);
    data[40..72].copy_from_slice(&tee_pubkey);
    data[72..104].copy_from_slice(&root_key);

    // leaf_count = 0 (already zero from fill)
    // current_root = empty_root(zero_subtree_roots) — computed below so the
    // post-migration root is a valid empty-tree root, not zero.
    let new_root = empty_root(&zero_subtree_roots)?;
    data[NEW_CURRENT_ROOT_OFFSET..NEW_CURRENT_ROOT_OFFSET + 32].copy_from_slice(&new_root);
    // Stay-zero: leaf_count (just confirms), roots[0..64], right_path, roots_head.
    let _ = NEW_LEAF_COUNT_OFFSET;

    // Move zero_subtree_roots into the NEW offset.
    for i in 0..(MERKLE_DEPTH as usize) {
        let start = NEW_ZERO_ROOTS_OFFSET + i * 32;
        data[start..start + 32].copy_from_slice(&zero_subtree_roots[i]);
    }

    // Store the canonical bump at the NEW offset (now where Anchor's
    // `bump = vault_config.load()?.bump` in other ixs reads from).
    data[NEW_BUMP_OFFSET] = canonical_bump;

    // Preserve governance state.
    data[NEW_PROTOCOL_OWNER_OFFSET..NEW_PROTOCOL_OWNER_OFFSET + 32]
        .copy_from_slice(&protocol_owner);
    data[NEW_FEE_RATE_OFFSET..NEW_FEE_RATE_OFFSET + 2].copy_from_slice(&fee_rate);

    msg!("realloc_vault_config: migrated 2488 -> 3512 bytes");
    Ok(())
}
