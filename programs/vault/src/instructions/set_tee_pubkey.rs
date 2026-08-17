//! Operations-admin-gated rotation of `VaultConfig.tee_pubkeys`.
//!
//! `tee_pubkey` is the attested TEE Ed25519 signer every TEE ix
//! (`lock_note`, `verify_match_batch`, `tee_forced_settle_batched`)
//! checks `tee_authority` against. It's set once at `initialize`; this
//! ix rotates it on a live deployment — needed whenever a fresh CVM
//! comes up with a new dstack-derived signer (each `app_id` derives a
//! distinct key).
//!
//! Authorisation: only `vault_config.admin` can call this.
//!
//! On mainnet `VaultConfig.admin` is the operations Squads account. Operators
//! must independently verify the new TEE attestation before that multisig
//! approves this instruction (see `docs/tee-attestation-flow.md` §5).

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SetTeeAddress {
    /// Admin signer — must equal `vault_config.admin`.
    pub admin: Signer,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,
}

/// Install the FULL authorized TEE signer set (the K shard fee-payer/authority
/// keys). Replaces the whole `tee_pubkeys` array + `num_tee_keys`. One ix sets
/// all K at the rotation ceremony (e.g. when a fresh CVM derives K dstack keys).
pub fn set_tee_pubkey_handler(ctx: &mut Context<SetTeeAddress>, keys: Vec<Address>) -> Result<()> {
    let mut cfg = ctx.accounts.vault_config;
    require!(
        ctx.accounts.admin.address() == cfg.admin,
        VaultError::Unauthorized
    );
    require!(
        keys.len() == cfg.num_trees as usize && keys.len() <= MAX_TEE_KEYS,
        VaultError::InvalidKeyCount
    );
    // F-09: reject the zero key + duplicates. A zero (default) key is an unusable
    // slot that would never authorize a signer; a duplicate silently shrinks the
    // effective authorized set AND corrupts the shard→key round-robin (keys[j]
    // settles shard j). n ≤ MAX_TEE_KEYS (16) → the O(n²) dup scan is trivial.
    for (i, k) in keys.iter().enumerate() {
        require!(
            *k != Address::default() && *k != cfg.admin && *k != cfg.root_key,
            VaultError::InvalidTeeKey
        );
        require!(!keys[..i].contains(k), VaultError::InvalidTeeKey);
    }

    let old = cfg.tee_pubkeys[0];
    cfg.tee_pubkeys = [Address::default(); MAX_TEE_KEYS];
    for (slot, k) in cfg.tee_pubkeys.iter_mut().zip(keys.iter()) {
        *slot = *k;
    }
    cfg.num_tee_keys = keys.len() as u8;

    emit!(TeeAddressRotated {
        admin: ctx.accounts.admin.address(),
        old_tee_pubkey: old,
        new_tee_pubkey: keys[0],
        num_keys: keys.len() as u8,
    });
    Ok(())
}

#[event]
pub struct TeeAddressRotated {
    pub admin: Address,
    pub old_tee_pubkey: Address,
    pub new_tee_pubkey: Address,
    pub num_keys: u8,
}
