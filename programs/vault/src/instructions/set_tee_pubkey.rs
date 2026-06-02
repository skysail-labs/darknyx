//! Admin-gated rotation of `VaultConfig.tee_pubkey`.
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
//! NOTE (devnet-simplified): production rotation is gated by the
//! governance multisig AND only after the new TEE's attestation has
//! been verified against the approved measurement set (see
//! docs/tee-attestation-flow.md §5). This admin-only setter is the
//! devnet/spot-check form; do not ship it as the sole rotation path to
//! mainnet without the multisig + attestation gate.

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SetTeePubkey<'info> {
    /// Admin signer — must equal `vault_config.admin`.
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,
}

pub fn set_tee_pubkey_handler(ctx: Context<SetTeePubkey>, new_tee_pubkey: Pubkey) -> Result<()> {
    let mut cfg = ctx.accounts.vault_config.load_mut()?;
    require!(
        ctx.accounts.admin.key() == cfg.admin,
        VaultError::Unauthorized
    );

    let old = cfg.tee_pubkey;
    cfg.tee_pubkey = new_tee_pubkey;

    emit!(TeePubkeyRotated {
        admin: ctx.accounts.admin.key(),
        old_tee_pubkey: old,
        new_tee_pubkey,
    });
    Ok(())
}

#[event]
pub struct TeePubkeyRotated {
    pub admin: Pubkey,
    pub old_tee_pubkey: Pubkey,
    pub new_tee_pubkey: Pubkey,
}
