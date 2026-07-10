//! Admin-gated mutator for the protocol-fee + matcher-governance fields of
//! `VaultConfig` (the single on-chain home for TEE-adopted config).
//!
//! `protocol_owner_commitment` + `fee_rate_bps` + `tick_size` +
//! `min_order_size` + `circuit_breaker_bps` are all zero at `initialize`
//! time; this ix is the post-deployment setter so governance can (a) enable
//! protocol fees on a live deployment without a full re-initialisation,
//! (b) rotate the commitment that protocol-fee notes are addressed to, and
//! (c) publish the matcher params the TEE adopts at boot (0 = leave the TEE
//! on its env/dev default).
//!
//! Authorisation: only `vault_config.admin` can call this. `fee_rate_bps`
//! is clamped to 10_000 (= 100%) to keep floor-division safe.

use crate::errors::VaultError;
use crate::state::*;
use anchor_lang::prelude::*;

/// Maximum allowed fee rate. 10_000 bps == 100%. Going above this would
/// break the conservation check in `tee_forced_settle` for honest inputs.
pub const MAX_FEE_RATE_BPS: u16 = 10_000;

#[derive(Accounts)]
pub struct SetProtocolConfig<'info> {
    /// Admin signer — must equal `vault_config.admin`.
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.load()?.bump,
    )]
    pub vault_config: AccountLoader<'info, VaultConfig>,
}

pub fn set_protocol_config_handler(
    ctx: Context<SetProtocolConfig>,
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u16,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Result<()> {
    require!(fee_rate_bps <= MAX_FEE_RATE_BPS, VaultError::InvalidFeeRate);

    let mut cfg = ctx.accounts.vault_config.load_mut()?;
    require!(
        ctx.accounts.admin.key() == cfg.admin,
        VaultError::Unauthorized
    );

    let old_commitment = cfg.protocol_owner_commitment;
    let old_rate = cfg.fee_rate_bps;
    cfg.protocol_owner_commitment = protocol_owner_commitment;
    cfg.fee_rate_bps = fee_rate_bps;
    // Matcher governance params (single-place config in VaultConfig). Not
    // enforced on the settle hot path — the TEE adopts them at boot; 0 = unset.
    cfg.tick_size = tick_size;
    cfg.min_order_size = min_order_size;
    cfg.circuit_breaker_bps = circuit_breaker_bps;

    emit!(ProtocolConfigUpdated {
        admin: ctx.accounts.admin.key(),
        old_protocol_owner_commitment: old_commitment,
        new_protocol_owner_commitment: protocol_owner_commitment,
        old_fee_rate_bps: old_rate,
        new_fee_rate_bps: fee_rate_bps,
        new_tick_size: tick_size,
        new_min_order_size: min_order_size,
        new_circuit_breaker_bps: circuit_breaker_bps,
    });
    Ok(())
}

#[event]
pub struct ProtocolConfigUpdated {
    pub admin: Pubkey,
    pub old_protocol_owner_commitment: [u8; 32],
    pub new_protocol_owner_commitment: [u8; 32],
    pub old_fee_rate_bps: u16,
    pub new_fee_rate_bps: u16,
    pub new_tick_size: u64,
    pub new_min_order_size: u64,
    pub new_circuit_breaker_bps: u64,
}
