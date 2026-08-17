//! Admin-gated mutator for the global protocol-fee fields of `VaultConfig`.
//!
//! `protocol_owner_commitment` + `fee_rate_bps` are zero at `initialize` time;
//! this ix enables or updates fees without a re-initialisation. Mint identity,
//! price scale, tick, minimum size, and breaker bounds live in `MarketConfig`.
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
pub struct SetProtocolConfig {
    /// Admin signer — must equal `vault_config.admin`.
    pub admin: Signer,

    #[account(
        mut,
        seeds = [VaultConfig::SEED],
        bump = vault_config.bump,
    )]
    pub vault_config: Account<VaultConfig>,
}

pub fn set_protocol_config_handler(
    ctx: &mut Context<SetProtocolConfig>,
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u16,
) -> Result<()> {
    require!(fee_rate_bps <= MAX_FEE_RATE_BPS, VaultError::InvalidFeeRate);

    let mut cfg = ctx.accounts.vault_config;
    require!(
        ctx.accounts.admin.address() == cfg.admin,
        VaultError::Unauthorized
    );

    let old_commitment = cfg.protocol_owner_commitment;
    let old_rate = cfg.fee_rate_bps;
    cfg.protocol_owner_commitment = protocol_owner_commitment;
    cfg.fee_rate_bps = fee_rate_bps;

    emit!(ProtocolConfigUpdated {
        admin: *ctx.accounts.admin.address(),
        old_protocol_owner_commitment: old_commitment,
        new_protocol_owner_commitment: protocol_owner_commitment,
        old_fee_rate_bps: old_rate,
        new_fee_rate_bps: fee_rate_bps,
    });
    Ok(())
}

#[event]
pub struct ProtocolConfigUpdated {
    pub admin: Address,
    pub old_protocol_owner_commitment: [u8; 32],
    pub new_protocol_owner_commitment: [u8; 32],
    pub old_fee_rate_bps: u16,
    pub new_fee_rate_bps: u16,
}
