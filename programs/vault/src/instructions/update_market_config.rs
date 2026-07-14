//! Operations-admin updates for an existing mint-pair `MarketConfig`.

use crate::errors::VaultError;
use crate::instructions::initialize_market::validate_market_parameters;
use crate::state::{MarketConfig, VaultConfig};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateMarketConfig<'info> {
    #[account(address = vault_config.load()?.admin @ VaultError::Unauthorized)]
    pub admin: Signer<'info>,

    #[account(seeds = [VaultConfig::SEED], bump = vault_config.load()?.bump)]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    #[account(
        mut,
        seeds = [
            MarketConfig::SEED,
            market_config.base_mint.as_ref(),
            market_config.quote_mint.as_ref(),
        ],
        bump = market_config.bump,
    )]
    pub market_config: Account<'info, MarketConfig>,
}

pub fn update_market_config_handler(
    ctx: Context<UpdateMarketConfig>,
    enabled: bool,
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Result<()> {
    validate_market_parameters(price_scale, tick_size, min_order_size, circuit_breaker_bps)?;

    let market = &mut ctx.accounts.market_config;
    market.enabled = enabled;
    market.price_scale = price_scale;
    market.tick_size = tick_size;
    market.min_order_size = min_order_size;
    market.circuit_breaker_bps = circuit_breaker_bps;

    emit!(MarketConfigUpdated {
        admin: ctx.accounts.admin.key(),
        market: market.key(),
        enabled,
        price_scale,
        tick_size,
        min_order_size,
        circuit_breaker_bps,
    });
    Ok(())
}

#[event]
pub struct MarketConfigUpdated {
    pub admin: Pubkey,
    pub market: Pubkey,
    pub enabled: bool,
    pub price_scale: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
    pub circuit_breaker_bps: u64,
}
