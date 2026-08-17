//! Operations-admin updates for an existing mint-pair `MarketConfig`.

use crate::errors::VaultError;
use crate::instructions::initialize_market::validate_market_parameters;
use crate::state::{MarketConfig, VaultConfig};
use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;

#[derive(Accounts)]
pub struct UpdateMarketConfig {
    #[account(address = vault_config.admin @ VaultError::Unauthorized)]
    pub admin: Signer,

    #[account(seeds = [VaultConfig::SEED], bump = vault_config.bump)]
    pub vault_config: Account<VaultConfig>,

    #[account(
        mut,
        seeds = [
            MarketConfig::SEED,
            market_config.base_mint.as_ref(),
            market_config.quote_mint.as_ref(),
        ],
        bump = market_config.bump,
    )]
    pub market_config: Account<MarketConfig>,
}

pub fn update_market_config_handler(
    ctx: &mut Context<UpdateMarketConfig>,
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
        admin: ctx.accounts.admin.address(),
        market: market.address(),
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
    pub admin: Address,
    pub market: Address,
    pub enabled: bool,
    pub price_scale: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
    pub circuit_breaker_bps: u64,
}
