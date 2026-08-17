//! Initialize one governed mint-pair `MarketConfig` PDA.

use crate::errors::VaultError;
use crate::state::{MarketConfig, VaultConfig, MAX_CIRCUIT_BREAKER_BPS};
use anchor_lang::prelude::*;
// v2: the re-exported wincode derives emit bare `wincode::` paths. Importing
// anchor's re-export (rather than taking a direct dep) guarantees they resolve
// to the SAME wincode anchor was built against — a direct dep silently created
// a second version in the graph and every Address failed its Schema bound.
use anchor_lang::wincode;
use anchor_spl::token::Mint;

#[derive(Accounts)]
pub struct InitializeMarket {
    #[account(mut, address = vault_config.admin @ VaultError::Unauthorized)]
    pub admin: Signer,

    #[account(seeds = [VaultConfig::SEED], bump = vault_config.bump)]
    pub vault_config: Account<VaultConfig>,

    pub base_mint: Account<Mint>,
    pub quote_mint: Account<Mint>,

    #[account(
        init,
        payer = admin,
        space = MarketConfig::SPACE,
        seeds = [
            MarketConfig::SEED,
            base_mint.address().as_ref(),
            quote_mint.address().as_ref(),
        ],
        bump,
    )]
    pub market_config: Account<MarketConfig>,

    pub system_program: Program<System>,
}

pub(crate) fn validate_market_parameters(
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Result<()> {
    require!(
        price_scale > 0
            && tick_size > 0
            && min_order_size > 0
            && (1..=MAX_CIRCUIT_BREAKER_BPS).contains(&circuit_breaker_bps),
        VaultError::InvalidMarketParameters
    );
    Ok(())
}

pub fn initialize_market_handler(
    ctx: &mut Context<InitializeMarket>,
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Result<()> {
    require_keys_neq!(
        ctx.accounts.base_mint.address(),
        ctx.accounts.quote_mint.address(),
        VaultError::InvalidMarketMints
    );
    validate_market_parameters(price_scale, tick_size, min_order_size, circuit_breaker_bps)?;

    let market = &mut ctx.accounts.market_config;
    market.base_mint = ctx.accounts.base_mint.address();
    market.quote_mint = ctx.accounts.quote_mint.address();
    market.price_scale = price_scale;
    market.tick_size = tick_size;
    market.min_order_size = min_order_size;
    market.circuit_breaker_bps = circuit_breaker_bps;
    market.base_decimals = ctx.accounts.base_mint.decimals;
    market.quote_decimals = ctx.accounts.quote_mint.decimals;
    market.enabled = true;
    market.bump = ctx.bumps.market_config;

    emit!(MarketInitialized {
        admin: ctx.accounts.admin.address(),
        market: market.address(),
        base_mint: market.base_mint,
        quote_mint: market.quote_mint,
        base_decimals: market.base_decimals,
        quote_decimals: market.quote_decimals,
        price_scale,
        tick_size,
        min_order_size,
        circuit_breaker_bps,
    });
    Ok(())
}

#[event]
pub struct MarketInitialized {
    pub admin: Address,
    pub market: Address,
    pub base_mint: Address,
    pub quote_mint: Address,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub price_scale: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
    pub circuit_breaker_bps: u64,
}
