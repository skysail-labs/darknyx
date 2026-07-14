//! Initialize one governed mint-pair `MarketConfig` PDA.

use crate::errors::VaultError;
use crate::state::{MarketConfig, VaultConfig, MAX_CIRCUIT_BREAKER_BPS};
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

#[derive(Accounts)]
pub struct InitializeMarket<'info> {
    #[account(mut, address = vault_config.load()?.admin @ VaultError::Unauthorized)]
    pub admin: Signer<'info>,

    #[account(seeds = [VaultConfig::SEED], bump = vault_config.load()?.bump)]
    pub vault_config: AccountLoader<'info, VaultConfig>,

    pub base_mint: Account<'info, Mint>,
    pub quote_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = admin,
        space = MarketConfig::SPACE,
        seeds = [
            MarketConfig::SEED,
            base_mint.key().as_ref(),
            quote_mint.key().as_ref(),
        ],
        bump,
    )]
    pub market_config: Account<'info, MarketConfig>,

    pub system_program: Program<'info, System>,
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
    ctx: Context<InitializeMarket>,
    price_scale: u64,
    tick_size: u64,
    min_order_size: u64,
    circuit_breaker_bps: u64,
) -> Result<()> {
    require_keys_neq!(
        ctx.accounts.base_mint.key(),
        ctx.accounts.quote_mint.key(),
        VaultError::InvalidMarketMints
    );
    validate_market_parameters(price_scale, tick_size, min_order_size, circuit_breaker_bps)?;

    let market = &mut ctx.accounts.market_config;
    market.base_mint = ctx.accounts.base_mint.key();
    market.quote_mint = ctx.accounts.quote_mint.key();
    market.price_scale = price_scale;
    market.tick_size = tick_size;
    market.min_order_size = min_order_size;
    market.circuit_breaker_bps = circuit_breaker_bps;
    market.base_decimals = ctx.accounts.base_mint.decimals;
    market.quote_decimals = ctx.accounts.quote_mint.decimals;
    market.enabled = true;
    market.bump = ctx.bumps.market_config;

    emit!(MarketInitialized {
        admin: ctx.accounts.admin.key(),
        market: market.key(),
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
    pub admin: Pubkey,
    pub market: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub price_scale: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
    pub circuit_breaker_bps: u64,
}
