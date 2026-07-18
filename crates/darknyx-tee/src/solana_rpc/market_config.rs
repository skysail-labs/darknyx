//! Fixed-layout reader for the on-chain mint-pair `MarketConfig` account.

use std::sync::LazyLock;

use sha2::{Digest, Sha256};

pub const MARKET_CONFIG_ACCOUNT_LEN: usize = 108;
const BASE_MINT_OFFSET: usize = 8;
const QUOTE_MINT_OFFSET: usize = 40;
const PRICE_SCALE_OFFSET: usize = 72;
const TICK_SIZE_OFFSET: usize = 80;
const MIN_ORDER_SIZE_OFFSET: usize = 88;
const CIRCUIT_BREAKER_BPS_OFFSET: usize = 96;
const BASE_DECIMALS_OFFSET: usize = 104;
const QUOTE_DECIMALS_OFFSET: usize = 105;
const ENABLED_OFFSET: usize = 106;

static MARKET_CONFIG_DISCRIMINATOR: LazyLock<[u8; 8]> = LazyLock::new(|| {
    let hash = Sha256::digest(b"account:MarketConfig");
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnChainMarketConfig {
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub price_scale: u64,
    pub tick_size: u64,
    pub min_order_size: u64,
    pub circuit_breaker_bps: u64,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub enabled: bool,
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("checked length"))
}

pub fn parse_market_config(data: &[u8]) -> Option<OnChainMarketConfig> {
    if data.len() != MARKET_CONFIG_ACCOUNT_LEN || data[..8] != *MARKET_CONFIG_DISCRIMINATOR {
        return None;
    }
    let enabled = match data[ENABLED_OFFSET] {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(OnChainMarketConfig {
        base_mint: data[BASE_MINT_OFFSET..QUOTE_MINT_OFFSET].try_into().ok()?,
        quote_mint: data[QUOTE_MINT_OFFSET..PRICE_SCALE_OFFSET]
            .try_into()
            .ok()?,
        price_scale: u64_at(data, PRICE_SCALE_OFFSET),
        tick_size: u64_at(data, TICK_SIZE_OFFSET),
        min_order_size: u64_at(data, MIN_ORDER_SIZE_OFFSET),
        circuit_breaker_bps: u64_at(data, CIRCUIT_BREAKER_BPS_OFFSET),
        base_decimals: data[BASE_DECIMALS_OFFSET],
        quote_decimals: data[QUOTE_DECIMALS_OFFSET],
        enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; MARKET_CONFIG_ACCOUNT_LEN];
        data[..8].copy_from_slice(&*MARKET_CONFIG_DISCRIMINATOR);
        data[BASE_MINT_OFFSET..QUOTE_MINT_OFFSET].copy_from_slice(&[0x11; 32]);
        data[QUOTE_MINT_OFFSET..PRICE_SCALE_OFFSET].copy_from_slice(&[0x22; 32]);
        data[PRICE_SCALE_OFFSET..TICK_SIZE_OFFSET].copy_from_slice(&100_000_000u64.to_le_bytes());
        data[TICK_SIZE_OFFSET..MIN_ORDER_SIZE_OFFSET].copy_from_slice(&5u64.to_le_bytes());
        data[MIN_ORDER_SIZE_OFFSET..CIRCUIT_BREAKER_BPS_OFFSET]
            .copy_from_slice(&1_000u64.to_le_bytes());
        data[CIRCUIT_BREAKER_BPS_OFFSET..BASE_DECIMALS_OFFSET]
            .copy_from_slice(&5_000u64.to_le_bytes());
        data[BASE_DECIMALS_OFFSET] = 9;
        data[QUOTE_DECIMALS_OFFSET] = 6;
        data[ENABLED_OFFSET] = 1;
        data
    }

    #[test]
    fn parses_the_pinned_market_layout() {
        let parsed = parse_market_config(&fixture()).unwrap();
        assert_eq!(parsed.base_mint, [0x11; 32]);
        assert_eq!(parsed.quote_mint, [0x22; 32]);
        assert_eq!(parsed.price_scale, 100_000_000);
        assert_eq!(parsed.tick_size, 5);
        assert_eq!(parsed.min_order_size, 1_000);
        assert_eq!(parsed.circuit_breaker_bps, 5_000);
        assert_eq!(parsed.base_decimals, 9);
        assert_eq!(parsed.quote_decimals, 6);
        assert!(parsed.enabled);
    }

    #[test]
    fn rejects_wrong_discriminator_length_and_bool_encoding() {
        let mut data = fixture();
        data[0] ^= 1;
        assert!(parse_market_config(&data).is_none());
        data[0] ^= 1;
        data[ENABLED_OFFSET] = 2;
        assert!(parse_market_config(&data).is_none());
        data.pop();
        assert!(parse_market_config(&data).is_none());
    }
}
