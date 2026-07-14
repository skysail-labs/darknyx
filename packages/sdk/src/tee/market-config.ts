/** Fixed-layout parser for the on-chain mint-pair MarketConfig PDA. */

import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

export const MARKET_CONFIG_ACCOUNT_LEN = 108;

export interface OnChainMarketConfig {
  baseMint: PublicKey;
  quoteMint: PublicKey;
  priceScale: bigint;
  tickSize: bigint;
  minOrderSize: bigint;
  circuitBreakerBps: bigint;
  baseDecimals: number;
  quoteDecimals: number;
  enabled: boolean;
  bump: number;
}

const MARKET_CONFIG_DISCRIMINATOR = createHash("sha256")
  .update("account:MarketConfig")
  .digest()
  .subarray(0, 8);

function u64(data: Uint8Array, offset: number): bigint {
  return new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getBigUint64(offset, true);
}

export function decodeMarketConfig(data: Uint8Array): OnChainMarketConfig {
  if (data.length !== MARKET_CONFIG_ACCOUNT_LEN) {
    throw new Error(`market_config length must be 108, got ${data.length}`);
  }
  if (
    !data
      .subarray(0, 8)
      .every((value, index) => value === MARKET_CONFIG_DISCRIMINATOR[index])
  ) {
    throw new Error("invalid MarketConfig discriminator");
  }
  if (data[106] !== 0 && data[106] !== 1) {
    throw new Error("invalid MarketConfig enabled encoding");
  }
  const market: OnChainMarketConfig = {
    baseMint: new PublicKey(data.subarray(8, 40)),
    quoteMint: new PublicKey(data.subarray(40, 72)),
    priceScale: u64(data, 72),
    tickSize: u64(data, 80),
    minOrderSize: u64(data, 88),
    circuitBreakerBps: u64(data, 96),
    baseDecimals: data[104],
    quoteDecimals: data[105],
    enabled: data[106] === 1,
    bump: data[107],
  };
  if (
    market.baseMint.equals(market.quoteMint) ||
    market.priceScale === 0n ||
    market.tickSize === 0n ||
    market.minOrderSize === 0n ||
    market.circuitBreakerBps === 0n ||
    market.circuitBreakerBps > 10_000n
  ) {
    throw new Error("invalid governed MarketConfig values");
  }
  return market;
}
