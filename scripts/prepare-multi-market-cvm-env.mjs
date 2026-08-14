#!/usr/bin/env node
/**
 * Prepare the gitignored encrypted-env input for the focused multi-market CVM
 * rehearsal. The output is both dotenv- and zsh-compatible so the same fresh
 * credentials can be sourced by the Vitest harness after deployment.
 *
 * Required env: SOLANA_RPC_URL.
 * Prerequisite: node scripts/setup-second-devnet-market.mjs
 */

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Connection } from "@solana/web3.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = resolve(REPO_ROOT, ".devnet/multi-market-e2e-config.json");
const OUTPUT_PATH = resolve(
  REPO_ROOT,
  ".devnet/darknyx-multimarket-deploy.env",
);
const RPC = process.env.SOLANA_RPC_URL?.trim();

if (!RPC) {
  throw new Error(
    "SOLANA_RPC_URL is required; use the private devnet endpoint from packages/sdk/.env",
  );
}
if (!existsSync(CONFIG_PATH)) {
  throw new Error(
    ".devnet/multi-market-e2e-config.json is missing; run setup-second-devnet-market.mjs first",
  );
}

const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
if (!Array.isArray(cfg.markets) || cfg.markets.length !== 2) {
  throw new Error(
    "the focused rehearsal requires exactly two configured markets",
  );
}

const markets = cfg.markets.map((market) => ({
  symbol: market.symbol,
  base_mint: market.baseMint.pubkey,
  quote_mint: market.quoteMint.pubkey,
  oracle_feed_id: market.oracleFeedId,
}));
const floor = await new Connection(RPC, "confirmed").getSlot("confirmed");

function envLine(key, value) {
  const text = String(value);
  if (text.includes("'") || text.includes("\n")) {
    throw new Error(`${key} contains a character unsupported by this env file`);
  }
  return `${key}='${text}'`;
}

const lines = [
  envLine("DARKNYX_TEE_API_KEY", `darknyx-${randomBytes(16).toString("hex")}`),
  envLine("DARKNYX_TEE_API_SECRET", randomBytes(32).toString("hex")),
  envLine("DARKNYX_TEE_PASSPHRASE", randomBytes(32).toString("hex")),
  envLine("DARKNYX_TEE_DEPLOYMENT_TIER", "development"),
  envLine("DARKNYX_TEE_ORACLE_MODE", "pyth-solana-push-v1"),
  envLine("DARKNYX_TEE_SOLANA_RPC_URL", RPC),
  envLine("DARKNYX_TEE_SYNC_FROM_SLOT", floor),
  envLine("DARKNYX_TEE_BASE_MINT", ""),
  envLine("DARKNYX_TEE_QUOTE_MINT", ""),
  envLine("DARKNYX_TEE_MARKET_SYMBOL", ""),
  envLine("DARKNYX_TEE_MARKETS_JSON", JSON.stringify(markets)),
  envLine("DARKNYX_TEE_SETTLE_LOOKUP_TABLE", cfg.settleLookupTable),
  envLine("DARKNYX_TEE_FEE_RATE_BPS", cfg.protocol.feeRateBps),
  envLine(
    "DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT",
    cfg.protocol.ownerCommitmentHex,
  ),
  envLine("DARKNYX_TEE_NUM_TREES", cfg.numTrees),
  envLine("DARKNYX_TEE_SETTLE_SEND_CONCURRENCY", 16),
  envLine("DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY", 2),
  envLine("DARKNYX_TEE_PROVER", "rapidsnark"),
  envLine("DARKNYX_TEE_WITNESS", "native"),
];

writeFileSync(OUTPUT_PATH, `${lines.join("\n")}\n`, { mode: 0o600 });
chmodSync(OUTPUT_PATH, 0o600);
console.log(
  `prepared ${OUTPUT_PATH} at sync floor ${floor} (two markets, native witness, rapidsnark, C2)`,
);
