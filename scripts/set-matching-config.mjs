#!/usr/bin/env node
// DEVNET helper: update both governance accounts consumed by the TEE:
//   * VaultConfig: protocol_owner_commitment + fee_rate_bps + fee key epoch
//   * mint-pair MarketConfig: price scale, tick, minimum size, breaker, enabled
// Reboot the CVM to re-read them.
//
// Usage:
//   FEE_RATE_BPS=30 TICK_SIZE=5 MIN_ORDER_SIZE=1000 CIRCUIT_BREAKER_BPS=5000 \
//     node scripts/set-matching-config.mjs
// Env: ADMIN_KEYPAIR, SOLANA_RPC_URL, VAULT_PROGRAM_ID (siblings); owner and
// fee-key PUBLIC binding/epoch default to .devnet/e2e-config.json. Never pass
// the secret fee epoch key to this script.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ADMIN_KP = process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const VAULT = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);
const FEE = Number(process.env.FEE_RATE_BPS ?? "30");

const cfg = JSON.parse(readFileSync(".devnet/e2e-config.json", "utf8"));
if (!cfg.market || !cfg.marketConfigPda) {
  throw new Error(
    ".devnet/e2e-config.json predates MarketConfig; run devnet-setup first",
  );
}
const PRICE_SCALE = BigInt(process.env.PRICE_SCALE ?? cfg.market.priceScale);
const TICK = BigInt(process.env.TICK_SIZE ?? cfg.market.tickSize);
const MIN = BigInt(process.env.MIN_ORDER_SIZE ?? cfg.market.minOrderSize);
const CB = BigInt(
  process.env.CIRCUIT_BREAKER_BPS ?? cfg.market.circuitBreakerBps,
);
const ENABLED = !["0", "false", "no"].includes(
  (process.env.MARKET_ENABLED ?? "true").toLowerCase(),
);
if (
  !Number.isInteger(FEE) ||
  FEE < 0 ||
  FEE > 10_000 ||
  PRICE_SCALE <= 0n ||
  TICK <= 0n ||
  MIN <= 0n ||
  CB <= 0n ||
  CB > 10_000n
) {
  throw new Error("invalid fee or market governance parameter");
}
const ownerHex =
  process.env.OWNER_COMMITMENT_HEX ?? cfg.protocol.ownerCommitmentHex;
const owner = Buffer.from(ownerHex, "hex");
if (owner.length !== 32)
  throw new Error(`owner commitment must be 32 bytes; got ${owner.length}`);
const feeKeyBindingHex =
  process.env.FEE_KEY_BINDING_HEX ?? cfg.protocol.feeKeyBindingHex;
const feeKeyBinding = Buffer.from(feeKeyBindingHex ?? "", "hex");
const feeKeyEpochValue =
  process.env.FEE_KEY_EPOCH ?? cfg.protocol.feeKeyEpoch ?? "0";
if (
  typeof feeKeyEpochValue === "number" &&
  !Number.isSafeInteger(feeKeyEpochValue)
) {
  throw new Error("numeric fee key epoch must be a safe integer");
}
const feeKeyEpoch = BigInt(feeKeyEpochValue);
if (feeKeyBinding.length !== 32 || feeKeyBinding.equals(Buffer.alloc(32))) {
  throw new Error("fee key binding must be a nonzero 32-byte hex value");
}
if (feeKeyEpoch <= 0n || feeKeyEpoch > 0xffff_ffff_ffff_ffffn) {
  throw new Error("fee key epoch must be a nonzero u64");
}

const protocolDisc = createHash("sha256")
  .update("global:set_protocol_config")
  .digest()
  .subarray(0, 8);
const protocolData = Buffer.alloc(8 + 32 + 2 + 32 + 8);
let o = 0;
protocolDisc.copy(protocolData, o);
o += 8;
owner.copy(protocolData, o);
o += 32;
protocolData.writeUInt16LE(FEE, o);
o += 2;
feeKeyBinding.copy(protocolData, o);
o += 32;
protocolData.writeBigUInt64LE(feeKeyEpoch, o);

const marketDisc = createHash("sha256")
  .update("global:update_market_config")
  .digest()
  .subarray(0, 8);
const marketData = Buffer.alloc(8 + 1 + 8 * 4);
o = 0;
marketDisc.copy(marketData, o);
o += 8;
marketData[o] = ENABLED ? 1 : 0;
o += 1;
marketData.writeBigUInt64LE(PRICE_SCALE, o);
o += 8;
marketData.writeBigUInt64LE(TICK, o);
o += 8;
marketData.writeBigUInt64LE(MIN, o);
o += 8;
marketData.writeBigUInt64LE(CB, o);

const admin = await Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))),
);
const [vaultPda] = await PublicKey.findProgramAddress(
  [Buffer.from("vault_config")],
  VAULT,
);
const baseMint = new PublicKey(cfg.baseMint.pubkey);
const quoteMint = new PublicKey(cfg.quoteMint.pubkey);
const [marketPda] = await PublicKey.findProgramAddress(
  [Buffer.from("market_config"), baseMint.toBytes(), quoteMint.toBytes()],
  VAULT,
);
if (marketPda.toBase58() !== cfg.marketConfigPda) {
  throw new Error("configured MarketConfig PDA does not match the mint pair");
}
const conn = new Connection(RPC, "finalized");

const protocolIx = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultPda, isSigner: false, isWritable: true },
  ],
  data: protocolData,
});
const marketIx = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultPda, isSigner: false, isWritable: false },
    { pubkey: marketPda, isSigner: false, isWritable: true },
  ],
  data: marketData,
});

const sig = await sendAndConfirmTransaction(
  conn,
  new Transaction().add(protocolIx, marketIx),
  [admin],
  {
    commitment: "finalized",
  },
);
console.log(`governance config update ok: ${sig}`);
console.log(
  `  fee_rate_bps=${FEE} fee_key_epoch=${feeKeyEpoch} fee_key_binding=${feeKeyBinding.toString("hex")} enabled=${ENABLED} price_scale=${PRICE_SCALE} tick_size=${TICK} min_order_size=${MIN} circuit_breaker_bps=${CB}`,
);
console.log(
  `  vault_config ${vaultPda.toBase58()}  market_config ${marketPda.toBase58()}  admin ${admin.publicKey.toBase58()}`,
);
