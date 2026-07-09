#!/usr/bin/env node
// DEVNET helper: call vault::set_protocol_config to (re)publish the on-chain
// governance config in VaultConfig — protocol_owner_commitment + fee_rate_bps +
// the matcher params tick_size / min_order_size / circuit_breaker_bps. The TEE
// adopts these at boot (0 = keep env/dev default). Reboot the CVM to re-read.
//
// Usage:
//   FEE_RATE_BPS=30 TICK_SIZE=5 MIN_ORDER_SIZE=1000 CIRCUIT_BREAKER_BPS=100000 \
//     node scripts/set-matching-config.mjs
// Env: ADMIN_KEYPAIR, SOLANA_RPC_URL, VAULT_PROGRAM_ID (siblings); the owner
//   commitment defaults to .devnet/e2e-config.json protocol.ownerCommitmentHex.

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
const TICK = BigInt(process.env.TICK_SIZE ?? "0");
const MIN = BigInt(process.env.MIN_ORDER_SIZE ?? "0");
const CB = BigInt(process.env.CIRCUIT_BREAKER_BPS ?? "0");

const cfg = JSON.parse(readFileSync(".devnet/e2e-config.json", "utf8"));
const ownerHex =
  process.env.OWNER_COMMITMENT_HEX ?? cfg.protocol.ownerCommitmentHex;
const owner = Buffer.from(ownerHex, "hex");
if (owner.length !== 32)
  throw new Error(`owner commitment must be 32 bytes; got ${owner.length}`);

const disc = createHash("sha256")
  .update("global:set_protocol_config")
  .digest()
  .subarray(0, 8);
const data = Buffer.alloc(8 + 32 + 2 + 8 + 8 + 8);
let o = 0;
disc.copy(data, o);
o += 8;
owner.copy(data, o);
o += 32;
data.writeUInt16LE(FEE, o);
o += 2;
data.writeBigUInt64LE(TICK, o);
o += 8;
data.writeBigUInt64LE(MIN, o);
o += 8;
data.writeBigUInt64LE(CB, o);
o += 8;

const admin = Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))),
);
const [vaultPda] = PublicKey.findProgramAddressSync(
  [Buffer.from("vault_config")],
  VAULT,
);
const conn = new Connection(RPC, "confirmed");

const ix = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultPda, isSigner: false, isWritable: true },
  ],
  data,
});

const sig = await sendAndConfirmTransaction(
  conn,
  new Transaction().add(ix),
  [admin],
  {
    commitment: "confirmed",
  },
);
console.log(`set_protocol_config ok: ${sig}`);
console.log(
  `  fee_rate_bps=${FEE} tick_size=${TICK} min_order_size=${MIN} circuit_breaker_bps=${CB}`,
);
console.log(
  `  vault_config ${vaultPda.toBase58()}  admin ${admin.publicKey.toBase58()}`,
);
