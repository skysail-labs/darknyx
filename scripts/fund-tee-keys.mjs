#!/usr/bin/env node
// Fund the K TEE shard signer addresses with SOL (DEVNET / STAGING).
//
// Each shard's settle Tx D is fee-paid by its own dstack-derived key
// (`nyx/ed25519-signer/v1/{j}`), and those keys also pay rent for the
// per-settle PDAs (consumed-note / nullifier / re-lock) they init. So every
// registered shard signer needs a SOL balance, not just shard 0. This tops up
// each address to (at least) the target balance from your local funder.
//
// Usage:
//   node scripts/fund-tee-keys.mjs <key0> [key1 ...]
//   node scripts/fund-tee-keys.mjs <key0,key1,key2,key3>
//   TEE_PUBKEYS=<key0,key1,...> node scripts/fund-tee-keys.mjs
//
// Env:
//   FUNDER_KEYPAIR    SOL source keypair JSON (default ~/.config/solana/id.json)
//   SOLANA_RPC_URL    RPC endpoint (default https://api.devnet.solana.com)
//   FUND_TARGET_SOL   per-key target balance in SOL (default 2)

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const raw = [...process.argv.slice(2), ...(process.env.TEE_PUBKEYS ?? "").split(",")]
  .flatMap((s) => s.split(","))
  .map((s) => s.trim())
  .filter(Boolean);
if (raw.length === 0) {
  console.error("usage: node scripts/fund-tee-keys.mjs <key0> [key1 ...]");
  console.error("  (the K shard signers from the CVM boot log)");
  process.exit(1);
}
let targets;
try {
  targets = raw.map((s) => new PublicKey(s));
} catch {
  console.error("one of the keys is not a valid base58 Solana pubkey");
  process.exit(1);
}

const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const FUNDER_KP = process.env.FUNDER_KEYPAIR ?? join(homedir(), ".config/solana/id.json");
const TARGET_SOL = Number(process.env.FUND_TARGET_SOL ?? "2");
if (!Number.isFinite(TARGET_SOL) || TARGET_SOL <= 0) {
  console.error(`FUND_TARGET_SOL must be a positive number, got "${process.env.FUND_TARGET_SOL}"`);
  process.exit(1);
}
const TARGET_LAMPORTS = Math.round(TARGET_SOL * LAMPORTS_PER_SOL);

const funder = Keypair.fromSecretKey(new Uint8Array(JSON.parse(readFileSync(FUNDER_KP, "utf8"))));
const conn = new Connection(RPC, "confirmed");

for (const [j, target] of targets.entries()) {
  const have = await conn.getBalance(target, "confirmed");
  if (have >= TARGET_LAMPORTS) {
    console.log(`shard ${j} ${target.toBase58()} already has ${(have / LAMPORTS_PER_SOL).toFixed(3)} SOL — skip`);
    continue;
  }
  const topUp = TARGET_LAMPORTS - have;
  const ix = SystemProgram.transfer({
    fromPubkey: funder.publicKey,
    toPubkey: target,
    lamports: topUp,
  });
  const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [funder]);
  console.log(
    `shard ${j} ${target.toBase58()} += ${(topUp / LAMPORTS_PER_SOL).toFixed(3)} SOL  (${sig})`,
  );
}
console.log(`  funder = ${funder.publicKey.toBase58()}`);
console.log(`  target = ${TARGET_SOL} SOL/key`);
console.log(`  rpc    = ${RPC.replace(/\?api-key=.*/, "?api-key=***")}`);
