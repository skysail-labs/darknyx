#!/usr/bin/env node
// DEVNET-ONLY: close the VaultConfig PDA so it can be re-`initialize`d under a
// new layout (admin-gated `vault::close_vault_config`). Needed once after a
// VaultConfig layout change (e.g. the tree-sharding split) — a program upgrade
// leaves the old-layout PDA in place, which then fails ConstraintSeeds and
// blocks `initialize` (init can't recreate an existing account). After this,
// re-run devnet-setup to rebuild vault_config + the shards fresh.
//
// Usage:   node scripts/close-vault-config.mjs
// Env:     ADMIN_KEYPAIR, SOLANA_RPC_URL, VAULT_PROGRAM_ID  (same as siblings)

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

const admin = await Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))),
);
const conn = new Connection(RPC, "confirmed");
const [vaultConfig] = await PublicKey.findProgramAddress(
  [Buffer.from("vault_config")],
  VAULT,
);

const info = await conn.getAccountInfo(vaultConfig);
if (!info) {
  console.log(
    `vault_config ${vaultConfig.toBase58()} already absent — nothing to close.`,
  );
  process.exit(0);
}

const disc = createHash("sha256")
  .update("global:close_vault_config")
  .digest()
  .subarray(0, 8);
const ix = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: true },
    { pubkey: vaultConfig, isSigner: false, isWritable: true },
  ],
  data: Buffer.from(disc),
});

const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [
  admin,
]);
console.log(`close_vault_config ok: ${sig}`);
console.log(
  `  vault_config closed: ${vaultConfig.toBase58()} (was ${info.data.length} bytes)`,
);
console.log(`  admin              ${admin.publicKey.toBase58()}`);
