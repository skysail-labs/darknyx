#!/usr/bin/env node
// Rotate `vault_config.tee_pubkey` to a new signer (admin-gated
// `vault::set_tee_pubkey`). Every TEE-authority ix (lock_note,
// verify_match_batch, tee_forced_settle_batched, …) gates on
// `tee_authority == cfg.tee_pubkey`, so a freshly-deployed CVM — whose
// dstack-derived signer is new — must be rotated in before it can settle.
//
// The CVM signer is deterministic per app_id, so this is ONE-TIME per CVM
// (it survives stop/start); only re-run it for a brand-new app_id.
// Get the signer from the running CVM: `curl <gateway>/info | jq .tee_pubkey`.
//
// Usage:
//   node scripts/rotate-tee-pubkey.mjs <signer-base58>
//   TEE_PUBKEY=<signer-base58> node scripts/rotate-tee-pubkey.mjs
//
// Env:
//   ADMIN_KEYPAIR     vault admin keypair JSON (default .devnet/keypairs/admin.json)
//   SOLANA_RPC_URL    RPC endpoint (default https://api.devnet.solana.com)
//   VAULT_PROGRAM_ID  vault program id (default the devnet id below)

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

const signerArg = process.argv[2] ?? process.env.TEE_PUBKEY;
if (!signerArg) {
  console.error("usage: node scripts/rotate-tee-pubkey.mjs <signer-base58>");
  console.error("  (get it from `curl <gateway>/info | jq -r .tee_pubkey`)");
  process.exit(1);
}
let newTeePubkey;
try {
  newTeePubkey = new PublicKey(signerArg);
} catch {
  console.error(`invalid signer public key: ${signerArg}`);
  console.error("  expected a base58-encoded Solana pubkey (from `curl <gateway>/info | jq -r .tee_pubkey`)");
  process.exit(1);
}

const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ADMIN_KP = process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const VAULT = new PublicKey(
  process.env.VAULT_PROGRAM_ID ?? "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const admin = Keypair.fromSecretKey(new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))));
const conn = new Connection(RPC, "confirmed");
const [vaultConfig] = PublicKey.findProgramAddressSync([Buffer.from("vault_config")], VAULT);

// disc("global:set_tee_pubkey")[..8] || new_tee_pubkey(32B).
const disc = createHash("sha256").update("global:set_tee_pubkey").digest().subarray(0, 8);
const data = Buffer.concat([disc, newTeePubkey.toBytes()]);

const ix = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultConfig, isSigner: false, isWritable: true },
  ],
  data,
});

const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
console.log(`set_tee_pubkey ok: ${sig}`);
console.log(`  tee_pubkey -> ${newTeePubkey.toBase58()}`);
console.log(`  vault        ${VAULT.toBase58()}`);
console.log(`  admin        ${admin.publicKey.toBase58()}`);
