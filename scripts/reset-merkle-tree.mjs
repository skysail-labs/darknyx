#!/usr/bin/env node
// Reset the vault's incremental Merkle tree (DEVNET / STAGING ONLY).
//
// Calls the admin-gated `vault::reset_merkle_tree` ix: wipes leaf_count,
// right_path[..], the roots[..] ring, and recomputes current_root from
// zero_subtree_roots. Nullifier / wallet / note-lock PDAs are NOT touched.
//
// Use it between CVM-settle e2e runs (the harness asserts the tree starts
// empty), or whenever the SDK MerkleShadow drifts → StaleMerkleRoot (6004).
// `devnet-setup.test.ts` also resets the tree, but this is the fast path
// when you only need the reset (mints/market/ALT already exist).
//
// Usage:
//   node scripts/reset-merkle-tree.mjs
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

const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ADMIN_KP = process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const VAULT = new PublicKey(
  process.env.VAULT_PROGRAM_ID ?? "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const admin = Keypair.fromSecretKey(new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))));
const conn = new Connection(RPC, "confirmed");
const [vaultConfig] = PublicKey.findProgramAddressSync([Buffer.from("vault_config")], VAULT);

// Anchor ix discriminator = sha256("global:reset_merkle_tree")[..8].
const disc = createHash("sha256").update("global:reset_merkle_tree").digest().subarray(0, 8);

const ix = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultConfig, isSigner: false, isWritable: true },
  ],
  data: Buffer.from(disc),
});

const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
console.log(`reset_merkle_tree ok: ${sig}`);
console.log(`  vault   = ${VAULT.toBase58()}`);
console.log(`  admin   = ${admin.publicKey.toBase58()}`);
console.log(`  rpc     = ${RPC.replace(/\?api-key=.*/, "?api-key=***")}`);
