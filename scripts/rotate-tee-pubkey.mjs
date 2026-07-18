#!/usr/bin/env node
// Install the vault's authorized TEE signer SET (admin-gated
// `vault::set_tee_pubkey(keys: Vec<Pubkey>)`). Every TEE-authority ix
// (lock_note, verify_match_batch, tee_forced_settle_batched, …) gates on
// `tee_authority ∈ cfg.tee_pubkeys`, so a freshly-deployed CVM — whose K
// dstack-derived shard signers are new — must register ALL of them before it
// can settle. Post-sharding the settle Tx D's round-robin across these K keys
// (one fee-payer per Merkle-tree shard), so register exactly `num_trees` keys
// in shard order: keys[j] settles shard j.
//
// The CVM signers are deterministic per app_id, so this is ONE-TIME per CVM
// (they survive stop/start); only re-run for a brand-new app_id. Get the
// shard signers from the running CVM boot log ("derived K-shard TEE signer
// set") — they are derived at `darknyx/ed25519-signer/v2/{0..K-1}`.
//
// Usage:
//   node scripts/rotate-tee-pubkey.mjs <key0> [key1 ...]
//   node scripts/rotate-tee-pubkey.mjs <key0,key1,key2,key3>
//   TEE_PUBKEYS=<key0,key1,...> node scripts/rotate-tee-pubkey.mjs
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

// Collect signer args from argv (space-separated) and/or TEE_PUBKEYS
// (comma-separated), in order — keys[j] is shard j's fee-payer/authority.
const raw = [
  ...process.argv.slice(2),
  ...(process.env.TEE_PUBKEYS ?? "").split(","),
]
  .flatMap((s) => s.split(","))
  .map((s) => s.trim())
  .filter(Boolean);
if (raw.length === 0) {
  console.error("usage: node scripts/rotate-tee-pubkey.mjs <key0> [key1 ...]");
  console.error(
    "  (the K shard signers from the CVM boot log, in shard order)",
  );
  process.exit(1);
}
if (raw.length > 16) {
  console.error(
    `too many keys (${raw.length}); the vault allows at most 16 (MAX_TEE_KEYS)`,
  );
  process.exit(1);
}
let teePubkeys;
try {
  teePubkeys = raw.map((s) => new PublicKey(s));
} catch {
  console.error("one of the signer keys is not a valid base58 Solana pubkey");
  process.exit(1);
}
if (
  teePubkeys.some((key) => key.equals(PublicKey.default)) ||
  new Set(teePubkeys.map((key) => key.toBase58())).size !== teePubkeys.length
) {
  console.error("TEE signer keys must be non-default and unique");
  process.exit(1);
}

const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const ADMIN_KP = process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const VAULT = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

const admin = Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))),
);
const conn = new Connection(RPC, "confirmed");
const [vaultConfig] = PublicKey.findProgramAddressSync(
  [Buffer.from("vault_config")],
  VAULT,
);
const vaultAccount = await conn.getAccountInfo(vaultConfig, "confirmed");
if (!vaultAccount || vaultAccount.owner.toBase58() !== VAULT.toBase58()) {
  throw new Error(
    `VaultConfig ${vaultConfig.toBase58()} is missing or has the wrong owner`,
  );
}
const NUM_TREES_OFFSET = 1259;
if (vaultAccount.data.length !== 1264) {
  throw new Error(
    `VaultConfig layout mismatch: expected 1264 bytes, got ${vaultAccount.data.length}`,
  );
}
const numTrees = vaultAccount.data[NUM_TREES_OFFSET];
if (teePubkeys.length !== numTrees) {
  throw new Error(
    `refusing partial signer rotation: got ${teePubkeys.length} keys for num_trees=${numTrees}`,
  );
}
const operationsAdmin = new PublicKey(vaultAccount.data.subarray(8, 40));
const rootKey = new PublicKey(vaultAccount.data.subarray(552, 584));
if (
  teePubkeys.some((key) => key.equals(operationsAdmin) || key.equals(rootKey))
) {
  throw new Error("TEE signer keys must be distinct from admin and root_key");
}

// data = disc("global:set_tee_pubkey")[..8] || Vec<Pubkey> (u32 LE len ++ len*32).
const disc = createHash("sha256")
  .update("global:set_tee_pubkey")
  .digest()
  .subarray(0, 8);
const lenLE = Buffer.alloc(4);
lenLE.writeUInt32LE(teePubkeys.length, 0);
const data = Buffer.concat([
  disc,
  lenLE,
  ...teePubkeys.map((k) => Buffer.from(k.toBytes())),
]);

const ix = new TransactionInstruction({
  programId: VAULT,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    { pubkey: vaultConfig, isSigner: false, isWritable: true },
  ],
  data,
});

const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [
  admin,
]);
console.log(`set_tee_pubkey ok: ${sig}`);
teePubkeys.forEach((k, j) =>
  console.log(`  tee_pubkeys[${j}] -> ${k.toBase58()}`),
);
console.log(`  num_trees      ${numTrees}`);
console.log(`  vault          ${VAULT.toBase58()}`);
console.log(`  admin          ${admin.publicKey.toBase58()}`);
