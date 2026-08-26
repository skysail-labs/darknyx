#!/usr/bin/env node
// Reset the vault's incremental Merkle tree(s) (DEVNET / STAGING ONLY).
//
// Calls the admin-gated `vault::reset_merkle_tree(tree_id)` ix per shard:
// wipes leaf_count, right_path[..], the roots[..] ring, and recomputes
// current_root from zero_subtree_roots. Nullifier / wallet / note-lock PDAs
// are NOT touched.
//
// Post-sharding the tree state lives in K per-shard `MerkleTree` accounts
// (PDA `[b"merkle_tree", &[tree_id]]`). This resets ALL of them by default
// (reading `num_trees` from vault_config), or a single shard with `--tree N`.
//
// Use it between CVM-settle e2e runs (the harness asserts the trees start
// empty), or whenever an SDK MerkleShadow drifts → StaleMerkleRoot (6004).
//
// Usage:
//   node scripts/reset-merkle-tree.mjs              # reset ALL shards
//   node scripts/reset-merkle-tree.mjs --all        # same
//   node scripts/reset-merkle-tree.mjs --tree 2     # reset shard 2 only
//
// Env:
//   ADMIN_KEYPAIR     vault admin keypair JSON (default .devnet/keypairs/admin.json)
//   SOLANA_RPC_URL    required private RPC endpoint
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
import { requirePrivateRpcUrl } from "./private-rpc.mjs";

const RPC = requirePrivateRpcUrl(process.env.SOLANA_RPC_URL);
const ADMIN_KP = process.env.ADMIN_KEYPAIR ?? ".devnet/keypairs/admin.json";
const VAULT = new PublicKey(
  process.env.VAULT_PROGRAM_ID ??
    "C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx",
);

// StaleLayoutDecode: consume the generated Rust layout so fee-key bytes can
// never be interpreted as `num_trees`.
const vaultLayout = JSON.parse(
  readFileSync("programs/vault/account-layout.json", "utf8"),
).accounts?.VaultConfig;
const VAULT_CONFIG_ACCOUNT_LEN = vaultLayout?.account_len;
const NUM_TREES_OFFSET = vaultLayout?.num_trees?.offset;
if (
  !Number.isInteger(VAULT_CONFIG_ACCOUNT_LEN) ||
  !Number.isInteger(NUM_TREES_OFFSET)
) {
  throw new Error(
    "generated VaultConfig layout fixture is missing required fields",
  );
}
const MAX_TREES = 16;

const admin = await Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(readFileSync(ADMIN_KP, "utf8"))),
);
const conn = new Connection(RPC, "confirmed");
const [vaultConfig] = await PublicKey.findProgramAddress(
  [Buffer.from("vault_config")],
  VAULT,
);

const merkleTreePda = async (treeId) =>
  (
    await PublicKey.findProgramAddress(
      [Buffer.from("merkle_tree"), Buffer.from([treeId & 0xff])],
      VAULT,
    )
  )[0];

// Anchor ix discriminator = sha256("global:reset_merkle_tree")[..8].
const disc = createHash("sha256")
  .update("global:reset_merkle_tree")
  .digest()
  .subarray(0, 8);

async function resetIx(treeId) {
  return new TransactionInstruction({
    programId: VAULT,
    keys: [
      { pubkey: admin.publicKey, isSigner: true, isWritable: false },
      { pubkey: vaultConfig, isSigner: false, isWritable: false },
      {
        pubkey: await merkleTreePda(treeId),
        isSigner: false,
        isWritable: true,
      },
    ],
    // data = disc(8) || tree_id(1)
    data: Buffer.concat([disc, Buffer.from([treeId & 0xff])]),
  });
}

// Decide which shards to reset.
const argv = process.argv.slice(2);
let treeIds;
const treeFlag = argv.indexOf("--tree");
if (treeFlag !== -1) {
  const id = Number(argv[treeFlag + 1]);
  if (!Number.isInteger(id) || id < 0 || id > 15) {
    console.error(`--tree expects an id in 0..15, got ${argv[treeFlag + 1]}`);
    process.exit(1);
  }
  treeIds = [id];
} else {
  // --all (default): read num_trees from vault_config.
  const info = await conn.getAccountInfo(vaultConfig);
  if (!info) {
    console.error(
      `vault_config not found at ${vaultConfig.toBase58()} — is the program initialised?`,
    );
    process.exit(1);
  }
  if (info.data.length !== VAULT_CONFIG_ACCOUNT_LEN) {
    throw new Error(
      `VaultConfig layout mismatch: expected ${VAULT_CONFIG_ACCOUNT_LEN} bytes, got ${info.data.length}`,
    );
  }
  const numTrees = info.data[NUM_TREES_OFFSET];
  if (numTrees < 1 || numTrees > MAX_TREES) {
    throw new Error(`vault_config num_trees out of range: ${numTrees}`);
  }
  treeIds = Array.from({ length: numTrees }, (_, i) => i);
}

for (const treeId of treeIds) {
  const sig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(await resetIx(treeId)),
    [admin],
  );
  console.log(`reset_merkle_tree(tree ${treeId}) ok: ${sig}`);
}
console.log(`  vault   = ${VAULT.toBase58()}`);
console.log(`  admin   = ${admin.publicKey.toBase58()}`);
console.log(`  shards  = [${treeIds.join(", ")}]`);
console.log(`  rpc     = ${RPC.replace(/\?api-key=.*/, "?api-key=***")}`);
