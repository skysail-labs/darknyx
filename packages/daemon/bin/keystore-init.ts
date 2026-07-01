#!/usr/bin/env node
/**
 * nyx-keystore-init — create (or recreate) an encrypted daemon keystore.
 *
 * Generates a fresh account identity (random 64-byte master seed + the
 * seed-derived owner/user blindings) bound to the operator's root (payer)
 * Solana key, seals it under a passphrase, and prints the seed to back up + the
 * commitments to register on-chain.
 *
 *   NYX_DAEMON_KEYSTORE_PASSPHRASE=<passphrase> \
 *   nyx-keystore-init --root-key <BASE58_PUBKEY> [--out ./nyx-keystore.json] \
 *                     [--seed <HEX_128>] [--force]
 *
 *   --root-key   (required) base58 pubkey of the funding/root wallet.
 *   --out        keystore path (default ./nyx-keystore.json).
 *   --seed       128-hex (64-byte) seed to RECREATE a keystore from a backup;
 *                omit to generate a fresh one.
 *   --force      overwrite an existing --out file.
 *
 * The passphrase comes from NYX_DAEMON_KEYSTORE_PASSPHRASE (scriptable; never a
 * CLI arg, so it doesn't land in shell history / the process table).
 */

import { existsSync } from "node:fs";
import { PublicKey } from "@solana/web3.js";

import {
  Keystore,
  deriveAccountIdentity,
  generateAccountIdentity,
  saveKeystore,
} from "../src/keystore.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

async function main(): Promise<void> {
  const rootKeyB58 = arg("root-key");
  if (!rootKeyB58) throw new Error("--root-key <BASE58_PUBKEY> is required");
  const out = arg("out") ?? "./nyx-keystore.json";
  const passphrase = process.env.NYX_DAEMON_KEYSTORE_PASSPHRASE;
  if (!passphrase)
    throw new Error("NYX_DAEMON_KEYSTORE_PASSPHRASE is required");

  if (existsSync(out) && !flag("force")) {
    throw new Error(`${out} exists; pass --force to overwrite`);
  }

  const rootKeyPubkey = new PublicKey(rootKeyB58).toBytes();
  const seedHex = arg("seed");
  const identity = seedHex
    ? deriveAccountIdentity(
        Uint8Array.from(Buffer.from(seedHex, "hex")),
        rootKeyPubkey,
      )
    : generateAccountIdentity(rootKeyPubkey);

  if (identity.masterSeed.length !== 64) {
    throw new Error("seed must be 64 bytes (128 hex chars)");
  }

  const ks = new Keystore(identity);
  const ownerCommit = await ks.ownerCommitment();
  const userCommit = await ks.userCommitment();

  saveKeystore(identity, out, passphrase);

  console.log(`keystore written: ${out} (encrypted, 0600)`);
  console.log("");
  console.log("BACK UP THIS SEED (the only disaster-recovery secret):");
  console.log(`  seed:             ${toHex(identity.masterSeed)}`);
  console.log("");
  console.log("Register these on-chain (create_wallet) before trading:");
  console.log(`  root_key:         ${rootKeyB58}`);
  console.log(`  owner_commitment: ${ownerCommit.toString(16)}`);
  console.log(`  user_commitment:  ${toHex(userCommit)}`);
}

main().catch((e) => {
  console.error(`keystore-init: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
