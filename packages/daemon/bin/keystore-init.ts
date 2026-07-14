#!/usr/bin/env node
/**
 * nyx-keystore-init — create (or recreate) an encrypted daemon keystore.
 *
 * Generates a fresh account identity (random 64-byte master seed + the
 * seed-derived owner/user blindings) bound to the operator's root (payer)
 * Solana key, seals it under a passphrase, and writes a separate encrypted,
 * versioned seed backup. Plaintext seed import/export is deliberately absent.
 *
 *   NYX_DAEMON_KEYSTORE_PASSPHRASE=<passphrase> \
 *   NYX_DAEMON_SEED_BACKUP_PASSPHRASE=<distinct-passphrase> \
 *   nyx-keystore-init --root-key <BASE58_PUBKEY> [--out ./nyx-keystore.json] \
 *                     --backup-out ./nyx-seed-backup.json [--force]
 *
 *   # Disaster recovery onto a fresh keystore:
 *   nyx-keystore-init --root-key <BASE58_PUBKEY> \
 *                     --import-backup ./nyx-seed-backup.json [--force]
 *
 *   --root-key   (required) base58 pubkey of the funding/root wallet.
 *   --out        keystore path (default ./nyx-keystore.json).
 *   --backup-out     encrypted backup destination when generating a new seed.
 *   --import-backup  encrypted backup v1 to restore; mutually exclusive with
 *                    --backup-out.
 *   --force      overwrite an existing --out file.
 *
 * The passphrase comes from NYX_DAEMON_KEYSTORE_PASSPHRASE (scriptable; never a
 * CLI arg, so it doesn't land in shell history / the process table).
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { PublicKey } from "@solana/web3.js";
import { exportEncryptedMasterSeed, importEncryptedMasterSeed } from "@nyx/sdk";

import {
  Keystore,
  deriveAccountIdentity,
  generateAccountIdentity,
  saveKeystore,
} from "../src/keystore.js";

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
  const backupPassphrase = process.env.NYX_DAEMON_SEED_BACKUP_PASSPHRASE;
  if (!backupPassphrase) {
    throw new Error("NYX_DAEMON_SEED_BACKUP_PASSPHRASE is required");
  }
  if (backupPassphrase === passphrase) {
    throw new Error("seed-backup and keystore passphrases must be distinct");
  }

  const backupOut = arg("backup-out");
  const importBackup = arg("import-backup");
  if (Boolean(backupOut) === Boolean(importBackup)) {
    throw new Error(
      "provide exactly one of --backup-out (new seed) or --import-backup (recovery)",
    );
  }
  if (backupOut === out) {
    throw new Error("--backup-out and --out must be different files");
  }

  if (existsSync(out) && !flag("force")) {
    throw new Error(`${out} exists; pass --force to overwrite`);
  }
  if (backupOut && existsSync(backupOut) && !flag("force")) {
    throw new Error(`${backupOut} exists; pass --force to overwrite`);
  }

  const rootKeyPubkey = new PublicKey(rootKeyB58).toBytes();
  const restoredSeed = importBackup
    ? importEncryptedMasterSeed(
        readFileSync(importBackup, "utf8"),
        backupPassphrase,
      )
    : null;
  const identity = restoredSeed
    ? deriveAccountIdentity(restoredSeed, rootKeyPubkey)
    : generateAccountIdentity(rootKeyPubkey);

  if (identity.masterSeed.length !== 64) {
    throw new Error("seed must be 64 bytes (128 hex chars)");
  }

  const ks = new Keystore(identity);
  const ownerCommit = await ks.ownerCommitment();
  const userCommit = await ks.userCommitment();

  if (backupOut) {
    const backup = exportEncryptedMasterSeed(
      identity.masterSeed,
      backupPassphrase,
    );
    writeFileSync(backupOut, `${JSON.stringify(backup, null, 2)}\n`, {
      mode: 0o600,
      flag: flag("force") ? "w" : "wx",
    });
    chmodSync(backupOut, 0o600);
  }
  saveKeystore(identity, out, passphrase);

  console.log(`keystore written: ${out} (encrypted, 0600)`);
  console.log(
    backupOut
      ? `encrypted seed backup written: ${backupOut} (version 1, 0600)`
      : `seed restored from encrypted backup: ${importBackup}`,
  );
  console.log("");
  console.log("Register these on-chain (create_wallet) before trading:");
  console.log(`  root_key:         ${rootKeyB58}`);
  console.log(`  owner_commitment: ${ownerCommit.toString(16)}`);
  console.log(`  user_commitment:  ${Buffer.from(userCommit).toString("hex")}`);
}

main().catch((e) => {
  console.error(`keystore-init: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
