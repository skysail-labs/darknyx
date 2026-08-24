#!/usr/bin/env node
/**
 * darknyx-keystore-init — create (or recreate) an encrypted daemon keystore.
 *
 * Generates a fresh account identity (one random 64-byte master seed), seals
 * it under a passphrase, and writes a separate encrypted,
 * versioned seed backup. It also creates the authenticated order-sequence
 * sidecar; back that file up with the keystore and restore its latest
 * `next_index`. Plaintext seed import/export is deliberately absent.
 *
 *   DARKNYX_DAEMON_KEYSTORE_PASSPHRASE=<passphrase> \
 *   DARKNYX_DAEMON_SEED_BACKUP_PASSPHRASE=<distinct-passphrase> \
 *   darknyx-keystore-init [--out ./darknyx-keystore.json] \
 *                     --backup-out ./darknyx-seed-backup.json [--force]
 *
 *   # Disaster recovery onto a fresh keystore:
 *   darknyx-keystore-init \
 *                     --import-backup ./darknyx-seed-backup.json [--force]
 *
 *   --out        keystore path (default ./darknyx-keystore.json).
 *   --sequence-out order-sequence path (default <out>.order-sequence).
 *   --sequence-start recovered next index; REQUIRED with --import-backup.
 *   --backup-out     encrypted backup destination when generating a new seed.
 *   --import-backup  encrypted backup v2 to restore; mutually exclusive with
 *                    --backup-out.
 *   --force      overwrite an existing --out file.
 *
 * The passphrase comes from DARKNYX_DAEMON_KEYSTORE_PASSPHRASE (scriptable; never a
 * CLI arg, so it doesn't land in shell history / the process table).
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  exportEncryptedMasterSeed,
  importEncryptedMasterSeed,
} from "@darknyx/sdk";

import {
  Keystore,
  deriveAccountIdentity,
  generateAccountIdentity,
  saveKeystore,
} from "../src/keystore.js";
import { DurableOrderSequence } from "../src/order-sequence.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

async function main(): Promise<void> {
  const out = arg("out") ?? "./darknyx-keystore.json";
  const sequenceOut = arg("sequence-out") ?? `${out}.order-sequence`;
  const passphrase = process.env.DARKNYX_DAEMON_KEYSTORE_PASSPHRASE;
  if (!passphrase)
    throw new Error("DARKNYX_DAEMON_KEYSTORE_PASSPHRASE is required");
  const backupPassphrase = process.env.DARKNYX_DAEMON_SEED_BACKUP_PASSPHRASE;
  if (!backupPassphrase) {
    throw new Error("DARKNYX_DAEMON_SEED_BACKUP_PASSPHRASE is required");
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
  if (sequenceOut === out || sequenceOut === backupOut) {
    throw new Error("--sequence-out must be distinct from keystore and backup");
  }

  if (existsSync(out) && !flag("force")) {
    throw new Error(`${out} exists; pass --force to overwrite`);
  }
  if (backupOut && existsSync(backupOut) && !flag("force")) {
    throw new Error(`${backupOut} exists; pass --force to overwrite`);
  }
  if (existsSync(sequenceOut) && !flag("force")) {
    throw new Error(`${sequenceOut} exists; pass --force to overwrite`);
  }

  const restoredSeed = importBackup
    ? importEncryptedMasterSeed(
        readFileSync(importBackup, "utf8"),
        backupPassphrase,
      )
    : null;
  const identity = restoredSeed
    ? deriveAccountIdentity(restoredSeed)
    : generateAccountIdentity();

  // A restored seed may have allocated indices that are not discoverable from
  // chain history (cancelled/unmatched orders never settle). Validate this
  // before writing any output so a bad recovery command is atomic.
  const sequenceStartRaw = arg("sequence-start");
  if (importBackup && sequenceStartRaw === undefined) {
    throw new Error(
      "--sequence-start is required with --import-backup; restore the backed-up next index",
    );
  }
  const sequenceStart = Number(sequenceStartRaw ?? "0");
  if (
    !Number.isSafeInteger(sequenceStart) ||
    sequenceStart < 0 ||
    sequenceStart > 0x1_0000_0000
  ) {
    throw new Error("--sequence-start must be an integer in 0..4294967296");
  }

  if (identity.masterSeed.length !== 64) {
    throw new Error("seed must be 64 bytes (128 hex chars)");
  }

  const ks = new Keystore(identity);
  const ownerCommit = await ks.ownerCommitment();

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
  DurableOrderSequence.create(
    sequenceOut,
    identity.masterSeed,
    sequenceStart,
    flag("force"),
  );

  console.log(`keystore written: ${out} (encrypted, 0600)`);
  console.log(
    `order sequence written: ${sequenceOut} (next index ${sequenceStart}, authenticated, 0600)`,
  );
  console.log(
    backupOut
      ? `encrypted seed backup written: ${backupOut} (version 2, 0600)`
      : `seed restored from encrypted backup: ${importBackup}`,
  );
  console.log("");
  console.log("Derived shielded account identity:");
  console.log(`  owner_commitment: ${ownerCommit.toString(16)}`);
}

main().catch((e) => {
  console.error(`keystore-init: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
