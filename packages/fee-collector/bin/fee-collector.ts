#!/usr/bin/env node

import { lstat } from "node:fs/promises";

import {
  buildFeeInventory,
  createFeeKeyring,
  feeKeyProvider,
  loadFeeKeyring,
  makeFinalizedMarketResolver,
  publicFeeKeyringSummary,
  recoverProtocolFees,
  rotateFeeKeyring,
  saveFeeKeyring,
  scanFinalizedVaultHistory,
  verifyFeeKeyringBackup,
  writeFeeDeploymentEnv,
  writeFeeInventory,
} from "../src/index.js";

type Flags = Map<string, string>;

function usage(): never {
  throw new Error(
    "usage: darknyx-fee-collector <init|rotate|verify-backup|write-deploy-env|recover> [options]",
  );
}

function parseFlags(args: string[]): Flags {
  const out = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (
      !name?.startsWith("--") ||
      value === undefined ||
      value.startsWith("--")
    ) {
      usage();
    }
    if (out.has(name)) throw new Error(`duplicate option ${name}`);
    out.set(name, value);
  }
  return out;
}

function exactFlags(flags: Flags, allowed: string[]): void {
  for (const flag of flags.keys()) {
    if (!allowed.includes(flag)) throw new Error(`unknown option ${flag}`);
  }
}

function required(flags: Flags, name: string): string {
  const value = flags.get(name);
  if (!value) throw new Error(`missing required option ${name}`);
  return value;
}

function parseU64(value: string, name: string, allowZero = false): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value))
    throw new Error(`${name} must be a u64`);
  const parsed = BigInt(value);
  if ((!allowZero && parsed === 0n) || parsed > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`${name} must be a ${allowZero ? "" : "nonzero "}u64`);
  }
  return parsed;
}

function envSecret(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function mustNotExist(path: string): Promise<void> {
  try {
    await lstat(path);
    throw new Error("refusing to overwrite an existing operator keyring");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function init(flags: Flags): Promise<void> {
  exactFlags(flags, ["--keystore", "--backup", "--epoch"]);
  const keystore = required(flags, "--keystore");
  const backup = required(flags, "--backup");
  const epoch = parseU64(flags.get("--epoch") ?? "1", "epoch");
  const passphrase = envSecret("DARKNYX_FEE_KEYSTORE_PASSPHRASE");
  await Promise.all([mustNotExist(keystore), mustNotExist(backup)]);
  const keyring = await createFeeKeyring(epoch);
  await saveFeeKeyring(keystore, keyring, passphrase);
  await saveFeeKeyring(backup, keyring, passphrase);
  const summary = publicFeeKeyringSummary(keyring).epochs[0];
  console.log(
    JSON.stringify({
      command: "init",
      epoch: summary.epoch.toString(),
      binding: summary.binding,
    }),
  );
}

async function rotate(flags: Flags): Promise<void> {
  exactFlags(flags, ["--keystore", "--backup", "--epoch"]);
  const keystore = required(flags, "--keystore");
  const backup = required(flags, "--backup");
  const epoch = parseU64(required(flags, "--epoch"), "epoch");
  const passphrase = envSecret("DARKNYX_FEE_KEYSTORE_PASSPHRASE");
  await verifyFeeKeyringBackup(keystore, backup, passphrase);
  const rotated = await rotateFeeKeyring(
    await loadFeeKeyring(keystore, passphrase),
    epoch,
  );
  await saveFeeKeyring(backup, rotated, passphrase);
  await saveFeeKeyring(keystore, rotated, passphrase);
  const summary = publicFeeKeyringSummary(rotated).epochs.at(-1);
  if (!summary) throw new Error("rotated fee keyring is empty");
  console.log(
    JSON.stringify({
      command: "rotate",
      epoch: summary.epoch.toString(),
      binding: summary.binding,
    }),
  );
}

async function verifyBackup(flags: Flags): Promise<void> {
  exactFlags(flags, ["--keystore", "--backup"]);
  const result = await verifyFeeKeyringBackup(
    required(flags, "--keystore"),
    required(flags, "--backup"),
    envSecret("DARKNYX_FEE_KEYSTORE_PASSPHRASE"),
  );
  console.log(
    JSON.stringify({
      command: "verify-backup",
      epochCount: result.epochs.length,
      activeEpoch: result.activeEpoch.toString(),
    }),
  );
}

async function writeDeployEnv(flags: Flags): Promise<void> {
  exactFlags(flags, ["--keystore", "--output"]);
  const result = await writeFeeDeploymentEnv(
    required(flags, "--output"),
    await loadFeeKeyring(
      required(flags, "--keystore"),
      envSecret("DARKNYX_FEE_KEYSTORE_PASSPHRASE"),
    ),
  );
  console.log(
    JSON.stringify({
      command: "write-deploy-env",
      epoch: result.epoch.toString(),
      binding: result.binding,
    }),
  );
}

async function recover(flags: Flags): Promise<void> {
  exactFlags(flags, [
    "--keystore",
    "--rpc-url",
    "--program-id",
    "--output",
    "--since-slot",
  ]);
  const rpcUrl = required(flags, "--rpc-url");
  const programId = required(flags, "--program-id");
  const output = required(flags, "--output");
  const since = parseU64(flags.get("--since-slot") ?? "0", "since-slot", true);
  if (since > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("since-slot exceeds the JavaScript safe-integer range");
  }
  const keyring = await loadFeeKeyring(
    required(flags, "--keystore"),
    envSecret("DARKNYX_FEE_KEYSTORE_PASSPHRASE"),
  );
  const transactions = await scanFinalizedVaultHistory({
    rpcUrl,
    programId,
    sinceSlot: Number(since),
  });
  const result = await recoverProtocolFees({
    transactions,
    programId,
    keyForEpoch: feeKeyProvider(keyring),
    resolveMarket: makeFinalizedMarketResolver(rpcUrl, programId),
  });
  const reasons: Record<string, number> = {};
  for (const issue of result.unresolved) {
    reasons[issue.reason] = (reasons[issue.reason] ?? 0) + 1;
  }
  const summary = {
    command: "recover",
    finalizedTransactions: transactions.length,
    recoveredNotes: result.notes.length,
    skippedUnsettledSlots: result.skippedUnsettledSlots,
    unresolved: result.unresolved.length,
    unresolvedReasons: reasons,
  };
  if (result.unresolved.length > 0) {
    console.log(JSON.stringify(summary));
    process.exitCode = 2;
    return;
  }
  const endSlot = transactions.reduce(
    (maximum, transaction) => Math.max(maximum, transaction.slot),
    Number(since),
  );
  const inventory = buildFeeInventory({
    programId,
    recoveryStartSlot: Number(since),
    recoveryEndSlot: endSlot,
    notes: result.notes,
  });
  await writeFeeInventory(
    output,
    inventory,
    envSecret("DARKNYX_FEE_INVENTORY_PASSPHRASE"),
  );
  console.log(JSON.stringify(summary));
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  const flags = parseFlags(args);
  switch (command) {
    case "init":
      return init(flags);
    case "rotate":
      return rotate(flags);
    case "verify-backup":
      return verifyBackup(flags);
    case "write-deploy-env":
      return writeDeployEnv(flags);
    case "recover":
      return recover(flags);
    default:
      usage();
  }
}

main().catch((error: unknown) => {
  console.error(
    `fee collector failed: ${error instanceof Error ? error.message : "unknown error"}`,
  );
  process.exitCode = 1;
});
