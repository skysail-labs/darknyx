import { readSealedJson, writeSealedJson } from "./sealed-file.js";
import type { RecoveredFeeNote } from "./types.js";

const INVENTORY_KIND = "fee-inventory";
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL_U64 = /^(0|[1-9][0-9]*)$/;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

export interface StoredFeeNote {
  epoch: string;
  batchRoot: string;
  verifySignature: string;
  settleSignature: string;
  matchIndex: number;
  side: "base" | "quote";
  tokenMint: string;
  amount: string;
  ownerCommitment: string;
  innerHash: string;
  commitment: string;
  treeId: number;
  leafIndex: string;
}

export interface FeeInventory {
  version: 1;
  programId: string;
  recoveryStartSlot: number;
  recoveryEndSlot: number;
  notes: StoredFeeNote[];
}

const toHex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

function fromHex(value: string, name: string): Uint8Array {
  if (!HEX_32.test(value))
    throw new Error(`${name} must be 32-byte lowercase hex`);
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function parseU64(value: string, name: string): bigint {
  if (!DECIMAL_U64.test(value))
    throw new Error(`${name} must be a decimal u64`);
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw new Error(`${name} must be a decimal u64`);
  return parsed;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: string[],
): boolean {
  return (
    Object.keys(value).sort().join("\0") === [...expected].sort().join("\0")
  );
}

function validateStoredNote(value: unknown): StoredFeeNote {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("malformed fee inventory note");
  }
  const note = value as Record<string, unknown>;
  if (
    !exactKeys(note, [
      "amount",
      "batchRoot",
      "commitment",
      "epoch",
      "innerHash",
      "leafIndex",
      "matchIndex",
      "ownerCommitment",
      "settleSignature",
      "side",
      "tokenMint",
      "treeId",
      "verifySignature",
    ]) ||
    typeof note.epoch !== "string" ||
    typeof note.batchRoot !== "string" ||
    typeof note.verifySignature !== "string" ||
    typeof note.settleSignature !== "string" ||
    typeof note.matchIndex !== "number" ||
    (note.side !== "base" && note.side !== "quote") ||
    typeof note.tokenMint !== "string" ||
    typeof note.amount !== "string" ||
    typeof note.ownerCommitment !== "string" ||
    typeof note.innerHash !== "string" ||
    typeof note.commitment !== "string" ||
    typeof note.treeId !== "number" ||
    typeof note.leafIndex !== "string" ||
    !Number.isInteger(note.matchIndex) ||
    note.matchIndex < 0 ||
    note.matchIndex >= 16 ||
    !Number.isInteger(note.treeId) ||
    note.treeId < 0 ||
    note.treeId > 255 ||
    note.verifySignature.length === 0 ||
    note.settleSignature.length === 0
  ) {
    throw new Error("malformed fee inventory note");
  }
  if (parseU64(note.epoch, "fee epoch") === 0n) {
    throw new Error("fee epoch must be a nonzero u64");
  }
  parseU64(note.amount, "fee amount");
  parseU64(note.leafIndex, "fee leaf index");
  fromHex(note.batchRoot, "batch root");
  fromHex(note.tokenMint, "token mint");
  fromHex(note.ownerCommitment, "owner commitment");
  fromHex(note.innerHash, "inner hash");
  fromHex(note.commitment, "commitment");
  return note as unknown as StoredFeeNote;
}

export function validateFeeInventory(value: unknown): FeeInventory {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("fee inventory must be an object");
  }
  const inventory = value as Record<string, unknown>;
  if (
    !exactKeys(inventory, [
      "notes",
      "programId",
      "recoveryEndSlot",
      "recoveryStartSlot",
      "version",
    ]) ||
    inventory.version !== 1 ||
    typeof inventory.programId !== "string" ||
    inventory.programId.length === 0 ||
    typeof inventory.recoveryStartSlot !== "number" ||
    typeof inventory.recoveryEndSlot !== "number" ||
    !Number.isSafeInteger(inventory.recoveryStartSlot) ||
    !Number.isSafeInteger(inventory.recoveryEndSlot) ||
    inventory.recoveryStartSlot < 0 ||
    inventory.recoveryEndSlot < inventory.recoveryStartSlot ||
    !Array.isArray(inventory.notes)
  ) {
    throw new Error("unsupported or malformed fee inventory");
  }
  const notes = inventory.notes.map(validateStoredNote);
  const commitments = new Set<string>();
  for (const note of notes) {
    if (commitments.has(note.commitment)) {
      throw new Error("fee inventory contains a duplicate commitment");
    }
    commitments.add(note.commitment);
  }
  return {
    version: 1,
    programId: inventory.programId,
    recoveryStartSlot: inventory.recoveryStartSlot,
    recoveryEndSlot: inventory.recoveryEndSlot,
    notes,
  };
}

export function buildFeeInventory(params: {
  programId: string;
  recoveryStartSlot: number;
  recoveryEndSlot: number;
  notes: readonly RecoveredFeeNote[];
}): FeeInventory {
  return validateFeeInventory({
    version: 1,
    programId: params.programId,
    recoveryStartSlot: params.recoveryStartSlot,
    recoveryEndSlot: params.recoveryEndSlot,
    notes: params.notes.map((note) => ({
      epoch: note.epoch.toString(),
      batchRoot: toHex(note.batchRoot),
      verifySignature: note.verifySignature,
      settleSignature: note.settleSignature,
      matchIndex: note.matchIndex,
      side: note.side,
      tokenMint: toHex(note.tokenMint),
      amount: note.amount.toString(),
      ownerCommitment: toHex(note.ownerCommitment),
      innerHash: toHex(note.innerHash),
      commitment: toHex(note.commitment),
      treeId: note.treeId,
      leafIndex: note.leafIndex.toString(),
    })),
  });
}

export async function writeFeeInventory(
  path: string,
  inventory: FeeInventory,
  passphrase: string,
): Promise<void> {
  await writeSealedJson(
    path,
    INVENTORY_KIND,
    validateFeeInventory(inventory),
    passphrase,
  );
}

export async function readFeeInventory(
  path: string,
  passphrase: string,
): Promise<FeeInventory> {
  return validateFeeInventory(
    await readSealedJson(path, INVENTORY_KIND, passphrase),
  );
}

export function openStoredFeeNote(note: StoredFeeNote): RecoveredFeeNote {
  const validated = validateStoredNote(note);
  return {
    epoch: parseU64(validated.epoch, "fee epoch"),
    batchRoot: fromHex(validated.batchRoot, "batch root"),
    verifySignature: validated.verifySignature,
    settleSignature: validated.settleSignature,
    matchIndex: validated.matchIndex,
    side: validated.side,
    tokenMint: fromHex(validated.tokenMint, "token mint"),
    amount: parseU64(validated.amount, "fee amount"),
    ownerCommitment: fromHex(validated.ownerCommitment, "owner commitment"),
    innerHash: fromHex(validated.innerHash, "inner hash"),
    commitment: fromHex(validated.commitment, "commitment"),
    treeId: validated.treeId,
    leafIndex: parseU64(validated.leafIndex, "leaf index"),
  };
}
