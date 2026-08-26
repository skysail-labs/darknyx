import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { deriveFeeKeyBinding } from "@darknyx/sdk";
import { readSealedJson, writeSealedJson } from "./sealed-file.js";
import type { FeeKeyMaterial } from "./types.js";

const KEYRING_KIND = "fee-keyring";
const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface StoredFeeKeyEpoch {
  epoch: string;
  key: string;
  binding: string;
  state: "active" | "retired";
}

export interface FeeKeyring {
  version: 1;
  epochs: StoredFeeKeyEpoch[];
}

const toHex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

function fromHex(value: string, name: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value))
    throw new Error(`${name} must be 32-byte lowercase hex`);
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function bytesToBigInt(value: Uint8Array): bigint {
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}

export function generateCanonicalFeeEpochKey(): Uint8Array {
  for (;;) {
    const key = Uint8Array.from(randomBytes(32));
    const scalar = bytesToBigInt(key);
    if (scalar > 0n && scalar < BN254_SCALAR_MODULUS) return key;
    key.fill(0);
  }
}

async function storedEpoch(
  epoch: bigint,
  key: Uint8Array,
  state: "active" | "retired",
): Promise<StoredFeeKeyEpoch> {
  if (epoch <= 0n || epoch > 0xffff_ffff_ffff_ffffn) {
    throw new Error("fee-key epoch must be a nonzero u64");
  }
  if (
    key.length !== 32 ||
    bytesToBigInt(key) <= 0n ||
    bytesToBigInt(key) >= BN254_SCALAR_MODULUS
  ) {
    throw new Error("fee epoch key must be a canonical nonzero BN254 scalar");
  }
  return {
    epoch: epoch.toString(),
    key: toHex(key),
    binding: toHex(await deriveFeeKeyBinding(key)),
    state,
  };
}

export async function createFeeKeyring(
  epoch = 1n,
  key = generateCanonicalFeeEpochKey(),
): Promise<FeeKeyring> {
  return { version: 1, epochs: [await storedEpoch(epoch, key, "active")] };
}

export async function rotateFeeKeyring(
  keyring: FeeKeyring,
  epoch: bigint,
  key = generateCanonicalFeeEpochKey(),
): Promise<FeeKeyring> {
  const validated = await validateFeeKeyring(keyring);
  const maximum = validated.epochs.reduce(
    (value, item) => (BigInt(item.epoch) > value ? BigInt(item.epoch) : value),
    0n,
  );
  if (epoch <= maximum) throw new Error("new fee-key epoch must be monotonic");
  return {
    version: 1,
    epochs: [
      ...validated.epochs.map((item) => ({
        ...item,
        state: "retired" as const,
      })),
      await storedEpoch(epoch, key, "active"),
    ],
  };
}

export async function validateFeeKeyring(value: unknown): Promise<FeeKeyring> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("fee keyring must be an object");
  }
  const candidate = value as Record<string, unknown>;
  if (
    Object.keys(candidate).sort().join("\0") !== "epochs\0version" ||
    candidate.version !== 1 ||
    !Array.isArray(candidate.epochs) ||
    candidate.epochs.length === 0
  ) {
    throw new Error("unsupported or malformed fee keyring");
  }
  const epochs: StoredFeeKeyEpoch[] = [];
  let active = 0;
  let previous = 0n;
  for (const raw of candidate.epochs) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error("malformed fee-key epoch");
    }
    const item = raw as Record<string, unknown>;
    if (
      Object.keys(item).sort().join("\0") !== "binding\0epoch\0key\0state" ||
      typeof item.epoch !== "string" ||
      typeof item.key !== "string" ||
      typeof item.binding !== "string" ||
      (item.state !== "active" && item.state !== "retired") ||
      !/^[1-9][0-9]*$/.test(item.epoch)
    ) {
      throw new Error("malformed fee-key epoch");
    }
    const epoch = BigInt(item.epoch);
    if (epoch <= previous || epoch > 0xffff_ffff_ffff_ffffn) {
      throw new Error("fee-key epochs must be unique monotonic u64 values");
    }
    previous = epoch;
    const key = fromHex(item.key, "fee epoch key");
    const binding = fromHex(item.binding, "fee key binding");
    if (
      bytesToBigInt(key) === 0n ||
      bytesToBigInt(key) >= BN254_SCALAR_MODULUS
    ) {
      throw new Error("fee epoch key is not a canonical nonzero BN254 scalar");
    }
    const expected = await deriveFeeKeyBinding(key);
    if (
      expected.length !== binding.length ||
      !expected.every((byte, index) => byte === binding[index])
    ) {
      throw new Error(`fee-key binding mismatch at epoch ${epoch}`);
    }
    if (item.state === "active") active += 1;
    epochs.push(item as unknown as StoredFeeKeyEpoch);
  }
  if (active !== 1 || epochs[epochs.length - 1].state !== "active") {
    throw new Error("fee keyring must have exactly one newest active epoch");
  }
  return { version: 1, epochs };
}

export async function saveFeeKeyring(
  path: string,
  keyring: FeeKeyring,
  passphrase: string,
): Promise<void> {
  await writeSealedJson(
    path,
    KEYRING_KIND,
    await validateFeeKeyring(keyring),
    passphrase,
  );
}

export async function loadFeeKeyring(
  path: string,
  passphrase: string,
): Promise<FeeKeyring> {
  return validateFeeKeyring(
    await readSealedJson(path, KEYRING_KIND, passphrase),
  );
}

export function feeKeyProvider(
  keyring: FeeKeyring,
): (epoch: bigint) => FeeKeyMaterial | null {
  const entries = new Map(
    keyring.epochs.map((item) => [BigInt(item.epoch), item]),
  );
  return (epoch) => {
    const item = entries.get(epoch);
    return item
      ? {
          epoch,
          key: fromHex(item.key, "fee epoch key"),
          binding: fromHex(item.binding, "fee key binding"),
        }
      : null;
  };
}

export async function verifyFeeKeyringBackup(
  primaryPath: string,
  backupPath: string,
  passphrase: string,
): Promise<{ epochs: bigint[]; activeEpoch: bigint }> {
  const [primary, backup] = await Promise.all([
    loadFeeKeyring(primaryPath, passphrase),
    loadFeeKeyring(backupPath, passphrase),
  ]);
  if (JSON.stringify(primary) !== JSON.stringify(backup)) {
    throw new Error("fee-key backup does not match the primary keyring");
  }
  const epochs = primary.epochs.map((item) => BigInt(item.epoch));
  return { epochs, activeEpoch: epochs[epochs.length - 1] };
}

/** Write the active secret for encrypted CVM deployment without printing it. */
export async function writeFeeDeploymentEnv(
  path: string,
  keyring: FeeKeyring,
): Promise<{ epoch: bigint; binding: string }> {
  const validated = await validateFeeKeyring(keyring);
  const active = validated.epochs[validated.epochs.length - 1];
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `DARKNYX_TEE_FEE_EPOCH_KEY=${active.key}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  return { epoch: BigInt(active.epoch), binding: active.binding };
}

export function publicFeeKeyringSummary(keyring: FeeKeyring): {
  epochs: { epoch: bigint; binding: string; state: "active" | "retired" }[];
} {
  return {
    epochs: keyring.epochs.map(({ epoch, binding, state }) => ({
      epoch: BigInt(epoch),
      binding,
      state,
    })),
  };
}
