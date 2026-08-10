import type { EncryptedSeedBackupV2, VaultStatus } from "@darknyx/client-core";
import { PublicKey } from "@solana/web3.js";
import {
  recoverNotesFromChain,
  type RawSettleTx,
} from "@darknyx/sdk/browser-recovery";
import {
  bn254ToBE32,
  deriveNoteUseTag,
  deriveOwnerCommitmentBlinding,
  deriveSpendingKey,
  noteCommitmentV2,
  ownerCommitment,
  pubkeyToFrPair,
} from "@darknyx/sdk/browser-inventory-crypto";
import { scrypt } from "scrypt-js";

import {
  aadForHeader,
  BACKUP_AAD,
  fromBase64Url,
  MASTER_SEED_BYTES,
  randomBytes,
  toBase64Url,
  validateBackup,
  type BrowserVaultRecord,
} from "./codec.js";

const encoder = new TextEncoder();
const BACKUP_FORMAT = "darknyx-master-seed-backup";
const BACKUP_VERSION = 2;
const CURRENT_SCRYPT_N = 131_072;
const ACCEPTED_SCRYPT_N = new Set([16_384, CURRENT_SCRYPT_N]);
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const MIN_PASSPHRASE_LENGTH = 12;
const INVENTORY_KEY_INFO = new TextEncoder().encode(
  "darknyx/browser-inventory-key/v1",
);
const INVENTORY_AAD = new TextEncoder().encode("darknyx/browser-inventory/v1");

type VaultHeader = Omit<BrowserVaultRecord, "cipher">;
type Cipher = BrowserVaultRecord["cipher"];

interface WorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse): void;
}

type WorkerRequest = {
  id: number;
  type: string;
  payload: Record<string, unknown>;
};

type WorkerResponse =
  | { id: number; ok: true; value: unknown }
  | { id: number; ok: false; error: string }
  | { kind: "event"; event: "locked"; reason: "inactivity" };

const workerScope = self as unknown as WorkerScope;
let seed: Uint8Array<ArrayBuffer> | null = null;
let inactivityTimer: ReturnType<typeof setTimeout> | null = null;
let configuredInactivityMs = 0;
let inactivityDeadline = 0;

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function be32ToBigInt(value: Uint8Array): bigint {
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function fromHex(
  value: unknown,
  length: number,
  label: string,
): Uint8Array<ArrayBuffer> {
  if (
    typeof value !== "string" ||
    value.length !== length * 2 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    throw new Error(`${label} must be exactly ${length} bytes of hex`);
  }
  return Uint8Array.from(value.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
}

function clearSeed(reason: "explicit" | "inactivity" = "explicit"): void {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  inactivityTimer = null;
  inactivityDeadline = 0;
  seed?.fill(0);
  seed = null;
  if (reason === "inactivity") {
    workerScope.postMessage({ kind: "event", event: "locked", reason });
  }
}

function configureInactivity(inactivityMs: unknown): void {
  if (
    typeof inactivityMs !== "number" ||
    !Number.isFinite(inactivityMs) ||
    inactivityMs <= 0
  ) {
    throw new Error("inactivity timeout must be a positive number");
  }
  configuredInactivityMs = inactivityMs;
}

function armInactivity(inactivityMs = configuredInactivityMs): void {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  inactivityDeadline = performance.now() + inactivityMs;
  inactivityTimer = setTimeout(() => clearSeed("inactivity"), inactivityMs);
}

function rearmUntil(deadline: number): void {
  if (!seed || deadline <= 0) return;
  const remaining = deadline - performance.now();
  if (remaining <= 0) {
    clearSeed("inactivity");
    return;
  }
  inactivityDeadline = deadline;
  inactivityTimer = setTimeout(() => clearSeed("inactivity"), remaining);
}

function requireSeed(): Uint8Array<ArrayBuffer> {
  if (!seed) throw new Error("browser vault is locked");
  return seed;
}

async function encryptVault(
  wrappingKey: CryptoKey,
  header: VaultHeader,
  value: Uint8Array<ArrayBuffer>,
): Promise<Cipher> {
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadForHeader(header) },
      wrappingKey,
      value,
    ),
  );
  return {
    name: "AES-256-GCM",
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

async function decryptVault(
  wrappingKey: CryptoKey,
  record: BrowserVaultRecord,
): Promise<Uint8Array<ArrayBuffer>> {
  let plaintext: Uint8Array<ArrayBuffer>;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: fromBase64Url(record.cipher.iv),
          additionalData: aadForHeader(record),
        },
        wrappingKey,
        fromBase64Url(record.cipher.ciphertext),
      ),
    );
  } catch {
    throw new Error("browser-vault decrypt failed");
  }
  if (plaintext.length !== MASTER_SEED_BYTES) {
    plaintext.fill(0);
    throw new Error("browser-vault plaintext has the wrong length");
  }
  return plaintext;
}

function requirePassphrase(passphrase: unknown): asserts passphrase is string {
  if (
    typeof passphrase !== "string" ||
    passphrase.length < MIN_PASSPHRASE_LENGTH
  ) {
    throw new Error(
      `seed-backup passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
    );
  }
}

async function deriveBackupKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  n: number,
): Promise<Uint8Array<ArrayBuffer>> {
  return Uint8Array.from(
    await scrypt(encoder.encode(passphrase), salt, n, SCRYPT_R, SCRYPT_P, 32),
  );
}

async function exportBackup(
  passphrase: unknown,
): Promise<EncryptedSeedBackupV2> {
  requirePassphrase(passphrase);
  const currentSeed = requireSeed();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const keyBytes = await deriveBackupKey(passphrase, salt, CURRENT_SCRYPT_N);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: BACKUP_AAD },
        key,
        currentSeed,
      ),
    );
    return {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      kdf: {
        name: "scrypt",
        n: CURRENT_SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: toHex(salt),
      },
      cipher: {
        name: "aes-256-gcm",
        iv: toHex(iv),
        ciphertext: toHex(sealed.subarray(0, MASTER_SEED_BYTES)),
        tag: toHex(sealed.subarray(MASTER_SEED_BYTES)),
      },
    };
  } finally {
    keyBytes.fill(0);
  }
}

async function importBackup(
  candidate: unknown,
  passphrase: unknown,
): Promise<Uint8Array<ArrayBuffer>> {
  requirePassphrase(passphrase);
  const backup = validateBackup(candidate);
  if (
    backup.format !== BACKUP_FORMAT ||
    backup.version !== BACKUP_VERSION ||
    backup.kdf.name !== "scrypt" ||
    !ACCEPTED_SCRYPT_N.has(backup.kdf.n) ||
    backup.kdf.r !== SCRYPT_R ||
    backup.kdf.p !== SCRYPT_P ||
    backup.cipher.name !== "aes-256-gcm"
  ) {
    throw new Error("unsupported encrypted seed-backup format or parameters");
  }
  const salt = fromHex(backup.kdf.salt, 16, "backup salt");
  const iv = fromHex(backup.cipher.iv, 12, "backup IV");
  const ciphertext = fromHex(
    backup.cipher.ciphertext,
    MASTER_SEED_BYTES,
    "backup ciphertext",
  );
  const tag = fromHex(backup.cipher.tag, 16, "backup authentication tag");
  const sealed = new Uint8Array(MASTER_SEED_BYTES + 16);
  sealed.set(ciphertext);
  sealed.set(tag, MASTER_SEED_BYTES);
  const keyBytes = await deriveBackupKey(passphrase, salt, backup.kdf.n);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: BACKUP_AAD },
        key,
        sealed,
      ),
    );
    if (plaintext.length !== MASTER_SEED_BYTES) {
      plaintext.fill(0);
      throw new Error("decrypted seed has the wrong length");
    }
    return plaintext;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "decrypted seed has the wrong length"
    ) {
      throw error;
    }
    throw new Error(
      "seed-backup decrypt failed (wrong passphrase or corrupt backup)",
    );
  } finally {
    keyBytes.fill(0);
    sealed.fill(0);
  }
}

async function deriveInventoryKey(): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    requireSeed(),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: INVENTORY_KEY_INFO,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

type Handler = (payload: Record<string, unknown>) => Promise<unknown>;

const handlers: Readonly<Record<string, Handler>> = Object.freeze({
  async provision({ wrappingKey, header, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = randomBytes(MASTER_SEED_BYTES);
    try {
      return {
        cipher: await encryptVault(
          wrappingKey as CryptoKey,
          header as VaultHeader,
          seed,
        ),
      };
    } catch (error) {
      clearSeed();
      throw error;
    }
  },
  async unlock({ wrappingKey, record, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = await decryptVault(
      wrappingKey as CryptoKey,
      record as BrowserVaultRecord,
    );
    return { state: "unlocked" } satisfies VaultStatus;
  },
  async lock() {
    clearSeed();
    return { state: "locked" } satisfies VaultStatus;
  },
  async status() {
    return { state: seed ? "unlocked" : "locked" } satisfies VaultStatus;
  },
  async exportBackup({ passphrase }) {
    return exportBackup(passphrase);
  },
  async restore({ backup, passphrase, wrappingKey, header, inactivityMs }) {
    clearSeed();
    configureInactivity(inactivityMs);
    seed = await importBackup(backup, passphrase);
    try {
      return {
        cipher: await encryptVault(
          wrappingKey as CryptoKey,
          header as VaultHeader,
          seed,
        ),
      };
    } catch (error) {
      clearSeed();
      throw error;
    }
  },
  async inventorySeal({ plaintext }) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new Error("inventory plaintext must be bytes");
    }
    const plaintextBytes = Uint8Array.from(plaintext);
    const iv = randomBytes(12);
    const key = await deriveInventoryKey();
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: INVENTORY_AAD },
        key,
        plaintextBytes,
      ),
    );
    return { iv, ciphertext };
  },
  async inventoryOpen({ iv, ciphertext }) {
    if (
      !(iv instanceof Uint8Array) ||
      iv.length !== 12 ||
      !(ciphertext instanceof Uint8Array) ||
      ciphertext.length < 16
    ) {
      throw new Error("malformed inventory ciphertext");
    }
    // Keep a locked vault distinguishable from authenticated-decryption
    // failure so the UI can request an unlock instead of reporting corruption.
    const key = await deriveInventoryKey();
    try {
      const ivBytes = Uint8Array.from(iv);
      const ciphertextBytes = Uint8Array.from(ciphertext);
      return new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ivBytes, additionalData: INVENTORY_AAD },
          key,
          ciphertextBytes,
        ),
      );
    } catch {
      throw new Error("browser inventory decrypt failed");
    }
  },
  async recoverNotes({
    programId,
    baseMint,
    quoteMint,
    transactions,
    sinceSlot,
  }) {
    if (typeof programId !== "string" || !Array.isArray(transactions)) {
      throw new Error("malformed browser recovery request");
    }
    if (
      sinceSlot !== undefined &&
      (!Number.isSafeInteger(sinceSlot) || (sinceSlot as number) < 0)
    ) {
      throw new Error("recovery sinceSlot must be a non-negative safe integer");
    }
    return recoverNotesFromChain({
      connection: undefined as never,
      programId: new PublicKey(programId),
      masterSeed: requireSeed(),
      baseMint: fromHex(baseMint, 32, "base mint"),
      quoteMint: fromHex(quoteMint, 32, "quote mint"),
      sinceSlot: sinceSlot as number | undefined,
      scan: async () => transactions as RawSettleTx[],
    });
  },
  async validInputWitness({ note, merkleRoot, siblings, pathIndices }) {
    if (!note || typeof note !== "object") {
      throw new Error("VALID_INPUT note is malformed");
    }
    const candidate = note as Record<string, unknown>;
    if (
      typeof candidate.commitment !== "string" ||
      !(candidate.tokenMint instanceof Uint8Array) ||
      candidate.tokenMint.length !== 32 ||
      typeof candidate.amount !== "bigint" ||
      candidate.amount <= 0n ||
      typeof candidate.ownerCommitment !== "bigint" ||
      typeof candidate.innerHash !== "bigint" ||
      !Array.isArray(siblings) ||
      siblings.length !== 20 ||
      !Array.isArray(pathIndices) ||
      pathIndices.length !== 20 ||
      pathIndices.some((index) => index !== 0 && index !== 1)
    ) {
      throw new Error("VALID_INPUT witness is malformed");
    }
    const root = fromHex(merkleRoot, 32, "Merkle root");
    const siblingValues = siblings.map((value, index) =>
      be32ToBigInt(fromHex(value, 32, `Merkle sibling ${index}`)),
    );
    const currentSeed = requireSeed();
    const spendingKey = deriveSpendingKey(currentSeed);
    const ownerBlinding = deriveOwnerCommitmentBlinding(currentSeed);
    const expectedOwner = await ownerCommitment(spendingKey, ownerBlinding);
    if (expectedOwner !== candidate.ownerCommitment) {
      throw new Error("inventory note is not owned by this vault");
    }
    const commitment = await noteCommitmentV2({
      tokenMint: candidate.tokenMint,
      amount: candidate.amount,
      ownerCommitment: candidate.ownerCommitment,
      innerHash: candidate.innerHash,
    });
    if (
      !equalBytes(commitment, fromHex(candidate.commitment, 32, "commitment"))
    ) {
      throw new Error("inventory note opening does not match its commitment");
    }
    const noteUseTag = await deriveNoteUseTag(
      commitment,
      bn254ToBE32(candidate.innerHash),
    );
    const [mintLo, mintHi] = pubkeyToFrPair(candidate.tokenMint);
    return {
      merkleRoot: be32ToBigInt(root).toString(),
      noteUseTag: be32ToBigInt(noteUseTag).toString(),
      tokenMint: [mintLo.toString(), mintHi.toString()],
      amount: candidate.amount.toString(),
      spendingKey: spendingKey.toString(),
      ownerCommitmentBlinding: ownerBlinding.toString(),
      innerHash: candidate.innerHash.toString(),
      merklePath: siblingValues.map(String),
      merkleIndices: (pathIndices as number[]).map(String),
    };
  },
});

const PASSIVE_COMMANDS = new Set(["status"]);

async function handleMessage(data: WorkerRequest): Promise<void> {
  const handler = Object.prototype.hasOwnProperty.call(handlers, data.type)
    ? handlers[data.type]
    : undefined;
  if (!handler) {
    workerScope.postMessage({
      id: data.id,
      ok: false,
      error: `unsupported vault command: ${data.type}`,
    });
    return;
  }
  const passive = PASSIVE_COMMANDS.has(data.type);
  const previousDeadline = inactivityDeadline;
  try {
    if (seed && previousDeadline > 0 && performance.now() >= previousDeadline) {
      clearSeed("inactivity");
    }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    const value = await handler(data.payload);
    if (seed) {
      if (passive) rearmUntil(previousDeadline);
      else if (data.type !== "lock") armInactivity();
    }
    workerScope.postMessage({ id: data.id, ok: true, value });
  } catch (error) {
    if (seed) {
      if (passive) rearmUntil(previousDeadline);
      else armInactivity();
    }
    workerScope.postMessage({
      id: data.id,
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "browser-vault operation failed",
    });
  }
}

// Worker callbacks may re-enter while an awaited crypto operation is running.
// Serialize them so lock/restore cannot zero or replace an in-use seed.
let commandQueue = Promise.resolve();
workerScope.onmessage = ({ data }) => {
  commandQueue = commandQueue.then(() => handleMessage(data)).catch(() => undefined);
};
