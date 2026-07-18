/**
 * Versioned, seed-only disaster-recovery envelope.
 *
 * Daily clients should keep the 64-byte CSPRNG master seed in their secure
 * {@link MasterSeedStorage}. This format is the portable offline backup: scrypt
 * derives an AES-256-GCM wrapping key from a distinct backup passphrase, and a
 * fixed AAD domain binds the ciphertext to Darknyx backup version 2.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

import { MASTER_SEED_BYTES } from "./key-generators.js";

export const MASTER_SEED_BACKUP_FORMAT = "darknyx-master-seed-backup" as const;
export const MASTER_SEED_BACKUP_VERSION = 2 as const;

const KDF = { name: "scrypt", n: 16_384, r: 8, p: 1 } as const;
const CIPHER = "aes-256-gcm" as const;
const AAD = Buffer.from("darknyx/master-seed-backup/v2", "utf8");
const MIN_PASSPHRASE_LENGTH = 12;

export interface EncryptedMasterSeedBackupV2 {
  format: typeof MASTER_SEED_BACKUP_FORMAT;
  version: typeof MASTER_SEED_BACKUP_VERSION;
  kdf: {
    name: typeof KDF.name;
    n: typeof KDF.n;
    r: typeof KDF.r;
    p: typeof KDF.p;
    salt: string;
  };
  cipher: {
    name: typeof CIPHER;
    iv: string;
    ciphertext: string;
    tag: string;
  };
}

function requirePassphrase(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `seed-backup passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
    );
  }
}

function decodeHex(value: unknown, bytes: number, label: string): Buffer {
  if (
    typeof value !== "string" ||
    value.length !== bytes * 2 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    throw new Error(`${label} must be exactly ${bytes} bytes of hex`);
  }
  return Buffer.from(value, "hex");
}

function deriveBackupKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: KDF.n,
    r: KDF.r,
    p: KDF.p,
    maxmem: 64 * 1024 * 1024,
  });
}

/** Encrypt a 64-byte CSPRNG master seed into backup format version 2. */
export function exportEncryptedMasterSeed(
  masterSeed: Uint8Array,
  passphrase: string,
): EncryptedMasterSeedBackupV2 {
  if (masterSeed.length !== MASTER_SEED_BYTES) {
    throw new Error(
      `master seed must be ${MASTER_SEED_BYTES} bytes, got ${masterSeed.length}`,
    );
  }
  requirePassphrase(passphrase);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveBackupKey(passphrase, salt);
  const plaintext = Buffer.from(masterSeed);
  try {
    const cipher = createCipheriv(CIPHER, key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    return {
      format: MASTER_SEED_BACKUP_FORMAT,
      version: MASTER_SEED_BACKUP_VERSION,
      kdf: {
        ...KDF,
        salt: salt.toString("hex"),
      },
      cipher: {
        name: CIPHER,
        iv: iv.toString("hex"),
        ciphertext: ciphertext.toString("hex"),
        tag: cipher.getAuthTag().toString("hex"),
      },
    };
  } finally {
    plaintext.fill(0);
    key.fill(0);
  }
}

function parseBackup(
  input: EncryptedMasterSeedBackupV2 | string,
): EncryptedMasterSeedBackupV2 {
  let value: unknown = input;
  if (typeof input === "string") {
    try {
      value = JSON.parse(input);
    } catch {
      throw new Error("invalid encrypted seed-backup JSON");
    }
  }
  if (!value || typeof value !== "object") {
    throw new Error("invalid encrypted seed-backup envelope");
  }
  const backup = value as Partial<EncryptedMasterSeedBackupV2>;
  const kdf = backup.kdf;
  const cipher = backup.cipher;
  if (
    backup.format !== MASTER_SEED_BACKUP_FORMAT ||
    backup.version !== MASTER_SEED_BACKUP_VERSION ||
    !kdf ||
    kdf.name !== KDF.name ||
    kdf.n !== KDF.n ||
    kdf.r !== KDF.r ||
    kdf.p !== KDF.p ||
    !cipher ||
    cipher.name !== CIPHER
  ) {
    throw new Error("unsupported encrypted seed-backup format or parameters");
  }
  return backup as EncryptedMasterSeedBackupV2;
}

/** Decrypt and authenticate backup v2, returning a new 64-byte seed copy. */
export function importEncryptedMasterSeed(
  input: EncryptedMasterSeedBackupV2 | string,
  passphrase: string,
): Uint8Array {
  requirePassphrase(passphrase);
  const backup = parseBackup(input);
  const salt = decodeHex(backup.kdf.salt, 16, "backup salt");
  const iv = decodeHex(backup.cipher.iv, 12, "backup IV");
  const ciphertext = decodeHex(
    backup.cipher.ciphertext,
    MASTER_SEED_BYTES,
    "backup ciphertext",
  );
  const tag = decodeHex(backup.cipher.tag, 16, "backup authentication tag");
  const key = deriveBackupKey(passphrase, salt);
  let plaintext: Buffer | null = null;
  try {
    const decipher = createDecipheriv(CIPHER, key, iv);
    decipher.setAAD(AAD);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length !== MASTER_SEED_BYTES) {
      throw new Error("decrypted seed has the wrong length");
    }
    return Uint8Array.from(plaintext);
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
    plaintext?.fill(0);
    key.fill(0);
  }
}
