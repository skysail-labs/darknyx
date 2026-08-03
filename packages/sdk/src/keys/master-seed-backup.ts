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

/**
 * Write-side KDF profile.
 *
 * SW-22: this was `n: 16_384` (2^14) while `daemon/src/keystore.ts` uses 2^17
 * and calls 2^14 `LEGACY_SCRYPT`, kept only to migrate v1 files. Both protect
 * the SAME 64-byte master seed, and the exposure profile ran backwards: the
 * keystore is an operational file on a running host, while this is the portable
 * offline backup — the artifact most likely to be copied to another machine,
 * synced to cloud storage, or printed. The more-exposed copy had the weaker KDF.
 */
const KDF = { name: "scrypt", n: 131_072, r: 8, p: 1 } as const;

/**
 * Profiles accepted when READING. Older backups were written at 2^14 and must
 * keep opening.
 *
 * An allowlist, not "trust `kdf.n` from the file": an attacker-supplied backup
 * could otherwise name an enormous `n` (a memory-exhaustion trigger on the
 * machine doing the restore) or a trivially small one, and the file's own
 * fields are not authenticated until after the KDF has already run.
 */
const ACCEPTED_KDF_N: readonly number[] = [16_384, 131_072];

/**
 * scrypt's working set is ~`128 * N * r` bytes: 128 MiB at N=2^17, r=8. Node
 * rejects the call unless `maxmem` clears that, and leaving it to the default
 * would make a valid invocation fail. Explicit so neither a runtime default nor
 * an untrusted file field controls the allocation.
 */
const KDF_MAXMEM = 256 * 1024 * 1024;
const CIPHER = "aes-256-gcm" as const;
const AAD = Buffer.from("darknyx/master-seed-backup/v2", "utf8");
const MIN_PASSPHRASE_LENGTH = 12;

export interface EncryptedMasterSeedBackupV2 {
  format: typeof MASTER_SEED_BACKUP_FORMAT;
  version: typeof MASTER_SEED_BACKUP_VERSION;
  kdf: {
    name: typeof KDF.name;
    /**
     * scrypt cost. This type describes a file that may have been written by an
     * OLDER version, so it is the accepted set, not the current write value —
     * pinning it to `typeof KDF.n` would make a legacy backup fail to typecheck
     * as well as to open. Validated at runtime against `ACCEPTED_KDF_N`.
     */
    n: 16_384 | 131_072;
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

function deriveBackupKey(
  passphrase: string,
  salt: Buffer,
  n: number = KDF.n,
): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: n,
    r: KDF.r,
    p: KDF.p,
    maxmem: KDF_MAXMEM,
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
    !ACCEPTED_KDF_N.includes(kdf.n) ||
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
  // Derive at the profile the FILE was written with (validated against
  // `ACCEPTED_KDF_N` above), so backups written before the raise still open.
  const key = deriveBackupKey(passphrase, salt, backup.kdf.n);
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
