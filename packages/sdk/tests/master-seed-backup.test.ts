/** Versioned encrypted seed-backup envelope — real scrypt + AES-256-GCM. */

import { describe, expect, it } from "vitest";

import {
  exportEncryptedMasterSeed,
  importEncryptedMasterSeed,
  MASTER_SEED_BACKUP_FORMAT,
  MASTER_SEED_BACKUP_VERSION,
  type EncryptedMasterSeedBackupV2,
} from "../src/keys/master-seed-backup.js";

const PASSPHRASE = "correct horse battery staple";
const seed = () => Uint8Array.from({ length: 64 }, (_, index) => index);

describe("encrypted master-seed backup v2", () => {
  it("round-trips from both the object and serialized JSON", () => {
    const original = seed();
    const backup = exportEncryptedMasterSeed(original, PASSPHRASE);
    expect(backup).toMatchObject({
      format: MASTER_SEED_BACKUP_FORMAT,
      version: MASTER_SEED_BACKUP_VERSION,
      kdf: { name: "scrypt", n: 16_384, r: 8, p: 1 },
      cipher: { name: "aes-256-gcm" },
    });
    expect(Buffer.from(importEncryptedMasterSeed(backup, PASSPHRASE))).toEqual(
      Buffer.from(original),
    );
    expect(
      Buffer.from(
        importEncryptedMasterSeed(JSON.stringify(backup), PASSPHRASE),
      ),
    ).toEqual(Buffer.from(original));
    expect(JSON.stringify(backup)).not.toContain(
      Buffer.from(original).toString("hex"),
    );
  });

  it("uses fresh salt and IV for every export", () => {
    const a = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    const b = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    expect(a.kdf.salt).not.toBe(b.kdf.salt);
    expect(a.cipher.iv).not.toBe(b.cipher.iv);
    expect(a.cipher.ciphertext).not.toBe(b.cipher.ciphertext);
  });

  it("rejects a wrong passphrase and authenticated-field tampering", () => {
    const backup = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    expect(() =>
      importEncryptedMasterSeed(backup, "this is the wrong passphrase"),
    ).toThrow(/decrypt failed/);

    const tampered = structuredClone(backup);
    tampered.cipher.ciphertext =
      (tampered.cipher.ciphertext.startsWith("00") ? "01" : "00") +
      tampered.cipher.ciphertext.slice(2);
    expect(() => importEncryptedMasterSeed(tampered, PASSPHRASE)).toThrow(
      /decrypt failed/,
    );
  });

  it("rejects unsupported or malformed envelopes before expensive work", () => {
    const backup = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    const unsafe = structuredClone(backup) as unknown as {
      kdf: { n: number };
    };
    unsafe.kdf.n = 1_048_576;
    expect(() =>
      importEncryptedMasterSeed(
        unsafe as unknown as EncryptedMasterSeedBackupV2,
        PASSPHRASE,
      ),
    ).toThrow(/unsupported/);
    expect(() => importEncryptedMasterSeed("not json", PASSPHRASE)).toThrow(
      /invalid.*JSON/,
    );

    const badIv = structuredClone(backup);
    badIv.cipher.iv = "00";
    expect(() => importEncryptedMasterSeed(badIv, PASSPHRASE)).toThrow(
      /backup IV/,
    );
  });

  it("rejects short passphrases and non-64-byte seeds", () => {
    expect(() => exportEncryptedMasterSeed(seed(), "too short")).toThrow(
      /at least 12/,
    );
    expect(() =>
      exportEncryptedMasterSeed(new Uint8Array(32), PASSPHRASE),
    ).toThrow(/master seed must be 64 bytes/);
  });
});
