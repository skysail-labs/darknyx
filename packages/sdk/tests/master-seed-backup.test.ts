/** Versioned encrypted seed-backup envelope — real scrypt + AES-256-GCM. */

import { createCipheriv, randomBytes, scryptSync } from "node:crypto";
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

/**
 * Produce a backup encrypted at the RETIRED 2^14 scrypt profile.
 *
 * Written out longhand rather than by calling the exporter, because the
 * exporter no longer can — it writes 2^17 only, which is the point of SW-22.
 * A test-only encrypt hook on the module would be the alternative, but that
 * widens the shipped surface to serve a test; the format is four fields and
 * mirroring it here keeps the production module closed.
 *
 * If this drifts from `exportEncryptedMasterSeed`, the round-trip below fails
 * loudly rather than silently testing a format nothing writes.
 */
function legacyBackupFixture(
  masterSeed: Uint8Array,
  passphrase: string,
): EncryptedMasterSeedBackupV2 {
  const LEGACY_N = 16_384;
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, {
    N: LEGACY_N,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from("darknyx/master-seed-backup/v2", "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(masterSeed)),
    cipher.final(),
  ]);
  return {
    format: MASTER_SEED_BACKUP_FORMAT,
    version: MASTER_SEED_BACKUP_VERSION,
    kdf: {
      name: "scrypt",
      n: LEGACY_N,
      r: 8,
      p: 1,
      salt: salt.toString("hex"),
    },
    cipher: {
      name: "aes-256-gcm",
      iv: iv.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      tag: cipher.getAuthTag().toString("hex"),
    },
  };
}

describe("encrypted master-seed backup v2", () => {
  it("round-trips from both the object and serialized JSON", () => {
    const original = seed();
    const backup = exportEncryptedMasterSeed(original, PASSPHRASE);
    expect(backup).toMatchObject({
      format: MASTER_SEED_BACKUP_FORMAT,
      version: MASTER_SEED_BACKUP_VERSION,
      // 2^17, matching the keystore that holds the same 64-byte secret. This
      // used to pin 2^14 — the profile the keystore calls LEGACY (SW-22).
      kdf: { name: "scrypt", n: 131_072, r: 8, p: 1 },
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

describe("master-seed backup KDF (SW-22)", () => {
  it("writes at the same strength as the keystore holding the same secret", () => {
    // The exposure profile ran backwards: the keystore is an operational file
    // on a running host, while this is the portable OFFLINE backup — the copy
    // most likely to be synced to cloud storage or printed. The more-exposed
    // artifact had the weaker KDF.
    const backup = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    expect(backup.kdf.n).toBe(131_072);
  });

  it("still opens a backup genuinely written at the old 2^14 profile", () => {
    // Raising the write side must not strand existing backups — this is a
    // recovery artifact, so a file that stops opening is lost funds.
    //
    // This test used to take an n=2^17 backup, rewrite `kdf.n` to 16_384, and
    // assert decryption THREW ("wrong key, not unsupported-kdf"). That proves
    // the reader passes `kdf.n` through to scrypt, and nothing else — it does
    // not prove a real legacy file opens, which is the property that matters.
    // Concretely, changing the reader back to `deriveBackupKey(passphrase,
    // salt)` — always 2^17, ignoring the file — kept that assertion passing
    // while making every existing 2^14 backup permanently unopenable. So the
    // test asserted a symptom of the fix and would have stayed green through
    // its removal. It needs real legacy ciphertext.
    const legacy = legacyBackupFixture(seed(), PASSPHRASE);
    expect(legacy.kdf.n).toBe(16_384);

    const restored = importEncryptedMasterSeed(legacy, PASSPHRASE);
    expect(Buffer.from(restored)).toEqual(Buffer.from(seed()));
  });

  it("rejects a legacy-profile backup under the wrong passphrase", () => {
    // The round-trip above must not be passing because authentication is weak;
    // the same fixture has to fail closed on a bad passphrase.
    const legacy = legacyBackupFixture(seed(), PASSPHRASE);
    expect(() =>
      importEncryptedMasterSeed(legacy, "wrong-passphrase-long-enough"),
    ).toThrow(/decrypt failed/i);
  });

  it("refuses a KDF parameter outside the accepted set", () => {
    // The file's fields are not authenticated until after the KDF has run, so
    // an attacker-supplied backup naming an enormous `n` would be a
    // memory-exhaustion trigger on the machine doing the restore.
    const backup = exportEncryptedMasterSeed(seed(), PASSPHRASE);
    expect(() =>
      importEncryptedMasterSeed(
        // Deliberately outside the accepted set — cast because the type
        // encodes that set, and the point of this test is the RUNTIME guard
        // for a file that did not come from us.
        { ...backup, kdf: { ...backup.kdf, n: (1 << 24) as never } },
        PASSPHRASE,
      ),
    ).toThrow();
  });
});
