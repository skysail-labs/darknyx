/**
 * Keystore tests — on-device identity derivation + encrypted-at-rest round-trip.
 * No CVM; exercises real SDK key derivation + tweetnacl signing + node:crypto.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createCipheriv, scryptSync } from "node:crypto";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import nacl from "tweetnacl";
import {
  exportEncryptedMasterSeed,
  importEncryptedMasterSeed,
  userCommitmentFromKeys,
} from "@darknyx/sdk";

import {
  Keystore,
  saveKeystore,
  loadKeystore,
  deriveAccountIdentity,
  generateAccountIdentity,
  type AccountIdentity,
} from "../src/keystore.js";
function identity(): AccountIdentity {
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (i * 7 + 3) & 0xff;
  const rootKeyPubkey = new Uint8Array(32).fill(11);
  return {
    masterSeed,
    ownerBlinding: 0xfeedn,
    r0: 1n,
    r1: 2n,
    r2: 3n,
    rootKeyPubkey,
  };
}

const tmpDirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
  tmpDirs.length = 0;
});
function tmpFile(): string {
  const d = fs.mkdtempSync(join(tmpdir(), "darknyx-keystore-"));
  tmpDirs.push(d);
  return join(d, "keystore.json");
}

function serializeIdentityForV1(id: AccountIdentity): string {
  return JSON.stringify({
    seed: Buffer.from(id.masterSeed).toString("hex"),
    ownerBlinding: id.ownerBlinding.toString(),
    r0: id.r0.toString(),
    r1: id.r1.toString(),
    r2: id.r2.toString(),
    rootKeyPubkey: Buffer.from(id.rootKeyPubkey).toString("hex"),
  });
}

function writeLegacyV1(
  path: string,
  passphrase: string,
  id = identity(),
  plaintext = serializeIdentityForV1(id),
): void {
  const salt = Buffer.alloc(16, 0x11);
  const iv = Buffer.alloc(12, 0x22);
  const key = scryptSync(passphrase, salt, 32, {
    N: 1 << 14,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
  });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final(),
  ]);
  fs.writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      kdf: "scrypt",
      n: 1 << 14,
      r: 8,
      p: 1,
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      tag: cipher.getAuthTag().toString("hex"),
    }),
    { mode: 0o600 },
  );
}

function readFileObject(path: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path, "utf8")) as Record<string, unknown>;
}

function writeFileObject(path: string, value: Record<string, unknown>): void {
  fs.writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
}

describe("Keystore — derivation", () => {
  it("validates seed + pubkey lengths", () => {
    expect(
      () => new Keystore({ ...identity(), masterSeed: new Uint8Array(32) }),
    ).toThrow(/64 bytes/);
    expect(
      () => new Keystore({ ...identity(), rootKeyPubkey: new Uint8Array(16) }),
    ).toThrow(/32 bytes/);
  });

  it("derives a stable spending key + owner/user commitments", async () => {
    const ks = new Keystore(identity());
    expect(typeof ks.spendingKey).toBe("bigint");
    const oc1 = await ks.ownerCommitment();
    const oc2 = await ks.ownerCommitment();
    expect(oc1).toBe(oc2); // deterministic
    const uc = await ks.userCommitment();
    expect(uc).toHaveLength(32);

    // T-07 regression. The keystore used to return this value with its top byte
    // forced to zero, which made it un-matchable against any registered
    // WalletEntry. Pin the property that actually matters: the keystore returns
    // the derivation UNMODIFIED.
    //
    // Asserting a top-byte bound instead would not regress. `uc[0] <= 0x30` is
    // satisfied by a zeroed byte too, so the old corrupting behaviour would sail
    // through — and for this fixture the honest answer is that we do not control
    // what the top byte is. Comparing against the raw derivation catches the
    // mutation whatever the byte happens to be.
    const raw = await userCommitmentFromKeys({
      rootKeyPubkey: identity().rootKeyPubkey,
      spendingKey: ks.spendingKey,
      viewingKey: ks.viewingKey,
      r0: 1n,
      r1: 2n,
      r2: 3n,
    });
    expect(uc).toEqual(raw);

    // And it is a canonical BN254 element — checked against the modulus, not by
    // a first-byte heuristic, which is not sufficient at the boundary.
    const BN254_R =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const asInt = uc.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    expect(asInt).toBeLessThan(BN254_R);
  });

  it("derives distinct per-order trading keys; signatures verify", () => {
    const ks = new Keystore(identity());
    const pk0 = ks.tradingPublicKey(0);
    const pk1 = ks.tradingPublicKey(1);
    expect(pk0).toHaveLength(32);
    expect(Buffer.from(pk0).equals(Buffer.from(pk1))).toBe(false);

    const digest = new Uint8Array(32).fill(9);
    const sig = ks.signWithTradingKey(0, digest);
    expect(sig).toHaveLength(64);
    expect(nacl.sign.detached.verify(digest, sig, pk0)).toBe(true);
    // wrong key must NOT verify
    expect(nacl.sign.detached.verify(digest, sig, pk1)).toBe(false);
  });
});

describe("account identity derivation", () => {
  const rootKey = new Uint8Array(32).fill(8);

  it("is deterministic from (seed, rootKey)", () => {
    const seed = new Uint8Array(64).fill(3);
    const a = deriveAccountIdentity(seed, rootKey);
    const b = deriveAccountIdentity(seed, rootKey);
    expect(a.ownerBlinding).toBe(b.ownerBlinding);
    expect(a.r0).toBe(b.r0);
    expect(a.r1).toBe(b.r1);
    expect(a.r2).toBe(b.r2);
    // the four blindings are distinct domains
    expect(new Set([a.ownerBlinding, a.r0, a.r1, a.r2]).size).toBe(4);
  });

  it("generate produces a fresh 64-byte seed each time", () => {
    const a = generateAccountIdentity(rootKey);
    const b = generateAccountIdentity(rootKey);
    expect(a.masterSeed).toHaveLength(64);
    expect(Buffer.from(a.masterSeed).equals(Buffer.from(b.masterSeed))).toBe(
      false,
    );
  });

  it("recreating from the same seed yields a usable, identical keystore", () => {
    const id = generateAccountIdentity(rootKey);
    const recreated = deriveAccountIdentity(id.masterSeed, rootKey);
    expect(new Keystore(recreated).spendingKey).toBe(
      new Keystore(id).spendingKey,
    );
    expect(recreated.ownerBlinding).toBe(id.ownerBlinding);
  });

  it("restores the same identity from an authenticated seed backup", async () => {
    const id = generateAccountIdentity(rootKey);
    const backup = exportEncryptedMasterSeed(
      id.masterSeed,
      "separate backup passphrase",
    );
    const restoredSeed = importEncryptedMasterSeed(
      JSON.stringify(backup),
      "separate backup passphrase",
    );
    const restored = deriveAccountIdentity(restoredSeed, rootKey);
    const before = new Keystore(id);
    const after = new Keystore(restored);

    expect(after.spendingKey).toBe(before.spendingKey);
    expect(await after.ownerCommitment()).toBe(await before.ownerCommitment());
    expect(await after.userCommitment()).toEqual(await before.userCommitment());

    const path = tmpFile();
    saveKeystore(restored, path, "new-device-passphrase");
    expect(readFileObject(path).version).toBe(2);
    expect(loadKeystore(path, "new-device-passphrase").spendingKey).toBe(
      before.spendingKey,
    );
  });
});

describe("Keystore — encrypted at rest", () => {
  it("writes only the fixed v2 profile at mode 0600 and round-trips", async () => {
    const path = tmpFile();
    const id = identity();
    const fsync = vi.spyOn(fs, "fsyncSync");
    saveKeystore(id, path, "correct horse battery");
    // One sync persists the temp file's bytes; the second persists the
    // same-directory rename that makes it the live keystore.
    expect(fsync).toHaveBeenCalledTimes(2);
    const file = readFileObject(path);
    expect(file).toMatchObject({
      version: 2,
      kdf: "scrypt",
      profile: "scrypt-n17-r8-p1-v1",
      cipher: "aes-256-gcm",
    });
    expect(file).not.toHaveProperty("n");
    expect(file).not.toHaveProperty("r");
    expect(file).not.toHaveProperty("p");
    expect(fs.statSync(path).mode & 0o777).toBe(0o600);

    const ks = loadKeystore(path, "correct horse battery");
    // same identity → same derived material
    expect(ks.spendingKey).toBe(new Keystore(id).spendingKey);
    expect(Buffer.from(ks.tradingPublicKey(3))).toEqual(
      Buffer.from(new Keystore(id).tradingPublicKey(3)),
    );
    const oc = await ks.ownerCommitment();
    expect(oc).toBe(await new Keystore(id).ownerCommitment());
  });

  it("rejects a wrong passphrase (GCM auth tag fails)", () => {
    const path = tmpFile();
    saveKeystore(identity(), path, "right-passphrase-01");
    const before = fs.readFileSync(path);
    expect(() => loadKeystore(path, "wrong")).toThrow(/decrypt failed/);
    expect(fs.readFileSync(path)).toEqual(before);
  });

  it("opens the pinned v2 known-answer vector", () => {
    const path = tmpFile();
    const vector =
      '{"version":2,"kdf":"scrypt","profile":"scrypt-n17-r8-p1-v1","cipher":"aes-256-gcm","salt":"000102030405060708090a0b0c0d0e0f","iv":"a0a1a2a3a4a5a6a7a8a9aaab","ciphertext":"324fd30dbcb5fd70c97e75843662aab3350264486a23e4b4ca3a1d7bc3534f7e61f513c894df13d48c481d452784dc9544daeaef8f4c3f01e3513eca3dc54da85656d9713bbeaceeba93d42feb527e30825aeae0bf6df3af7ad39ea5b9c7518cdd0d3477bd73060839395459b16e7dac66dc18e750209dbd6258112ab00d10de74b8169d27021f76787d2deeb6f793f3202008f6c845ec569ffd7610ac109ac70c0f5790bbb0c774173013c9ff88dce76c40ad6e49b044da2b6cfc6b0234f4bebcfb0b550e179c6ad7d3cb89bb02022a86c42fe0d979e61f8fe681674fe37e161ba03b070a3d491a0aa1e5ffd2b5a07f78cf7448e9203b1e7f8cc3ef51bbf1bb10477d559b44beac03c9269068f28e10ef","tag":"e9afdb5bcd7c00744d5ccda24c1d109a"}';
    fs.writeFileSync(path, vector, { mode: 0o600 });
    const ks = loadKeystore(path, "correct horse battery staple");
    expect(ks.spendingKey).toBe(new Keystore(identity()).spendingKey);
    expect(fs.readFileSync(path, "utf8")).toBe(vector);
  });

  it("migrates a valid v1 file only after decrypting and validating it", () => {
    const path = tmpFile();
    writeLegacyV1(path, "legacy passphrase");
    const expected = new Keystore(identity());

    const loaded = loadKeystore(path, "legacy passphrase");
    expect(loaded.spendingKey).toBe(expected.spendingKey);
    expect(readFileObject(path)).toMatchObject({
      version: 2,
      profile: "scrypt-n17-r8-p1-v1",
    });
    expect(fs.statSync(path).mode & 0o777).toBe(0o600);

    // The migrated file is independently usable; v1 is read/migrate-only.
    expect(loadKeystore(path, "legacy passphrase").spendingKey).toBe(
      expected.spendingKey,
    );
  });

  it("does not rewrite v1 when the passphrase is wrong", () => {
    const path = tmpFile();
    writeLegacyV1(path, "right-passphrase-01");
    const before = fs.readFileSync(path);
    expect(() => loadKeystore(path, "wrong")).toThrow(/decrypt failed/);
    expect(fs.readFileSync(path)).toEqual(before);
    expect(readFileObject(path).version).toBe(1);
  });

  it("validates v1 plaintext before replacing the legacy file", () => {
    const path = tmpFile();
    const malformed = {
      ...JSON.parse(serializeIdentityForV1(identity())),
      seed: "00",
    };
    writeLegacyV1(path, "right-passphrase-01", identity(), JSON.stringify(malformed));
    const before = fs.readFileSync(path);

    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(/seed must be 64 bytes/);
    expect(fs.readFileSync(path)).toEqual(before);
    expect(readFileObject(path).version).toBe(1);
  });

  it("rejects hostile v1 KDF fields before they can select work", () => {
    const path = tmpFile();
    writeLegacyV1(path, "right-passphrase-01");
    const file = readFileObject(path);
    file.n = 2 ** 30;
    writeFileObject(path, file);
    const before = fs.readFileSync(path);

    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
      /unsupported keystore v1 profile/,
    );
    expect(fs.readFileSync(path)).toEqual(before);
  });

  it("leaves the original v1 intact when the atomic rename is interrupted", () => {
    const path = tmpFile();
    writeLegacyV1(path, "right-passphrase-01");
    const before = fs.readFileSync(path);
    vi.spyOn(fs, "renameSync").mockImplementationOnce(() => {
      throw new Error("simulated interruption");
    });

    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
      /atomic migration to v2 failed/,
    );
    expect(fs.readFileSync(path)).toEqual(before);
    expect(
      fs.readdirSync(dirname(path)).filter((name) => name.endsWith(".tmp")),
    ).toEqual([]);
  });

  it("strictly rejects unknown fields, profiles, and encoded lengths", () => {
    const path = tmpFile();
    saveKeystore(identity(), path, "right-passphrase-01");

    const withUnknown = readFileObject(path);
    withUnknown.n = 1;
    writeFileObject(path, withUnknown);
    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
      /unknown or missing fields/,
    );

    saveKeystore(identity(), path, "right-passphrase-01");
    const wrongProfile = readFileObject(path);
    wrongProfile.profile = "scrypt-n14-r8-p1-v1";
    writeFileObject(path, wrongProfile);
    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
      /unsupported keystore v2 profile/,
    );

    saveKeystore(identity(), path, "right-passphrase-01");
    const shortSalt = readFileObject(path);
    shortSalt.salt = "00";
    writeFileObject(path, shortSalt);
    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(/salt must be 16 bytes/);
  });

  it("authenticates the v2 header and rejects tampering", () => {
    const path = tmpFile();
    saveKeystore(identity(), path, "right-passphrase-01");
    const file = readFileObject(path);
    const iv = file.iv as string;
    file.iv = `${iv.slice(0, -2)}${iv.endsWith("00") ? "01" : "00"}`;
    writeFileObject(path, file);
    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(/decrypt failed/);
  });

  it("rejects an oversized file before parsing or deriving a key", () => {
    const path = tmpFile();
    fs.writeFileSync(path, "x".repeat(32 * 1024 + 1), { mode: 0o600 });
    expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
      /keystore file must be 1\.\.32768 bytes/,
    );
  });
});

// ── SW-16: custody edges ────────────────────────────────────────────────
describe("keystore custody edges (SW-16)", () => {
  it("refuses a keystore that is group- or world-accessible", () => {
    // Every write path creates this 0600 and says so, but nothing checked it on
    // READ — so a keystore restored 0644 from a backup loaded silently. This is
    // OpenSSH's refusal case: the file is only as private as its mode, and the
    // moment to notice is before it is decrypted.
    const path = tmpFile();
    saveKeystore(identity(), path, "right-passphrase-01");

    for (const mode of [0o644, 0o640, 0o604]) {
      fs.chmodSync(path, mode);
      expect(() => loadKeystore(path, "right-passphrase-01")).toThrow(
        /group\/world-accessible/,
      );
    }

    // ...and 0600 still loads.
    fs.chmodSync(path, 0o600);
    expect(loadKeystore(path, "right-passphrase-01")).toBeTruthy();
  });

  it("refuses to seal under a passphrase short enough to enumerate", () => {
    // A strong KDF profile buys TIME against a weak secret, not immunity: at
    // N=2^17 a short passphrase is still enumerable, and this file is exactly
    // what an attacker walks off with.
    expect(() =>
      saveKeystore(identity(), tmpFile(), "hunter2"),
    ).toThrow(/at least 12 characters/);
  });
});
