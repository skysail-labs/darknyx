/**
 * Keystore tests — on-device identity derivation + encrypted-at-rest round-trip.
 * No CVM; exercises real SDK key derivation + tweetnacl signing + node:crypto.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
  tmpDirs.length = 0;
});
function tmpFile(): string {
  const d = mkdtempSync(join(tmpdir(), "darknyx-keystore-"));
  tmpDirs.push(d);
  return join(d, "keystore.json");
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
  });
});

describe("Keystore — encrypted at rest", () => {
  it("round-trips through save → load with the passphrase", async () => {
    const path = tmpFile();
    const id = identity();
    saveKeystore(id, path, "correct horse");
    const ks = loadKeystore(path, "correct horse");
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
    saveKeystore(identity(), path, "right");
    expect(() => loadKeystore(path, "wrong")).toThrow(/decrypt failed/);
  });
});
