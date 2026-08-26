import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildFeeInventory,
  createFeeKeyring,
  feeKeyProvider,
  loadFeeKeyring,
  openStoredFeeNote,
  readFeeInventory,
  rotateFeeKeyring,
  saveFeeKeyring,
  validateFeeInventory,
  verifyFeeKeyringBackup,
  writeFeeDeploymentEnv,
  writeFeeInventory,
} from "../src/index.js";
import type { RecoveredFeeNote } from "../src/types.js";

const PASSPHRASE = "correct horse battery staple";
const bytes = (value: number): Uint8Array => new Uint8Array(32).fill(value);

function recoveredNote(): RecoveredFeeNote {
  return {
    epoch: 1n,
    batchRoot: bytes(1),
    verifySignature: "verify-signature",
    settleSignature: "settle-signature",
    matchIndex: 0,
    side: "base",
    tokenMint: bytes(2),
    amount: 7n,
    ownerCommitment: bytes(3),
    innerHash: bytes(4),
    commitment: bytes(5),
    treeId: 1,
    leafIndex: 9n,
  };
}

describe("fee epoch key custody", () => {
  it("encrypts the keyring, retains retired keys, and verifies its backup", async () => {
    const directory = await mkdtemp(join(tmpdir(), "darknyx-fee-keyring-"));
    const primary = join(directory, "primary.json");
    const backup = join(directory, "backup.json");
    const firstKey = bytes(0);
    firstKey[31] = 7;
    const secondKey = bytes(0);
    secondKey[31] = 8;
    const initial = await createFeeKeyring(1n, firstKey);
    await saveFeeKeyring(primary, initial, PASSPHRASE);
    await saveFeeKeyring(backup, initial, PASSPHRASE);
    const encoded = await readFile(primary, "utf8");
    expect(encoded).not.toContain(Buffer.from(firstKey).toString("hex"));
    expect((await stat(primary)).mode & 0o777).toBe(0o600);
    expect(await verifyFeeKeyringBackup(primary, backup, PASSPHRASE)).toEqual({
      epochs: [1n],
      activeEpoch: 1n,
    });

    const rotated = await rotateFeeKeyring(initial, 2n, secondKey);
    expect(rotated.epochs.map((item) => item.state)).toEqual([
      "retired",
      "active",
    ]);
    expect(feeKeyProvider(rotated)(1n)?.key).toEqual(firstKey);
    expect(feeKeyProvider(rotated)(2n)?.key).toEqual(secondKey);
    await expect(rotateFeeKeyring(rotated, 2n)).rejects.toThrow(/monotonic/);
    expect(await loadFeeKeyring(primary, PASSPHRASE)).toEqual(initial);
  });

  it("rejects a corrupted sealed keyring without leaking a key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "darknyx-fee-tamper-"));
    const path = join(directory, "keyring.json");
    await saveFeeKeyring(path, await createFeeKeyring(), PASSPHRASE);
    const envelope = JSON.parse(await readFile(path, "utf8")) as {
      ciphertext: string;
    };
    const suffix = envelope.ciphertext.endsWith("00") ? "01" : "00";
    envelope.ciphertext = `${envelope.ciphertext.slice(0, -2)}${suffix}`;
    await writeFile(path, JSON.stringify(envelope), { mode: 0o600 });
    await expect(loadFeeKeyring(path, PASSPHRASE)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("writes only the secret while finalized governance supplies the epoch", async () => {
    const directory = await mkdtemp(join(tmpdir(), "darknyx-fee-deploy-"));
    const path = join(directory, "fee.env");
    const key = bytes(0);
    key[31] = 7;
    const keyring = await createFeeKeyring(4n, key);

    await expect(writeFeeDeploymentEnv(path, keyring)).resolves.toMatchObject({
      epoch: 4n,
    });
    expect(await readFile(path, "utf8")).toBe(
      `DARKNYX_TEE_FEE_EPOCH_KEY=${Buffer.from(key).toString("hex")}\n`,
    );
  });
});

describe("encrypted recovered fee inventory", () => {
  it("roundtrips openings without exposing them in the file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "darknyx-fee-inventory-"));
    const path = join(directory, "inventory.json");
    const note = recoveredNote();
    const inventory = buildFeeInventory({
      programId: "vault-program",
      recoveryStartSlot: 10,
      recoveryEndSlot: 20,
      notes: [note],
    });
    await writeFeeInventory(path, inventory, PASSPHRASE);
    const encoded = await readFile(path, "utf8");
    expect(encoded).not.toContain(Buffer.from(note.innerHash).toString("hex"));
    const opened = await readFeeInventory(path, PASSPHRASE);
    expect(openStoredFeeNote(opened.notes[0])).toEqual(note);
  });

  it("rejects duplicate recovered commitments", () => {
    const note = recoveredNote();
    expect(() =>
      buildFeeInventory({
        programId: "vault-program",
        recoveryStartSlot: 10,
        recoveryEndSlot: 20,
        notes: [note, { ...note, side: "quote" }],
      }),
    ).toThrow(/duplicate commitment/);
  });

  it("rejects the reserved zero fee epoch at the inventory boundary", () => {
    const inventory = buildFeeInventory({
      programId: "vault-program",
      recoveryStartSlot: 10,
      recoveryEndSlot: 20,
      notes: [recoveredNote()],
    });
    inventory.notes[0].epoch = "0";
    expect(() => validateFeeInventory(inventory)).toThrow(/nonzero u64/);
  });
});
