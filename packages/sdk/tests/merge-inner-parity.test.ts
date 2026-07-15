/** VALID_MERGE output-inner parity: TS, Rust, and the circuit use
 * Poseidon6(26, c0, c1, c2, c3, active_bitmap). */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { deriveMergeOutputInnerHash } from "../src/utxo/merge.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const rustHelper = resolve(repoRoot, "target/debug/examples/merge-inner-hash");
const be32 = (n: number): Uint8Array => {
  const out = new Uint8Array(32);
  out[31] = n;
  return out;
};
const hex = (value: bigint): string => value.toString(16).padStart(64, "0");

describe("VALID_MERGE commitment-derived inner hash", () => {
  it("matches the pinned v3 KAT and K=2/K=4 padding parity", async () => {
    const c0 = be32(1);
    const c1 = be32(2);
    const expected =
      "1ed62782faeb9cd43f741e189ade09a0406a22f9c633cb9311b00e692c1458d5";
    const k2 = await deriveMergeOutputInnerHash([c0, c1]);
    const k4 = await deriveMergeOutputInnerHash([
      c0,
      c1,
      new Uint8Array(32),
      new Uint8Array(32),
    ]);
    expect(hex(k2)).toBe(expected);
    expect(k4).toBe(k2);
  });

  it.skipIf(!existsSync(rustHelper))(
    "matches the Rust helper byte-for-byte",
    async () => {
      const commitments = [be32(1), be32(2), be32(0), be32(0)];
      const rust = spawnSync(
        rustHelper,
        [...commitments.map((c) => Buffer.from(c).toString("hex")), "3"],
        { encoding: "utf8" },
      );
      expect(rust.status, rust.stderr).toBe(0);
      expect(rust.stdout.trim()).toBe(
        hex(await deriveMergeOutputInnerHash(commitments)),
      );
    },
  );

  it("rejects an all-dummy or malformed commitment vector", async () => {
    await expect(
      deriveMergeOutputInnerHash([new Uint8Array(32), new Uint8Array(32)]),
    ).rejects.toThrow(/at least one active/);
    await expect(deriveMergeOutputInnerHash([be32(1)])).rejects.toThrow(
      /exactly 2 or 4/,
    );
  });
});
