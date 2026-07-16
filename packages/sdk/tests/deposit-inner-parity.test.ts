/** VALID_DEPOSIT inner parity across TS, Rust, and the circuit domain. */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { deriveDepositInnerHash } from "../src/utxo/deposit-inner.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const rustHelper = resolve(
  repoRoot,
  "target/debug/examples/deposit-inner-hash",
);
const scalar = (value: number): Uint8Array => {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
};
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("VALID_DEPOSIT recoverable inner hash", () => {
  it("is deterministic and input separated", async () => {
    const owner = scalar(7);
    const nonce = scalar(9);
    const first = await deriveDepositInnerHash(owner, nonce);
    expect(await deriveDepositInnerHash(owner, nonce)).toEqual(first);
    expect(await deriveDepositInnerHash(owner, scalar(10))).not.toEqual(first);
    expect(await deriveDepositInnerHash(scalar(8), nonce)).not.toEqual(first);
  });

  it.skipIf(!existsSync(rustHelper))("matches Rust byte-for-byte", async () => {
    const owner = scalar(7);
    const nonce = scalar(9);
    const rust = spawnSync(rustHelper, [hex(owner), hex(nonce)], {
      encoding: "utf8",
    });
    expect(rust.status, rust.stderr).toBe(0);
    expect(rust.stdout.trim()).toBe(
      hex(await deriveDepositInnerHash(owner, nonce)),
    );
  });

  it("rejects malformed byte inputs", async () => {
    expect(() =>
      deriveDepositInnerHash(new Uint8Array(31), scalar(1)),
    ).toThrow(/ownerCommitment/);
    expect(() =>
      deriveDepositInnerHash(scalar(1), new Uint8Array(33)),
    ).toThrow(/recoveryNonce/);
  });
});
