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
    const nonce = scalar(9);
    const secret = scalar(11);
    const first = await deriveDepositInnerHash(nonce, secret);
    expect(await deriveDepositInnerHash(nonce, secret)).toEqual(first);
    expect(await deriveDepositInnerHash(scalar(10), secret)).not.toEqual(first);
    expect(await deriveDepositInnerHash(nonce, scalar(12))).not.toEqual(
      first,
    );
  });

  /**
   * The public recovery nonce alone cannot derive the inner. The seed-derived
   * note secret is the observer-secret input that keeps the later use tag
   * unlinkable while preserving seed-plus-chain recovery.
   */
  it("separates deposits that agree on every public input", async () => {
    const nonce = scalar(9);
    expect(await deriveDepositInnerHash(nonce, scalar(1))).not.toEqual(
      await deriveDepositInnerHash(nonce, scalar(2)),
    );
  });

  it.skipIf(!existsSync(rustHelper))("matches Rust byte-for-byte", async () => {
    const nonce = scalar(9);
    const secret = scalar(11);
    const rust = spawnSync(rustHelper, [hex(nonce), hex(secret)], {
      encoding: "utf8",
    });
    expect(rust.status, rust.stderr).toBe(0);
    expect(rust.stdout.trim()).toBe(
      hex(await deriveDepositInnerHash(nonce, secret)),
    );
  });

  it("rejects malformed byte inputs", async () => {
    expect(() =>
      deriveDepositInnerHash(new Uint8Array(31), scalar(1)),
    ).toThrow(/recoveryNonce/);
    expect(() =>
      deriveDepositInnerHash(scalar(1), new Uint8Array(31)),
    ).toThrow(/noteSecret/);
  });
});
