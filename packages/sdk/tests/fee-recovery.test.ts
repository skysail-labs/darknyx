import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  decryptProtocolFeeRecovery,
  encryptProtocolFeeRecovery,
  FEE_RECOVERY_CIPHERTEXT_LEN,
  FEE_RECOVERY_SLOTS,
  type ProtocolFeeAmounts,
} from "../src/utxo/fee-recovery.js";

const here = dirname(fileURLToPath(import.meta.url));
const rustHelper = resolve(repoRoot(), "target/debug/examples/fee-recovery");
const bytes = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

function repoRoot(): string {
  return resolve(here, "..", "..", "..");
}

function fixture(): {
  epochKey: Uint8Array;
  epoch: bigint;
  batchRoot: Uint8Array;
  market: Uint8Array;
  baseMint: Uint8Array;
  quoteMint: Uint8Array;
  amounts: ProtocolFeeAmounts[];
} {
  const amounts = Array.from({ length: FEE_RECOVERY_SLOTS }, () => ({
    base: 0n,
    quote: 0n,
  }));
  amounts[0] = { base: 7n, quote: 11n };
  amounts[15] = { base: 13n, quote: 17n };
  return {
    epochKey: bytes(1),
    epoch: 4n,
    batchRoot: bytes(2),
    market: bytes(3),
    baseMint: bytes(4),
    quoteMint: bytes(5),
    amounts,
  };
}

describe("protocol fee recovery wire", () => {
  it("roundtrips the fixed N=16 record", () => {
    const input = fixture();
    const encrypted = encryptProtocolFeeRecovery(input);
    expect(encrypted).toHaveLength(FEE_RECOVERY_CIPHERTEXT_LEN);
    expect(
      decryptProtocolFeeRecovery({ ...input, ciphertext: encrypted }),
    ).toEqual(input.amounts);
  });

  it.skipIf(!existsSync(rustHelper))("matches Rust byte-for-byte", () => {
    const encrypted = encryptProtocolFeeRecovery(fixture());
    const rust = spawnSync(rustHelper, { encoding: "utf8" });
    expect(rust.status, rust.stderr).toBe(0);
    expect(rust.stdout.trim()).toBe(hex(encrypted));
  });

  it("binds the epoch, root, market, and mints and rejects tampering", () => {
    const input = fixture();
    const ciphertext = encryptProtocolFeeRecovery(input);
    const mutations = [
      { ...input, epoch: 5n },
      { ...input, batchRoot: bytes(9) },
      { ...input, market: bytes(9) },
      { ...input, baseMint: bytes(9) },
      { ...input, quoteMint: bytes(9) },
    ];
    for (const mutation of mutations) {
      expect(() =>
        decryptProtocolFeeRecovery({ ...mutation, ciphertext }),
      ).toThrow();
    }
    const tampered = ciphertext.slice();
    tampered[17] ^= 1;
    expect(() =>
      decryptProtocolFeeRecovery({ ...input, ciphertext: tampered }),
    ).toThrow();
  });

  it("rejects a wrong slot count and non-u64 amounts", () => {
    const input = fixture();
    expect(() =>
      encryptProtocolFeeRecovery({ ...input, amounts: input.amounts.slice(1) }),
    ).toThrow(/16 slots/);
    const invalid = [...input.amounts];
    invalid[0] = { base: -1n, quote: 0n };
    expect(() =>
      encryptProtocolFeeRecovery({ ...input, amounts: invalid }),
    ).toThrow(/non-u64/);
  });
});
