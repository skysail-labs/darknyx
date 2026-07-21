import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { matchConfigDigest } from "../src/utxo/match-config.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const rustHelper = resolve(repoRoot, "target/debug/examples/match-config-digest");
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const owner = new Uint8Array(32).fill(7);
const baseMint = new Uint8Array(32);
baseMint[0] = 1;
baseMint[31] = 0xb1;
const quoteMint = new Uint8Array(32);
quoteMint[0] = 1;
quoteMint[31] = 0x9e;

describe("VALID_MATCH_BATCH config digest", () => {
  it.skipIf(!existsSync(rustHelper))("matches Rust byte-for-byte", async () => {
    const rust = spawnSync(
      rustHelper,
      ["30", hex(owner), hex(baseMint), hex(quoteMint), "100000000"],
      { encoding: "utf8" },
    );
    expect(rust.status, rust.stderr).toBe(0);
    const sdkDigest = hex(
      await matchConfigDigest({
        feeRateBps: 30n,
        protocolOwnerCommitment: owner,
        baseMint,
        quoteMint,
        priceScale: 100_000_000n,
      }),
    );
    expect(sdkDigest).toBe(
      "053d4a1e1aa0c604c482f58e4afb9327ac4793922fc6be567c2120459be10758",
    );
    expect(rust.stdout.trim()).toBe(sdkDigest);
  });

  it("binds field order and rejects non-canonical owners", async () => {
    const digest = await matchConfigDigest({
      feeRateBps: 30n,
      protocolOwnerCommitment: owner,
      baseMint,
      quoteMint,
      priceScale: 100_000_000n,
    });
    expect(
      await matchConfigDigest({
        feeRateBps: 30n,
        protocolOwnerCommitment: owner,
        baseMint: quoteMint,
        quoteMint: baseMint,
        priceScale: 100_000_000n,
      }),
    ).not.toEqual(digest);
    await expect(
      matchConfigDigest({
        feeRateBps: 30n,
        protocolOwnerCommitment: new Uint8Array(32).fill(0xff),
        baseMint,
        quoteMint,
        priceScale: 100_000_000n,
      }),
    ).rejects.toThrow(/canonical BN254 scalar/);
  });
});
