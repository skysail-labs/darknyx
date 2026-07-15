import { describe, expect, it } from "vitest";

import {
  deriveMatchFeeInner,
  deriveMatchOutputInner,
  MATCH_ROLE_TRADE_BUYER,
} from "../src/utxo/match-output.js";

const scalar = (value: number): Uint8Array => {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
};

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("VALID_MATCH_BATCH v3 output-inner KATs", () => {
  it("matches the Rust Poseidon3 domain-24 vector", async () => {
    expect(
      hex(await deriveMatchOutputInner(scalar(7), MATCH_ROLE_TRADE_BUYER)),
    ).toBe("13e02ab830905bd6a94bbf1c9c1d231150db9ee480d9cd2b596a1fc425c6dde0");
  });

  it("matches the Rust Poseidon3 domain-25 vector", async () => {
    expect(
      hex(await deriveMatchFeeInner(scalar(7), MATCH_ROLE_TRADE_BUYER)),
    ).toBe("18b28713db5e2e0ebd3a8382ca32d363811d5d2bf4244e916330204be6484c74");
  });

  it("changes fee inners when the consumed commitment changes", async () => {
    expect(hex(await deriveMatchFeeInner(scalar(1), 0xfb))).not.toBe(
      hex(await deriveMatchFeeInner(scalar(2), 0xfb)),
    );
  });
});
