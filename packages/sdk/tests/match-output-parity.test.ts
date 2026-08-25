import { describe, expect, it } from "vitest";

import {
  deriveFeeKeyBinding,
  deriveMatchFeeInner,
  deriveMatchOutputInner,
  MATCH_ROLE_TRADE_BUYER,
} from "../src/utxo/match-output.js";
import { noteUseTagFromBytes } from "../src/utxo/note-identity.js";

const scalar = (value: number): Uint8Array => {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
};

const scalarU64 = (value: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  new DataView(out.buffer).setBigUint64(24, value, false);
  return out;
};

const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("VALID_MATCH_BATCH v3 output-inner KATs", () => {
  it("matches the Rust Poseidon3 domain-24 vector", async () => {
    expect(
      hex(await deriveMatchOutputInner(scalar(7), MATCH_ROLE_TRADE_BUYER)),
    ).toBe("13e02ab830905bd6a94bbf1c9c1d231150db9ee480d9cd2b596a1fc425c6dde0");
  });

  it("matches the frozen fee-key binding and fee-inner vectors", async () => {
    const key = scalarU64(4004n);
    const tag = scalarU64(5005n);
    expect(hex(await deriveFeeKeyBinding(key))).toBe(
      "0dea674cc22c4550b60604faaa62edd0ce4fe22ca4b38ebe24506cc9795faa19",
    );
    expect(
      hex(await deriveMatchFeeInner(key, noteUseTagFromBytes(tag), 2)),
    ).toBe("25b0e3d61c48456c00303a06d9dcea509389561a8e9f379cb694fec042a769e4");
  });

  it("changes fee inners when the governed key or consumed tag changes", async () => {
    expect(hex(await deriveMatchFeeInner(scalar(9), noteUseTagFromBytes(scalar(1)), 0xfb))).not.toBe(
      hex(await deriveMatchFeeInner(scalar(9), noteUseTagFromBytes(scalar(2)), 0xfb)),
    );
    expect(hex(await deriveMatchFeeInner(scalar(9), noteUseTagFromBytes(scalar(1)), 0xfb))).not.toBe(
      hex(await deriveMatchFeeInner(scalar(10), noteUseTagFromBytes(scalar(1)), 0xfb)),
    );
  });
});
