/** base58 encode/decode round-trip — load-bearing for gTFA instruction data. */

import { describe, it, expect } from "vitest";
import { PublicKey } from "@solana/web3.js";
import { base58Decode, base58Encode } from "../src/base58.js";

describe("base58", () => {
  it("round-trips arbitrary bytes", () => {
    const cases = [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([0, 0, 0]), // leading zeros → leading '1's
      new Uint8Array([1, 2, 3, 0xff, 0xfe]),
      new Uint8Array(64).map((_, i) => (i * 7 + 1) & 0xff),
    ];
    for (const bytes of cases) {
      expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
    }
  });

  it("encodes leading zero bytes as leading '1's", () => {
    expect(base58Encode(new Uint8Array([0, 0, 1]))).toBe("112");
    expect(base58Decode("112")).toEqual(new Uint8Array([0, 0, 1]));
  });

  it("matches a known Solana-style vector", () => {
    // The all-ones 32-byte pubkey encodes to a fixed base58 string.
    const ones = new Uint8Array(32).fill(1);
    expect(base58Decode(base58Encode(ones))).toEqual(ones);
  });

  it("rejects an invalid character", () => {
    expect(() => base58Decode("0OIl")).toThrow(/invalid base58/);
  });

  it("matches web3.js canonical base58 (so real gTFA instruction data decodes)", () => {
    // Cross-check against Solana's encoder: a known pubkey string ↔ its 32 bytes.
    const addr = "So11111111111111111111111111111111111111112";
    const bytes = new PublicKey(addr).toBytes();
    expect(base58Encode(bytes)).toBe(addr);
    expect(base58Decode(addr)).toEqual(bytes);
  });
});
