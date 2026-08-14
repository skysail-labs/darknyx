import { describe, expect, it } from "vitest";

import {
  defaultGtcExpirySlot,
  decimalToAtoms,
  decimalToPriceTicks,
} from "../src/trader/controller.js";

describe("browser trader decimal boundary", () => {
  it("converts token amounts exactly and rejects excess precision", () => {
    expect(decimalToAtoms("1.25", 9)).toBe(1_250_000_000n);
    expect(() => decimalToAtoms("0", 9)).toThrow(/positive/);
    expect(() => decimalToAtoms("0.0000000001", 9)).toThrow(/precision/);
    expect(() => decimalToAtoms("00.1", 9)).toThrow(/canonical/);
  });

  it("requires a price representable by scale and governed tick size", () => {
    expect(decimalToPriceTicks("151.20", 100n, 5n)).toBe(15_120n);
    expect(decimalToPriceTicks("0", 100n, 5n)).toBe(0n);
    expect(() => decimalToPriceTicks("151.21", 100n, 5n)).toThrow(/tick size/);
    expect(() => decimalToPriceTicks("0.001", 100n, 1n)).toThrow(/represented/);
  });
});

describe("browser trader bounded GTC", () => {
  it("anchors the order expiry on the venue's live slot", async () => {
    const fetchImpl = async () =>
      new Response(JSON.stringify({ slot: 1_000, unix_ms: 5_000 }));
    await expect(
      defaultGtcExpirySlot("https://venue.example/", fetchImpl),
    ).resolves.toBe(5_500n);
  });

  it("rejects a malformed venue slot instead of signing an expired order", async () => {
    const fetchImpl = async () =>
      new Response(JSON.stringify({ slot: -1, unix_ms: 5_000 }));
    await expect(
      defaultGtcExpirySlot("https://venue.example/", fetchImpl),
    ).rejects.toThrow(/invalid Solana slot/);
  });
});
