import { describe, expect, it } from "vitest";

import {
  decimalToAtoms,
  decimalToPriceTicks,
} from "../src/trader/controller.js";

describe("browser trader decimal boundary", () => {
  it("converts token amounts exactly and rejects excess precision", () => {
    expect(decimalToAtoms("1.25", 9)).toBe(1_250_000_000n);
    expect(() => decimalToAtoms("0.0000000001", 9)).toThrow(/precision/);
    expect(() => decimalToAtoms("00.1", 9)).toThrow(/canonical/);
  });

  it("requires a price representable by scale and governed tick size", () => {
    expect(decimalToPriceTicks("151.20", 100n, 5n)).toBe(15_120n);
    expect(() => decimalToPriceTicks("151.21", 100n, 5n)).toThrow(/tick size/);
    expect(() => decimalToPriceTicks("0.001", 100n, 1n)).toThrow(/represented/);
  });
});
