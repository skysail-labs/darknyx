import { describe, expect, it } from "vitest";

import { floorPriceToTick } from "./cvm-harness.js";

describe("floorPriceToTick", () => {
  it("preserves an aligned positive price", () => {
    expect(floorPriceToTick(125n, 5n)).toBe(125n);
  });

  it("floors an off-tick price", () => {
    expect(floorPriceToTick(129n, 5n)).toBe(125n);
  });

  it("rejects non-positive inputs and a tick larger than the price", () => {
    expect(() => floorPriceToTick(0n, 5n)).toThrow("price must be positive");
    expect(() => floorPriceToTick(10n, 0n)).toThrow(
      "tickSize must be positive",
    );
    expect(() => floorPriceToTick(4n, 5n)).toThrow(
      "tickSize exceeds the positive price",
    );
  });
});
