import { describe, expect, it } from "vitest";

import { runtimeInternals } from "../src/trader/runtime.js";

describe("browser runtime account reconciliation", () => {
  it("keeps bounded browser GTC orders alive across disconnects", () => {
    expect(runtimeInternals.cancelOnDisconnect).toBe(false);
  });

  it("accepts only canonical venue open-order ids", () => {
    expect(
      runtimeInternals.decodeOpenOrderIds({
        account_id: "browser",
        open_orders: [{ order_id: "ab".repeat(16) }],
      }),
    ).toEqual(["ab".repeat(16)]);
    expect(() =>
      runtimeInternals.decodeOpenOrderIds({
        account_id: "browser",
        open_orders: [{ order_id: "AB".repeat(16) }],
      }),
    ).toThrow(/invalid order id/);
  });
});
