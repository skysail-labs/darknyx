import { buildCancel } from "../src/browser-orders.js";
import { describe, expect, it } from "vitest";

describe("lossless cancel nonce wire format", () => {
  it("preserves a u64 above JavaScript's safe-integer range", async () => {
    const cancelNonce = (1n << 64n) - 1n;
    const request = await buildCancel({
      orderId: new Uint8Array(16).fill(1),
      tradingKey: new Uint8Array(32).fill(2),
      cancelNonce,
      sessionId: new Uint8Array(32).fill(3),
      sign: async () => new Uint8Array(64).fill(4),
    });
    expect(request.cancel_nonce).toBe(cancelNonce.toString());
    expect(JSON.parse(JSON.stringify(request)).cancel_nonce).toBe(
      cancelNonce.toString(),
    );
  });
});
