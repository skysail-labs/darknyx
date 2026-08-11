import { DarknyxApiError } from "@darknyx/sdk/browser-orders";
import { describe, expect, it, vi } from "vitest";

import type { BrowserInventory } from "../src/inventory/browser-inventory.js";
import { BrowserOrderTransport } from "../src/trader/order-transport.js";

const orderId = "ab".repeat(16);
const envelope = {
  clientOrderId: orderId,
  body: new TextEncoder().encode(JSON.stringify({ order_id: orderId })),
};

function inventory() {
  return {
    updateOrder: vi.fn(async () => undefined),
    order: vi.fn(async () => ({ reservationId: "reservation-1" })),
    releaseReservation: vi.fn(async () => undefined),
  };
}

describe("browser order transport outcomes", () => {
  it("releases collateral only after a definitive placement rejection", async () => {
    const state = inventory();
    const transport = new BrowserOrderTransport(
      {
        place: vi.fn(async () => {
          throw new DarknyxApiError(400, "bad order", 400);
        }),
        cancel: vi.fn(),
      },
      state as unknown as BrowserInventory,
    );
    await expect(transport.submitAuthorized(envelope)).resolves.toEqual({
      status: "rejected",
    });
    expect(state.releaseReservation).toHaveBeenCalledWith("reservation-1");
  });

  it("keeps collateral reserved when a 5xx placement outcome is ambiguous", async () => {
    const state = inventory();
    const transport = new BrowserOrderTransport(
      {
        place: vi.fn(async () => {
          throw new DarknyxApiError(500, "upstream unavailable", 503);
        }),
        cancel: vi.fn(),
      },
      state as unknown as BrowserInventory,
    );
    await expect(transport.submitAuthorized(envelope)).resolves.toEqual({
      status: "ambiguous",
      orderId,
    });
    expect(state.releaseReservation).not.toHaveBeenCalled();
  });

  it("does not release collateral for an inconsistent cancel response", async () => {
    const state = inventory();
    const transport = new BrowserOrderTransport(
      {
        place: vi.fn(),
        cancel: vi.fn(async () => ({ order_id: orderId, status: "rejected" })),
      },
      state as unknown as BrowserInventory,
    );
    await expect(
      transport.cancel(orderId, {
        trading_key: "00".repeat(32),
        cancel_nonce: "1",
        session_id: "11".repeat(32),
        trading_key_signature: "22".repeat(64),
      }),
    ).resolves.toBe("ambiguous");
    expect(state.releaseReservation).not.toHaveBeenCalled();
    expect(state.updateOrder).toHaveBeenCalledWith(
      orderId,
      expect.objectContaining({
        kind: "ambiguous",
        reason: expect.stringContaining("unexpected cancellation status"),
      }),
    );
  });
});
