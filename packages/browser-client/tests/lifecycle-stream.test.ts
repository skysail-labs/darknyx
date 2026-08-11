import { describe, expect, it, vi } from "vitest";

import {
  BrowserLifecycleStream,
  lifecycleInternals,
} from "../src/trader/lifecycle-stream.js";
import type { BrowserInventory } from "../src/inventory/browser-inventory.js";

function harness() {
  const handlers = new Map<string, (frame: unknown) => void>();
  const inventory = {
    order: vi.fn(async () => ({
      orderId: "ab".repeat(16),
      reservationId: "reservation-1",
      noteCommitment: "cd".repeat(32),
    })),
    updateOrder: vi.fn(async () => undefined),
    markPendingSettlement: vi.fn(async () => undefined),
    markConsumed: vi.fn(async () => undefined),
    markOrderLocked: vi.fn(async () => undefined),
    releaseReservation: vi.fn(async () => undefined),
  };
  const reconcile = vi.fn<() => Promise<void>>(async () => undefined);
  const stream = new BrowserLifecycleStream({
    stream: {
      subscribeChannel(channel, handler) {
        handlers.set(channel, handler);
        return { close: vi.fn() };
      },
    },
    inventory: inventory as unknown as BrowserInventory,
    reconcile,
  });
  stream.start();
  return { handlers, inventory, reconcile, stream };
}

describe("browser lifecycle stream", () => {
  it("validates lifecycle frames instead of trusting SDK casts", () => {
    expect(() =>
      lifecycleInternals.parseOrderUpdate({
        order_id: "ab".repeat(16),
        kind: "partially_filled",
        filled_quantity: 4.5,
      }),
    ).toThrow(/safe integer/);
    expect(
      lifecycleInternals.parseOrderUpdate({
        order_id: "ab".repeat(16),
        kind: "settlement_failed",
        lock_expiry_slot: 42,
      }),
    ).toMatchObject({ lockExpirySlot: "42" });
  });

  it("moves matched collateral to pending settlement", async () => {
    const { handlers, inventory } = harness();
    handlers.get("orders")?.({
      order_id: "ab".repeat(16),
      kind: "pending_settlement",
    });
    await vi.waitFor(() =>
      expect(inventory.markPendingSettlement).toHaveBeenCalledWith(
        "reservation-1",
      ),
    );
  });

  it("reconciles finalized outputs after a confirmed partial fill", async () => {
    const { handlers, inventory, reconcile } = harness();
    handlers.get("orders")?.({
      order_id: "ab".repeat(16),
      kind: "partially_filled",
      filled_quantity: 10,
    });
    await vi.waitFor(() =>
      expect(inventory.markConsumed).toHaveBeenCalledWith("cd".repeat(32)),
    );
    expect(reconcile).toHaveBeenCalledWith("order partially_filled");
  });

  it("treats fill frames as hints and deduplicates concurrent chain reconciliation", async () => {
    let finish!: () => void;
    const { handlers, reconcile } = harness();
    reconcile.mockImplementation(
      () => new Promise<void>((resolve) => (finish = resolve)),
    );
    handlers.get("fills")?.({ channel: "fills" });
    handlers.get("fills")?.({ channel: "fills" });
    await vi.waitFor(() => expect(reconcile).toHaveBeenCalledTimes(1));
    finish();
  });
});
