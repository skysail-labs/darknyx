/** DaemonActionExecutor merge seam tests — no live CVM. */

import { describe, expect, it, vi } from "vitest";

import {
  DaemonActionExecutor,
  type MergeRunner,
} from "../src/action-executor.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";

const ORDER_ID = "00112233445566778899aabbccddeeff";

function openOrder(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const order = newManagedOrder({
    orderId: ORDER_ID,
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    now: 1000,
  });
  return { ...order, phase: "open", ...overrides };
}

describe("DaemonActionExecutor — merge", () => {
  it("delegates to the runner and reports the order\u2019s remaining residuals", async () => {
    const runner: MergeRunner = {
      run: vi.fn(async () => ({ consumed: 3, remaining: 2 })),
    };
    const executor = new DaemonActionExecutor({ merge: runner });

    const event = await executor.merge(
      openOrder({ pendingChangeNotes: 4 }),
      { type: "merge", orderId: ORDER_ID, noteCount: 4 },
    );

    // The event carries the trigger order's REMAINING residuals, not the
    // account-wide consumed count (SW-13).
    expect(event).toEqual({ type: "merge-confirmed", remaining: 2 });
    expect(runner.run).toHaveBeenCalledWith(expect.any(Object), 4);
  });

  it("propagates a runner failure for the engine to convert", async () => {
    const executor = new DaemonActionExecutor({
      merge: {
        run: vi.fn(async () => {
          throw new Error("chain unavailable");
        }),
      },
    });

    await expect(
      executor.merge(openOrder(), {
        type: "merge",
        orderId: ORDER_ID,
        noteCount: 2,
      }),
    ).rejects.toThrow(/chain unavailable/);
  });
});
