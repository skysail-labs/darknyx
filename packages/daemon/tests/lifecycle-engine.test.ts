/** LifecycleEngine store/reducer/merge-executor tests — no CVM. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import {
  LifecycleEngine,
  type ActionExecutor,
} from "../src/lifecycle-engine.js";
import type { LifecycleEvent } from "../src/order-lifecycle.js";

let store: DaemonStore;

beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => store.close());

function openOrder(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const order = newManagedOrder({
    orderId: "ab".repeat(8),
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    now: 1000,
  });
  return { ...order, phase: "open", ...overrides };
}

class FakeExecutor implements ActionExecutor {
  mergeCalls: ManagedOrder[] = [];

  constructor(
    private readonly result: LifecycleEvent = {
      type: "merge-confirmed",
      remaining: 4,
    },
  ) {}

  async merge(order: ManagedOrder): Promise<LifecycleEvent> {
    this.mergeCalls.push(order);
    return this.result;
  }
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("LifecycleEngine — dispatch + persistence", () => {
  it("persists each transition", async () => {
    const engine = new LifecycleEngine(store, new FakeExecutor());
    engine.register(openOrder());
    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      producedChangeNote: true,
    });

    expect(store.getOrder("ab".repeat(8))?.pendingChangeNotes).toBe(1);
  });

  it("throws on an unknown order", async () => {
    const engine = new LifecycleEngine(store, new FakeExecutor());
    await expect(
      engine.dispatch("ff".repeat(8), { type: "cancelled" }),
    ).rejects.toThrow(/unknown order/);
  });
});

describe("LifecycleEngine — auto-merge loop", () => {
  it("fires at the threshold and adopts the reported residual count", async () => {
    const executor = new FakeExecutor();
    const engine = new LifecycleEngine(store, executor);
    engine.register(openOrder({ pendingChangeNotes: 3 }));

    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      producedChangeNote: true,
    });
    await flush();

    expect(executor.mergeCalls).toHaveLength(1);
    const order = store.getOrder("ab".repeat(8))!;
    // The fake executor reports `remaining: 4`, and the count is now SET from
    // that store-derived value rather than subtracted (SW-13).
    expect(order.pendingChangeNotes).toBe(4);
    expect(order.mergeInFlight).toBe(false);
  });

  it("clears the latch after a reported failure", async () => {
    const engine = new LifecycleEngine(
      store,
      new FakeExecutor({ type: "merge-failed" }),
    );
    engine.register(openOrder({ pendingChangeNotes: 3 }));

    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      producedChangeNote: true,
    });
    await flush();

    expect(store.getOrder("ab".repeat(8))?.mergeInFlight).toBe(false);
  });

  it("converts an executor throw to merge-failed", async () => {
    const executor: ActionExecutor = {
      merge: vi.fn(async () => {
        throw new Error("network down");
      }),
    };
    const onError = vi.fn();
    const engine = new LifecycleEngine(store, executor, { onError });
    engine.register(openOrder({ pendingChangeNotes: 3 }));

    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      producedChangeNote: true,
    });
    await flush();

    expect(onError).toHaveBeenCalled();
    expect(store.getOrder("ab".repeat(8))?.mergeInFlight).toBe(false);
  });
});
