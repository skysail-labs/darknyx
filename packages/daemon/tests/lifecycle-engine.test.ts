/**
 * LifecycleEngine tests — the store + reducer + executor wiring, no CVM.
 *
 * A fake ActionExecutor records the intents it's handed and returns a canned
 * follow-up event, so we can assert: (a) intents reach the executor, (b) their
 * outcomes fold back into persisted state, (c) throws become `*-failed` events
 * that clear the latch.
 */

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
afterEach(() => {
  store.close();
});

function openOrder(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const o = newManagedOrder({
    orderId: "ab".repeat(8),
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    anchorPoolSize: 10,
    now: 1000,
  });
  return { ...o, phase: "open", ...overrides };
}

/** Executor that records calls and resolves with caller-supplied follow-ups. */
class FakeExecutor implements ActionExecutor {
  topupCalls: ManagedOrder[] = [];
  mergeCalls: ManagedOrder[] = [];
  constructor(
    private readonly topupResult: LifecycleEvent = {
      type: "topup-confirmed",
      count: 5,
    },
    private readonly mergeResult: LifecycleEvent = {
      type: "merge-confirmed",
      consumed: 4,
    },
  ) {}
  async topup(order: ManagedOrder): Promise<LifecycleEvent> {
    this.topupCalls.push(order);
    return this.topupResult;
  }
  async merge(order: ManagedOrder): Promise<LifecycleEvent> {
    this.mergeCalls.push(order);
    return this.mergeResult;
  }
}

/** Let detached action promises (and their follow-up dispatches) settle. */
const flush = () => new Promise((r) => setTimeout(r, 0));

describe("LifecycleEngine — dispatch + persistence", () => {
  it("persists each transition", async () => {
    const engine = new LifecycleEngine(store, new FakeExecutor());
    engine.register(openOrder());
    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 0,
      isPartial: true,
      producedChangeNote: true,
    });
    const got = store.getOrder("ab".repeat(8))!;
    expect(got.anchorsConsumed).toBe(1);
    expect(got.pendingChangeNotes).toBe(1);
  });

  it("throws on an unknown order", async () => {
    const engine = new LifecycleEngine(store, new FakeExecutor());
    await expect(
      engine.dispatch("ff".repeat(8), { type: "cancelled" }),
    ).rejects.toThrow(/unknown order/);
  });
});

describe("LifecycleEngine — auto anchor top-up loop", () => {
  it("fires the top-up intent and folds the confirmation back into state", async () => {
    const exec = new FakeExecutor();
    const engine = new LifecycleEngine(store, exec);
    engine.register(openOrder({ anchorsConsumed: 6 }));

    // remaining hits 3 → topup intent → executor → topup-confirmed → pool 10→15
    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 6,
      isPartial: true,
      producedChangeNote: false,
    });
    await flush();

    expect(exec.topupCalls).toHaveLength(1);
    const got = store.getOrder("ab".repeat(8))!;
    expect(got.anchorPoolSize).toBe(15);
    expect(got.topupInFlight).toBe(false);
    expect(got.topupNonce).toBe(1);
  });

  it("a failed top-up clears the latch (next fill retries)", async () => {
    const exec = new FakeExecutor({ type: "topup-failed" });
    const engine = new LifecycleEngine(store, exec);
    engine.register(openOrder({ anchorsConsumed: 6 }));

    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 6,
      isPartial: true,
      producedChangeNote: false,
    });
    await flush();

    let got = store.getOrder("ab".repeat(8))!;
    expect(got.topupInFlight).toBe(false);
    expect(got.anchorPoolSize).toBe(10); // unchanged

    // next fill at the same remaining re-fires the intent
    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 7,
      isPartial: true,
      producedChangeNote: false,
    });
    await flush();
    expect(exec.topupCalls).toHaveLength(2);
    got = store.getOrder("ab".repeat(8))!;
    expect(got.topupInFlight).toBe(false);
  });

  it("an executor throw becomes a topup-failed (latch cleared)", async () => {
    const exec: ActionExecutor = {
      topup: vi.fn(async () => {
        throw new Error("network down");
      }),
      merge: vi.fn(async () => ({ type: "merge-confirmed", consumed: 0 })),
    };
    const onError = vi.fn();
    const engine = new LifecycleEngine(store, exec, { onError });
    engine.register(openOrder({ anchorsConsumed: 6 }));

    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 6,
      isPartial: true,
      producedChangeNote: false,
    });
    await flush();

    expect(onError).toHaveBeenCalled();
    const got = store.getOrder("ab".repeat(8))!;
    expect(got.topupInFlight).toBe(false);
    expect(got.anchorPoolSize).toBe(10);
  });
});

describe("LifecycleEngine — auto-merge loop", () => {
  it("fires merge at the threshold and draws down residuals on confirm", async () => {
    const exec = new FakeExecutor(undefined, {
      type: "merge-confirmed",
      consumed: 4,
    });
    const engine = new LifecycleEngine(store, exec);
    engine.register(openOrder({ pendingChangeNotes: 3 }));

    // 3 → 4 residuals → merge intent → executor → merge-confirmed → 4-4 = 0
    await engine.dispatch("ab".repeat(8), {
      type: "fill",
      anchorIndex: 3,
      isPartial: true,
      producedChangeNote: true,
    });
    await flush();

    expect(exec.mergeCalls).toHaveLength(1);
    const got = store.getOrder("ab".repeat(8))!;
    expect(got.pendingChangeNotes).toBe(0);
    expect(got.mergeInFlight).toBe(false);
  });
});
