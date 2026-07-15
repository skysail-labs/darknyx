/**
 * Order-lifecycle reducer unit tests — pure, no CVM.
 *
 * Event model is decoupled: `fill` drives residual counting; phase comes from
 * `filled` / `cancelled` / `expired` / `accepted`. Covers both plus auto-merge.
 */

import { describe, expect, it } from "vitest";

import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import {
  DEFAULT_THRESHOLDS,
  reduceOrder,
  type LifecycleEvent,
} from "../src/order-lifecycle.js";

const T0 = 1_000_000;

function freshOpen(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const o = newManagedOrder({
    orderId: "00112233445566778899aabbccddeeff",
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    now: T0,
  });
  return { ...o, phase: "open", ...overrides };
}

describe("reduceOrder — phase transitions", () => {
  it("pending → open on accepted", () => {
    const o = newManagedOrder({
      orderId: "ab".repeat(8),
      seedIndex: 1,
      side: "ask",
      priceRaw: 1n,
      sizeRaw: 1n,
      now: T0,
    });
    const { order, actions } = reduceOrder(
      o,
      { type: "accepted", arrivalSlot: 5 },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("open");
    expect(actions).toEqual([]);
  });

  it("pending → rejected on rejected", () => {
    const o = newManagedOrder({
      orderId: "cd".repeat(8),
      seedIndex: 2,
      side: "bid",
      priceRaw: 1n,
      sizeRaw: 1n,
      now: T0,
    });
    const { order } = reduceOrder(
      o,
      { type: "rejected", reason: "bad proof" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("rejected");
  });

  it("open → filled on a filled event", () => {
    const { order } = reduceOrder(
      freshOpen(),
      { type: "filled" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("filled");
  });

  it("pending → filled too (fully_filled implies it was accepted)", () => {
    const o = newManagedOrder({
      orderId: "ef".repeat(8),
      seedIndex: 3,
      side: "bid",
      priceRaw: 1n,
      sizeRaw: 1n,
      now: T0,
    });
    const { order } = reduceOrder(
      o,
      { type: "filled" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("filled");
  });

  it("open → cancelled / expired", () => {
    expect(
      reduceOrder(freshOpen(), { type: "cancelled" }, DEFAULT_THRESHOLDS, T0)
        .order.phase,
    ).toBe("cancelled");
    expect(
      reduceOrder(freshOpen(), { type: "expired" }, DEFAULT_THRESHOLDS, T0)
        .order.phase,
    ).toBe("expired");
  });

  it("does not revive a terminal order", () => {
    for (const term of [
      "closed",
      "cancelled",
      "expired",
      "rejected",
    ] as const) {
      const { order } = reduceOrder(
        freshOpen({ phase: term }),
        { type: "cancelled" },
        DEFAULT_THRESHOLDS,
        T0,
      );
      expect(order.phase).toBe(term);
    }
  });

  it("a fill carries NO phase meaning (stays open)", () => {
    const { order } = reduceOrder(
      freshOpen(),
      { type: "fill", producedChangeNote: false },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("open");
    expect(order.pendingChangeNotes).toBe(0);
  });

  it("is immutable — does not mutate the input order", () => {
    const o = freshOpen();
    reduceOrder(
      o,
      { type: "fill", producedChangeNote: true },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(o.pendingChangeNotes).toBe(0);
  });
});

describe("reduceOrder — auto-merge", () => {
  it("emits a merge once residual change notes reach the threshold", () => {
    const o = freshOpen({ pendingChangeNotes: 3 });
    const { order, actions } = reduceOrder(
      o,
      { type: "fill", producedChangeNote: true },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.pendingChangeNotes).toBe(4);
    expect(actions).toContainEqual({
      type: "merge",
      orderId: o.orderId,
      noteCount: 4,
    });
    expect(order.mergeInFlight).toBe(true);
  });

  it("does not emit a second merge while one is in flight", () => {
    const o = freshOpen({ pendingChangeNotes: 5, mergeInFlight: true });
    const { actions } = reduceOrder(
      o,
      { type: "fill", producedChangeNote: true },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(actions.filter((a) => a.type === "merge")).toHaveLength(0);
  });

  it("merge-confirmed draws down the residual count + clears the latch", () => {
    const o = freshOpen({ pendingChangeNotes: 4, mergeInFlight: true });
    const { order } = reduceOrder(
      o,
      { type: "merge-confirmed", consumed: 4 },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.pendingChangeNotes).toBe(0);
    expect(order.mergeInFlight).toBe(false);
  });

  it("consolidates leftover residuals when an order goes filled below the quota", () => {
    // 2 residuals (< mergeThreshold 4) but the order just fully filled → merge now.
    const o = freshOpen({ pendingChangeNotes: 2 });
    const { order, actions } = reduceOrder(
      o,
      { type: "filled" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("filled");
    expect(actions).toContainEqual({
      type: "merge",
      orderId: o.orderId,
      noteCount: 2,
    });
  });

  it("consolidates leftover residuals on expiry / cancel too", () => {
    for (const ev of [{ type: "expired" }, { type: "cancelled" }] as const) {
      const o = freshOpen({ pendingChangeNotes: 1 });
      const { actions } = reduceOrder(o, ev, DEFAULT_THRESHOLDS, T0);
      expect(actions).toContainEqual({
        type: "merge",
        orderId: o.orderId,
        noteCount: 1,
      });
    }
  });

  it("no merge when a quiescent order has zero residuals", () => {
    const o = freshOpen({ pendingChangeNotes: 0 });
    const { actions } = reduceOrder(
      o,
      { type: "filled" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(actions.filter((a) => a.type === "merge")).toHaveLength(0);
  });
});
