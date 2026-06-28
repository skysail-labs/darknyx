/**
 * Order-lifecycle reducer unit tests — pure, no CVM. Drives the two automation
 * decisions (auto anchor top-up, auto-merge) + phase transitions.
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
    anchorPoolSize: 10,
    now: T0,
  });
  return { ...o, phase: "open", ...overrides };
}

/** Fold a sequence of events through the reducer, collecting all actions. */
function run(start: ManagedOrder, events: LifecycleEvent[]) {
  let order = start;
  const actions = [];
  for (const ev of events) {
    const r = reduceOrder(order, ev, DEFAULT_THRESHOLDS, T0);
    order = r.order;
    actions.push(...r.actions);
  }
  return { order, actions };
}

describe("reduceOrder — phase transitions", () => {
  it("pending → open on accepted", () => {
    const o = newManagedOrder({
      orderId: "ab".repeat(8),
      seedIndex: 1,
      side: "ask",
      priceRaw: 1n,
      sizeRaw: 1n,
      anchorPoolSize: 10,
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
      anchorPoolSize: 10,
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

  it("does not revive a terminal order", () => {
    const o = freshOpen({ phase: "closed" });
    const { order } = reduceOrder(
      o,
      { type: "cancelled" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("closed");
  });

  it("fully-filled fill moves open → filled", () => {
    const { order } = reduceOrder(
      freshOpen(),
      {
        type: "fill",
        anchorIndex: 0,
        isPartial: false,
        producedChangeNote: false,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("filled");
  });

  it("is immutable — does not mutate the input order", () => {
    const o = freshOpen();
    reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 4,
        isPartial: true,
        producedChangeNote: true,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(o.anchorsConsumed).toBe(0);
    expect(o.pendingChangeNotes).toBe(0);
  });
});

describe("reduceOrder — auto anchor top-up", () => {
  it("emits a top-up when remaining anchors hit the threshold", () => {
    // pool 10, threshold 3 → top up once consumed reaches 7 (remaining 3).
    const o = freshOpen({ anchorsConsumed: 6 });
    const { order, actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 6,
        isPartial: true,
        producedChangeNote: true,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.anchorsConsumed).toBe(7); // remaining = 3
    expect(actions).toContainEqual({
      type: "topup",
      orderId: o.orderId,
      startIndex: 10,
      count: DEFAULT_THRESHOLDS.anchorTopUpSize,
      nonce: 0,
    });
    expect(order.topupInFlight).toBe(true);
  });

  it("does not emit a second top-up while one is in flight", () => {
    const o = freshOpen({ anchorsConsumed: 7, topupInFlight: true });
    const { actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 8,
        isPartial: true,
        producedChangeNote: true,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(0);
  });

  it("top-up-confirmed grows the pool, clears the latch, bumps the nonce", () => {
    const o = freshOpen({
      anchorsConsumed: 7,
      topupInFlight: true,
      topupNonce: 0,
    });
    const { order } = reduceOrder(
      o,
      { type: "topup-confirmed", count: 5 },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.anchorPoolSize).toBe(15);
    expect(order.topupInFlight).toBe(false);
    expect(order.topupNonce).toBe(1);
  });

  it("a confirmed top-up restores headroom (no immediate re-topup)", () => {
    const { order, actions } = run(freshOpen({ anchorsConsumed: 7 }), [
      // remaining 3 → topup intent, latch set
      {
        type: "fill",
        anchorIndex: 6,
        isPartial: true,
        producedChangeNote: false,
      },
      // pool 10 → 15, latch cleared, nonce 1
      { type: "topup-confirmed", count: 5 },
    ]);
    expect(order.anchorPoolSize).toBe(15);
    expect(order.anchorsConsumed).toBe(7); // remaining now 8
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(1);
    expect(order.topupInFlight).toBe(false);
  });

  it("top-up-failed clears the latch so the next fill retries", () => {
    const { order, actions } = run(freshOpen({ anchorsConsumed: 7 }), [
      {
        type: "fill",
        anchorIndex: 6,
        isPartial: true,
        producedChangeNote: false,
      },
      { type: "topup-failed" },
      // still at remaining 3 with the latch cleared → a fresh topup intent
      {
        type: "fill",
        anchorIndex: 7,
        isPartial: true,
        producedChangeNote: false,
      },
    ]);
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(2);
    expect(order.topupInFlight).toBe(true);
  });

  it("topup-failed below the threshold emits NO action (edge-triggered, no hot loop)", () => {
    // Regression: intents are derived only on fill/cancelled, never on action
    // outcomes — otherwise a permanently-failing top-up would re-fire on every
    // `topup-failed` (remaining stays ≤ threshold) and spin forever.
    const o = freshOpen({ anchorsConsumed: 7, topupInFlight: true });
    const { order, actions } = reduceOrder(
      o,
      { type: "topup-failed" },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(actions).toEqual([]);
    expect(order.topupInFlight).toBe(false);
  });

  it("does not top up a filled (no-longer-matching) order", () => {
    const o = freshOpen({ anchorsConsumed: 9, phase: "open" });
    const { order, actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 9,
        isPartial: false,
        producedChangeNote: true,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("filled");
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(0);
  });
});

describe("reduceOrder — auto-merge", () => {
  it("emits a merge once residual change notes reach the threshold", () => {
    const o = freshOpen({ pendingChangeNotes: 3 });
    const { order, actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 3,
        isPartial: true,
        producedChangeNote: true,
      },
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
      {
        type: "fill",
        anchorIndex: 5,
        isPartial: true,
        producedChangeNote: true,
      },
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
    const o = freshOpen({ pendingChangeNotes: 2, anchorsConsumed: 8 });
    const { order, actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 8,
        isPartial: false,
        producedChangeNote: false,
      },
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

  it("no merge when a quiescent order has zero residuals", () => {
    const o = freshOpen({ pendingChangeNotes: 0, anchorsConsumed: 5 });
    const { actions } = reduceOrder(
      o,
      {
        type: "fill",
        anchorIndex: 5,
        isPartial: false,
        producedChangeNote: false,
      },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(actions.filter((a) => a.type === "merge")).toHaveLength(0);
  });
});
