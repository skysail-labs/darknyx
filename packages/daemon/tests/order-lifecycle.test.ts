/**
 * Order-lifecycle reducer unit tests — pure, no CVM.
 *
 * Event model is decoupled: `fill` (from the fills channel) drives ONLY anchor
 * consumption + residual counting; phase comes from `filled` / `cancelled` /
 * `expired` / `accepted` (from the orders channel + placement). Covers both, plus the
 * two automation decisions (auto anchor top-up, auto-merge).
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
      anchorPoolSize: 10,
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
      { type: "fill", anchorIndex: 0, producedChangeNote: false },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.phase).toBe("open");
    expect(order.anchorsConsumed).toBe(1);
  });

  it("is immutable — does not mutate the input order", () => {
    const o = freshOpen();
    reduceOrder(
      o,
      { type: "fill", anchorIndex: 4, producedChangeNote: true },
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
      { type: "fill", anchorIndex: 6, producedChangeNote: true },
      DEFAULT_THRESHOLDS,
      T0,
    );
    expect(order.anchorsConsumed).toBe(7); // remaining = 3
    expect(actions).toContainEqual({
      type: "topup",
      orderId: o.orderId,
      startIndex: 10,
      count: DEFAULT_THRESHOLDS.anchorTopUpSize,
      nonce: 1, // 1-based: the initial pool is nonce 0
    });
    expect(order.topupInFlight).toBe(true);
  });

  it("does not emit a second top-up while one is in flight", () => {
    const o = freshOpen({ anchorsConsumed: 7, topupInFlight: true });
    const { actions } = reduceOrder(
      o,
      { type: "fill", anchorIndex: 8, producedChangeNote: true },
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
      { type: "fill", anchorIndex: 6, producedChangeNote: false },
      { type: "topup-confirmed", count: 5 },
    ]);
    expect(order.anchorPoolSize).toBe(15);
    expect(order.anchorsConsumed).toBe(7); // remaining now 8
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(1);
    expect(order.topupInFlight).toBe(false);
  });

  it("top-up-failed clears the latch so the next fill retries", () => {
    const { order, actions } = run(freshOpen({ anchorsConsumed: 7 }), [
      { type: "fill", anchorIndex: 6, producedChangeNote: false },
      { type: "topup-failed" },
      { type: "fill", anchorIndex: 7, producedChangeNote: false },
    ]);
    expect(actions.filter((a) => a.type === "topup")).toHaveLength(2);
    expect(order.topupInFlight).toBe(true);
  });

  it("topup-failed below the threshold emits NO action (edge-triggered, no hot loop)", () => {
    // Regression: intents are derived only on fill/filled/cancelled/expired,
    // never on action outcomes — otherwise a permanently-failing top-up would
    // re-fire on every `topup-failed` (remaining stays ≤ threshold) and spin.
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
    const o = freshOpen({ anchorsConsumed: 9 });
    const { order, actions } = reduceOrder(
      o,
      { type: "filled" },
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
      { type: "fill", anchorIndex: 3, producedChangeNote: true },
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
      { type: "fill", anchorIndex: 5, producedChangeNote: true },
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
