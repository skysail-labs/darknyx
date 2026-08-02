/**
 * OrdersListener tests — the `/v1/stream` orders channel, no live socket.
 *
 * `subscribeOrderUpdates` is injected as a fake that captures the options, so a
 * test can push synthetic OrderUpdates and assert the listener maps them to the
 * right phase transition on the persisted order — including the cancel-on-
 * disconnect `cancelled` the TEE emits when it sweeps a session's resting orders.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  OrdersListener,
  updateToEvent,
  type SubscribeOrderUpdatesFn,
} from "../src/orders-listener.js";
import { LifecycleEngine } from "../src/lifecycle-engine.js";
import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import type { OrderUpdate } from "@darknyx/sdk";

const ORDER_ID = "00112233445566778899aabbccddeeff";

let store: DaemonStore;
beforeEach(() => {
  store = new DaemonStore(":memory:");
});
afterEach(() => store.close());

function openOrder(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const o = newManagedOrder({
    orderId: ORDER_ID,
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    now: 1000,
  });
  return { ...o, phase: "open", ...overrides };
}

const noopExecutor = {
  merge: async () => ({ type: "merge-confirmed" as const, remaining: 0 }),
};

function captureSubscribe() {
  const captured: {
    opts?: Parameters<SubscribeOrderUpdatesFn>[0];
    closed: boolean;
  } = { closed: false };
  const fn: SubscribeOrderUpdatesFn = (opts) => {
    captured.opts = opts;
    return {
      close() {
        captured.closed = true;
      },
    };
  };
  return { captured, fn };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("updateToEvent", () => {
  it("maps each OrderUpdate kind to the right phase event", () => {
    expect(
      updateToEvent({
        order_id: ORDER_ID,
        kind: "pending_settlement",
        lock_expiry_slot: 99,
      }),
    ).toEqual({ type: "settlement-pending", lockExpirySlot: 99 });
    expect(
      updateToEvent({ order_id: ORDER_ID, kind: "partially_filled" }),
    ).toEqual({ type: "partial-fill-confirmed" });
    expect(updateToEvent({ order_id: ORDER_ID, kind: "fully_filled" })).toEqual(
      {
        type: "filled",
      },
    );
    expect(updateToEvent({ order_id: ORDER_ID, kind: "cancelled" })).toEqual({
      type: "cancelled",
    });
    expect(updateToEvent({ order_id: ORDER_ID, kind: "expired" })).toEqual({
      type: "expired",
    });
    expect(
      updateToEvent({
        order_id: ORDER_ID,
        kind: "settlement_failed",
        reason: "reverted",
        lock_expiry_slot: 123,
      }),
    ).toEqual({
      type: "settlement-failed",
      reason: "reverted",
      lockExpirySlot: 123,
    });
  });
});

describe("OrdersListener", () => {
  function mkListener(captured: ReturnType<typeof captureSubscribe>) {
    const engine = new LifecycleEngine(store, noopExecutor);
    const listener = new OrdersListener({
      engine,
      gatewayWsUrl: "wss://gw",
      token: "tok",
      subscribeFn: captured.fn,
    });
    return { engine, listener };
  }

  it("subscribes + closes", () => {
    const cap = captureSubscribe();
    const { listener } = mkListener(cap);
    listener.start();
    expect(cap.captured.opts?.gatewayWsUrl).toBe("wss://gw");
    expect(cap.captured.opts?.token).toBe("tok");
    listener.stop();
    expect(cap.captured.closed).toBe(true);
  });

  it("drives a pending order open on partially_filled, then filled", async () => {
    const cap = captureSubscribe();
    const { engine, listener } = mkListener(cap);
    engine.register(openOrder({ phase: "pending" }));
    listener.start();

    cap.captured.opts!.onUpdate({
      order_id: ORDER_ID,
      kind: "partially_filled",
    });
    await flush();
    expect(store.getOrder(ORDER_ID)!.phase).toBe("open");

    cap.captured.opts!.onUpdate({ order_id: ORDER_ID, kind: "fully_filled" });
    await flush();
    expect(store.getOrder(ORDER_ID)!.phase).toBe("filled");
  });

  it("holds an order pending until finality and records terminal settlement failure", async () => {
    const cap = captureSubscribe();
    const { engine, listener } = mkListener(cap);
    engine.register(openOrder());
    listener.start();

    cap.captured.opts!.onUpdate({
      order_id: ORDER_ID,
      kind: "pending_settlement",
      lock_expiry_slot: 777,
    });
    await flush();
    expect(store.getOrder(ORDER_ID)!.phase).toBe("pending_settlement");

    cap.captured.opts!.onUpdate({
      order_id: ORDER_ID,
      kind: "settlement_failed",
      reason: "Tx D reverted",
      lock_expiry_slot: 777,
    });
    await flush();
    const failed = store.getOrder(ORDER_ID)!;
    expect(failed.phase).toBe("settlement_failed");
    expect(failed.settlementFailureReason).toBe("Tx D reverted");
    expect(failed.settlementUnlockSlot).toBe(777);
  });

  it("a cancel-on-disconnect sweep (synthetic cancelled) marks the order cancelled", async () => {
    const cap = captureSubscribe();
    const { engine, listener } = mkListener(cap);
    engine.register(openOrder());
    listener.start();

    // The TEE routes a synthetic `cancelled` onto the orders channel when it sweeps a
    // session's resting orders on disconnect.
    cap.captured.opts!.onUpdate({ order_id: ORDER_ID, kind: "cancelled" });
    await flush();
    expect(store.getOrder(ORDER_ID)!.phase).toBe("cancelled");
  });

  it("expired marks the order expired", async () => {
    const cap = captureSubscribe();
    const { engine, listener } = mkListener(cap);
    engine.register(openOrder());
    listener.start();

    cap.captured.opts!.onUpdate({ order_id: ORDER_ID, kind: "expired" });
    await flush();
    expect(store.getOrder(ORDER_ID)!.phase).toBe("expired");
  });

  it("an update for an unknown order surfaces an error, no throw", async () => {
    const cap = captureSubscribe();
    const onError = vi.fn();
    const engine = new LifecycleEngine(store, noopExecutor);
    new OrdersListener({
      engine,
      gatewayWsUrl: "wss://gw",
      token: "t",
      subscribeFn: cap.fn,
      onError,
    }).start();

    cap.captured.opts!.onUpdate({ order_id: ORDER_ID, kind: "fully_filled" });
    await flush();
    expect(onError).toHaveBeenCalledOnce();
    expect((onError.mock.calls[0][0] as Error).message).toMatch(
      /unknown order/,
    );
  });

  it("passes resync/close through", () => {
    const cap = captureSubscribe();
    const onResync = vi.fn();
    const onClose = vi.fn();
    const engine = new LifecycleEngine(store, noopExecutor);
    new OrdersListener({
      engine,
      gatewayWsUrl: "wss://gw",
      token: "t",
      subscribeFn: cap.fn,
      onResync,
      onClose,
    }).start();
    cap.captured.opts!.onResync!("lagged");
    cap.captured.opts!.onClose!(1011, "lagged");
    expect(onResync).toHaveBeenCalledWith("lagged");
    expect(onClose).toHaveBeenCalledWith(1011, "lagged");
  });
});
