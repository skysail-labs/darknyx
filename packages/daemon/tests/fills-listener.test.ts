/**
 * FillsListener tests — the `/v1/stream` fills channel, no live socket.
 *
 * `subscribeFills` is injected as a fake that captures the options, so a test
 * can invoke the captured `onFill` with a synthetic change-note record and
 * assert the listener drives the engine (which updates the persisted order).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FillsListener, type SubscribeFillsFn } from "../src/fills-listener.js";
import { LifecycleEngine } from "../src/lifecycle-engine.js";
import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import type { StoredNote } from "@darknyx/sdk";

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

const fillNote = (index: number, amount: bigint): StoredNote => ({
  commitment: `c${index}`,
  tokenMint: Uint8Array.from([1, 2]),
  amount,
  ownerCommitment: 9n,
  innerHash: 7n,
  orderId: ORDER_ID,
  consumedCommitment: `input${index}`,
});

/** A fake subscribeFills that captures the options it was called with. */
function captureSubscribe() {
  const captured: { opts?: Parameters<SubscribeFillsFn>[0]; closed: boolean } =
    {
      closed: false,
    };
  const fn: SubscribeFillsFn = (opts) => {
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

describe("FillsListener", () => {
  it("subscribes with the gateway/token/account material", () => {
    const { captured, fn } = captureSubscribe();
    const engine = new LifecycleEngine(store, {
      merge: async () => ({ type: "merge-confirmed", remaining: 0 }),
    });
    engine.register(openOrder());

    const listener = new FillsListener({
      engine,
      store,
      gatewayWsUrl: "wss://gw.example",
      token: "tok",
      masterSeed: new Uint8Array(64),
      ownerCommitment: 1n,
      subscribeFn: fn,
    });
    listener.start();

    expect(captured.opts?.gatewayWsUrl).toBe("wss://gw.example");
    expect(captured.opts?.token).toBe("tok");
    expect(captured.opts?.store).toBe(store);
    listener.stop();
    expect(captured.closed).toBe(true);
  });

  it("dispatches a fill event per change note and counts residuals", async () => {
    const { captured, fn } = captureSubscribe();
    const engine = new LifecycleEngine(store, {
      merge: async () => ({ type: "merge-confirmed", remaining: 0 }),
    });
    engine.register(openOrder());

    const seen: StoredNote[] = [];
    new FillsListener({
      engine,
      store,
      gatewayWsUrl: "wss://gw",
      token: "t",
      masterSeed: new Uint8Array(64),
      ownerCommitment: 1n,
      subscribeFn: fn,
      onFill: (r) => seen.push(r),
    }).start();

    // Simulate the SDK delivering two verified change notes.
    captured.opts!.onFill!(fillNote(0, 100n));
    captured.opts!.onFill!(fillNote(1, 0n)); // exact residual (amount 0)
    await flush();

    const got = store.getOrder(ORDER_ID)!;
    expect(got.pendingChangeNotes).toBe(1); // only the amount>0 note counts
    expect(seen).toHaveLength(2);
  });

  it("an unknown-order fill surfaces an error but does not throw out of the handler", async () => {
    const { captured, fn } = captureSubscribe();
    const engine = new LifecycleEngine(store, {
      merge: async () => ({ type: "merge-confirmed", remaining: 0 }),
    });
    // NOTE: no order registered.
    const onError = vi.fn();
    new FillsListener({
      engine,
      store,
      gatewayWsUrl: "wss://gw",
      token: "t",
      masterSeed: new Uint8Array(64),
      ownerCommitment: 1n,
      subscribeFn: fn,
      onError,
    }).start();

    captured.opts!.onFill!(fillNote(0, 1n));
    await flush();

    expect(onError).toHaveBeenCalledOnce();
    expect((onError.mock.calls[0][0] as Error).message).toMatch(
      /unknown order/,
    );
  });

  it("passes resync/close through", () => {
    const { captured, fn } = captureSubscribe();
    const engine = new LifecycleEngine(store, {
      merge: async () => ({ type: "merge-confirmed", remaining: 0 }),
    });
    const onResync = vi.fn();
    const onClose = vi.fn();
    new FillsListener({
      engine,
      store,
      gatewayWsUrl: "wss://gw",
      token: "t",
      masterSeed: new Uint8Array(64),
      ownerCommitment: 1n,
      subscribeFn: fn,
      onResync,
      onClose,
    }).start();

    captured.opts!.onResync!("lagged");
    captured.opts!.onClose!(1011, "lagged");
    expect(onResync).toHaveBeenCalledWith("lagged");
    expect(onClose).toHaveBeenCalledWith(1011, "lagged");
  });
});
