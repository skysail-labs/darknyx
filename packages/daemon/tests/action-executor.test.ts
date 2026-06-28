/**
 * DaemonActionExecutor tests — the CVM/SDK seam, no live CVM.
 *
 * top-up exercises the REAL SDK `buildAnchorTopUp` (so the signed body shape is
 * covered) against a fake poster + fake keys; merge + the HTTP poster use
 * fakes/injected fetch. A capstone wires the executor into a LifecycleEngine to
 * prove the fill → top-up → confirm loop closes against real crypto.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  DaemonActionExecutor,
  HttpAnchorTopUpPoster,
  type AnchorTopUpPoster,
  type KeyProvider,
  type MergeRunner,
  type OrderKeys,
} from "../src/action-executor.js";
import { LifecycleEngine } from "../src/lifecycle-engine.js";
import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import type { AnchorTopUpBody } from "@nyx/sdk";

const ORDER_ID = "00112233445566778899aabbccddeeff"; // 16 bytes

function openOrder(overrides: Partial<ManagedOrder> = {}): ManagedOrder {
  const o = newManagedOrder({
    orderId: ORDER_ID,
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 1000n,
    anchorPoolSize: 10,
    now: 1000,
  });
  return { ...o, phase: "open", ...overrides };
}

/** Deterministic, Fr-safe key material — enough for buildAnchorTopUp's hashes. */
const fakeKeys: KeyProvider = {
  keysForOrder(): OrderKeys {
    return {
      masterSeed: new Uint8Array(64).fill(7),
      spendingKey: 12345n,
      tradingKeyPubkey: new Uint8Array(32).fill(3),
      sign: () => new Uint8Array(64).fill(9),
    };
  },
};

class RecordingPoster implements AnchorTopUpPoster {
  calls: { orderId: string; body: AnchorTopUpBody }[] = [];
  async post(orderId: string, body: AnchorTopUpBody): Promise<void> {
    this.calls.push({ orderId, body });
  }
}

describe("DaemonActionExecutor — top-up", () => {
  it("builds a signed body and posts it; resolves topup-confirmed", async () => {
    const poster = new RecordingPoster();
    const exec = new DaemonActionExecutor({
      keys: fakeKeys,
      anchors: poster,
      merge: { run: async () => 0 },
    });

    const ev = await exec.topup(openOrder(), {
      type: "topup",
      orderId: ORDER_ID,
      startIndex: 10,
      count: 5,
      nonce: 0,
    });

    expect(ev).toEqual({ type: "topup-confirmed", count: 5 });
    expect(poster.calls).toHaveLength(1);
    const { orderId, body } = poster.calls[0];
    expect(orderId).toBe(ORDER_ID);
    expect(body.anchors).toHaveLength(5); // count anchors provisioned
    expect(body.topup_nonce).toBe(0);
    expect(body.trading_key).toBe("03".repeat(32));
    // each anchor carries hex inner_hash + nullifier
    for (const a of body.anchors) {
      expect(a.inner_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(a.nullifier).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("rejects a malformed (non-16-byte) order id", async () => {
    const exec = new DaemonActionExecutor({
      keys: fakeKeys,
      anchors: new RecordingPoster(),
      merge: { run: async () => 0 },
    });
    await expect(
      exec.topup(openOrder({ orderId: "abcd" }), {
        type: "topup",
        orderId: "abcd",
        startIndex: 10,
        count: 5,
        nonce: 0,
      }),
    ).rejects.toThrow(/16 bytes/);
  });

  it("propagates a poster failure (engine converts it to topup-failed)", async () => {
    const poster: AnchorTopUpPoster = {
      post: vi.fn(async () => {
        throw new Error("gateway 503");
      }),
    };
    const exec = new DaemonActionExecutor({
      keys: fakeKeys,
      anchors: poster,
      merge: { run: async () => 0 },
    });
    await expect(
      exec.topup(openOrder(), {
        type: "topup",
        orderId: ORDER_ID,
        startIndex: 10,
        count: 5,
        nonce: 0,
      }),
    ).rejects.toThrow(/503/);
  });
});

describe("DaemonActionExecutor — merge", () => {
  it("delegates to the runner and resolves merge-confirmed with the consumed count", async () => {
    const runner: MergeRunner = { run: vi.fn(async () => 3) };
    const exec = new DaemonActionExecutor({
      keys: fakeKeys,
      anchors: new RecordingPoster(),
      merge: runner,
    });
    const ev = await exec.merge(openOrder({ pendingChangeNotes: 4 }), {
      type: "merge",
      orderId: ORDER_ID,
      noteCount: 4,
    });
    expect(ev).toEqual({ type: "merge-confirmed", consumed: 3 });
    expect(runner.run).toHaveBeenCalledOnce();
  });
});

describe("HttpAnchorTopUpPoster", () => {
  const body: AnchorTopUpBody = {
    anchors: [{ inner_hash: "00".repeat(32), nullifier: "11".repeat(32) }],
    topup_nonce: 1,
    trading_key: "22".repeat(32),
    trading_key_signature: "33".repeat(64),
  };

  it("POSTs to /orders/{id}/anchors with the bearer token", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(null, { status: 200 }),
    ) as unknown as typeof fetch;
    const poster = new HttpAnchorTopUpPoster({
      baseUrl: "https://gw.example",
      token: "tok123",
      fetchImpl,
    });
    await poster.post(ORDER_ID, body);

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0];
    expect(url).toBe(`https://gw.example/orders/${ORDER_ID}/anchors`);
    expect(init.method).toBe("POST");
    expect(init.headers.authorization).toBe("Bearer tok123");
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("throws NyxApiError on a non-2xx", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ code: 4090, message: "nonce reuse" }), {
          status: 409,
          headers: { "x-request-id": "req-7" },
        }),
    ) as unknown as typeof fetch;
    const poster = new HttpAnchorTopUpPoster({
      baseUrl: "https://gw.example",
      token: "tok",
      fetchImpl,
    });
    await expect(poster.post(ORDER_ID, body)).rejects.toMatchObject({
      name: "NyxApiError",
      code: 4090,
      status: 409,
      requestId: "req-7",
    });
  });
});

describe("executor ↔ engine integration", () => {
  let store: DaemonStore;
  beforeEach(() => {
    store = new DaemonStore(":memory:");
  });
  afterEach(() => store.close());

  const flush = () => new Promise((r) => setTimeout(r, 0));

  it("a fill that exhausts the pool drives a real top-up through to confirmation", async () => {
    const poster = new RecordingPoster();
    const exec = new DaemonActionExecutor({
      keys: fakeKeys,
      anchors: poster,
      merge: { run: async () => 0 },
    });
    const engine = new LifecycleEngine(store, exec);
    engine.register(openOrder({ anchorsConsumed: 6 }));

    // remaining hits 3 → topup intent → executor builds+posts → topup-confirmed
    await engine.dispatch(ORDER_ID, {
      type: "fill",
      anchorIndex: 6,
      producedChangeNote: false,
    });
    await flush();

    expect(poster.calls).toHaveLength(1);
    expect(poster.calls[0].body.anchors).toHaveLength(5);
    const got = store.getOrder(ORDER_ID)!;
    expect(got.anchorPoolSize).toBe(15);
    expect(got.topupInFlight).toBe(false);
    expect(got.topupNonce).toBe(1);
  });
});
