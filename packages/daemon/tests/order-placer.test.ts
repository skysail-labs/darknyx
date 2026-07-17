/**
 * OrderPlacer tests — WS default (reconnect) + REST fallback + the placement
 * bridge, no live socket/CVM.
 *
 * WsOrderPlacer uses an injected clientFactory (fake TradingClient) so the
 * connect/reuse/reconnect logic is testable without a WebSocket; RestOrderPlacer
 * uses an injected fetch; placeManagedOrder drives a :memory: engine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  RestOrderPlacer,
  WsOrderPlacer,
  type TradingClientLike,
} from "../src/order-placer.js";
import { placeManagedOrder } from "../src/place.js";
import { LifecycleEngine } from "../src/lifecycle-engine.js";
import { DaemonStore } from "../src/store.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import {
  DarknyxApiError,
  type PlaceOrderRequest,
  type PlaceOrderResponse,
} from "@darknyx/sdk";

const ORDER_ID = "00112233445566778899aabbccddeeff";

// A minimal stand-in place body (the transport doesn't inspect it).
const REQ = { foo: "bar" } as unknown as PlaceOrderRequest;
const ACCEPT: PlaceOrderResponse = {
  order_id: ORDER_ID,
  status: "accepted",
  arrival_slot: 42,
};

// ── WsOrderPlacer ──

interface FakeClientOpts {
  cancelOnDisconnect?: boolean;
}

/** A fake TradingClient whose connect/place behaviour the test scripts. */
class FakeClient implements TradingClientLike {
  connected = false;
  connectCalls = 0;
  closed = false;
  constructor(
    public readonly opts: FakeClientOpts,
    private readonly behavior: {
      connect?: () => Promise<void>;
      place?: () => Promise<PlaceOrderResponse>;
    } = {},
  ) {}
  async connect(): Promise<void> {
    this.connectCalls += 1;
    if (this.behavior.connect) return this.behavior.connect();
    this.connected = true;
  }
  place(): Promise<PlaceOrderResponse> {
    return this.behavior.place
      ? this.behavior.place()
      : Promise.resolve(ACCEPT);
  }
  cancel(): Promise<never> {
    throw new Error("unused");
  }
  modify(): Promise<never> {
    throw new Error("unused");
  }
  close(): void {
    this.closed = true;
  }
}

describe("WsOrderPlacer", () => {
  it("connects once and reuses the client across calls", async () => {
    const built: FakeClient[] = [];
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      clientFactory: (o) => {
        const c = new FakeClient(o);
        built.push(c);
        return c;
      },
    });
    await placer.place(REQ);
    await placer.place(REQ);
    expect(built).toHaveLength(1);
    expect(built[0].connected).toBe(true);
  });

  it("defaults cancel-on-disconnect ON", async () => {
    let seen: FakeClientOpts | undefined;
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      clientFactory: (o) => {
        seen = o;
        return new FakeClient(o);
      },
    });
    await placer.place(REQ);
    expect(seen?.cancelOnDisconnect).toBe(true);
  });

  it("rebuilds the client and retries on a transport error", async () => {
    const built: FakeClient[] = [];
    let call = 0;
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      clientFactory: (o) => {
        const c = new FakeClient(o, {
          place: () => {
            call += 1;
            // first client's send fails as if the socket dropped
            if (call === 1)
              return Promise.reject(new Error("ws closed (code 1006)"));
            return Promise.resolve(ACCEPT);
          },
        });
        built.push(c);
        return c;
      },
    });
    const resp = await placer.place(REQ);
    expect(resp).toEqual(ACCEPT);
    expect(built).toHaveLength(2); // rebuilt after the transport error
    expect(built[0].closed).toBe(true); // dead client was closed
  });

  it("reconnects the shared multiplexed client without permanently closing it", async () => {
    let calls = 0;
    const shared = new FakeClient(
      {},
      {
        place: () => {
          calls += 1;
          return calls === 1
            ? Promise.reject(new Error("stream closed (code 1006)"))
            : Promise.resolve(ACCEPT);
        },
      },
    );
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      client: shared,
    });
    await expect(placer.place(REQ)).resolves.toEqual(ACCEPT);
    expect(shared.connectCalls).toBe(2);
    expect(shared.closed).toBe(false);
  });

  it("does NOT retry a DarknyxApiError (definitive server reply)", async () => {
    const built: FakeClient[] = [];
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      clientFactory: (o) => {
        const c = new FakeClient(o, {
          place: () =>
            Promise.reject(new DarknyxApiError(4090, "nonce reuse", 409)),
        });
        built.push(c);
        return c;
      },
    });
    await expect(placer.place(REQ)).rejects.toMatchObject({
      name: "DarknyxApiError",
      code: 4090,
    });
    expect(built).toHaveLength(1); // no rebuild/retry
  });

  it("gives up after maxRetries transport errors", async () => {
    const built: FakeClient[] = [];
    const placer = new WsOrderPlacer({
      gatewayWsUrl: "wss://gw",
      token: "t",
      maxRetries: 2,
      clientFactory: (o) => {
        const c = new FakeClient(o, {
          place: () => Promise.reject(new Error("socket not connected")),
        });
        built.push(c);
        return c;
      },
    });
    await expect(placer.place(REQ)).rejects.toThrow(/socket not connected/);
    expect(built).toHaveLength(3); // initial + 2 retries
  });
});

// ── RestOrderPlacer ──

describe("RestOrderPlacer", () => {
  it("POSTs place to /orders with the bearer token", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify(ACCEPT), { status: 200 }),
    ) as unknown as typeof fetch;
    const placer = new RestOrderPlacer({
      baseUrl: "https://gw.example",
      token: "tok",
      fetchImpl,
    });
    const resp = await placer.place(REQ);
    expect(resp).toEqual(ACCEPT);
    const [url, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0];
    expect(url).toBe("https://gw.example/orders");
    expect(init.method).toBe("POST");
    expect(init.headers.authorization).toBe("Bearer tok");
  });
});

// ── placeManagedOrder bridge ──

describe("placeManagedOrder", () => {
  let store: DaemonStore;
  beforeEach(() => {
    store = new DaemonStore(":memory:");
  });
  afterEach(() => store.close());

  const noopExecutor = {
    merge: async () => ({ type: "merge-confirmed" as const, consumed: 0 }),
  };

  const pendingOrder = (): ManagedOrder =>
    newManagedOrder({
      orderId: ORDER_ID,
      seedIndex: 0,
      side: "bid",
      priceRaw: 100n,
      sizeRaw: 1000n,
      now: 1000,
    });

  it("registers pending, places, and moves the order to open on acceptance", async () => {
    const engine = new LifecycleEngine(store, noopExecutor);
    const placer = { place: vi.fn(async () => ACCEPT) } as never;
    const resp = await placeManagedOrder({
      engine,
      placer,
      order: pendingOrder(),
      request: REQ,
    });
    expect(resp).toEqual(ACCEPT);
    expect(store.getOrder(ORDER_ID)!.phase).toBe("open");
  });

  it("marks the order rejected and rethrows on a placement failure", async () => {
    const engine = new LifecycleEngine(store, noopExecutor);
    const placer = {
      place: vi.fn(async () => {
        throw new DarknyxApiError(4000, "bad proof", 400);
      }),
    } as never;
    await expect(
      placeManagedOrder({
        engine,
        placer,
        order: pendingOrder(),
        request: REQ,
      }),
    ).rejects.toThrow(/bad proof/);
    expect(store.getOrder(ORDER_ID)!.phase).toBe("rejected");
  });
});
