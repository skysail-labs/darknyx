/**
 * Daemon wiring tests — the assembled object with all I/O faked (no CVM).
 * Real Keystore + :memory: store + real engine; fake prover/placer/fetch/streams.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Daemon, type DaemonEvent } from "../src/daemon.js";
import { DaemonStore } from "../src/store.js";
import { Keystore, type AccountIdentity } from "../src/keystore.js";
import { DEFAULT_THRESHOLDS } from "../src/order-lifecycle.js";
import type { DaemonConfig } from "../src/config.js";
import type { OrderPlacer } from "../src/order-placer.js";
import {
  limitPolicy,
  OrderSide,
  type PlaceOrderResponse,
  type StoredNote,
  type ValidInputProver,
} from "@nyx/sdk";

function keystore(): Keystore {
  const masterSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) masterSeed[i] = (i * 13 + 5) & 0xff;
  const id: AccountIdentity = {
    masterSeed,
    ownerBlinding: 0xabcn,
    r0: 1n,
    r1: 2n,
    r2: 3n,
    rootKeyPubkey: new Uint8Array(32).fill(4),
  };
  return new Keystore(id);
}

const config = (): DaemonConfig => ({
  gatewayUrl: "https://gw",
  gatewayWsUrl: "wss://gw",
  token: "tok",
  rpcUrl: "https://rpc",
  dbPath: ":memory:",
  controlPort: 0,
  keystorePath: "x",
  thresholds: DEFAULT_THRESHOLDS,
});

const note: StoredNote = {
  commitment: "aa".repeat(32),
  tokenMint: new Uint8Array(32).fill(9),
  amount: 1_000_000n,
  ownerCommitment: 12345n,
  innerHash: 7n,
  leafIndex: 0n,
};

const fakeProver: ValidInputProver = async (p) => ({
  proofBytes: new Uint8Array(256).fill(1),
  merkleRoot: p.witness.merkleRoot,
});

function fakeFetch(): typeof fetch {
  return vi.fn(async () => {
    const body = {
      leaf_index: 0,
      merkle_root: "bb".repeat(32),
      siblings: Array.from({ length: 20 }, (_, i) =>
        i.toString(16).padStart(2, "0").repeat(32),
      ),
    };
    return new Response(JSON.stringify(body), { status: 200 });
  }) as unknown as typeof fetch;
}

const ACCEPT: PlaceOrderResponse = {
  order_id: "x",
  status: "accepted",
  arrival_slot: 7,
};

/** Capture the injected stream options so tests can push frames. */
function capture<T>() {
  const cap: { opts?: T; closed: boolean } = { closed: false };
  const fn = (opts: T) => {
    cap.opts = opts;
    return {
      close() {
        cap.closed = true;
      },
    };
  };
  return { cap, fn };
}

let store: DaemonStore;
let placer: OrderPlacer & { placed: unknown[]; cancelled: string[] };

beforeEach(() => {
  store = new DaemonStore(":memory:");
  placer = {
    placed: [],
    cancelled: [],
    place: vi.fn(async (o: unknown) => {
      placer.placed.push(o);
      return ACCEPT;
    }),
    cancel: vi.fn(async (id: string) => {
      placer.cancelled.push(id);
      return { order_id: id, status: "cancelled" };
    }),
    modify: vi.fn(),
    close: vi.fn(),
  } as never;
});
afterEach(() => store.close());

function mkDaemon(
  extra: Partial<Parameters<typeof Daemon.prototype.constructor>[0]> = {},
) {
  return new Daemon({
    config: config(),
    keystore: keystore(),
    store,
    prover: fakeProver,
    placer,
    fetchImpl: fakeFetch(),
    subscribeFills: capture().fn as never,
    subscribeOrders: capture().fn as never,
    ...extra,
  });
}

describe("Daemon — placeOrder", () => {
  it("builds, places, and moves the order to open; emits an order event", async () => {
    const daemon = mkDaemon();
    const events: DaemonEvent[] = [];
    daemon.subscribe((e) => events.push(e));

    const { orderId, arrivalSlot } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      note,
    );

    expect(arrivalSlot).toBe(7);
    expect(placer.placed).toHaveLength(1);
    expect(store.getOrder(orderId)!.phase).toBe("open");
    expect(events.some((e) => e.type === "order")).toBe(true);
  });

  it("allocates a fresh HD seed index per order", async () => {
    const daemon = mkDaemon();
    const intent = {
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy: limitPolicy({ priceLimit: 100n }),
      amount: 500n,
    };
    const a = await daemon.placeOrder(intent, note);
    const b = await daemon.placeOrder(intent, note);
    expect(a.orderId).not.toBe(b.orderId);
    const idxs = daemon.listOrders().map((o) => o.seedIndex);
    expect(new Set(idxs).size).toBe(2);
  });
});

describe("Daemon — cancelOrder", () => {
  it("signs + sends a cancel and drives the order to cancelled", async () => {
    const daemon = mkDaemon();
    const { orderId } = await daemon.placeOrder(
      {
        symbol: "SOL-USDC",
        side: OrderSide.Bid,
        policy: limitPolicy({ priceLimit: 100n }),
        amount: 500n,
      },
      note,
    );
    await daemon.cancelOrder(orderId);
    expect(placer.cancelled).toContain(orderId);
    expect(store.getOrder(orderId)!.phase).toBe("cancelled");
  });

  it("rejects an unknown order", async () => {
    const daemon = mkDaemon();
    await expect(daemon.cancelOrder("ab".repeat(8))).rejects.toThrow(
      /unknown order/,
    );
  });
});

describe("Daemon — balances + streams", () => {
  it("aggregates unspent notes per mint", () => {
    const daemon = mkDaemon();
    store.put(note);
    store.put({ ...note, commitment: "bb".repeat(32), amount: 5n });
    store.put({
      ...note,
      commitment: "cc".repeat(32),
      tokenMint: new Uint8Array(32).fill(2),
      amount: 3n,
    });
    const balances = daemon.balances();
    const byMint = Object.fromEntries(balances.map((b) => [b.mint, b]));
    expect(byMint["09".repeat(32)].amount).toBe("1000005");
    expect(byMint["09".repeat(32)].notes).toBe(2);
    expect(byMint["02".repeat(32)].amount).toBe("3");
  });

  it("start() opens both streams; stop() closes the placer", async () => {
    const fills = capture();
    const orders = capture();
    const daemon = mkDaemon({
      subscribeFills: fills.fn as never,
      subscribeOrders: orders.fn as never,
    });
    await daemon.start();
    expect(fills.cap.opts).toBeDefined();
    expect(orders.cap.opts).toBeDefined();
    daemon.stop();
    expect((placer.close as ReturnType<typeof vi.fn>).mock.calls.length).toBe(
      1,
    );
  });
});
