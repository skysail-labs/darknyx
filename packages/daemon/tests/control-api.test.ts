/**
 * Control-API tests — the local HTTP surface over a fake Daemon. Real node:http
 * server on an ephemeral port; asserts routes, auth gate, and the SSE stream.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";

import { startControlServer, type PlaceMapper } from "../src/control-api.js";
import type { Daemon, DaemonEvent } from "../src/daemon.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import { limitPolicy, OrderSide, type StoredNote } from "@nyx/sdk";

const ORDER: ManagedOrder = {
  ...newManagedOrder({
    orderId: "ab".repeat(8),
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 500n,
    anchorPoolSize: 10,
  }),
  phase: "open",
};

const NOTE: StoredNote = {
  commitment: "aa".repeat(32),
  tokenMint: new Uint8Array(32).fill(9),
  amount: 1000n,
  ownerCommitment: 1n,
  innerHash: 2n,
  leafIndex: 0n,
};

/** A structural fake Daemon exposing only what the control-API calls. */
function fakeDaemon() {
  const subs = new Set<(e: DaemonEvent) => void>();
  return {
    listOrders: vi.fn(() => [ORDER]),
    getOrder: vi.fn((id: string) => (id === ORDER.orderId ? ORDER : undefined)),
    getNote: vi.fn((c: string) => (c === NOTE.commitment ? NOTE : undefined)),
    listNotes: vi.fn(() => [NOTE]),
    balances: vi.fn(() => [
      { mint: "09".repeat(32), amount: "1000", notes: 1 },
    ]),
    getTrustStatus: vi.fn(() => ({
      tradingEnabled: true,
      pauseReason: null,
      lastFinalizedKeyRefreshMs: 123,
      onchainKeyMonitoring: true,
    })),
    placeOrder: vi.fn(async () => ({
      orderId: "cd".repeat(8),
      arrivalSlot: 9,
    })),
    cancelOrder: vi.fn(async () => {}),
    tee: {
      account: vi.fn(async () => ({ account_id: "acct" })),
      instruments: vi.fn(async () => [{ symbol: "SOL-USDC" }]),
      instrument: vi.fn(async (s: string) => ({ symbol: s })),
      settlementStatus: vi.fn(async (b: string | number) => ({ batch_id: b })),
      systemStatus: vi.fn(async () => ({ ok: true })),
      serverTime: vi.fn(async () => ({ slot: 1 })),
      transparency: vi.fn(async () => ({ leaf_count: 7 })),
    },
    subscribe: vi.fn((l: (e: DaemonEvent) => void) => {
      subs.add(l);
      return () => subs.delete(l);
    }),
    _emit: (e: DaemonEvent) => subs.forEach((l) => l(e)),
  };
}

const mapPlace: PlaceMapper = (raw) => {
  const b = raw as { note_commitment: string; price_limit: number };
  return {
    note: NOTE,
    intent: {
      symbol: "SOL-USDC",
      side: OrderSide.Bid,
      policy: limitPolicy({ priceLimit: BigInt(b.price_limit) }),
      amount: 500n,
    },
  };
};

let server: Server;
let base: string;
let daemon: ReturnType<typeof fakeDaemon>;

async function listen(controlToken?: string) {
  daemon = fakeDaemon();
  const started = await startControlServer(
    { daemon: daemon as unknown as Daemon, mapPlace, controlToken },
    0,
  );
  server = started.server;
  base = `http://127.0.0.1:${started.port}`;
}

afterEach(() => server?.close());

describe("control-api — routes", () => {
  beforeEach(() => listen());

  it("GET /health", async () => {
    const r = await fetch(`${base}/health`);
    expect(await r.json()).toEqual({
      ok: true,
      trading_enabled: true,
      trust: {
        pause_reason: null,
        last_finalized_key_refresh_ms: 123,
        onchain_key_monitoring: true,
      },
    });
  });

  it("GET /orders + /orders/:id", async () => {
    const list = (await (await fetch(`${base}/orders`)).json()) as {
      orders: unknown[];
    };
    expect(list.orders).toHaveLength(1);
    const one = (await (
      await fetch(`${base}/orders/${ORDER.orderId}`)
    ).json()) as { order_id: string; phase: string };
    expect(one.order_id).toBe(ORDER.orderId);
    expect(one.phase).toBe("open");
    expect((await fetch(`${base}/orders/deadbeef`)).status).toBe(404);
  });

  it("POST /orders maps the body and places", async () => {
    const r = await fetch(`${base}/orders`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        note_commitment: NOTE.commitment,
        price_limit: 100,
      }),
    });
    const body = (await r.json()) as { order_id: string; arrival_slot: number };
    expect(body.arrival_slot).toBe(9);
    expect(daemon.placeOrder).toHaveBeenCalledOnce();
  });

  it("DELETE /orders/:id cancels", async () => {
    const r = await fetch(`${base}/orders/${ORDER.orderId}`, {
      method: "DELETE",
    });
    expect(await r.json()).toEqual({ ok: true });
    expect(daemon.cancelOrder).toHaveBeenCalledWith(ORDER.orderId);
  });

  it("GET /balances", async () => {
    const b = (await (await fetch(`${base}/balances`)).json()) as {
      balances: unknown[];
    };
    expect(b.balances).toHaveLength(1);
  });

  it("404s an unknown route", async () => {
    expect((await fetch(`${base}/nope`)).status).toBe(404);
  });

  it("proxies the read-only TEE surface under /tee/*", async () => {
    const acct = (await (await fetch(`${base}/tee/account`)).json()) as {
      account_id: string;
    };
    expect(acct.account_id).toBe("acct");
    expect(daemon.tee.account).toHaveBeenCalledOnce();
    const inst = (await (
      await fetch(`${base}/tee/instruments/SOL-USDC`)
    ).json()) as { symbol: string };
    expect(inst.symbol).toBe("SOL-USDC");
    const sett = (await (await fetch(`${base}/tee/settlement/42`)).json()) as {
      batch_id: string;
    };
    expect(String(sett.batch_id)).toBe("42");
    const t = (await (await fetch(`${base}/tee/transparency`)).json()) as {
      leaf_count: number;
    };
    expect(t.leaf_count).toBe(7);
    expect((await fetch(`${base}/tee/bogus`)).status).toBe(404);
  });
});

describe("control-api — auth", () => {
  beforeEach(() => listen("secret"));

  it("401s without the bearer token", async () => {
    expect((await fetch(`${base}/health`)).status).toBe(401);
  });
  it("allows with the bearer token", async () => {
    const r = await fetch(`${base}/health`, {
      headers: { authorization: "Bearer secret" },
    });
    expect(r.status).toBe(200);
  });
});

describe("control-api — SSE stream", () => {
  beforeEach(() => listen());

  it("streams a daemon event", async () => {
    const res = await fetch(`${base}/stream`);
    const reader = res.body!.getReader();
    // emit after the stream is open
    daemon._emit({ type: "order", order: ORDER });
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain("connected");
    // read the event frame (may arrive in the same or next chunk)
    const more = await reader.read();
    const frame =
      text + new TextDecoder().decode(more.value ?? new Uint8Array());
    expect(frame).toContain('"type":"order"');
    await reader.cancel();
  });
});
