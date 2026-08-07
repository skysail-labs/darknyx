/**
 * Control-API tests — the local HTTP surface over a fake Daemon. Real node:http
 * server on an ephemeral port; asserts routes, auth gate, and the SSE stream.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import nodeHttp, { type Server } from "node:http";

import {
  controlApiTesting,
  createControlServer,
  startControlServer,
  type PlaceMapper,
} from "../src/control-api.js";
import type { Daemon, DaemonEvent } from "../src/daemon.js";
import { newManagedOrder, type ManagedOrder } from "../src/types.js";
import { limitPolicy, OrderSide, type StoredNote } from "@darknyx/sdk";

const ORDER: ManagedOrder = {
  ...newManagedOrder({
    orderId: "ab".repeat(8),
    seedIndex: 0,
    side: "bid",
    priceRaw: 100n,
    sizeRaw: 500n,
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

/**
 * The control plane is authenticated by default (SW-19) — it places orders and
 * moves funds, and a token-less local server is reachable from any page the
 * operator's browser visits. The suite therefore runs the SECURE configuration
 * and authenticates, rather than encoding the old default.
 */
const TEST_TOKEN = "test-control-token";

async function listen(controlToken: string = TEST_TOKEN) {
  daemon = fakeDaemon();
  const started = await startControlServer(
    { daemon: daemon as unknown as Daemon, mapPlace, controlToken },
    0,
  );
  server = started.server;
  base = `http://127.0.0.1:${started.port}`;
}

/** Raw `node:http` GET — needed for headers `fetch` refuses to send (`Host`). */
function rawGet(
  path: string,
  headers: Record<string, string>,
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const url = new URL(base);
    const req = nodeHttp.request(
      {
        host: url.hostname,
        port: Number(url.port),
        path,
        method: "GET",
        headers,
        // `headers.host` must win over the socket's computed value.
        setHost: false,
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () =>
          resolvePromise({ statusCode: res.statusCode ?? 0, body }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/** Authenticated request; mutations also carry the non-simple content type. */
function authed(init: RequestInit = {}): RequestInit {
  const headers: Record<string, string> = {
    authorization: `Bearer ${TEST_TOKEN}`,
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (init.method && init.method !== "GET" && !headers["content-type"]) {
    headers["content-type"] = "application/json";
  }
  return { ...init, headers };
}

afterEach(() => server?.close());

describe("control-api — routes", () => {
  beforeEach(() => listen());

  it("GET /health", async () => {
    const r = await fetch(`${base}/health`, authed());
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
    const list = (await (await fetch(`${base}/orders`, authed())).json()) as {
      orders: unknown[];
    };
    expect(list.orders).toHaveLength(1);
    const one = (await (
      await fetch(`${base}/orders/${ORDER.orderId}`, authed())
    ).json()) as { order_id: string; phase: string };
    expect(one.order_id).toBe(ORDER.orderId);
    expect(one.phase).toBe("open");
    expect((await fetch(`${base}/orders/deadbeef`, authed())).status).toBe(404);
  });

  it("POST /orders maps the body and places", async () => {
    const r = await fetch(`${base}/orders`, authed({
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        note_commitment: NOTE.commitment,
        price_limit: 100,
      }),
    }));
    const body = (await r.json()) as { order_id: string; arrival_slot: number };
    expect(body.arrival_slot).toBe(9);
    expect(daemon.placeOrder).toHaveBeenCalledOnce();
  });

  it("DELETE /orders/:id cancels", async () => {
    const r = await fetch(`${base}/orders/${ORDER.orderId}`, authed({
      method: "DELETE",
    }));
    expect(await r.json()).toEqual({ ok: true });
    expect(daemon.cancelOrder).toHaveBeenCalledWith(ORDER.orderId);
  });

  it("GET /balances", async () => {
    const b = (await (await fetch(`${base}/balances`, authed())).json()) as {
      balances: unknown[];
    };
    expect(b.balances).toHaveLength(1);
  });

  it("404s an unknown route", async () => {
    expect((await fetch(`${base}/nope`, authed())).status).toBe(404);
  });

  it("proxies the read-only TEE surface under /tee/*", async () => {
    const acct = (await (await fetch(`${base}/tee/account`, authed())).json()) as {
      account_id: string;
    };
    expect(acct.account_id).toBe("acct");
    expect(daemon.tee.account).toHaveBeenCalledOnce();
    const inst = (await (
      await fetch(`${base}/tee/instruments/SOL-USDC`, authed())
    ).json()) as { symbol: string };
    expect(inst.symbol).toBe("SOL-USDC");
    const sett = (await (await fetch(`${base}/tee/settlement/42`, authed())).json()) as {
      batch_id: string;
    };
    expect(String(sett.batch_id)).toBe("42");
    const t = (await (await fetch(`${base}/tee/transparency`, authed())).json()) as {
      leaf_count: number;
    };
    expect(t.leaf_count).toBe(7);
    expect((await fetch(`${base}/tee/bogus`, authed())).status).toBe(404);
  });
});

describe("control-api — auth", () => {
  beforeEach(() => listen("secret"));

  it("401s without the bearer token", async () => {
    expect((await fetch(`${base}/health`, authed())).status).toBe(401);
  });
  it("allows with the bearer token", async () => {
    const r = await fetch(`${base}/health`, authed({
      headers: { authorization: "Bearer secret" },
    }));
    expect(r.status).toBe(200);
  });
});

describe("control-api — SSE stream", () => {
  beforeEach(() => listen());

  it("streams a daemon event", async () => {
    const res = await fetch(`${base}/stream`, authed());
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

  it("disconnects a lagged consumer with one bounded resync marker", () => {
    let listener: ((event: DaemonEvent) => void) | undefined;
    const unsubscribe = vi.fn();
    const handlers = new Map<string, () => void>();
    const response = {
      writableEnded: false,
      destroyed: false,
      writeHead: vi.fn(),
      write: vi.fn().mockReturnValueOnce(true).mockReturnValueOnce(false),
      end: vi.fn(),
      on: vi.fn((name: string, handler: () => void) => {
        handlers.set(name, handler);
        return response;
      }),
    };

    controlApiTesting.streamEvents(response as never, (next) => {
      listener = next;
      return unsubscribe;
    });
    listener!({ type: "order", order: ORDER });
    listener!({ type: "order", order: ORDER });

    expect(response.write).toHaveBeenCalledTimes(2); // hello + first event
    expect(unsubscribe).toHaveBeenCalledOnce();
    expect(response.end).toHaveBeenCalledOnce();
    expect(response.end.mock.calls[0][0]).toContain("resync_required");
    handlers.get("close")?.();
    expect(unsubscribe).toHaveBeenCalledOnce(); // idempotent cleanup
  });
});

// ── SW-19 / SW-20: the control plane is secure by default ──────────────
//
// Binding to loopback stops other HOSTS, not the operator's own BROWSER. Any
// page they visit can POST to 127.0.0.1; `POST /orders` spends a real note and
// `POST /deposit` moves funds. DNS rebinding makes every GET readable too —
// including `/notes` and the `/tee/*` proxy the daemon services with the
// operator's gateway credential.

describe("control-api — browser defences (SW-19)", () => {
  beforeEach(() => listen());

  it("refuses a request carrying Origin, before it can learn anything", async () => {
    // A browser always attaches Origin cross-origin and page script cannot
    // forge it. Checked BEFORE auth so a probe cannot even distinguish a valid
    // token from an invalid one.
    const r = await fetch(`${base}/health`, {
      headers: { origin: "https://evil.example" },
    });
    expect(r.status).toBe(403);
    expect((await r.json()) as unknown).toEqual({ error: "origin_not_allowed" });
  });

  it("refuses a cross-site Sec-Fetch-Site", async () => {
    const r = await fetch(
      `${base}/health`,
      authed({ headers: { "sec-fetch-site": "cross-site" } }),
    );
    expect(r.status).toBe(403);
  });

  it("refuses a rebound Host", async () => {
    // The DNS-rebinding shape: a domain resolving to 127.0.0.1 is same-origin
    // to the browser, so every GET becomes readable unless Host is checked.
    //
    // Raw node:http, because `Host` is a forbidden header for fetch/undici and
    // is silently ignored there — a fetch-based version of this test would pass
    // against unfixed code.
    const { statusCode, body } = await rawGet("/notes", {
      host: "evil.example",
      authorization: `Bearer ${TEST_TOKEN}`,
    });
    expect(statusCode).toBe(403);
    expect(JSON.parse(body)).toEqual({ error: "host_not_loopback" });
  });

  it("refuses a CORS simple request that mislabels JSON as text/plain", async () => {
    // The exact CSRF path: text/plain is a simple content type, so the browser
    // sends it with no preflight, and a JSON body parses regardless.
    const r = await fetch(`${base}/orders`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TEST_TOKEN}`,
        "content-type": "text/plain",
      },
      body: JSON.stringify({ note_commitment: NOTE.commitment, price_limit: 100 }),
    });
    expect(r.status).toBe(415);
    expect(daemon.placeOrder).not.toHaveBeenCalled();
  });

  it("refuses to start without a control token at all", async () => {
    // Not a warning: a default-insecure local server that moves value IS the
    // finding. `bin/daemon.ts` generates one rather than omitting it.
    expect(() =>
      createControlServer({
        daemon: fakeDaemon() as unknown as Daemon,
        mapPlace,
        controlToken: "",
      }),
    ).toThrow(/controlToken is required/);
  });
});

describe("control-api — input and error hygiene (SW-20)", () => {
  beforeEach(() => listen());

  it("bounds the request body", async () => {
    const r = await fetch(
      `${base}/orders`,
      authed({ method: "POST", body: "x".repeat(300 * 1024) }),
    );
    expect(r.status).toBe(413);
    expect((await r.json()) as unknown).toEqual({ error: "body_too_large" });
  });

  it("returns a closed-set label, never the internal message", async () => {
    // SW-01's twin on the client side. The daemon holds
    // DARKNYX_DAEMON_RPC_URL, whose Helius key rides in the query string, and a
    // Solana transport error typically embeds the request URL in its message.
    daemon.placeOrder.mockRejectedValueOnce(
      new Error("connect ECONNREFUSED https://rpc.example/?api-key=SUPERSECRET"),
    );
    const r = await fetch(
      `${base}/orders`,
      authed({
        method: "POST",
        body: JSON.stringify({
          note_commitment: NOTE.commitment,
          price_limit: 100,
        }),
      }),
    );
    const body = JSON.stringify(await r.json());
    expect(body).not.toContain("SUPERSECRET");
    expect(body).not.toContain("rpc.example");
    expect(body).toContain("bad_request");
  });

  it("rejects a token of the wrong length without comparing content", async () => {
    const r = await fetch(`${base}/health`, {
      headers: { authorization: "Bearer short" },
    });
    expect(r.status).toBe(401);
  });
});
