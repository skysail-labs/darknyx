/**
 * Control API — the local surface the MM strategy drives the daemon through.
 *
 * Plain `node:http` (zero deps): a small REST control plane + a Server-Sent
 * Events stream for the push side (order updates + fills). SSE rather than a WS
 * server keeps it dependency-free and is the right shape — commands are REST
 * request/response, the stream is one-way daemon → strategy.
 *
 *   GET  /health                 → { ok }
 *   GET  /orders                 → { orders: ManagedOrder[] }
 *   GET  /orders/:id             → ManagedOrder | 404
 *   POST /orders                 → { order_id, arrival_slot }  (body: see below)
 *   DELETE /orders/:id           → { ok }
 *   GET  /notes                  → { notes }
 *   GET  /balances               → { balances }
 *   GET  /stream                 → text/event-stream of DaemonEvent
 *
 * SECURITY: bind to loopback. An optional bearer token (`controlToken`) gates
 * every route — set it whenever the host isn't single-tenant.
 *
 * The `POST /orders` body is the strategy's intent + the note to spend; mapping
 * it to the SDK `OrderIntent` (policy/side) is the caller's job via `mapPlace`,
 * so this module stays free of the SDK's order-builders.
 */

import http from "node:http";

import type { Daemon, DaemonEvent } from "./daemon.js";
import type { OrderIntent } from "./build-place-request.js";
import type { ManagedOrder } from "./types.js";
import type { StoredNote } from "@nyx/sdk";

/** Translate a `POST /orders` JSON body into the SDK intent + the note to spend. */
export type PlaceMapper = (body: unknown) => {
  intent: OrderIntent;
  note: StoredNote;
};

export interface ControlApiOptions {
  daemon: Daemon;
  /** Maps the wire body → SDK intent + note (keeps SDK builders out of here). */
  mapPlace: PlaceMapper;
  /** Optional bearer token gating every route. */
  controlToken?: string;
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": buf.length,
  });
  res.end(buf);
}

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

export function createControlServer(opts: ControlApiOptions): http.Server {
  const { daemon, mapPlace, controlToken } = opts;

  return http.createServer((req, res) => {
    void handle(req, res).catch((err) => {
      send(res, 400, { error: err instanceof Error ? err.message : "error" });
    });
  });

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    if (controlToken) {
      const auth = req.headers.authorization;
      if (auth !== `Bearer ${controlToken}`) {
        return send(res, 401, { error: "unauthorized" });
      }
    }
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === "/health") {
      return send(res, 200, { ok: true });
    }
    if (method === "GET" && path === "/orders") {
      return send(res, 200, { orders: serializeOrders(daemon.listOrders()) });
    }
    if (method === "GET" && path.startsWith("/orders/")) {
      const id = path.slice("/orders/".length);
      const o = daemon.getOrder(id);
      return o
        ? send(res, 200, serializeOrder(o))
        : send(res, 404, { error: "not found" });
    }
    if (method === "POST" && path === "/orders") {
      const body = await readJson(req);
      const { intent, note } = mapPlace(body);
      const r = await daemon.placeOrder(intent, note);
      return send(res, 200, {
        order_id: r.orderId,
        arrival_slot: r.arrivalSlot,
      });
    }
    if (method === "DELETE" && path.startsWith("/orders/")) {
      const id = path.slice("/orders/".length);
      await daemon.cancelOrder(id);
      return send(res, 200, { ok: true });
    }
    if (method === "GET" && path === "/notes") {
      return send(res, 200, { notes: daemon.listNotes().map(serializeNote) });
    }
    if (method === "GET" && path === "/balances") {
      return send(res, 200, { balances: daemon.balances() });
    }
    if (method === "GET" && path === "/stream") {
      return streamEvents(res);
    }
    return send(res, 404, { error: "not found" });
  }

  function streamEvents(res: http.ServerResponse): void {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    res.write(": connected\n\n");
    const unsub = daemon.subscribe((e: DaemonEvent) => {
      res.write(`data: ${JSON.stringify(serializeEvent(e))}\n\n`);
    });
    res.on("close", unsub);
  }
}

/** Start listening; resolves with the bound port (port 0 → ephemeral, for tests). */
export function startControlServer(
  opts: ControlApiOptions,
  port: number,
  host = "127.0.0.1",
): Promise<{ server: http.Server; port: number }> {
  const server = createControlServer(opts);
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      const addr = server.address();
      const bound = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, port: bound });
    });
  });
}

// ── wire serialization (bigints → decimal strings, bytes → hex) ──

interface OrderJson {
  order_id: string;
  side: string;
  phase: string;
  price: string;
  size: string;
  anchor_pool_size: number;
  anchors_consumed: number;
  pending_change_notes: number;
}
function serializeOrder(o: ManagedOrder): OrderJson {
  return {
    order_id: o.orderId,
    side: o.side,
    phase: o.phase,
    price: o.priceRaw.toString(),
    size: o.sizeRaw.toString(),
    anchor_pool_size: o.anchorPoolSize,
    anchors_consumed: o.anchorsConsumed,
    pending_change_notes: o.pendingChangeNotes,
  };
}
function serializeOrders(os: ManagedOrder[]): OrderJson[] {
  return os.map(serializeOrder);
}
function serializeNote(n: StoredNote): Record<string, unknown> {
  return {
    commitment: n.commitment,
    mint: Buffer.from(n.tokenMint).toString("hex"),
    amount: n.amount.toString(),
    order_id: n.orderId,
    anchor_index: n.anchorIndex,
  };
}
function serializeEvent(e: DaemonEvent): Record<string, unknown> {
  if (e.type === "order")
    return { type: "order", order: serializeOrder(e.order) };
  if (e.type === "fill") return { type: "fill", note: serializeNote(e.note) };
  return { type: "error", context: e.context, message: e.message };
}
