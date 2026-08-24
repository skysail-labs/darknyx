/**
 * Control API — the local surface the MM strategy drives the daemon through.
 *
 * Plain `node:http` (zero deps): a small REST control plane + a Server-Sent
 * Events stream for the push side (order updates + fills). SSE rather than a WS
 * server keeps it dependency-free and is the right shape — commands are REST
 * request/response, the stream is one-way daemon → strategy.
 *
 *   GET  /health                 → { ok, trading_enabled, trust }
 *   GET  /orders                 → { orders: ManagedOrder[] }
 *   GET  /orders/:id             → ManagedOrder | 404
 *   POST /orders                 → { order_id, arrival_slot }  (body: see below)
 *   DELETE /orders/:id           → { ok }
 *   GET  /notes                  → { notes }
 *   GET  /balances               → { balances }
 *   GET  /stream                 → text/event-stream of DaemonEvent
 *
 * # SECURITY
 *
 * Binding to loopback stops other HOSTS. It does not stop the operator's own
 * BROWSER, and that is the vector this surface has to defend (SW-19).
 *
 * Any page the operator visits can `POST` to `http://127.0.0.1:<port>`. With
 * `Content-Type: text/plain` that is a CORS *simple request* — no preflight —
 * and a body that is JSON but mislabelled parses exactly like a legitimate
 * call. The attacker cannot read the response and does not need to: `POST
 * /orders` spends a real note and `POST /deposit` moves funds on-chain. The
 * stronger variant is DNS rebinding: a domain resolving to `127.0.0.1` is
 * same-origin, which makes every `GET` readable too — `/notes`, `/balances`,
 * `/orders`, and the `/tee/*` proxy the daemon services with the operator's own
 * gateway credential. For a privacy protocol, an attacker reading the
 * operator's complete note set and order flow is a first-class failure.
 *
 * The previous guidance here — "set a token whenever the host isn't
 * single-tenant" — framed the threat as other USERS on the machine, so an
 * operator on their own workstation correctly concluded they needed no token.
 * That is precisely the machine with a browser on it. The advice pointed away
 * from the risk, so the token is no longer optional:
 *
 * 1. **A bearer token is REQUIRED.** `bin/daemon.ts` generates one at boot when
 *    `DARKNYX_DAEMON_CONTROL_TOKEN` is unset, writes it `0600` beside the DB,
 *    and prints the path — the pattern Jupyter and similar local servers use.
 *    A cross-origin page cannot read that file, which is what defeats rebinding
 *    as well as CSRF.
 * 2. **Browser-originated requests are rejected** on `Origin` / `Referer` /
 *    `Sec-Fetch-Site`, and `Host` must be loopback. A browser cannot forge
 *    these; a non-browser local client never sends them.
 * 3. **Mutations require `Content-Type: application/json`**, which is not a
 *    simple content type and therefore forces a preflight.
 *
 * Each is bypassable alone and they are layered deliberately.
 *
 * The `POST /orders` body is the strategy's intent + the note to spend; mapping
 * it to the SDK `OrderIntent` (policy/side) is the caller's job via `mapPlace`,
 * so this module stays free of the SDK's order-builders.
 */

import http from "node:http";
import { timingSafeEqual } from "node:crypto";

import type { Daemon, DaemonEvent } from "./daemon.js";
import type { OrderIntent } from "./build-place-request.js";
import type { ManagedOrder } from "./types.js";
import type { StoredNote } from "@darknyx/sdk";

type SubscribeEvents = (listener: (event: DaemonEvent) => void) => () => void;

const RESYNC_REQUIRED_FRAME =
  'event: resync_required\ndata: {"reason":"client_backpressure"}\n\n';

/**
 * Attach one bounded SSE subscriber.
 *
 * `ServerResponse.write(false)` means Node has already buffered the frame up to
 * its high-water mark. At that point we unsubscribe immediately and end with a
 * single resync marker. We deliberately do not queue private event history in
 * the daemon: the client reconnects and reconciles through the normal REST /
 * chain paths, matching the TEE stream's lagged-client contract.
 */
function streamEvents(
  res: http.ServerResponse,
  subscribe: SubscribeEvents,
): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });

  let closed = false;
  let unsubscribe = (): void => {};
  const cleanup = (): void => {
    if (closed) return;
    closed = true;
    unsubscribe();
  };
  const disconnectLagged = (): void => {
    if (closed) return;
    cleanup();
    if (!res.writableEnded && !res.destroyed) {
      // One bounded terminal frame; no event queue is retained after this.
      res.end(RESYNC_REQUIRED_FRAME);
    }
  };

  res.on("close", cleanup);
  res.on("error", cleanup);
  if (!res.write(": connected\n\n")) {
    disconnectLagged();
    return;
  }

  unsubscribe = subscribe((event) => {
    if (closed) return;
    const accepted = res.write(
      `data: ${JSON.stringify(serializeEvent(event))}\n\n`,
    );
    if (!accepted) disconnectLagged();
  });
  // Defensive against a subscribe implementation that emits synchronously.
  if (closed) unsubscribe();
}

/** Translate a `POST /orders` JSON body into the SDK intent + the note to spend. */
export type PlaceMapper = (body: unknown) => {
  intent: OrderIntent;
  note: StoredNote;
};

/** Parsed `POST /deposit` request (keeps web3.js/hex parsing out of the HTTP
 *  layer — the caller supplies `mapDeposit`). */
export interface DepositRequest {
  tokenMint: Uint8Array;
  amount: bigint;
  depositorTokenAccount: import("@solana/web3.js").PublicKey;
  treeId?: number;
}
export type DepositMapper = (body: unknown) => DepositRequest;

export interface ControlApiOptions {
  daemon: Daemon;
  /** Maps the wire body → SDK intent + note (keeps SDK builders out of here). */
  mapPlace: PlaceMapper;
  /** Maps the `POST /deposit` body → DepositRequest (optional; 404 without it). */
  mapDeposit?: DepositMapper;
  /** Bearer token gating every route. **Required** — see the module header.
   *  `bin/daemon.ts` generates and persists one when the env var is unset. */
  controlToken: string;
  /** Port the server is bound to, for `Host` validation. */
  port?: number;
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": buf.length,
  });
  res.end(buf);
}

/** Largest control-plane request body. Generous for an order or deposit intent,
 *  and bounded so a local client cannot stream gigabytes into memory before any
 *  handler runs (SW-20). */
const MAX_BODY_BYTES = 256 * 1024;

class BodyTooLarge extends Error {}

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    const buf = c as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES)
      throw new BodyTooLarge("request body too large");
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

/**
 * Constant-time bearer comparison (SW-20).
 *
 * `!==` on strings short-circuits at the first differing byte. Over loopback
 * there is no network jitter to mask that, and `timingSafeEqual` costs nothing.
 * Lengths are compared first because `timingSafeEqual` throws on a mismatch —
 * that leaks only the length, which the file's `0600` mode already protects.
 */
function bearerMatches(header: string | undefined, token: string): boolean {
  if (!header) return false;
  const expected = Buffer.from(`Bearer ${token}`);
  const got = Buffer.from(header);
  if (got.length !== expected.length) return false;
  return timingSafeEqual(got, expected);
}

/**
 * Reject anything a browser originated (SW-19).
 *
 * A browser always attaches `Origin` to a cross-origin request and always sets
 * `Sec-Fetch-Site`; neither can be forged by page script. A legitimate local
 * client (curl, a strategy process) sends neither. `Host` must be loopback so a
 * rebound DNS name cannot present itself as same-origin.
 *
 * Returns a refusal reason, or `null` when the request may proceed.
 */
function browserRefusal(
  req: http.IncomingMessage,
  port: number | undefined,
): string | null {
  const h = req.headers;
  if (h.origin) return "origin_not_allowed";
  if (h.referer) return "referer_not_allowed";
  const site = h["sec-fetch-site"];
  if (typeof site === "string" && site !== "same-origin" && site !== "none") {
    return "cross_site_not_allowed";
  }
  const host = (h.host ?? "").toLowerCase();
  const hostname = host.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  const loopback =
    hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1";
  if (!loopback) return "host_not_loopback";
  if (port !== undefined && host.includes(":")) {
    const declared = Number(host.slice(host.lastIndexOf(":") + 1));
    if (Number.isFinite(declared) && declared !== port) return "host_bad_port";
  }
  return null;
}

export function createControlServer(opts: ControlApiOptions): http.Server {
  const { daemon, mapPlace, mapDeposit, controlToken } = opts;

  if (!controlToken) {
    // Not a warning. A default-insecure local server that moves value is the
    // whole of SW-19; `bin/daemon.ts` generates a token rather than omitting it.
    throw new Error(
      "controlToken is required — the control plane places orders and moves funds",
    );
  }

  return http.createServer((req, res) => {
    void handle(req, res).catch((err) => {
      if (err instanceof BodyTooLarge) {
        return send(res, 413, { error: "body_too_large" });
      }
      // Closed-set label, detail to the log (SW-20, and the same defect class
      // as SW-01 server-side). The daemon holds DARKNYX_DAEMON_RPC_URL, whose
      // Helius key rides in the query string, and a Solana transport error
      // typically embeds the request URL in its message. That must not be
      // echoed to an HTTP caller.
      console.error("[control] request failed:", err);
      send(res, 400, { error: "bad_request" });
    });
  });

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    // Ordered cheapest-first, and before auth so a browser probe cannot even
    // learn whether a token is valid.
    const refusal = browserRefusal(req, opts.port);
    if (refusal) return send(res, 403, { error: refusal });

    if (!bearerMatches(req.headers.authorization, controlToken)) {
      return send(res, 401, { error: "unauthorized" });
    }

    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    // A mutation must not be a CORS *simple request*. `application/json` is not
    // a simple content type, so requiring it forces a preflight that a
    // cross-origin page cannot satisfy (SW-19).
    if (method !== "GET" && method !== "HEAD") {
      const ct = String(req.headers["content-type"] ?? "")
        .split(";")[0]
        .trim()
        .toLowerCase();
      if (ct !== "application/json") {
        return send(res, 415, {
          error: "content_type_must_be_application_json",
        });
      }
    }

    if (method === "GET" && path === "/health") {
      const trust = daemon.getTrustStatus();
      return send(res, 200, {
        ok: true,
        trading_enabled: trust.tradingEnabled,
        trust: {
          pause_reason: trust.pauseReason,
          last_finalized_key_refresh_ms: trust.lastFinalizedKeyRefreshMs,
          onchain_key_monitoring: trust.onchainKeyMonitoring,
          transport_state: trust.transportState,
          transport_pause_reason: trust.transportPauseReason,
          transport_recovery_attempts: trust.transportRecoveryAttempts,
          transport_next_attempt_ms: trust.transportNextAttemptMs,
        },
      });
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
    if (method === "POST" && path === "/deposit") {
      if (!mapDeposit) return send(res, 404, { error: "deposit not enabled" });
      const r = mapDeposit(await readJson(req));
      const out = await daemon.deposit(r);
      return send(res, 200, {
        commitment: out.commitment,
        leaf_index: out.leafIndex.toString(),
      });
    }
    if (method === "GET" && path === "/notes") {
      return send(res, 200, { notes: daemon.listNotes().map(serializeNote) });
    }
    if (method === "GET" && path === "/balances") {
      return send(res, 200, { balances: daemon.balances() });
    }
    if (method === "GET" && path === "/attestation") {
      const a = daemon.getAttestation();
      return a
        ? send(res, 200, {
            tee_pubkey: a.teePubkey,
            compose_hash: a.composeHash,
            mrtd: a.mrtd,
          })
        : send(res, 404, { error: "not attested" });
    }
    if (method === "GET" && path === "/stream") {
      return streamEvents(res, (listener) => daemon.subscribe(listener));
    }
    // Read-only TEE surface, proxied so the strategy reads everything locally.
    if (method === "GET" && path.startsWith("/tee/")) {
      const sub = path.slice("/tee/".length);
      if (sub === "account") return send(res, 200, await daemon.tee.account());
      if (sub === "instruments")
        return send(res, 200, await daemon.tee.instruments());
      if (sub.startsWith("instruments/"))
        return send(
          res,
          200,
          await daemon.tee.instrument(sub.slice("instruments/".length)),
        );
      if (sub.startsWith("settlement/"))
        return send(
          res,
          200,
          await daemon.tee.settlementStatus(sub.slice("settlement/".length)),
        );
      if (sub === "system")
        return send(res, 200, await daemon.tee.systemStatus());
      if (sub === "time") return send(res, 200, await daemon.tee.serverTime());
      if (sub === "transparency")
        return send(res, 200, await daemon.tee.transparency());
      return send(res, 404, { error: "unknown tee endpoint" });
    }
    return send(res, 404, { error: "not found" });
  }
}

export const controlApiTesting = { streamEvents };

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
  symbol: string;
  side: string;
  phase: string;
  price: string;
  size: string;
  pending_change_notes: number;
  settlement_failure_reason?: string;
  settlement_unlock_slot?: number;
}
function serializeOrder(o: ManagedOrder): OrderJson {
  return {
    order_id: o.orderId,
    symbol: o.symbol,
    side: o.side,
    phase: o.phase,
    price: o.priceRaw.toString(),
    size: o.sizeRaw.toString(),
    pending_change_notes: o.pendingChangeNotes,
    settlement_failure_reason: o.settlementFailureReason,
    settlement_unlock_slot: o.settlementUnlockSlot,
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
    consumed_commitment: n.consumedCommitment,
  };
}
function serializeEvent(e: DaemonEvent): Record<string, unknown> {
  if (e.type === "order")
    return { type: "order", order: serializeOrder(e.order) };
  if (e.type === "fill") return { type: "fill", note: serializeNote(e.note) };
  return { type: "error", context: e.context, message: e.message };
}
