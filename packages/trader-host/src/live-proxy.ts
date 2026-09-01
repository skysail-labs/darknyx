import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { once } from "node:events";
import type { Duplex } from "node:stream";
import WebSocket, { WebSocketServer, type RawData } from "ws";

import { fetchBounded, gatewayBase, isLoopbackHttp } from "./http.js";
import { authenticatedSessionId } from "./session.js";
import type { ReleaseHostOptions } from "./types.js";

const VENUE_PREFIX = "/api/darknyx/venue";
const RPC_PATH = "/api/darknyx/rpc";
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_WS_MESSAGE_BYTES = 1024 * 1024;
const MAX_WS_BUFFERED_BYTES = 2 * MAX_WS_MESSAGE_BYTES;
const MAX_WS_CONNECTIONS_PER_SESSION = 4;
const WS_KEEPALIVE_MS = 30_000;

const RPC_METHODS = new Set([
  "getAccountInfo",
  "getMultipleAccounts",
  "getSignaturesForAddress",
  "getTransaction",
  "getSlot",
  "getLatestBlockhash",
  "getSignatureStatuses",
  "getBlockHeight",
  "getBalance",
  "getTokenAccountBalance",
  "getMinimumBalanceForRentExemption",
  "isBlockhashValid",
]);
const RPC_WS_METHODS = new Set(["signatureSubscribe", "signatureUnsubscribe"]);
const RPC_CONFIG_INDEX = new Map<string, number>([
  ["getAccountInfo", 1],
  ["getMultipleAccounts", 1],
  ["getSignaturesForAddress", 1],
  ["getTransaction", 1],
  ["getSlot", 0],
  ["getLatestBlockhash", 0],
  ["getBlockHeight", 0],
  ["getBalance", 1],
  ["getTokenAccountBalance", 1],
  ["getMinimumBalanceForRentExemption", 1],
  ["isBlockhashValid", 1],
  ["signatureSubscribe", 1],
]);

interface RateWindow {
  window: number;
  count: number;
}

export interface LiveProxy {
  handles(pathname: string): boolean;
  handleHttp(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
  ): Promise<void>;
  install(server: Server): void;
}

function json(response: ServerResponse, status: number, error: string): void {
  const bytes = Buffer.from(JSON.stringify({ error }));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(bytes.length),
    "cache-control": "no-store",
  });
  response.end(bytes);
}

async function requestBytes(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BYTES) throw new Error("request_too_large");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

async function streamResponse(
  upstream: Response,
  downstream: ServerResponse,
  timeoutMs: number,
): Promise<void> {
  const declared = upstream.headers.get("content-length");
  if (
    declared !== null &&
    (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)
  ) {
    throw new Error("upstream_response_too_large");
  }
  downstream.writeHead(upstream.status, {
    "content-type": "application/json; charset=utf-8",
    ...(declared !== null ? { "content-length": declared } : {}),
    "cache-control": "no-store",
    ...(upstream.headers.get("retry-after")
      ? { "retry-after": upstream.headers.get("retry-after")! }
      : {}),
    ...(upstream.headers.get("x-request-id")
      ? { "x-request-id": upstream.headers.get("x-request-id")! }
      : {}),
  });
  if (!upstream.body) {
    downstream.end();
    return;
  }
  const reader = upstream.body.getReader();
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      void reader.cancel().catch(() => undefined);
      reject(new Error("upstream_response_timed_out"));
    }, timeoutMs);
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      total += value.length;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("upstream_response_too_large");
      }
      if (!downstream.write(value)) {
        await Promise.race([once(downstream, "drain"), timeout]);
      }
    }
  } finally {
    if (timer) clearTimeout(timer);
    reader.releaseLock();
  }
  downstream.end();
}

function rawBytes(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

function normalizeCommitments(value: unknown, allowConfirmed: boolean): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) normalizeCommitments(item, allowConfirmed);
    return;
  }
  const object = value as Record<string, unknown>;
  for (const [key, nested] of Object.entries(object)) {
    if (key === "commitment") {
      object[key] =
        allowConfirmed && nested === "confirmed" ? "confirmed" : "finalized";
    } else normalizeCommitments(nested, allowConfirmed);
  }
}

function normalizeRpcPayload(
  value: unknown,
  methods: ReadonlySet<string>,
): unknown | null {
  const requests = Array.isArray(value) ? value : [value];
  if (requests.length === 0 || requests.length > 50) return null;
  for (const request of requests) {
    if (
      request === null ||
      typeof request !== "object" ||
      Array.isArray(request)
    ) {
      return null;
    }
    const object = request as Record<string, unknown>;
    if (
      object.jsonrpc !== "2.0" ||
      typeof object.method !== "string" ||
      !methods.has(object.method)
    ) {
      return null;
    }
    if (object.params !== undefined && !Array.isArray(object.params)) {
      return null;
    }
    const params = (object.params ?? []) as unknown[];
    // A browser must read the NoteCreated / NoteMerged event from its own
    // just-confirmed transaction to update local inventory without a reload.
    // This exception is deliberately method-local: account/governance/root
    // reads continue to be upgraded to finalized below.
    const allowConfirmed = object.method === "getTransaction";
    normalizeCommitments(params, allowConfirmed);
    const configIndex = RPC_CONFIG_INDEX.get(object.method);
    if (configIndex !== undefined) {
      while (params.length <= configIndex) params.push(undefined);
      const existing = params[configIndex];
      if (
        existing !== undefined &&
        (existing === null ||
          typeof existing !== "object" ||
          Array.isArray(existing))
      ) {
        return null;
      }
      params[configIndex] = {
        ...((existing as Record<string, unknown> | undefined) ?? {}),
        commitment:
          allowConfirmed &&
          (existing as Record<string, unknown> | undefined)?.commitment ===
            "confirmed"
            ? "confirmed"
            : "finalized",
      };
      object.params = params;
    }
  }
  return Array.isArray(value) ? requests : requests[0];
}

function normalizeRpc(
  bytes: Uint8Array,
  methods: ReadonlySet<string>,
): Uint8Array | null {
  try {
    const normalized = normalizeRpcPayload(
      JSON.parse(new TextDecoder().decode(bytes)),
      methods,
    );
    return normalized === null
      ? null
      : new TextEncoder().encode(JSON.stringify(normalized));
  } catch {
    return null;
  }
}

function venueRoute(pathname: string, method: string): boolean {
  const path = pathname.slice(VENUE_PREFIX.length) || "/";
  if (
    method === "GET" &&
    [
      "/health",
      "/info",
      "/attestation",
      "/tree/root",
      "/instruments",
      "/transparency",
      "/system/status",
      "/time",
      "/tree/inclusion",
      "/tree/leaves",
      "/account",
      "/account/settings",
    ].includes(path)
  ) {
    return true;
  }
  if (method === "GET" && /^\/instruments\/[A-Z0-9-]{5,33}$/.test(path)) {
    return true;
  }
  if (
    ["GET", "DELETE", "PUT"].includes(method) &&
    /^\/orders\/[0-9a-f]{32}$/.test(path)
  ) {
    return true;
  }
  if (method === "POST" && path === "/orders") return true;
  if (method === "PUT" && path === "/account/settings") return true;
  return (
    method === "GET" && /^\/settlement\/status\/[0-9a-f-]{16,64}$/.test(path)
  );
}

function queryAllowed(pathname: string, search: URLSearchParams): boolean {
  const path = pathname.slice(VENUE_PREFIX.length);
  if (search.size === 0) return true;
  const allowed =
    path === "/attestation"
      ? new Set(["reportData"])
      : path === "/tree/inclusion"
        ? new Set(["commitment", "tree_id"])
        : path === "/tree/leaves"
          ? new Set(["tree_id", "start", "limit"])
          : path === "/tree/root"
            ? new Set(["tree_id"])
            : null;
  if (!allowed || [...search.keys()].some((key) => !allowed.has(key))) {
    return false;
  }
  if (path === "/attestation") {
    return (
      search.size === 1 && /^[0-9a-f]{64}$/.test(search.get("reportData") ?? "")
    );
  }
  return [...search.values()].every((value) => /^[0-9a-f]{1,128}$/.test(value));
}

function websocketUrl(value: URL): string {
  const target = new URL(value);
  target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
  return target.toString();
}

function rejectUpgrade(socket: Duplex, status: number): void {
  socket.end(
    `HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`,
  );
}

function forwardClose(peer: WebSocket, code: number, reason: Buffer): void {
  if (peer.readyState >= WebSocket.CLOSING) return;
  // 1005/1006 are local sentinels and are forbidden on the wire.
  if (code === 1005 || code === 1006) peer.close();
  else peer.close(code, reason);
}

function debugStreamFrame(
  direction: "client" | "cvm",
  bytes: Uint8Array,
): void {
  if (process.env.DARKNYX_DEBUG_WS !== "1") return;
  try {
    const frame = JSON.parse(new TextDecoder().decode(bytes)) as Record<
      string,
      unknown
    >;
    const result =
      frame.result && typeof frame.result === "object"
        ? (frame.result as Record<string, unknown>)
        : undefined;
    process.stderr.write(
      `[trader-host ws] ${JSON.stringify({
        direction,
        op: frame.op,
        requestId: frame.request_id,
        channel: frame.channel,
        orderId: frame.order_id ?? result?.order_id,
        status: frame.kind ?? result?.status,
        accountId: frame.account_id,
        code: frame.code,
        message: frame.message,
      })}\n`,
    );
  } catch {
    process.stderr.write(`[trader-host ws] ${direction} non-JSON frame\n`);
  }
}

export function createLiveProxy(options: ReleaseHostOptions): LiveProxy | null {
  if (!options.gatewayUpstreamUrl && !options.rpcUpstreamUrl) return null;
  if (!options.gatewayUpstreamUrl || !options.rpcUpstreamUrl) {
    throw new Error("live proxy requires both gateway and RPC upstreams");
  }
  if (Boolean(options.cvmFetch) !== Boolean(options.cvmWebSocketFactory)) {
    throw new Error(
      "verified CVM HTTP and WebSocket transports must be supplied together",
    );
  }
  const gateway = gatewayBase(options.gatewayUpstreamUrl, {
    allowLoopbackHttp: true,
  });
  const rpc = new URL(options.rpcUpstreamUrl);
  const localRpc = isLoopbackHttp(rpc);
  if (
    (rpc.protocol !== "https:" && !localRpc) ||
    rpc.username ||
    rpc.password ||
    rpc.hash
  ) {
    throw new Error("RPC upstream must be HTTPS or http://localhost");
  }
  const expectedGateway = new URL(
    `${VENUE_PREFIX}/`,
    options.origin,
  ).toString();
  const expectedRpc = new URL(RPC_PATH, options.origin).toString();
  if (
    options.release.gateway_url !== expectedGateway ||
    options.release.rpc_url !== expectedRpc
  ) {
    throw new Error("public release endpoints do not match the live proxy");
  }
  // T-03P: CVM-bound requests may use a verified transport; the RPC upstream
  // must not (it is the chain RPC, not the enclave — see `cvmFetch` in types.ts).
  const cvmFetch = options.cvmFetch ?? fetch;
  const timeoutMs = options.proxyTimeoutMs ?? 20_000;
  const rateLimit = options.maxProxyRequestsPerMinute ?? 600;
  const rates = new Map<string, RateWindow>();
  const activeRelays = new Map<string, number>();
  let lastSweptWindow = -1;
  const webSocketServer = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_WS_MESSAGE_BYTES,
    perMessageDeflate: false,
  });

  const admit = (request: IncomingMessage): string | null => {
    const session = authenticatedSessionId(request, options);
    if (!session) return null;
    const now = options.now?.() ?? Date.now();
    const window = Math.floor(now / 60_000);
    if (window !== lastSweptWindow) {
      for (const [key, value] of rates) {
        if (value.window < window) rates.delete(key);
      }
      lastSweptWindow = window;
    }
    const current = rates.get(session);
    if (current?.window === window && current.count >= rateLimit) return null;
    if (!current && rates.size >= (options.maxTrackedSessions ?? 10_000)) {
      return null;
    }
    rates.set(session, {
      window,
      count: current?.window === window ? current.count + 1 : 1,
    });
    return session;
  };

  const relay = (
    session: string,
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    target: URL,
    transform: (bytes: Uint8Array) => Uint8Array | null,
    useVerifiedCvmStream: boolean,
  ) => {
    webSocketServer.handleUpgrade(request, socket, head, (downstream) => {
      if (useVerifiedCvmStream && options.cvmWebSocketFactory) {
        const upstream = options.cvmWebSocketFactory(websocketUrl(target));
        let upstreamOpened = false;
        let pendingBytes = 0;
        let downstreamAlive = true;
        let released = false;
        const release = () => {
          if (released) return;
          released = true;
          const current = activeRelays.get(session) ?? 0;
          if (current <= 1) activeRelays.delete(session);
          else activeRelays.set(session, current - 1);
        };
        const closeBoth = (code = 1011, reason = "proxy unavailable") => {
          if (downstream.readyState < WebSocket.CLOSING) {
            downstream.close(code, reason);
          }
          upstream.close();
        };

        downstream.on("message", (data, binary) => {
          if (binary) return closeBoth(1003, "binary frames are not supported");
          const normalized = transform(rawBytes(data));
          if (!normalized) return closeBoth(1008, "message rejected");
          debugStreamFrame("client", normalized);
          if (!upstreamOpened) {
            pendingBytes += normalized.length;
            if (pendingBytes > MAX_WS_MESSAGE_BYTES) {
              return closeBoth(1009, "pending data too large");
            }
          }
          if (
            upstream.bufferedAmount + normalized.length >
            MAX_WS_BUFFERED_BYTES
          ) {
            return closeBoth(1009, "relay buffer exceeded");
          }
          // `/v1/stream` is a JSON text protocol. The verified SDK gate queues
          // this frame until the upgrade socket's SPKI matches the attested
          // boot, so a login token never crosses an unverified connection.
          upstream.send(new TextDecoder().decode(normalized));
        });
        upstream.addEventListener("open", () => {
          upstreamOpened = true;
          pendingBytes = 0;
        });
        upstream.addEventListener("message", (event) => {
          let bytes: Buffer;
          try {
            if (typeof event.data === "string") bytes = Buffer.from(event.data);
            else if (event.data instanceof ArrayBuffer) {
              bytes = Buffer.from(event.data);
            } else if (ArrayBuffer.isView(event.data)) {
              bytes = Buffer.from(
                event.data.buffer,
                event.data.byteOffset,
                event.data.byteLength,
              );
            } else {
              return closeBoth(1003, "upstream frame is not text");
            }
          } catch {
            return closeBoth(1003, "upstream frame is malformed");
          }
          if (bytes.length > MAX_WS_MESSAGE_BYTES) {
            return closeBoth(1009, "upstream message too large");
          }
          debugStreamFrame("cvm", bytes);
          if (downstream.readyState === WebSocket.OPEN) {
            if (
              downstream.bufferedAmount + bytes.length >
              MAX_WS_BUFFERED_BYTES
            ) {
              return closeBoth(1009, "relay buffer exceeded");
            }
            downstream.send(bytes.toString("utf8"));
          }
        });
        downstream.on("close", () => {
          clearInterval(keepalive);
          release();
          upstream.close();
        });
        upstream.addEventListener("close", (event) => {
          clearInterval(keepalive);
          release();
          if (downstream.readyState < WebSocket.CLOSING) {
            const code =
              event.code === 1005 || event.code === 1006 ? 1011 : event.code;
            downstream.close(code || 1011, event.reason ?? "upstream closed");
          }
        });
        downstream.on("pong", () => (downstreamAlive = true));
        downstream.on("error", () => closeBoth());
        upstream.addEventListener("error", () => closeBoth());
        // The CVM stream has its own application heartbeat. This transport
        // keepalive covers the browser-facing socket without reaching through
        // the SDK gate to the raw, deliberately encapsulated TLS socket.
        const keepalive = setInterval(() => {
          if (!downstreamAlive) {
            downstream.terminate();
            upstream.close();
            release();
            clearInterval(keepalive);
            return;
          }
          downstreamAlive = false;
          if (downstream.readyState === WebSocket.OPEN) downstream.ping();
        }, WS_KEEPALIVE_MS);
        keepalive.unref();
        return;
      }

      const upstream = new WebSocket(websocketUrl(target), {
        headers: { origin: options.origin },
        perMessageDeflate: false,
        maxPayload: MAX_WS_MESSAGE_BYTES,
        handshakeTimeout: timeoutMs,
      });
      const pending: Array<{ data: RawData; binary: boolean }> = [];
      let pendingBytes = 0;
      let downstreamAlive = true;
      let upstreamAlive = true;
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        const current = activeRelays.get(session) ?? 0;
        if (current <= 1) activeRelays.delete(session);
        else activeRelays.set(session, current - 1);
      };
      const closeBoth = (code = 1011, reason = "proxy unavailable") => {
        if (downstream.readyState < WebSocket.CLOSING)
          downstream.close(code, reason);
        if (upstream.readyState < WebSocket.CLOSING)
          upstream.close(code, reason);
      };
      downstream.on("message", (data, binary) => {
        const bytes = rawBytes(data);
        const normalized = transform(bytes);
        if (!normalized) return closeBoth(1008, "message rejected");
        debugStreamFrame("client", normalized);
        if (upstream.readyState === WebSocket.OPEN) {
          if (
            upstream.bufferedAmount + normalized.length >
            MAX_WS_BUFFERED_BYTES
          ) {
            return closeBoth(1009, "relay buffer exceeded");
          }
          upstream.send(normalized, { binary });
        } else if (upstream.readyState === WebSocket.CONNECTING) {
          pendingBytes += normalized.length;
          if (pendingBytes > MAX_WS_MESSAGE_BYTES) {
            closeBoth(1009, "pending data too large");
          } else {
            pending.push({ data: Buffer.from(normalized), binary });
          }
        }
      });
      upstream.on("open", () => {
        for (const message of pending) {
          const length = rawBytes(message.data).length;
          if (upstream.bufferedAmount + length > MAX_WS_BUFFERED_BYTES) {
            closeBoth(1009, "relay buffer exceeded");
            break;
          }
          upstream.send(message.data, { binary: message.binary });
        }
        pending.length = 0;
        pendingBytes = 0;
      });
      upstream.on("message", (data, binary) => {
        debugStreamFrame("cvm", rawBytes(data));
        if (downstream.readyState === WebSocket.OPEN) {
          if (
            downstream.bufferedAmount + rawBytes(data).length >
            MAX_WS_BUFFERED_BYTES
          ) {
            return closeBoth(1009, "relay buffer exceeded");
          }
          downstream.send(data, { binary });
        }
      });
      downstream.on("close", (code, reason) => {
        if (process.env.DARKNYX_DEBUG_WS === "1") {
          process.stderr.write(
            `[trader-host ws] downstream close ${code} ${reason.toString()}\n`,
          );
        }
        clearInterval(keepalive);
        release();
        forwardClose(upstream, code, reason);
      });
      upstream.on("close", (code, reason) => {
        if (process.env.DARKNYX_DEBUG_WS === "1") {
          process.stderr.write(
            `[trader-host ws] upstream close ${code} ${reason.toString()}\n`,
          );
        }
        clearInterval(keepalive);
        forwardClose(downstream, code, reason);
      });
      downstream.on("pong", () => (downstreamAlive = true));
      upstream.on("pong", () => (upstreamAlive = true));
      downstream.on("error", () => closeBoth());
      upstream.on("error", () => closeBoth());
      const keepalive = setInterval(() => {
        if (!downstreamAlive || !upstreamAlive) {
          downstream.terminate();
          upstream.terminate();
          release();
          clearInterval(keepalive);
          return;
        }
        downstreamAlive = false;
        upstreamAlive = false;
        if (downstream.readyState === WebSocket.OPEN) downstream.ping();
        if (upstream.readyState === WebSocket.OPEN) upstream.ping();
      }, WS_KEEPALIVE_MS);
      keepalive.unref();
    });
  };

  return {
    handles: (pathname) =>
      pathname === RPC_PATH || pathname.startsWith(`${VENUE_PREFIX}/`),
    async handleHttp(request, response, url) {
      if (!admit(request)) return json(response, 401, "proxy_access_denied");
      const method = request.method ?? "GET";
      const isRpc = url.pathname === RPC_PATH;
      if (isRpc && method !== "POST") {
        return json(response, 405, "method_not_allowed");
      }
      if (!isRpc && !venueRoute(url.pathname, method)) {
        return json(response, 404, "route_not_available");
      }
      if (!isRpc && !queryAllowed(url.pathname, url.searchParams)) {
        return json(response, 400, "query_rejected");
      }
      let body: Uint8Array | undefined;
      if (!["GET", "HEAD"].includes(method)) {
        try {
          body = await requestBytes(request);
        } catch {
          response.setHeader("connection", "close");
          return json(response, 413, "request_too_large");
        }
      }
      if (isRpc) {
        const normalized = body ? normalizeRpc(body, RPC_METHODS) : null;
        if (!normalized) return json(response, 400, "rpc_method_rejected");
        body = normalized;
      }
      const target = isRpc
        ? rpc
        : new URL(
            `${url.pathname.slice(VENUE_PREFIX.length + 1)}${url.search}`,
            gateway,
          );
      const headers: Record<string, string> = {
        accept: "application/json",
        "user-agent": "darknyx-trader-host/1",
      };
      const authorization = request.headers.authorization;
      if (authorization) headers.authorization = authorization;
      const contentType = request.headers["content-type"];
      if (contentType) headers["content-type"] = contentType;
      const requestBody = body ? Uint8Array.from(body).buffer : undefined;
      try {
        const upstream = await fetchBounded(
          isRpc ? fetch : cvmFetch,
          target,
          {
            method,
            headers,
            redirect: "manual",
            ...(requestBody ? { body: requestBody } : {}),
          },
          timeoutMs,
        );
        await streamResponse(upstream, response, timeoutMs);
      } catch {
        if (response.headersSent) response.destroy();
        else json(response, 502, "upstream_unavailable");
      }
    },
    install(server) {
      server.on("upgrade", (request, socket, head) => {
        let url: URL;
        try {
          url = new URL(request.url ?? "/", options.origin);
        } catch {
          return rejectUpgrade(socket, 400);
        }
        if (request.headers.origin !== options.origin || url.search) {
          return rejectUpgrade(socket, 401);
        }
        const session = admit(request);
        if (!session) return rejectUpgrade(socket, 401);
        if (
          (activeRelays.get(session) ?? 0) >= MAX_WS_CONNECTIONS_PER_SESSION
        ) {
          return rejectUpgrade(socket, 429);
        }
        activeRelays.set(session, (activeRelays.get(session) ?? 0) + 1);
        const releaseAdmission = () => {
          const current = activeRelays.get(session) ?? 1;
          if (current <= 1) activeRelays.delete(session);
          else activeRelays.set(session, current - 1);
        };
        const beginRelay = (
          target: URL,
          transform: (bytes: Uint8Array) => Uint8Array | null,
          useVerifiedCvmStream = false,
        ) => {
          try {
            relay(
              session,
              request,
              socket,
              head,
              target,
              transform,
              useVerifiedCvmStream,
            );
          } catch {
            releaseAdmission();
            socket.destroy();
          }
        };
        if (url.pathname === `${VENUE_PREFIX}/v1/stream`) {
          return beginRelay(
            new URL("v1/stream", gateway),
            (bytes) => (bytes.length <= MAX_WS_MESSAGE_BYTES ? bytes : null),
            true,
          );
        }
        if (url.pathname === RPC_PATH) {
          return beginRelay(rpc, (bytes) =>
            normalizeRpc(bytes, RPC_WS_METHODS),
          );
        }
        releaseAdmission();
        rejectUpgrade(socket, 404);
      });
    },
  };
}
