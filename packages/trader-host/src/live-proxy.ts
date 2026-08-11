import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import WebSocket, { WebSocketServer, type RawData } from "ws";

import { fetchBounded, gatewayBase } from "./http.js";
import { authenticatedSessionId } from "./session.js";
import type { ReleaseHostOptions } from "./types.js";

const VENUE_PREFIX = "/api/darknyx/venue";
const RPC_PATH = "/api/darknyx/rpc";
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_WS_MESSAGE_BYTES = 1024 * 1024;

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

interface RateWindow {
  window: number;
  count: number;
}

interface LiveProxy {
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

async function responseBytes(
  response: Response,
  timeoutMs: number,
): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (
    declared !== null &&
    (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)
  ) {
    throw new Error("upstream_response_too_large");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
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
      chunks.push(value);
    }
  } finally {
    if (timer) clearTimeout(timer);
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function rawBytes(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

function rpcPayload(value: unknown, methods: ReadonlySet<string>): boolean {
  const requests = Array.isArray(value) ? value : [value];
  return (
    requests.length > 0 &&
    requests.length <= 50 &&
    requests.every(
      (request) =>
        request !== null &&
        typeof request === "object" &&
        !Array.isArray(request) &&
        (request as Record<string, unknown>).jsonrpc === "2.0" &&
        typeof (request as Record<string, unknown>).method === "string" &&
        methods.has((request as Record<string, unknown>).method as string),
    )
  );
}

function parseRpc(bytes: Uint8Array, methods: ReadonlySet<string>): boolean {
  try {
    return rpcPayload(JSON.parse(new TextDecoder().decode(bytes)), methods);
  } catch {
    return false;
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
    path === "/tree/inclusion"
      ? new Set(["commitment", "tree_id"])
      : path === "/tree/leaves"
        ? new Set(["tree_id", "start", "limit"])
        : path === "/tree/root"
          ? new Set(["tree_id"])
          : null;
  if (!allowed || [...search.keys()].some((key) => !allowed.has(key))) {
    return false;
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

export function createLiveProxy(options: ReleaseHostOptions): LiveProxy | null {
  if (!options.gatewayUpstreamUrl && !options.rpcUpstreamUrl) return null;
  if (!options.gatewayUpstreamUrl || !options.rpcUpstreamUrl) {
    throw new Error("live proxy requires both gateway and RPC upstreams");
  }
  const gateway = gatewayBase(options.gatewayUpstreamUrl);
  const rpc = new URL(options.rpcUpstreamUrl);
  const localRpc = rpc.protocol === "http:" && rpc.hostname === "localhost";
  if (
    (rpc.protocol !== "https:" && !localRpc) ||
    rpc.username ||
    rpc.password ||
    rpc.hash
  ) {
    throw new Error("RPC upstream must be an HTTPS URL");
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
  const timeoutMs = options.proxyTimeoutMs ?? 20_000;
  const rateLimit = options.maxProxyRequestsPerMinute ?? 600;
  const rates = new Map<string, RateWindow>();
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
    for (const [key, value] of rates) {
      if (value.window < window) rates.delete(key);
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
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    target: URL,
    validate: (bytes: Uint8Array) => boolean,
  ) => {
    webSocketServer.handleUpgrade(request, socket, head, (downstream) => {
      const upstream = new WebSocket(websocketUrl(target), {
        headers: { origin: options.origin },
        perMessageDeflate: false,
        maxPayload: MAX_WS_MESSAGE_BYTES,
        handshakeTimeout: timeoutMs,
      });
      const pending: Array<{ data: RawData; binary: boolean }> = [];
      let pendingBytes = 0;
      const closeBoth = (code = 1011, reason = "proxy unavailable") => {
        if (downstream.readyState < WebSocket.CLOSING)
          downstream.close(code, reason);
        if (upstream.readyState < WebSocket.CLOSING)
          upstream.close(code, reason);
      };
      downstream.on("message", (data, binary) => {
        const bytes = rawBytes(data);
        if (!validate(bytes)) return closeBoth(1008, "message rejected");
        if (upstream.readyState === WebSocket.OPEN) {
          upstream.send(data, { binary });
        } else if (upstream.readyState === WebSocket.CONNECTING) {
          pendingBytes += bytes.length;
          if (pendingBytes > MAX_WS_MESSAGE_BYTES) {
            closeBoth(1009, "pending data too large");
          } else {
            pending.push({ data, binary });
          }
        }
      });
      upstream.on("open", () => {
        for (const message of pending) {
          upstream.send(message.data, { binary: message.binary });
        }
        pending.length = 0;
      });
      upstream.on("message", (data, binary) => {
        if (downstream.readyState === WebSocket.OPEN) {
          downstream.send(data, { binary });
        }
      });
      downstream.on("close", (code, reason) => {
        forwardClose(upstream, code, reason);
      });
      upstream.on("close", (code, reason) => {
        forwardClose(downstream, code, reason);
      });
      downstream.on("error", () => closeBoth());
      upstream.on("error", () => closeBoth());
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
          return json(response, 413, "request_too_large");
        }
      }
      if (isRpc && (!body || !parseRpc(body, RPC_METHODS))) {
        return json(response, 400, "rpc_method_rejected");
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
          fetch,
          target,
          {
            method,
            headers,
            redirect: "manual",
            ...(requestBody ? { body: requestBody } : {}),
          },
          timeoutMs,
        );
        const bytes = await responseBytes(upstream, timeoutMs);
        response.writeHead(upstream.status, {
          "content-type":
            upstream.headers.get("content-type") ?? "application/json",
          "content-length": String(bytes.length),
          "cache-control": "no-store",
          ...(upstream.headers.get("retry-after")
            ? { "retry-after": upstream.headers.get("retry-after")! }
            : {}),
          ...(upstream.headers.get("x-request-id")
            ? { "x-request-id": upstream.headers.get("x-request-id")! }
            : {}),
        });
        response.end(bytes);
      } catch {
        json(response, 502, "upstream_unavailable");
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
        if (
          request.headers.origin !== options.origin ||
          !admit(request) ||
          url.search
        ) {
          return rejectUpgrade(socket, 401);
        }
        if (url.pathname === `${VENUE_PREFIX}/v1/stream`) {
          return relay(
            request,
            socket,
            head,
            new URL("v1/stream", gateway),
            (bytes) => bytes.length <= MAX_WS_MESSAGE_BYTES,
          );
        }
        if (url.pathname === RPC_PATH) {
          return relay(request, socket, head, rpc, (bytes) =>
            parseRpc(bytes, RPC_WS_METHODS),
          );
        }
        rejectUpgrade(socket, 404);
      });
    },
  };
}
