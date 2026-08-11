import { createReadStream, realpathSync, statSync } from "node:fs";
import { createServer, type Server, type ServerResponse } from "node:http";
import { realpath, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { pipeline } from "node:stream/promises";

import { publicReleaseJson } from "./release.js";
import { createLiveProxy } from "./live-proxy.js";
import { securityHeaders } from "./security.js";
import { handleSession, type SessionRuntimeState } from "./session.js";
import type { ReleaseHostOptions } from "./types.js";

const MIME: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function apply(
  response: ServerResponse,
  headers: Readonly<Record<string, string>>,
): void {
  for (const [name, value] of Object.entries(headers)) {
    response.setHeader(name, value);
  }
}

function candidatePath(root: string, pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.includes("\\") || decoded.includes("\0")) return null;
  const candidate = resolve(
    root,
    `.${decoded === "/" ? "/index.html" : decoded}`,
  );
  return candidate === root || candidate.startsWith(`${root}${sep}`)
    ? candidate
    : null;
}

function validateInteger(
  value: number,
  label: string,
  minimum: number,
  maximum: number,
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be between ${minimum} and ${maximum}`);
  }
}

export function createReleaseHost(options: ReleaseHostOptions): Server {
  if (options.cookieKey.length !== 32) {
    throw new Error("cookieKey must be 32 bytes");
  }
  let origin: URL;
  try {
    origin = new URL(options.origin);
  } catch {
    throw new Error("release host origin is invalid");
  }
  if (origin.protocol !== "https:" && origin.hostname !== "localhost") {
    throw new Error("release host requires HTTPS outside localhost");
  }
  if (
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error(
      "release host origin must not contain credentials, path, query, or hash",
    );
  }
  const canonicalOrigin = origin.origin;
  const normalized: ReleaseHostOptions = {
    ...options,
    origin: canonicalOrigin,
  };
  const maxBytes = options.maxStaticBytes ?? 40 * 1024 * 1024;
  validateInteger(maxBytes, "maxStaticBytes", 1, 512 * 1024 * 1024);
  validateInteger(
    options.maxNewSessionsPerMinute ?? 5,
    "maxNewSessionsPerMinute",
    1,
    100,
  );
  validateInteger(
    options.maxTokenRequestsPerMinute ?? 30,
    "maxTokenRequestsPerMinute",
    1,
    600,
  );
  validateInteger(
    options.sessionTtlSeconds ?? 7 * 24 * 60 * 60,
    "sessionTtlSeconds",
    60,
    30 * 24 * 60 * 60,
  );
  validateInteger(
    options.maxTrackedSessions ?? 10_000,
    "maxTrackedSessions",
    1,
    1_000_000,
  );
  validateInteger(
    options.proxyTimeoutMs ?? 20_000,
    "proxyTimeoutMs",
    1_000,
    60_000,
  );
  validateInteger(
    options.maxProxyRequestsPerMinute ?? 600,
    "maxProxyRequestsPerMinute",
    1,
    10_000,
  );

  const staticRoot = realpathSync(options.staticRoot);
  if (!statSync(staticRoot).isDirectory()) {
    throw new Error("staticRoot must be a directory");
  }
  const headers = securityHeaders(origin, options.release);
  const releaseBytes = publicReleaseJson(options.release);
  const liveProxy = createLiveProxy(normalized);
  const state: SessionRuntimeState = {
    accountBySession: new Map(),
    sessionByAccount: new Map(),
    creationRate: new Map(),
    tokenRate: new Map(),
  };

  const server = createServer((request, response) => {
    void (async () => {
      apply(response, headers);
      let url: URL;
      try {
        url = new URL(request.url ?? "/", canonicalOrigin);
      } catch {
        response.writeHead(400, { "cache-control": "no-store" });
        return response.end();
      }
      if (url.origin !== canonicalOrigin) {
        response.writeHead(400, { "cache-control": "no-store" });
        return response.end();
      }
      if (url.pathname === "/healthz" && !url.search) {
        if (request.method !== "GET" && request.method !== "HEAD") {
          response.writeHead(405, { ...headers, "cache-control": "no-store" });
          return response.end();
        }
        const body = Buffer.from("ok\n");
        response.writeHead(200, {
          ...headers,
          "content-type": "text/plain; charset=utf-8",
          "content-length": String(body.length),
          "cache-control": "no-store",
        });
        return response.end(request.method === "HEAD" ? undefined : body);
      }
      if (url.pathname === "/api/darknyx/session/start") {
        await handleSession(request, response, normalized, state, false);
        return;
      }
      if (url.pathname === "/api/darknyx/session") {
        await handleSession(request, response, normalized, state);
        return;
      }
      if (liveProxy?.handles(url.pathname)) {
        await liveProxy.handleHttp(request, response, url);
        return;
      }
      if (url.search) {
        response.writeHead(400, { "cache-control": "no-store" });
        return response.end();
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        response.writeHead(405, { "cache-control": "no-store" });
        return response.end();
      }
      if (url.pathname === "/release.json") {
        response.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "content-length": String(releaseBytes.length),
          "cache-control": "no-store",
        });
        return response.end(
          request.method === "HEAD" ? undefined : releaseBytes,
        );
      }
      const candidate = candidatePath(staticRoot, url.pathname);
      if (!candidate) {
        response.writeHead(400, { "cache-control": "no-store" });
        return response.end();
      }
      let path: string;
      try {
        path = await realpath(candidate);
      } catch {
        response.writeHead(404, { "cache-control": "no-store" });
        return response.end();
      }
      if (path !== staticRoot && !path.startsWith(`${staticRoot}${sep}`)) {
        response.writeHead(404, { "cache-control": "no-store" });
        return response.end();
      }
      const metadata = await stat(path);
      if (
        !metadata.isFile() ||
        metadata.size <= 0 ||
        metadata.size > maxBytes
      ) {
        response.writeHead(404, { "cache-control": "no-store" });
        return response.end();
      }
      const immutable = /\.[0-9a-f]{16,}\.[A-Za-z0-9]+$/.test(path);
      const etag = `"${metadata.size.toString(16)}-${Math.trunc(metadata.mtimeMs).toString(16)}"`;
      if (!immutable && request.headers["if-none-match"] === etag) {
        response.writeHead(304, {
          etag,
          "cache-control": "no-cache",
        });
        return response.end();
      }
      response.writeHead(200, {
        "content-type": MIME[extname(path)] ?? "application/octet-stream",
        "content-length": String(metadata.size),
        "cache-control": immutable
          ? "public, max-age=31536000, immutable"
          : "no-cache",
        etag,
      });
      if (request.method === "HEAD") return response.end();
      await pipeline(createReadStream(path), response);
    })().catch((error: unknown) => {
      options.onError?.(error);
      if (!response.headersSent) {
        response.writeHead(500, { "cache-control": "no-store" });
        response.end();
      } else if (!response.destroyed) {
        response.destroy(error instanceof Error ? error : undefined);
      }
    });
  });
  liveProxy?.install(server);
  return server;
}
