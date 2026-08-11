import { createServer, type Server } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";

import { publicReleaseJson } from "./release.js";
import { securityHeaders } from "./security.js";
import { handleSession } from "./session.js";
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
  response: import("node:http").ServerResponse,
  headers: Readonly<Record<string, string>>,
): void {
  for (const [name, value] of Object.entries(headers))
    response.setHeader(name, value);
}

function safePath(root: string, pathname: string): string | null {
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
  const base = resolve(root);
  return candidate === base || candidate.startsWith(`${base}${sep}`)
    ? candidate
    : null;
}

export function createReleaseHost(options: ReleaseHostOptions): Server {
  if (options.cookieKey.length !== 32)
    throw new Error("cookieKey must be 32 bytes");
  const origin = new URL(options.origin);
  if (origin.protocol !== "https:" && origin.hostname !== "localhost") {
    throw new Error("release host requires HTTPS outside localhost");
  }
  if (origin.pathname !== "/" || origin.search || origin.hash) {
    throw new Error(
      "release host origin must not contain a path, query, or hash",
    );
  }
  const headers = securityHeaders(origin, options.release);
  const releaseBytes = publicReleaseJson(options.release);
  const maxBytes = options.maxStaticBytes ?? 40 * 1024 * 1024;
  const accountBySession = new Map<string, string>();
  const sessionByAccount = new Map<string, string>();
  const creationRate = new Map<string, { window: number; count: number }>();
  return createServer(async (request, response) => {
    apply(response, headers);
    const url = new URL(request.url ?? "/", options.origin);
    if (url.pathname === "/api/darknyx/session") {
      await handleSession(
        request,
        response,
        options,
        accountBySession,
        sessionByAccount,
        creationRate,
      );
      return;
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
      return response.end(request.method === "HEAD" ? undefined : releaseBytes);
    }
    const path = safePath(options.staticRoot, url.pathname);
    if (!path) {
      response.writeHead(400, { "cache-control": "no-store" });
      return response.end();
    }
    try {
      const metadata = await stat(path);
      if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maxBytes)
        throw new Error("invalid asset");
      const bytes = await readFile(path);
      const immutable = /\.[0-9a-f]{16,}\.[A-Za-z0-9]+$/.test(path);
      response.writeHead(200, {
        "content-type": MIME[extname(path)] ?? "application/octet-stream",
        "content-length": String(bytes.length),
        "cache-control": immutable
          ? "public, max-age=31536000, immutable"
          : "no-cache",
      });
      response.end(request.method === "HEAD" ? undefined : bytes);
    } catch {
      response.writeHead(404, { "cache-control": "no-store" });
      response.end();
    }
  });
}
