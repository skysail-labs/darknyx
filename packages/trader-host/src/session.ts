import {
  createHmac,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { ReleaseHostOptions } from "./types.js";

const COOKIE = "__Host-darknyx_session";
const SESSION = /^[0-9a-f]{64}$/;

function mac(key: Uint8Array, session: string): string {
  return createHmac("sha256", key).update(session).digest("hex");
}

function existingSession(
  request: IncomingMessage,
  key: Uint8Array,
): string | null {
  const raw = request.headers.cookie
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
  if (!raw) return null;
  const [session, signature, ...extra] = raw.split(".");
  if (
    !session ||
    !signature ||
    extra.length ||
    !SESSION.test(session) ||
    !SESSION.test(signature)
  ) {
    return null;
  }
  const expected = Buffer.from(mac(key, session), "hex");
  const actual = Buffer.from(signature, "hex");
  return timingSafeEqual(expected, actual) ? session : null;
}

async function body(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > 1024) throw new Error("request body is too large");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(bytes.length),
    "cache-control": "no-store",
    pragma: "no-cache",
  });
  response.end(bytes);
}

export async function handleSession(
  request: IncomingMessage,
  response: ServerResponse,
  options: ReleaseHostOptions,
  accountBySession: Map<string, string>,
  sessionByAccount: Map<string, string>,
  creationRate: Map<string, { window: number; count: number }>,
): Promise<void> {
  if (request.method !== "POST")
    return json(response, 405, { error: "method_not_allowed" });
  if (request.headers.origin !== options.origin)
    return json(response, 403, { error: "origin_rejected" });
  const fetchSite = request.headers["sec-fetch-site"];
  if (fetchSite !== undefined && fetchSite !== "same-origin") {
    return json(response, 403, { error: "site_rejected" });
  }
  if (
    !String(request.headers["content-type"] ?? "")
      .toLowerCase()
      .startsWith("application/json")
  ) {
    return json(response, 415, { error: "content_type_required" });
  }
  let parsed: unknown;
  try {
    parsed = await body(request);
  } catch {
    return json(response, 400, { error: "malformed_request" });
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).length !== 1 ||
    (parsed as Record<string, unknown>).venue_id !== options.release.venue_id
  ) {
    return json(response, 400, { error: "unknown_venue" });
  }
  const generate =
    options.randomBytes ?? ((length: number) => nodeRandomBytes(length));
  let sessionId = existingSession(request, options.cookieKey);
  if (!sessionId) {
    const clientKey =
      options.clientKey?.(request) ?? request.socket.remoteAddress ?? "unknown";
    const window = Math.floor((options.now?.() ?? Date.now()) / 60_000);
    const current = creationRate.get(clientKey);
    const limit = options.maxNewSessionsPerMinute ?? 5;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("maxNewSessionsPerMinute must be between 1 and 100");
    }
    if (current?.window === window && current.count >= limit) {
      response.setHeader("retry-after", "60");
      return json(response, 429, { error: "session_rate_limited" });
    }
    creationRate.set(clientKey, {
      window,
      count: current?.window === window ? current.count + 1 : 1,
    });
    const generated = generate(32);
    if (generated.length !== 32) {
      throw new Error("randomBytes returned the wrong length");
    }
    sessionId = Buffer.from(generated).toString("hex");
    response.setHeader(
      "set-cookie",
      `${COOKIE}=${sessionId}.${mac(options.cookieKey, sessionId)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000`,
    );
  }
  try {
    const token = await options.issueToken({
      venueId: options.release.venue_id,
      sessionId,
      request,
    });
    if (
      !token.accountId ||
      token.accessToken.length < 32 ||
      token.accessToken.length > 16_384 ||
      !Number.isSafeInteger(token.expiresIn) ||
      token.expiresIn < 30 ||
      token.expiresIn > 3_600
    ) {
      throw new Error("isolated token issuer returned an invalid result");
    }
    const boundAccount = accountBySession.get(sessionId);
    const boundSession = sessionByAccount.get(token.accountId);
    if (
      (boundAccount !== undefined && boundAccount !== token.accountId) ||
      (boundSession !== undefined && boundSession !== sessionId)
    ) {
      throw new Error("token issuer violated per-session account isolation");
    }
    accountBySession.set(sessionId, token.accountId);
    sessionByAccount.set(token.accountId, sessionId);
    return json(response, 200, {
      access_token: token.accessToken,
      expires_in: token.expiresIn,
    });
  } catch {
    return json(response, 503, { error: "session_unavailable" });
  }
}
