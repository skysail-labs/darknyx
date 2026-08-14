import {
  createHmac,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { ReleaseHostOptions } from "./types.js";

const COOKIE = "__Host-darknyx_session";
const SESSION = /^[0-9a-f]{64}$/;
const ISSUED_AT = /^(0|[1-9]\d{0,15})$/;

interface RateWindow {
  window: number;
  count: number;
}

interface AccountBinding {
  accountId: string;
  expiresAtMs: number;
}

interface SessionBinding {
  sessionId: string;
  expiresAtMs: number;
}

export interface SessionRuntimeState {
  accountBySession: Map<string, AccountBinding>;
  sessionByAccount: Map<string, SessionBinding>;
  creationRate: Map<string, RateWindow>;
  tokenRate: Map<string, RateWindow>;
}

interface BrowserSession {
  id: string;
  issuedAtSeconds: number;
  expiresAtMs: number;
}

class AccountIsolationError extends Error {
  constructor(
    readonly details: {
      sessionId: string;
      accountId: string;
      conflictingSessionId?: string;
      conflictingAccountId?: string;
    },
  ) {
    super("token issuer violated per-session account isolation");
    this.name = "AccountIsolationError";
  }
}

function mac(key: Uint8Array, session: string, issuedAt: string): string {
  return createHmac("sha256", key)
    .update(session)
    .update(".")
    .update(issuedAt)
    .digest("hex");
}

function existingSession(
  request: IncomingMessage,
  key: Uint8Array,
  nowMs: number,
  ttlSeconds: number,
): BrowserSession | null {
  const raw = request.headers.cookie
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
  if (!raw) return null;
  const [session, issuedAt, signature, ...extra] = raw.split(".");
  if (
    !session ||
    !issuedAt ||
    !signature ||
    extra.length ||
    !SESSION.test(session) ||
    !ISSUED_AT.test(issuedAt) ||
    !SESSION.test(signature)
  ) {
    return null;
  }
  const issuedAtSeconds = Number(issuedAt);
  const nowSeconds = Math.floor(nowMs / 1_000);
  if (
    !Number.isSafeInteger(issuedAtSeconds) ||
    issuedAtSeconds > nowSeconds + 60 ||
    nowSeconds - issuedAtSeconds >= ttlSeconds
  ) {
    return null;
  }
  const expected = Buffer.from(mac(key, session, issuedAt), "hex");
  const actual = Buffer.from(signature, "hex");
  if (!timingSafeEqual(expected, actual)) return null;
  return {
    id: session,
    issuedAtSeconds,
    expiresAtMs: (issuedAtSeconds + ttlSeconds) * 1_000,
  };
}

export function authenticatedSessionId(
  request: IncomingMessage,
  options: ReleaseHostOptions,
): string | null {
  return (
    existingSession(
      request,
      options.cookieKey,
      options.now?.() ?? Date.now(),
      options.sessionTtlSeconds ?? 7 * 24 * 60 * 60,
    )?.id ?? null
  );
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

function consume(
  entries: Map<string, RateWindow>,
  key: string,
  nowMs: number,
  limit: number,
): boolean {
  const window = Math.floor(nowMs / 60_000);
  const current = entries.get(key);
  if (current?.window === window && current.count >= limit) return false;
  entries.set(key, {
    window,
    count: current?.window === window ? current.count + 1 : 1,
  });
  return true;
}

function prune(state: SessionRuntimeState, nowMs: number): void {
  const currentWindow = Math.floor(nowMs / 60_000);
  for (const [key, value] of state.creationRate) {
    if (value.window < currentWindow) state.creationRate.delete(key);
  }
  for (const [key, value] of state.tokenRate) {
    if (value.window < currentWindow) state.tokenRate.delete(key);
  }
  for (const [sessionId, binding] of state.accountBySession) {
    if (binding.expiresAtMs <= nowMs) {
      state.accountBySession.delete(sessionId);
      const reverse = state.sessionByAccount.get(binding.accountId);
      if (reverse?.sessionId === sessionId) {
        state.sessionByAccount.delete(binding.accountId);
      }
    }
  }
}

export async function handleSession(
  request: IncomingMessage,
  response: ServerResponse,
  options: ReleaseHostOptions,
  state: SessionRuntimeState,
  issueCredentials = true,
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

  const nowMs = options.now?.() ?? Date.now();
  const ttlSeconds = options.sessionTtlSeconds ?? 7 * 24 * 60 * 60;
  const maxTracked = options.maxTrackedSessions ?? 10_000;
  prune(state, nowMs);
  const generate =
    options.randomBytes ?? ((length: number) => nodeRandomBytes(length));
  let session = existingSession(request, options.cookieKey, nowMs, ttlSeconds);
  if (!session) {
    const clientKey =
      options.clientKey?.(request) ?? request.socket.remoteAddress ?? "unknown";
    if (
      !state.creationRate.has(clientKey) &&
      state.creationRate.size >= maxTracked
    ) {
      return json(response, 503, { error: "session_capacity_reached" });
    }
    if (
      !consume(
        state.creationRate,
        clientKey,
        nowMs,
        options.maxNewSessionsPerMinute ?? 5,
      )
    ) {
      response.setHeader("retry-after", "60");
      return json(response, 429, { error: "session_rate_limited" });
    }
    const generated = generate(32);
    if (generated.length !== 32) {
      throw new Error("randomBytes returned the wrong length");
    }
    const issuedAtSeconds = Math.floor(nowMs / 1_000);
    const issuedAt = String(issuedAtSeconds);
    const sessionId = Buffer.from(generated).toString("hex");
    session = {
      id: sessionId,
      issuedAtSeconds,
      expiresAtMs: (issuedAtSeconds + ttlSeconds) * 1_000,
    };
    response.setHeader(
      "set-cookie",
      `${COOKIE}=${sessionId}.${issuedAt}.${mac(options.cookieKey, sessionId, issuedAt)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ttlSeconds}`,
    );
  }

  // Trust bootstrap needs only the signed HttpOnly cookie so same-origin
  // venue/RPC reads can pass through the proxy. Do not provision a CVM
  // account or mint a bearer token until attestation and finalized governance
  // have both passed in the browser.
  if (!issueCredentials) {
    response.writeHead(204, {
      "cache-control": "no-store",
      pragma: "no-cache",
    });
    response.end();
    return;
  }

  if (!state.tokenRate.has(session.id) && state.tokenRate.size >= maxTracked) {
    return json(response, 503, { error: "session_capacity_reached" });
  }
  if (
    !consume(
      state.tokenRate,
      session.id,
      nowMs,
      options.maxTokenRequestsPerMinute ?? 30,
    )
  ) {
    response.setHeader("retry-after", "60");
    return json(response, 429, { error: "token_rate_limited" });
  }

  try {
    const token = await options.issueToken({
      venueId: options.release.venue_id,
      sessionId: session.id,
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
    const boundAccount = state.accountBySession.get(session.id);
    const boundSession = state.sessionByAccount.get(token.accountId);
    if (
      (boundAccount !== undefined &&
        boundAccount.accountId !== token.accountId) ||
      (boundSession !== undefined && boundSession.sessionId !== session.id)
    ) {
      throw new AccountIsolationError({
        sessionId: session.id,
        accountId: token.accountId,
        ...(boundSession
          ? { conflictingSessionId: boundSession.sessionId }
          : {}),
        ...(boundAccount
          ? { conflictingAccountId: boundAccount.accountId }
          : {}),
      });
    }
    if (!boundAccount && state.accountBySession.size >= maxTracked) {
      return json(response, 503, { error: "session_capacity_reached" });
    }
    state.accountBySession.set(session.id, {
      accountId: token.accountId,
      expiresAtMs: session.expiresAtMs,
    });
    state.sessionByAccount.set(token.accountId, {
      sessionId: session.id,
      expiresAtMs: session.expiresAtMs,
    });
    return json(response, 200, {
      access_token: token.accessToken,
      expires_in: token.expiresIn,
    });
  } catch (error) {
    if (error instanceof AccountIsolationError) {
      try {
        await options.onIsolationViolation?.(error.details);
      } catch (callbackError) {
        options.onError?.(callbackError);
      }
      return json(response, 503, { error: "account_isolation_failed" });
    }
    return json(response, 503, { error: "session_unavailable" });
  }
}
