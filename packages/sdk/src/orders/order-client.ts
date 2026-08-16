/**
 * REST order client — thin wrappers over the authenticated order endpoints that
 * parse the Phase-1 error envelope into a typed {@link DarknyxApiError}.
 *
 * Bodies are built by the SDK: a place body by `buildOrder`, a cancel body by
 * {@link buildCancel}, a modify body by composing a cancel + a place. The client
 * itself only does HTTP + error decoding, so it stays agnostic to your signer.
 */

import { cancelCanonicalDigest } from "./canonical.js";
import type { PlaceOrderRequest, OrderSigner } from "./build-order.js";
import { apiUrl } from "../api-url.js";

const toHex = (b: Uint8Array): string =>
  Array.from(b, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** A structured API error (mirrors the REST error envelope `{ code, message }`
 *  + the `x-request-id` correlation header). */
export class DarknyxApiError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly status: number,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "DarknyxApiError";
  }
}

export interface OrderClientOptions {
  /** Gateway origin, e.g. `https://<gateway-host>`. */
  baseUrl: string;
  /** Bearer token from `POST /auth/token`. */
  token: string;
  /**
   * REQUIRED. The transport this call must use.
   *
   * Not optional and not defaulted: an omitted `fetchImpl` used to fall back
   * to `globalThis.fetch`, which silently bypasses the verified transport.
   * Seven call sites did exactly that, each looking correct, and each only
   * surfaced during a billable live CVM run. Making it required converts every
   * one of those into a compile error.
   *
   * Browser and legacy callers pass `globalThis.fetch` explicitly — a
   * statement of intent rather than an accident.
   */
  fetchImpl: typeof fetch;
}

export interface PlaceOrderResponse {
  order_id: string;
  status: string;
  arrival_slot: number;
}
export interface CancelOrderResponse {
  order_id: string;
  status: string;
}
export interface ModifyOrderResponse {
  old_order_id: string;
  order_id: string;
  status: string;
  arrival_slot: number;
}

/** A signed cancel body (mirrors the server `CancelOrderRequest`). */
export interface CancelOrderRequest {
  trading_key: string;
  /** Canonical decimal u64 string; JSON numbers cannot preserve the full range. */
  cancel_nonce: string;
  /** 32-byte hex boot session the cancel signature is scoped to (S-07). */
  session_id: string;
  trading_key_signature: string;
}

/** A modify body: a signed cancel of the old order + a full replacement. */
export interface ModifyOrderRequest {
  cancel_signature: string;
  /** Canonical decimal u64 string; JSON numbers cannot preserve the full range. */
  cancel_nonce: string;
  replacement: PlaceOrderRequest;
}

async function decode<T>(res: Response): Promise<T> {
  if (res.ok) return (await res.json()) as T;
  const requestId = res.headers.get("x-request-id") ?? undefined;
  let code = res.status;
  let message = res.statusText;
  try {
    const body = (await res.json()) as { code?: number; message?: string };
    if (typeof body.code === "number") code = body.code;
    if (typeof body.message === "string") message = body.message;
  } catch {
    // non-JSON error body — keep the status text
  }
  throw new DarknyxApiError(code, message, res.status, requestId);
}

function authHeaders(token: string): Record<string, string> {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  };
}

/** `POST /orders`. Returns the acceptance (or throws `DarknyxApiError`). */
export async function placeOrder(
  opts: OrderClientOptions,
  order: PlaceOrderRequest,
): Promise<PlaceOrderResponse> {
  const f = opts.fetchImpl;
  const res = await f(apiUrl(opts.baseUrl, "orders"), {
    method: "POST",
    headers: authHeaders(opts.token),
    body: JSON.stringify(order),
  });
  return decode<PlaceOrderResponse>(res);
}

/** `DELETE /orders/{order_id}`. */
export async function cancelOrder(
  opts: OrderClientOptions,
  orderIdHex: string,
  cancel: CancelOrderRequest,
): Promise<CancelOrderResponse> {
  const f = opts.fetchImpl;
  const res = await f(apiUrl(opts.baseUrl, `orders/${orderIdHex}`), {
    method: "DELETE",
    headers: authHeaders(opts.token),
    body: JSON.stringify(cancel),
  });
  return decode<CancelOrderResponse>(res);
}

/** `PUT /orders/{order_id}` — atomic cancel + replace. */
export async function modifyOrder(
  opts: OrderClientOptions,
  oldOrderIdHex: string,
  modify: ModifyOrderRequest,
): Promise<ModifyOrderResponse> {
  const f = opts.fetchImpl;
  const res = await f(apiUrl(opts.baseUrl, `orders/${oldOrderIdHex}`), {
    method: "PUT",
    headers: authHeaders(opts.token),
    body: JSON.stringify(modify),
  });
  return decode<ModifyOrderResponse>(res);
}

/** `GET /orders/{order_id}` — order status. */
export async function getOrder(
  opts: OrderClientOptions,
  orderIdHex: string,
): Promise<unknown> {
  const f = opts.fetchImpl;
  const res = await f(apiUrl(opts.baseUrl, `orders/${orderIdHex}`), {
    headers: { authorization: `Bearer ${opts.token}` },
  });
  return decode<unknown>(res);
}

/**
 * Build a signed cancel body for `orderId`. Signs `CancelCanonical{ orderId,
 * tradingKey, cancelNonce, sessionId }` via the provided {@link OrderSigner}.
 *
 * `sessionId` (from `GET /info`) scopes the signature to one CVM boot, so a
 * captured cancel body cannot kill a re-placed order after a restart (S-07).
 */
export async function buildCancel(args: {
  orderId: Uint8Array;
  tradingKey: Uint8Array;
  cancelNonce: bigint;
  sessionId: Uint8Array;
  sign: OrderSigner;
}): Promise<CancelOrderRequest> {
  if (args.orderId.length !== 16) throw new Error("orderId must be 16 bytes");
  if (args.tradingKey.length !== 32)
    throw new Error("tradingKey must be 32 bytes");
  if (args.sessionId.length !== 32)
    throw new Error("sessionId must be 32 bytes");
  const digest = cancelCanonicalDigest({
    orderId: args.orderId,
    tradingKey: args.tradingKey,
    cancelNonce: args.cancelNonce,
    sessionId: args.sessionId,
  });
  const sig = await args.sign(digest);
  if (sig.length !== 64)
    throw new Error("sign() must return a 64-byte signature");
  return {
    trading_key: toHex(args.tradingKey),
    cancel_nonce: args.cancelNonce.toString(),
    session_id: toHex(args.sessionId),
    trading_key_signature: toHex(sig),
  };
}
