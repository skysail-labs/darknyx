/**
 * REST order client — thin wrappers over the authenticated order endpoints that
 * parse the Phase-1 error envelope into a typed {@link NyxApiError}.
 *
 * Bodies are built by the SDK: a place body by `buildOrder`, a cancel body by
 * {@link buildCancel}, a modify body by composing a cancel + a place. The client
 * itself only does HTTP + error decoding, so it stays agnostic to your signer.
 */

import { cancelCanonicalDigest } from "./canonical.js";
import type { PlaceOrderRequest, OrderSigner } from "./build-order.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** A structured API error (mirrors the REST error envelope `{ code, message }`
 *  + the `x-request-id` correlation header). */
export class NyxApiError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly status: number,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "NyxApiError";
  }
}

export interface OrderClientOptions {
  /** Gateway origin, e.g. `https://<gateway-host>`. */
  baseUrl: string;
  /** Bearer token from `POST /auth/token`. */
  token: string;
  fetchImpl?: typeof fetch;
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
  cancel_nonce: number;
  trading_key_signature: string;
}

/** A modify body: a signed cancel of the old order + a full replacement. */
export interface ModifyOrderRequest {
  cancel_signature: string;
  cancel_nonce: number;
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
  throw new NyxApiError(code, message, res.status, requestId);
}

function authHeaders(token: string): Record<string, string> {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  };
}

/** `POST /orders`. Returns the acceptance (or throws `NyxApiError`). */
export async function placeOrder(
  opts: OrderClientOptions,
  order: PlaceOrderRequest,
): Promise<PlaceOrderResponse> {
  const f = opts.fetchImpl ?? fetch;
  const res = await f(new URL("/orders", opts.baseUrl).toString(), {
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
  const f = opts.fetchImpl ?? fetch;
  const res = await f(
    new URL(`/orders/${orderIdHex}`, opts.baseUrl).toString(),
    {
      method: "DELETE",
      headers: authHeaders(opts.token),
      body: JSON.stringify(cancel),
    },
  );
  return decode<CancelOrderResponse>(res);
}

/** `PUT /orders/{order_id}` — atomic cancel + replace. */
export async function modifyOrder(
  opts: OrderClientOptions,
  oldOrderIdHex: string,
  modify: ModifyOrderRequest,
): Promise<ModifyOrderResponse> {
  const f = opts.fetchImpl ?? fetch;
  const res = await f(
    new URL(`/orders/${oldOrderIdHex}`, opts.baseUrl).toString(),
    {
      method: "PUT",
      headers: authHeaders(opts.token),
      body: JSON.stringify(modify),
    },
  );
  return decode<ModifyOrderResponse>(res);
}

/** `GET /orders/{order_id}` — order status. */
export async function getOrder(
  opts: OrderClientOptions,
  orderIdHex: string,
): Promise<unknown> {
  const f = opts.fetchImpl ?? fetch;
  const res = await f(
    new URL(`/orders/${orderIdHex}`, opts.baseUrl).toString(),
    {
      headers: { authorization: `Bearer ${opts.token}` },
    },
  );
  return decode<unknown>(res);
}

/**
 * Build a signed cancel body for `orderId`. Signs `CancelCanonical{ orderId,
 * tradingKey, cancelNonce }` via the provided {@link OrderSigner}.
 */
export async function buildCancel(args: {
  orderId: Uint8Array;
  tradingKey: Uint8Array;
  cancelNonce: bigint;
  sign: OrderSigner;
}): Promise<CancelOrderRequest> {
  if (args.orderId.length !== 16) throw new Error("orderId must be 16 bytes");
  if (args.tradingKey.length !== 32)
    throw new Error("tradingKey must be 32 bytes");
  const digest = cancelCanonicalDigest({
    orderId: args.orderId,
    tradingKey: args.tradingKey,
    cancelNonce: args.cancelNonce,
  });
  const sig = await args.sign(digest);
  if (sig.length !== 64)
    throw new Error("sign() must return a 64-byte signature");
  return {
    trading_key: toHex(args.tradingKey),
    cancel_nonce: Number(args.cancelNonce),
    trading_key_signature: toHex(sig),
  };
}
