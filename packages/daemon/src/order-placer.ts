/**
 * OrderPlacer — the daemon's order-submission transport seam.
 *
 * Placement is transport-agnostic: the SDK builds + signs the body the same way
 * for both paths (`proveAndBuildOrder` / `buildCancel`); only the wire differs.
 * Per the finalized policy, the **default is `/v1/stream`** (a warm,
 * in-band-authenticated session with cancel-on-disconnect — the right transport for a
 * market maker, since a crashed daemon auto-pulls its resting quotes), with
 * **REST `POST/DELETE/PUT /orders` as a thin fallback** for bring-up/debug or a
 * flapping socket.
 *
 * Both TEE paths dispatch to the SAME intake core (one verification path), so
 * the choice is purely operational. The one piece of machinery the WS path needs
 * — and that REST doesn't — is reconnect and exact request correlation, both
 * owned by the shared `TradingClient` session.
 */

import {
  TradingClient,
  placeOrder,
  cancelOrder,
  modifyOrder,
  DarknyxApiError,
  type TradingClientOptions,
  type SendableWebSocketFactory,
  type PlaceOrderRequest,
  type PlaceOrderResponse,
  type CancelOrderRequest,
  type CancelOrderResponse,
  type ModifyOrderRequest,
  type ModifyOrderResponse,
} from "@darknyx/sdk";

/** Transport for placing / cancelling / modifying orders against the TEE. */
export interface OrderPlacer {
  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse>;
  cancel(
    orderIdHex: string,
    req: CancelOrderRequest,
  ): Promise<CancelOrderResponse>;
  modify(
    orderIdHex: string,
    req: ModifyOrderRequest,
  ): Promise<ModifyOrderResponse>;
  /** Release any underlying connection. */
  close(): void;
}

// ─────────────────────────────────────────────────────────────────────────────
// REST fallback
// ─────────────────────────────────────────────────────────────────────────────

export interface RestOrderPlacerOptions {
  /** Gateway origin, e.g. `https://<app>-8080.dstack-…`. */
  baseUrl: string;
  token: string;
  /** REQUIRED — the CVM transport. See `OrderClientOptions.fetchImpl`: an
   *  omitted value used to fall back to global fetch and bypass verification. */
  fetchImpl: typeof fetch;
}

/** REST {@link OrderPlacer} — thin wrapper over the SDK order-client. Stateless;
 *  `close` is a no-op. The fallback path. */
export class RestOrderPlacer implements OrderPlacer {
  constructor(private readonly opts: RestOrderPlacerOptions) {}

  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse> {
    return placeOrder(this.opts, order);
  }
  cancel(
    orderIdHex: string,
    req: CancelOrderRequest,
  ): Promise<CancelOrderResponse> {
    return cancelOrder(this.opts, orderIdHex, req);
  }
  modify(
    orderIdHex: string,
    req: ModifyOrderRequest,
  ): Promise<ModifyOrderResponse> {
    return modifyOrder(this.opts, orderIdHex, req);
  }
  close(): void {
    /* stateless */
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// WS default (TradingClient + reconnect)
// ─────────────────────────────────────────────────────────────────────────────

/** The subset of `TradingClient` {@link WsOrderPlacer} drives (a factory seam
 *  for tests). */
export interface TradingClientLike {
  connect(): Promise<void>;
  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse>;
  cancel(
    orderIdHex: string,
    req: CancelOrderRequest,
  ): Promise<CancelOrderResponse>;
  modify(
    orderIdHex: string,
    req: ModifyOrderRequest,
  ): Promise<ModifyOrderResponse>;
  close(): void;
}

export interface WsOrderPlacerOptions {
  gatewayWsUrl: string;
  token: string;
  /** Cancel-on-disconnect for the session. Defaults to ON — a daemon that drops
   *  off should NOT leave stale quotes resting. */
  cancelOnDisconnect?: boolean;
  webSocketFactory?: SendableWebSocketFactory;
  onClose?: (code: number, reason?: string) => void;
  /** Reconnect+retry attempts per call on a transport error (default 1). */
  maxRetries?: number;
  /** Factory seam; defaults to building a real `TradingClient`. */
  clientFactory?: (opts: TradingClientOptions) => TradingClientLike;
  /** Existing multiplexed session shared with fills and order updates. */
  client?: TradingClientLike;
}

/**
 * WS {@link OrderPlacer} over `/v1/stream`. It reuses the daemon's multiplexed
 * client when supplied; otherwise it lazily creates one. Transport failures are
 * retried up to `maxRetries`; a {@link DarknyxApiError} is a definitive server answer
 * and is never retried.
 */
export class WsOrderPlacer implements OrderPlacer {
  private client: TradingClientLike | null = null;
  private connecting: Promise<TradingClientLike> | null = null;
  private readonly maxRetries: number;

  constructor(private readonly opts: WsOrderPlacerOptions) {
    this.maxRetries = opts.maxRetries ?? 1;
  }

  private build(): TradingClientLike {
    if (this.opts.client) return this.opts.client;
    const factory = this.opts.clientFactory ?? ((o) => new TradingClient(o));
    const created = factory({
      gatewayWsUrl: this.opts.gatewayWsUrl,
      token: this.opts.token,
      cancelOnDisconnect: this.opts.cancelOnDisconnect ?? true,
      webSocketFactory: this.opts.webSocketFactory,
      autoReconnect: false,
      onClose: (code, reason) => {
        // Drop a dead idle connection so the next call rebuilds eagerly.
        if (this.client === created) this.client = null;
        this.opts.onClose?.(code, reason);
      },
    });
    return created;
  }

  private async ensureConnected(): Promise<TradingClientLike> {
    if (this.client) return this.client;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      const c = this.build();
      await c.connect();
      this.client = c;
      return c;
    })();
    try {
      return await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async withReconnect<T>(
    fn: (c: TradingClientLike) => Promise<T>,
  ): Promise<T> {
    let attempt = 0;
    for (;;) {
      const c = await this.ensureConnected();
      try {
        return await fn(c);
      } catch (err) {
        // A DarknyxApiError is the server's definitive reply — never retry it.
        if (err instanceof DarknyxApiError || attempt >= this.maxRetries) throw err;
        attempt += 1;
        // A shared stream reconnects itself; a private one is rebuilt here.
        if (!this.opts.client) {
          try {
            c.close();
          } catch {
            /* best effort */
          }
        }
        if (this.client === c) this.client = null;
      }
    }
  }

  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse> {
    return this.withReconnect((c) => c.place(order));
  }
  cancel(
    orderIdHex: string,
    req: CancelOrderRequest,
  ): Promise<CancelOrderResponse> {
    return this.withReconnect((c) => c.cancel(orderIdHex, req));
  }
  modify(
    orderIdHex: string,
    req: ModifyOrderRequest,
  ): Promise<ModifyOrderResponse> {
    return this.withReconnect((c) => c.modify(orderIdHex, req));
  }
  close(): void {
    this.client?.close();
    this.client = null;
  }
}
