/**
 * `/ws/trading` send-client — submit orders over one warm, pre-authenticated
 * socket and await a reply per request (correlated by `request_id`).
 *
 * This is the SDK's first order-submission *transport*: `place` / `cancel` /
 * `modify` each send a framed request and resolve with the server's result (or
 * reject with a {@link NyxApiError} carrying the numeric code). Bodies are built
 * by the SDK (`buildOrder`, `buildCancel`) exactly as for REST — the socket only
 * changes the transport. Optional cancel-on-disconnect (`?cancel_on_disconnect`)
 * tears down this session's resting orders if the connection drops.
 *
 * `WebSocket` is injectable (the `webSocketFactory`) so tests can drive frames
 * without a server.
 */

import { NyxApiError } from "./order-client.js";
import type {
  PlaceOrderResponse,
  CancelOrderResponse,
  ModifyOrderResponse,
  CancelOrderRequest,
  ModifyOrderRequest,
} from "./order-client.js";
import type { PlaceOrderRequest } from "./build-order.js";

/** Minimal bidirectional WebSocket surface (send + lifecycle). */
export interface SendableWebSocketLike {
  addEventListener(type: "open", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
  addEventListener(
    type: "close",
    cb: (ev: { code: number; reason?: string }) => void,
  ): void;
  addEventListener(type: "error", cb: (ev: unknown) => void): void;
  send(data: string): void;
  close(): void;
}
export type SendableWebSocketFactory = (url: string) => SendableWebSocketLike;

const defaultFactory: SendableWebSocketFactory = (url) =>
  new (
    globalThis as { WebSocket: new (u: string) => SendableWebSocketLike }
  ).WebSocket(url);

export interface TradingClientOptions {
  /** Gateway WS origin, e.g. `wss://<gateway-host>`. `/ws/trading` is appended. */
  gatewayWsUrl: string;
  token: string;
  /** Enable cancel-on-disconnect for this session (else the account default). */
  cancelOnDisconnect?: boolean;
  webSocketFactory?: SendableWebSocketFactory;
  /** Notified on a server reply that doesn't correlate to a pending request. */
  onUnsolicited?: (frame: unknown) => void;
  onClose?: (code: number, reason?: string) => void;
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
}

/** One bidirectional trading socket. Open with {@link connect}, then place /
 *  cancel / modify; each resolves when its reply frame arrives. */
export class TradingClient {
  private ws: SendableWebSocketLike | null = null;
  private seq = 0;
  private readonly pending = new Map<string, Pending>();
  private closed = false;

  constructor(private readonly opts: TradingClientOptions) {}

  private nextId(): string {
    return `r-${++this.seq}`;
  }

  /** Open the socket and resolve once it's connected (rejects on early close). */
  connect(): Promise<void> {
    const base = this.opts.gatewayWsUrl.replace(/\/$/, "");
    const params = new URLSearchParams({ token: this.opts.token });
    if (this.opts.cancelOnDisconnect !== undefined) {
      params.set("cancel_on_disconnect", String(this.opts.cancelOnDisconnect));
    }
    const url = `${base}/ws/trading?${params.toString()}`;
    const ws = (this.opts.webSocketFactory ?? defaultFactory)(url);
    this.ws = ws;

    return new Promise<void>((resolve, reject) => {
      let opened = false;
      ws.addEventListener("open", () => {
        opened = true;
        resolve();
      });
      ws.addEventListener("message", (ev) => this.onMessage(ev.data));
      ws.addEventListener("error", (e) => {
        if (!opened)
          reject(e instanceof Error ? e : new Error("ws error before open"));
      });
      ws.addEventListener("close", (ev) => {
        this.closed = true;
        if (!opened)
          reject(new Error(`ws closed before open (code ${ev.code})`));
        // Fail any in-flight requests so callers don't hang.
        for (const p of this.pending.values()) {
          p.reject(new Error(`ws closed (code ${ev.code})`));
        }
        this.pending.clear();
        this.opts.onClose?.(ev.code, ev.reason);
      });
    });
  }

  private onMessage(data: unknown): void {
    let frame: {
      op?: string;
      request_id?: string;
      result?: unknown;
      code?: number;
      message?: string;
    };
    try {
      frame = JSON.parse(typeof data === "string" ? data : String(data));
    } catch {
      return;
    }
    const id = frame.request_id;
    const pending = id ? this.pending.get(id) : undefined;
    if (!pending) {
      this.opts.onUnsolicited?.(frame);
      return;
    }
    this.pending.delete(id!);
    if (frame.op === "error") {
      pending.reject(
        new NyxApiError(
          frame.code ?? 5000,
          frame.message ?? "error",
          frame.code ?? 0,
        ),
      );
    } else {
      pending.resolve(frame.result ?? null);
    }
  }

  private request<T>(frame: Record<string, unknown>): Promise<T> {
    if (!this.ws || this.closed)
      return Promise.reject(new Error("socket not connected"));
    const request_id = this.nextId();
    const p = new Promise<T>((resolve, reject) => {
      this.pending.set(request_id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
    });
    this.ws.send(JSON.stringify({ ...frame, request_id }));
    return p;
  }

  /** Place an order (`buildOrder` body). Resolves with the acceptance. */
  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse> {
    return this.request<PlaceOrderResponse>({
      op: "order.place",
      params: order,
    });
  }

  /** Cancel a resting order (`buildCancel` body). */
  cancel(
    orderIdHex: string,
    cancel: CancelOrderRequest,
  ): Promise<CancelOrderResponse> {
    return this.request<CancelOrderResponse>({
      op: "order.cancel",
      order_id: orderIdHex,
      params: cancel,
    });
  }

  /** Atomic cancel + replace. */
  modify(
    oldOrderIdHex: string,
    modify: ModifyOrderRequest,
  ): Promise<ModifyOrderResponse> {
    return this.request<ModifyOrderResponse>({
      op: "order.modify",
      order_id: oldOrderIdHex,
      params: modify,
    });
  }

  /** Application-level heartbeat. */
  ping(): Promise<void> {
    return this.request<void>({ op: "ping" });
  }

  close(): void {
    this.closed = true;
    this.ws?.close();
  }
}
