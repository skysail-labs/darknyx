/**
 * `/v1/stream` session client — the SDK's sole WebSocket transport.
 *
 * Authentication happens in-band (`op: login`). One socket multiplexes order
 * requests with the per-account `orders` / `fills` channels and the global
 * `tree` channel. It enforces the connection-global sequence, refreshes a JWT
 * when the server emits `auth_expired`, reconnects and resubscribes after
 * transport loss, and carries cancel-on-disconnect on every login.
 */

import { DarknyxApiError } from "./order-client.js";
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

export type StreamChannel = "orders" | "fills" | "tree";
export type StreamTokenProvider = () => Promise<string>;

export interface StreamChannelHooks {
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
}

export interface StreamChannelSubscription {
  close(): void;
}

export interface TradingClientOptions {
  /** Gateway WS origin, e.g. `wss://<gateway-host>`. `/v1/stream` is appended. */
  gatewayWsUrl: string;
  /** Initial/static bearer token. A `tokenProvider` supersedes it on login. */
  token: string;
  /** Called for initial login and every `auth_expired` refresh reminder. */
  tokenProvider?: StreamTokenProvider;
  /** Enable cancel-on-disconnect for this session (else the account default). */
  cancelOnDisconnect?: boolean;
  /** Reopen and resubscribe after an unexpected close. Default true. */
  autoReconnect?: boolean;
  reconnectDelayMs?: number;
  webSocketFactory?: SendableWebSocketFactory;
  /** Notified on a reply that does not correlate to a pending request. */
  onUnsolicited?: (frame: unknown) => void;
  onClose?: (code: number, reason?: string) => void;
  onError?: (error: Error) => void;
  onSequenceGap?: (expected: number, received: number) => void;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

interface ChannelListener {
  onMessage: (frame: unknown) => void;
  hooks: StreamChannelHooks;
}

interface ServerFrame {
  op?: string;
  seq?: number;
  channel?: string;
  request_id?: string;
  result?: unknown;
  code?: number;
  message?: string;
}

/** One reconnecting, in-band-authenticated `/v1/stream` session. */
export class TradingClient {
  private ws: SendableWebSocketLike | null = null;
  private requestSeq = 0;
  private lastServerSeq = 0;
  private readonly pending = new Map<string, Pending>();
  private readonly channelListeners = new Map<
    StreamChannel,
    Set<ChannelListener>
  >();
  private permanentlyClosed = false;
  private ready = false;
  private connectPromise: Promise<void> | null = null;
  private connectResolve: (() => void) | null = null;
  private connectReject: ((error: Error) => void) | null = null;
  private loginRequestId: string | null = null;
  private refreshInFlight = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly opts: TradingClientOptions) {}

  private nextId(prefix = "r"): string {
    return `${prefix}-${++this.requestSeq}`;
  }

  /** Open `/v1/stream` and resolve only after the in-band login succeeds. */
  connect(): Promise<void> {
    if (this.ready) return Promise.resolve();
    if (this.permanentlyClosed) {
      return Promise.reject(new Error("stream client is closed"));
    }
    if (this.connectPromise) return this.connectPromise;

    this.connectPromise = new Promise<void>((resolve, reject) => {
      this.connectResolve = resolve;
      this.connectReject = reject;
    });
    this.openSocket();
    return this.connectPromise;
  }

  private openSocket(): void {
    const base = this.opts.gatewayWsUrl.replace(/\/$/, "");
    const ws = (this.opts.webSocketFactory ?? defaultFactory)(
      `${base}/v1/stream`,
    );
    this.ws = ws;
    this.lastServerSeq = 0;

    ws.addEventListener("open", () => {
      void this.sendLogin(false);
    });
    ws.addEventListener("message", (event) => this.onMessage(event.data));
    ws.addEventListener("error", (event) => {
      const error =
        event instanceof Error ? event : new Error("WebSocket transport error");
      this.opts.onError?.(error);
      if (!this.ready) this.failConnect(error);
    });
    ws.addEventListener("close", (event) => {
      if (this.ws !== ws) return;
      this.onSocketClose(event.code, event.reason);
    });
  }

  private async currentToken(): Promise<string> {
    const token = this.opts.tokenProvider
      ? await this.opts.tokenProvider()
      : this.opts.token;
    if (!token)
      throw new Error("stream token provider returned an empty token");
    return token;
  }

  private async sendLogin(refresh: boolean): Promise<void> {
    if (!this.ws || (refresh && this.refreshInFlight)) return;
    this.refreshInFlight = refresh;
    try {
      const token = await this.currentToken();
      if (!this.ws) return;
      const requestId = this.nextId(refresh ? "refresh" : "login");
      this.loginRequestId = requestId;
      this.ws.send(
        JSON.stringify({
          op: "login",
          request_id: requestId,
          token,
          ...(this.opts.cancelOnDisconnect === undefined
            ? {}
            : { cancel_on_disconnect: this.opts.cancelOnDisconnect }),
        }),
      );
    } catch (error) {
      this.refreshInFlight = false;
      const err = error instanceof Error ? error : new Error(String(error));
      this.opts.onError?.(err);
      if (!this.ready) this.failConnect(err);
      this.ws?.close();
    }
  }

  private onMessage(data: unknown): void {
    let frame: ServerFrame;
    try {
      frame = JSON.parse(typeof data === "string" ? data : String(data));
    } catch {
      this.protocolFailure("malformed JSON frame from /v1/stream");
      return;
    }

    if (!Number.isSafeInteger(frame.seq) || (frame.seq ?? 0) <= 0) {
      this.protocolFailure(
        "/v1/stream frame is missing a positive integer seq",
      );
      return;
    }
    const expected = this.lastServerSeq + 1;
    if (frame.seq !== expected) {
      this.opts.onSequenceGap?.(expected, frame.seq!);
      this.notifyResync(
        `stream sequence gap: expected ${expected}, received ${frame.seq}`,
      );
      this.ws?.close();
      return;
    }
    this.lastServerSeq = frame.seq!;

    if (frame.op === "auth_expired") {
      void this.sendLogin(true);
      return;
    }

    if (frame.request_id === this.loginRequestId) {
      if (frame.op === "error") {
        const error = new DarknyxApiError(
          frame.code ?? 4010,
          frame.message ?? "stream login failed",
          401,
        );
        this.loginRequestId = null;
        this.refreshInFlight = false;
        if (!this.ready) this.failConnect(error);
        this.opts.onError?.(error);
        this.ws?.close();
        return;
      }
      if (frame.op === "login") {
        const firstLogin = !this.ready;
        this.loginRequestId = null;
        this.refreshInFlight = false;
        this.ready = true;
        if (firstLogin) {
          this.finishConnect();
          this.startHeartbeat();
          this.resubscribe();
        }
        return;
      }
    }

    if (frame.channel) {
      const channel = frame.channel as StreamChannel;
      const listeners = this.channelListeners.get(channel);
      if (!listeners) return;
      for (const listener of listeners) {
        try {
          listener.onMessage(frame);
        } catch (error) {
          this.opts.onError?.(
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      }
      return;
    }

    const requestId = frame.request_id;
    const pending = requestId ? this.pending.get(requestId) : undefined;
    if (!pending) {
      this.opts.onUnsolicited?.(frame);
      return;
    }
    this.pending.delete(requestId!);
    if (frame.op === "error") {
      pending.reject(
        new DarknyxApiError(
          frame.code ?? 5000,
          frame.message ?? "stream request failed",
          frame.code ?? 0,
        ),
      );
    } else {
      pending.resolve(frame.result ?? null);
    }
  }

  private protocolFailure(message: string): void {
    const error = new Error(message);
    this.opts.onError?.(error);
    this.notifyResync(message);
    this.ws?.close();
  }

  private finishConnect(): void {
    this.connectResolve?.();
    this.connectPromise = null;
    this.connectResolve = null;
    this.connectReject = null;
  }

  private failConnect(error: Error): void {
    this.connectReject?.(error);
    this.connectPromise = null;
    this.connectResolve = null;
    this.connectReject = null;
  }

  private onSocketClose(code: number, reason?: string): void {
    const wasReady = this.ready;
    this.ready = false;
    this.ws = null;
    this.loginRequestId = null;
    this.refreshInFlight = false;
    this.stopHeartbeat();
    if (!wasReady) {
      this.failConnect(new Error(`stream closed before login (code ${code})`));
    }
    for (const pending of this.pending.values()) {
      pending.reject(new Error(`stream closed (code ${code})`));
    }
    this.pending.clear();
    if (code === 1011) this.notifyResync(reason ?? "stream lagged");
    for (const listeners of this.channelListeners.values()) {
      for (const listener of listeners) listener.hooks.onClose?.(code, reason);
    }
    this.opts.onClose?.(code, reason);
    if (!this.permanentlyClosed && (this.opts.autoReconnect ?? true)) {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.connect().catch((error) => {
        this.opts.onError?.(error as Error);
        if (!this.permanentlyClosed) this.scheduleReconnect();
      });
    }, this.opts.reconnectDelayMs ?? 250);
    this.reconnectTimer.unref?.();
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ready && this.ws) {
        this.ws.send(JSON.stringify({ op: "ping" }));
      }
    }, 25_000);
    this.heartbeatTimer.unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  private notifyResync(reason: string): void {
    for (const listeners of this.channelListeners.values()) {
      for (const listener of listeners) listener.hooks.onResync?.(reason);
    }
  }

  private sendControl(
    op: "subscribe" | "unsubscribe",
    channels: string[],
  ): void {
    if (!this.ready || !this.ws || channels.length === 0) return;
    this.ws.send(
      JSON.stringify({
        op,
        request_id: this.nextId(op),
        channels,
      }),
    );
  }

  private resubscribe(): void {
    this.sendControl("subscribe", [...this.channelListeners.keys()]);
  }

  /** Register a channel listener on this session. */
  subscribeChannel(
    channel: StreamChannel,
    onMessage: (frame: unknown) => void,
    hooks: StreamChannelHooks = {},
  ): StreamChannelSubscription {
    let listeners = this.channelListeners.get(channel);
    const wasEmpty = !listeners || listeners.size === 0;
    if (!listeners) {
      listeners = new Set();
      this.channelListeners.set(channel, listeners);
    }
    const listener = { onMessage, hooks };
    listeners.add(listener);
    if (wasEmpty) this.sendControl("subscribe", [channel]);
    void this.connect().catch((error) => this.opts.onError?.(error as Error));

    return {
      close: () => {
        const current = this.channelListeners.get(channel);
        current?.delete(listener);
        if (current?.size === 0) {
          this.channelListeners.delete(channel);
          this.sendControl("unsubscribe", [channel]);
        }
      },
    };
  }

  private async request<T>(frame: Record<string, unknown>): Promise<T> {
    await this.connect();
    if (!this.ws || !this.ready) throw new Error("stream not connected");
    const requestId = this.nextId();
    const promise = new Promise<T>((resolve, reject) => {
      this.pending.set(requestId, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
    });
    this.ws.send(JSON.stringify({ ...frame, request_id: requestId }));
    return promise;
  }

  place(order: PlaceOrderRequest): Promise<PlaceOrderResponse> {
    return this.request<PlaceOrderResponse>({
      op: "order.place",
      params: order,
    });
  }

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

  ping(): Promise<void> {
    return this.request<void>({ op: "ping" });
  }

  close(): void {
    this.permanentlyClosed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.stopHeartbeat();
    const ws = this.ws;
    this.ws = null;
    this.ready = false;
    for (const pending of this.pending.values()) {
      pending.reject(new Error("stream client closed"));
    }
    this.pending.clear();
    this.failConnect(new Error("stream client closed"));
    ws?.close();
  }
}
