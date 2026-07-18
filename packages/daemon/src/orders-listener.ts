/**
 * OrdersListener — the daemon's `/v1/stream` orders channel (order PHASE).
 *
 * Wraps the SDK `subscribeOrderUpdates`: the TEE emits one `OrderUpdate` per
 * state transition of this account's orders (`pending_settlement` /
 * `partially_filled` / `fully_filled` / `settlement_failed` / `cancelled` /
 * `expired`). This listener maps each to the lifecycle phase
 * event that drives the state machine's terminal transitions + the
 * merge-on-quiescence sweep:
 *
 *   pending_settlement → `settlement-pending` (reserve; no fill yet)
 *   partially_filled → `partial-fill-confirmed` (advances the reserved order
 *                                   back to `open`; residual-note bookkeeping
 *                                   comes from the `fills` channel, NOT here)
 *   fully_filled     → `filled`
 *   settlement_failed → `settlement-failed` (terminal; explicit resubmit)
 *   cancelled        → `cancelled`
 *   expired          → `expired`
 *
 * This is also how the daemon learns its quotes were pulled by
 * **cancel-on-disconnect**: the TEE's sweep routes a synthetic `cancelled`
 * onto the `orders` channel (`announce_cancel`), so after a reconnect the strategy sees
 * the order go `cancelled` and can re-quote — no server change, fully observable.
 *
 * `subscribeOrderUpdates` is injected (a seam) so the listener is unit-testable
 * with synthetic updates and no live socket. A `seq` gap means missed updates;
 * the orchestrator should reconcile via `GET /orders/:id` (surfaced via
 * `onResync`/`onError`) — the channel is a notifier, not a durable log.
 */

import {
  subscribeOrderUpdates,
  type OrderUpdate,
  type OrderUpdatesSubscription,
  type TradingClient,
  type WebSocketFactory,
} from "@darknyx/sdk";

import type { LifecycleEngine } from "./lifecycle-engine.js";
import type { LifecycleEvent } from "./order-lifecycle.js";

/** The SDK entrypoint this listener wraps (injected for tests). */
export type SubscribeOrderUpdatesFn = typeof subscribeOrderUpdates;

export interface OrdersListenerOptions {
  engine: LifecycleEngine;
  /** Gateway WS origin (`/v1/stream` is appended by the SDK). */
  gatewayWsUrl: string;
  token: string;
  webSocketFactory?: WebSocketFactory;
  streamClient?: TradingClient;
  /** Fired after each update is mapped + dispatched. */
  onUpdate?: (u: OrderUpdate) => void;
  onError?: (err: Error) => void;
  /** Server closed 1011 (lagged) — reconcile open orders via `GET /orders/:id`. */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  /** Seam for tests; defaults to the real SDK `subscribeOrderUpdates`. */
  subscribeFn?: SubscribeOrderUpdatesFn;
}

/** Map an `orders` channel update kind to the lifecycle phase event, or `null` if
 *  it carries no phase transition the reducer needs. */
export function updateToEvent(u: OrderUpdate): LifecycleEvent | null {
  switch (u.kind) {
    case "pending_settlement":
      return {
        type: "settlement-pending",
        lockExpirySlot: u.lock_expiry_slot ?? 0,
      };
    case "partially_filled":
      return { type: "partial-fill-confirmed" };
    case "fully_filled":
      return { type: "filled" };
    case "settlement_failed":
      return {
        type: "settlement-failed",
        reason: u.reason ?? "settlement failed",
        lockExpirySlot: u.lock_expiry_slot ?? 0,
      };
    case "cancelled":
      return { type: "cancelled" };
    case "expired":
      return { type: "expired" };
    default:
      return null;
  }
}

export class OrdersListener {
  private sub: OrderUpdatesSubscription | null = null;

  constructor(private readonly opts: OrdersListenerOptions) {}

  start(): void {
    const subscribe = this.opts.subscribeFn ?? subscribeOrderUpdates;
    this.sub = subscribe({
      gatewayWsUrl: this.opts.gatewayWsUrl,
      token: this.opts.token,
      webSocketFactory: this.opts.webSocketFactory,
      streamClient: this.opts.streamClient,
      onUpdate: (u) => {
        void this.handleUpdate(u);
      },
      onError: this.opts.onError,
      onResync: this.opts.onResync,
      onClose: this.opts.onClose,
    });
  }

  private async handleUpdate(u: OrderUpdate): Promise<void> {
    this.opts.onUpdate?.(u);
    const event = updateToEvent(u);
    if (!event) return;
    try {
      await this.opts.engine.dispatch(u.order_id, event);
    } catch (err) {
      // An update for an order the daemon doesn't track (or that races ahead of
      // registration) must not tear down the socket — surface + keep listening.
      this.opts.onError?.(err as Error);
    }
  }

  stop(): void {
    this.sub?.close();
    this.sub = null;
  }
}
