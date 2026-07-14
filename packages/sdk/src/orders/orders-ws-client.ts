/**
 * Live order-lifecycle transport — the per-account `orders` channel on the
 * multiplexed `/v1/stream` session.
 *
 * The matcher emits an `OrderUpdate` each time one of the account's orders
 * changes state in a tick (partial/full fill, expiry); an explicit cancel
 * (DELETE /orders/:id, or the cancel leg of a PUT /orders/:id modify) emits a
 * synthetic `cancelled`. Terminal kinds (`fully_filled` / `cancelled` /
 * `expired`) are the order's last event.
 *
 * Authentication is in-band and the TEE routes per-account so a subscriber
 * only ever sees its own orders. Unlike fills, an order update carries no
 * secret-bearing memo to verify — it's a state-transition notice keyed by
 * `order_id`.
 */

import type { WebSocketFactory } from "../fills/ws-client.js";
import {
  TradingClient,
  type StreamTokenProvider,
} from "./trading-ws-client.js";

/** Wire shape of one order-lifecycle event (mirrors `OrderUpdateMsg`). */
export interface OrderUpdate {
  /** Per-connection monotonic sequence. A gap means missed events — reconcile
   *  via `GET /orders/:id` (the channel is a notifier, not a durable log). */
  seq?: number;
  order_id: string; // 16-byte hex
  kind: "partially_filled" | "fully_filled" | "cancelled" | "expired";
  /** Present on fills. */
  filled_quantity?: number;
  /** Present on a partial fill: the residual base amount still resting. */
  new_amount?: number;
  /** Present on a partial fill: the residual collateral-note amount. */
  new_note_amount?: number;
}

/** A terminal update is the order's last event (it has left the book). */
export function isTerminalUpdate(u: OrderUpdate): boolean {
  return (
    u.kind === "fully_filled" || u.kind === "cancelled" || u.kind === "expired"
  );
}

export interface SubscribeOrderUpdatesOptions {
  /** Gateway WS origin. `/v1/stream` is appended. */
  gatewayWsUrl: string;
  token: string;
  tokenProvider?: StreamTokenProvider;
  onUpdate: (u: OrderUpdate) => void;
  onError?: (err: Error) => void;
  /** Server closed with 1011 (lagged past the buffer) — caller should resync from the indexer. */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  webSocketFactory?: WebSocketFactory;
  /** Reuse an existing multiplexed session (recommended for daemons). */
  streamClient?: TradingClient;
}

export interface OrderUpdatesSubscription {
  close(): void;
}

/** Subscribe to the per-account order-lifecycle channel. */
export function subscribeOrderUpdates(
  opts: SubscribeOrderUpdatesOptions,
): OrderUpdatesSubscription {
  const owned = !opts.streamClient;
  const stream =
    opts.streamClient ??
    new TradingClient({
      gatewayWsUrl: opts.gatewayWsUrl,
      token: opts.token,
      tokenProvider: opts.tokenProvider,
      webSocketFactory: opts.webSocketFactory,
      onError: opts.onError,
    });
  const channel = stream.subscribeChannel(
    "orders",
    (frame) => {
      try {
        const update = frame as OrderUpdate;
        opts.onUpdate(update);
      } catch (e) {
        opts.onError?.(e as Error);
      }
    },
    { onResync: opts.onResync, onClose: opts.onClose },
  );

  return {
    close() {
      channel.close();
      if (owned) stream.close();
    },
  };
}
