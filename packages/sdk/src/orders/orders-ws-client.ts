/**
 * Live order-lifecycle transport — the per-account `GET /ws/orders` stream.
 *
 * The matcher emits an `OrderUpdate` each time one of the account's orders
 * changes state in a tick (partial/full fill, expiry); an explicit cancel
 * (DELETE /orders/:id, or the cancel leg of a PUT /orders/:id modify) emits a
 * synthetic `cancelled`. Terminal kinds (`fully_filled` / `cancelled` /
 * `expired`) are the order's last event.
 *
 * Same self-auth + injectable-WebSocket shape as `fills/ws-client.ts`: the
 * token rides as `?token=` (the global `WebSocket` can't set an Authorization
 * header), and the TEE routes per-account so a subscriber only ever sees its
 * own orders. Unlike fills, an order update carries no secret-bearing memo to
 * verify — it's a state-transition notice keyed by `order_id`.
 */

import type { WebSocketLike, WebSocketFactory } from "../fills/ws-client.js";

const defaultWsFactory: WebSocketFactory = (url) =>
  new (globalThis as { WebSocket: new (u: string) => WebSocketLike }).WebSocket(
    url,
  );

/** Wire shape of one order-lifecycle event (mirrors `OrderUpdateMsg`). */
export interface OrderUpdate {
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
  /** Gateway WS origin, e.g. `wss://<app>-8080.dstack-…`. `/ws/orders` is appended. */
  gatewayWsUrl: string;
  token: string;
  onUpdate: (u: OrderUpdate) => void;
  onError?: (err: Error) => void;
  /** Server closed with 1011 (lagged past the buffer) — caller should resync from the indexer. */
  onResync?: (reason: string) => void;
  onClose?: (code: number, reason?: string) => void;
  webSocketFactory?: WebSocketFactory;
}

export interface OrderUpdatesSubscription {
  close(): void;
}

/** Open one per-account order-lifecycle WebSocket. Single connection. */
export function subscribeOrderUpdates(
  opts: SubscribeOrderUpdatesOptions,
): OrderUpdatesSubscription {
  const base = opts.gatewayWsUrl.replace(/\/$/, "");
  const url = `${base}/ws/orders?token=${encodeURIComponent(opts.token)}`;
  const ws = (opts.webSocketFactory ?? defaultWsFactory)(url);
  let closedByCaller = false;

  ws.addEventListener("message", (ev) => {
    try {
      const text = typeof ev.data === "string" ? ev.data : String(ev.data);
      const update = JSON.parse(text) as OrderUpdate;
      opts.onUpdate(update);
    } catch (e) {
      opts.onError?.(e as Error);
    }
  });
  ws.addEventListener("error", (e) => opts.onError?.(e as Error));
  ws.addEventListener("close", (ev) => {
    if (closedByCaller) return;
    if (ev.code === 1011) opts.onResync?.(ev.reason ?? "lagged");
    opts.onClose?.(ev.code, ev.reason);
  });

  return {
    close() {
      closedByCaller = true;
      ws.close();
    },
  };
}
