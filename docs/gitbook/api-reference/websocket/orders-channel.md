---
description: "A per-account stream of settlement reservations, confirmed fills, terminal failures, cancellations, and expiries."
---


# Orders Channel

{% hint style="info" %}
**TL;DR**

The `orders` channel on `/v1/stream` streams **order-lifecycle events** for your account: each time one
of your orders is reserved, confirms a fill, fails settlement, cancels, or expires, the
engine pushes an event. The stream is per-account: you only ever see your own
orders. Use it instead of polling `GET /orders/{id}`.
{% endhint %}

## Connect

```text
wss://<gateway-host>/v1/stream
```

Login in-band, then send `{"op":"subscribe","channels":["orders"]}` on the
same session used for order operations and fills. The channel is
**per-account**: events are routed to you
by the order-id → account mapping the engine records at intake, so a subscriber
only ever receives events for orders it placed.

## Event shape

Each message is a JSON object describing one state transition:

```json
{
  "seq": 12,
  "order_id": "aa00000000000000000000000000000001",
  "market_id": "DZyMmY4a6QEmh2xvmhUQwYcxbphtfJxwcvYSEdLobBEo",
  "match_id": "42",
  "server_time_ms": 1784271002880,
  "kind": "partially_filled",
  "filled_quantity": 3000000,
  "new_amount": 7000000,
  "new_note_amount": 1050000000
}
```

| Field | Type | Present when | Description |
|---|---|---|---|
| `seq` | integer | always | Per-connection monotonic sequence, starting at 1. A gap means missed events. |
| `order_id` | string | always | The 16-byte order id, hex. |
| `market_id` | string | always | Base58 on-chain `MarketConfig` PDA identifying the order's market. |
| `match_id` | string | settlement events | Per-market match id encoded as a decimal string to preserve u64 precision. |
| `server_time_ms` | integer | always | Venue emission time in Unix milliseconds. |
| `kind` | string | always | `pending_settlement`, `partially_filled`, `fully_filled`, `settlement_failed`, `cancelled`, or `expired`. |
| `filled_quantity` | integer | on fills | Cumulative filled quantity. |
| `new_amount` | integer | on partial fill | The residual base amount still resting. |
| `new_note_amount` | integer | on partial fill | The residual collateral-note value after the fill re-locked the remainder. |
| `reason` | string | settlement failure | Human-readable definitive rejection reason. |
| `lock_expiry_slot` | integer | pending/failure | Earliest relevant unlock boundary. After failure, wait until this slot before reusing the input in a fresh order. |

## Event kinds

| `kind` | Terminal? | Meaning |
|---|---|---|
| `pending_settlement` | No | A private match reserved the order. Quantities have not changed and no fill is final yet. |
| `partially_filled` | No | Part of the order filled; the remainder keeps resting (re-locked into a new note). |
| `fully_filled` | Yes | The order filled completely. |
| `settlement_failed` | Yes | Settlement definitively failed. The old order is never auto-rebooked; submit a fresh signed order after `lock_expiry_slot`. |
| `cancelled` | Yes | The order was cancelled, whether by you, by a modify, or on session disconnect. |
| `expired` | Yes | The order reached its `expiry_slot` without fully filling. |

A **terminal** event is the order's last; after it, the order has left the book
and produces no further events.

## Event flow

```text
order.place ──► pending_settlement ──► partially_filled ──► … ──► fully_filled
                                                                       └── terminal
                    └──► settlement_failed             (terminal; fresh order required)
            └──► (rests) ──► expired / cancelled             (terminal)
```

A partial fill carries the residual size so you always know how much is still
working; the matching fill *memo* (which note the change went into) arrives on
the [Fills Channel](./fills-channel.md).

## Gap recovery

Every event carries a per-connection monotonic `seq` (starting at 1). Track the
last `seq` you processed; if the next event's `seq` is not exactly one greater,
you missed events in between, so reconcile the orders you care about with
`GET /orders/{order_id}`.

If a slow consumer falls behind the per-account buffer, the server also closes the
socket with code **1011**. On a 1011 close, reconnect and reconcile. The channel
is a low-latency notifier, not a durable log.

## Example

```javascript
const ws = new WebSocket(`${WSS}/v1/stream`);

ws.onopen = () => {
  ws.send(JSON.stringify({ op: "login", request_id: "login-1", token: TOKEN }));
};

ws.onmessage = (e) => {
  const ev = JSON.parse(e.data);
  if (ev.op === "login") {
    ws.send(JSON.stringify({ op: "subscribe", channels: ["orders"] }));
    return;
  }
  if (ev.channel !== "orders") return;
  switch (ev.kind) {
    case "pending_settlement":
      console.log(`reserved until settlement resolves: ${ev.order_id}`);
      break;
    case "partially_filled":
      console.log(`partial: ${ev.filled_quantity} filled, ${ev.new_amount} resting`);
      break;
    case "fully_filled":
      console.log(`filled: ${ev.order_id}`);
      break;
    case "cancelled":
    case "expired":
      console.log(`${ev.kind}: ${ev.order_id}`);
      break;
    case "settlement_failed":
      console.error(ev.reason, `retry after slot ${ev.lock_expiry_slot}`);
      break;
  }
};

ws.onclose = (e) => {
  if (e.code === 1011) reconnectAndReconcile();
};
```
