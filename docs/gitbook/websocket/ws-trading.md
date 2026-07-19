---
description: "Submit framed place, cancel, and modify requests on the multiplexed session stream."
---


# Order Operations

{% hint style="info" %}
**TL;DR**

`/v1/stream` is the sole bidirectional WebSocket. Authenticate in-band, stream framed
`order.place` / `order.cancel` / `order.modify` requests and receive one reply
per frame, dispatched to the **same** intake and verification the REST endpoints
use. The same session carries `orders`, `fills`, and `tree` subscriptions,
short-lived-token refresh, and **cancel-on-disconnect** for market makers.
{% endhint %}

## Connect

```text
wss://<gateway-host>/v1/stream
```

The socket upgrades without credentials in the URL. Its first authenticated
operation is a `login` frame. Set `cancel_on_disconnect` in that frame:

```json
{
  "op": "login",
  "request_id": "login-1",
  "token": "<access_token>",
  "cancel_on_disconnect": true
}
```

{% hint style="warning" %}
**The order signature is still required**

Authenticating the socket establishes *who is connected*, not *who owns an
order*. Every `order.place` / `order.cancel` / `order.modify` frame still carries
the per-order **trading-key signature** (the same one the REST endpoints require).
An authenticated socket cannot move another key's orders.
{% endhint %}

## Message format

Every frame is JSON, tagged by `op`. Requests may carry a `request_id`, which the
reply echoes so a client can correlate responses on the multiplexed socket.

### Request frames

| `op` | Fields | Equivalent REST |
|---|---|---|
| `login` | `request_id?`, `token`, `cancel_on_disconnect?` | establishes or refreshes session auth |
| `subscribe` | `request_id?`, `channels` | subscribes to `orders`, `fills`, or `tree` |
| `order.place` | `request_id?`, `params` (a full [Place Order](../orders/place-order.md) body) | `POST /orders` |
| `order.cancel` | `request_id?`, `order_id`, `params` (`trading_key`, `cancel_nonce`, `trading_key_signature`) | `DELETE /orders/{id}` |
| `order.modify` | `request_id?`, `order_id`, `params` (a [Modify Order](../orders/modify-order.md) body) | `PUT /orders/{id}` |
| `ping` | `request_id?` | none |

```json
{ "op": "order.place", "request_id": "r1", "params": { "symbol": "SOL-USDC", "side": "bid", "…": "…" } }
```

### Reply frames

Every reply carries a per-connection monotonic `seq` (starting at 1) so a client
can detect a dropped frame.

| `op` | Fields | Meaning |
|---|---|---|
| `order.place` | `seq`, `request_id?`, `result` | Order accepted; `result` mirrors the REST place response. |
| `order.cancel` | `seq`, `request_id?`, `result` | Order cancelled. |
| `order.modify` | `seq`, `request_id?`, `result` | Order modified. |
| `pong` | `seq`, `request_id?` | Heartbeat reply. |
| `auth_expired` | `seq`, `expires_at` | Refresh the token with another `login` before expiry. |
| `error` | `seq`, `request_id?`, `code`, `message` | A frame failed. `code` is the stable numeric [error code](../reference/error-codes.md); `message` is the same reason the REST path would have returned. |

```json
{ "op": "order.place", "seq": 1, "request_id": "r1", "result": { "order_id": "aa…01", "status": "accepted", "arrival_slot": 309482113 } }
```

```json
{ "op": "error", "seq": 2, "request_id": "r2", "code": 1102, "message": "trading_key_signature does not verify against the canonical body" }
```

## Cancel-on-disconnect

When you login with `cancel_on_disconnect: true`, the engine tracks the orders
placed on **this** socket and, when the socket closes, cancels the ones still
resting. This protects a market maker that loses connectivity from leaving stale
quotes crossing.

You can also set an **account-wide default** so every socket gets the behavior
without setting it in each login: `PUT /account/settings` with
`{ "cancel_on_disconnect_default": true }`. An explicit login value overrides
the account default for that connection.

The teardown is a server-initiated cancel using each order's own booked key. It
needs no client signature, because the order was placed on this authenticated
session and a cancel only un-rests an order (it never settles or moves funds).

```text
socket opens  ──►  order.place ×N  ──►  (connectivity lost / socket closes)
                                              │
                                              ▼
                          engine cancels this session's still-resting orders
```

Orders that have already filled, expired, or been cancelled are left as-is; only
still-resting orders from this session are swept.

## Heartbeat

Send a `ping` frame periodically to keep the connection live and detect a
half-open socket; the server replies `pong`. Transport-level WebSocket pings are
also answered.

## Example

```javascript
const ws = new WebSocket(`${WSS}/v1/stream`);
let id = 0;
const next = () => `r-${++id}`;

ws.onopen = () => {
  ws.send(JSON.stringify({
    op: "login",
    request_id: next(),
    token: TOKEN,
    cancel_on_disconnect: true,
  }));
};

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.op === "login") {
    ws.send(JSON.stringify({ op: "subscribe", request_id: next(), channels: ["orders", "fills"] }));
    ws.send(JSON.stringify({ op: "order.place", request_id: next(), params: order }));
  }
  if (msg.op === "auth_expired") refreshToken().then((token) => {
    ws.send(JSON.stringify({ op: "login", request_id: next(), token }));
  });
  if (msg.op === "error") console.error("rejected", msg.code, msg.message);
  else if (msg.op === "order.place") console.log("accepted", msg.result.order_id);
};

setInterval(() => ws.send(JSON.stringify({ op: "ping", request_id: next() })), 20000);
```

## REST vs. WebSocket

| Aspect | REST | Session stream |
|---|---|---|
| Latency | Higher (TLS + HTTP per request) | Lower (one persistent socket) |
| Auth | Bearer header per request | In-band login/refresh; order signature per frame |
| Disconnect safety | None | Optional cancel-on-disconnect |
| Best for | One-off calls, cold starts | Long-running trading clients, market makers |

For live order state and fill memos, subscribe to the [Orders Channel](./orders-channel.md)
and [Fills Channel](./fills-channel.md) on this same socket.
