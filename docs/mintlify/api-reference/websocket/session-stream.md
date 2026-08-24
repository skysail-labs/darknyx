---
description: "The sole authenticated WebSocket, with in-band login, order operations, and dynamic channel subscriptions."
---

# Session Stream

{% hint style="info" %}
**TL;DR**

`/v1/stream` is the sole multiplexed socket: place, cancel, and modify orders, and receive
order, fill, and tree-append pushes. You authenticate **in-band** with an
`op: login` frame (not a `?token=` query param), then subscribe to the channels
you want.
{% endhint %}

The legacy `/ws/trading`, `/ws/orders`, and `/ws/fills` routes are removed. The
[order operations](./ws-trading.md), [orders channel](./orders-channel.md), and
[fills channel](./fills-channel.md) pages document facets of this one session.

## Connect and log in

```text
wss://<ra-tls-origin>/v1/stream
```

The socket upgrades **unauthenticated**. Every op except `ping` is rejected until
a successful `login`. Login must complete within **10 seconds** of opening the
socket; traffic and pings do not extend that absolute window:

```json
{ "op": "login", "token": "<access_token>", "cancel_on_disconnect": true }
```

| Field                  | Required | Description                                                                                                                          |
| ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `op`                   | Yes      | `"login"`.                                                                                                                           |
| `token`                | Yes      | A bearer token from [`POST /auth/token`](../getting-started/authentication.md).                                                                  |
| `cancel_on_disconnect` | No       | If `true`, the engine cancels still-resting orders placed through this session when the socket drops. Recommended for market makers. |

To refresh an expiring token, send another `login` on the same socket without
dropping your subscriptions. The server emits an `auth_expired` reminder about
60 seconds before expiry.

The venue also caps total sockets and concurrent sockets per account. A full
venue refuses the HTTP upgrade with `503` plus `Retry-After`; an over-limit
account receives stream error `4290` and remains unauthenticated. Reuse one
multiplexed session instead of opening one socket per market or channel. A
token refresh must retain the same account identity; attempting to switch
accounts on an authenticated socket returns stream error `4030` and requires a
new connection.

For Node clients, open this URL with the verified WebSocket factory returned by
`createVerifiedTransport`, not a stock WebSocket or an accept-any-certificate
setting. That factory gates the upgrade socket against the enclave's
quote-bound, boot-scoped certificate before a login frame can leave.

## Subscribe to channels

```json
{ "op": "subscribe", "channels": ["orders", "fills", "tree"] }
```

| Channel  | Scope       | What it pushes                                                                                                                                        |
| -------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `orders` | Per-account | Settlement reservations, confirmed fills, terminal failures, cancellations, and expiries. Same payloads as the [Orders Channel](./orders-channel.md). |
| `fills`  | Per-account | Your continuation-fill memos. Same payloads, and the same verify-before-store rule, as the [Fills Channel](./fills-channel.md).                       |
| `tree`   | Global      | Leaf-append events, for keeping an incremental view of the note tree (for example, live portfolio state).                                             |

`unsubscribe` takes the same `channels` array. Each server push is tagged with a
top-level `channel` field so you can route it.

Every server frame also carries one connection-global monotonic `seq`. A gap,
or close code `1011`, means state may have been missed. Reconnect, re-read the
orders you track, recover notes from chain, refresh the relevant tree snapshot,
and then resume tailing. A server-side fan-out loss closes every active session
with `1011`, even if your own consumer was fast, so silence must never be read as
completeness.

## Submit orders

The order ops dispatch to the **same** intake and verification as
[`POST /orders`](../orders/place-order.md) and the [order operations](./ws-trading.md), so
the bodies are identical and an order-level trading-key signature is still
required on every frame. Each carries a `request_id` the server echoes in its
reply; later state changes arrive on the `orders` channel.

```json
{ "op": "order.place",  "request_id": "r1", "params": { /* a Place Order body */ } }
{ "op": "order.cancel", "request_id": "r2", "order_id": "aa00…01",
  "params": { "trading_key": "…", "cancel_nonce": "2", "session_id": "…",
    "trading_key_signature": "…" } }
{ "op": "order.modify", "request_id": "r3", "order_id": "aa00…01",
  "params": { "cancel_signature": "…", "cancel_nonce": "2",
    "replacement": { /* a Place Order body */ } } }
```

`order.modify` is an atomic cancel-and-replace under one matcher lock, the same as
[`PUT /orders/{order_id}`](../orders/modify-order.md).

## Heartbeat

Send `{ "op": "ping" }` at least every 30 seconds; the server replies
`{ "op": "pong" }`. A session silent for more than 60 seconds is dropped.
Send `{ "op": "logout" }` for a clean client-initiated close.

## What is not served here

`account` and `settlement` are not channels on this socket. Account state is
reconstructed client-side from the `tree` channel (or the [`/tree/*`](../tree/README.md)
endpoints) plus your keys, never delivered as a balance (see
[Account Model](/documentation/account/account-model)); settlement status is read with
[`GET /settlement/status/{batch_id}`](../settlement/settlement-status.md).
