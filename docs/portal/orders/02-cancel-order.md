---
sidebar_position: 2
title: Cancel Order
description: Cancel a resting order with a signed cancel request from the owning trading key.
---

# Cancel Order

:::info TL;DR
`DELETE /orders/{order_id}` removes a resting order. The body carries a fresh
**trading-key signature** over the order id and a cancel nonce, proving the
caller owns the order. Only the trading key that placed the order can cancel it.
:::

```text
DELETE /orders/{order_id}
```

Auth: `Authorization: Bearer <token>` **and** a trading-key cancel signature in
the body.

## Path parameters

| Parameter | Type | Description |
|---|---|---|
| `order_id` | string | The 16-byte order id (hex) to cancel. |

## Request body

```json
{
  "trading_key": "…",
  "cancel_nonce": 1,
  "trading_key_signature": "…"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `trading_key` | string | Yes | 32-byte hex. Must be the key that placed the order. |
| `cancel_nonce` | integer | Yes | A nonce bound into the signed cancel body (replay protection). |
| `trading_key_signature` | string | Yes | 64-byte hex. Ed25519 signature over the canonical cancel body — `{ order_id, trading_key, cancel_nonce }`. |

The cancel nonce is part of the signed bytes, so a captured cancel request cannot
be replayed to cancel a *different* (later, same-id) order — the canonical body,
and therefore the signature, differs.

## Example

```bash
curl -s -X DELETE "$GATEWAY/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trading_key": "…",
    "cancel_nonce": 1,
    "trading_key_signature": "…"
  }'
```

## Success response

```json
{
  "order_id": "aa00000000000000000000000000000001",
  "status": "cancelled"
}
```

| Field | Type | Description |
|---|---|---|
| `order_id` | string | The cancelled order's id. |
| `status` | string | `"cancelled"`. |

When an order is cancelled, the engine releases its collateral note and discards
its continuation anchor pool. A `cancelled` event is also emitted on the
[Orders Channel](../websocket/orders-channel) so a streaming client sees the
order leave without polling.

## Errors

| Condition | Status |
|---|---|
| Malformed `order_id` / `trading_key` / signature hex | `400` |
| Missing or invalid bearer token | `401` |
| The signature does not verify, or the key does not own the order | `403` |
| No such (resting) order — already filled, expired, or cancelled | `404` |

:::note Cancelling races the match
An order can match in a batch between when you decide to cancel and when the
cancel lands. If the order has already left the book, the cancel returns `404`.
Treat a `404` on cancel as "the order is no longer resting" and reconcile via
[`GET /orders/{order_id}`](./get-order) or the orders stream.
:::
