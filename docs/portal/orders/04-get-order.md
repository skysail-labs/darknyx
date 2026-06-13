---
sidebar_position: 4
title: Get Order
description: Read the current status of one order — its state, filled quantity, and the batch it matched in.
---

# Get Order

:::info TL;DR
`GET /orders/{order_id}` returns the current state of one order: its status,
filled quantity, and remaining size. For live updates without polling, subscribe
to the [Orders Channel](../websocket/orders-channel) instead.
:::

```text
GET /orders/{order_id}
```

Auth: `Authorization: Bearer <token>`.

## Path parameters

| Parameter | Type | Description |
|---|---|---|
| `order_id` | string | The 16-byte order id (hex). |

## Example

```bash
curl -s "$GATEWAY/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

## Response

```json
{
  "order_id": "aa00000000000000000000000000000001",
  "side": "bid",
  "order_type": "limit",
  "status": "pending",
  "amount": 10000000,
  "filled_quantity": 0,
  "price_limit": 150000000,
  "expiry_slot": 309490000,
  "arrival_slot": 309482113
}
```

## Field reference

| Field | Type | Description |
|---|---|---|
| `order_id` | string | The order id. |
| `side` | string | `"bid"` or `"ask"`. |
| `order_type` | string | `"limit"`, `"ioc"`, or `"fok"`. |
| `status` | string | `pending`, `matched`, `expired`, or `cancelled`. |
| `amount` | integer | The order's original size, in base units. |
| `filled_quantity` | integer | How much has filled so far. |
| `price_limit` | integer | The worst acceptable price (quote units per base). |
| `expiry_slot` | integer | The slot the order auto-expires at. |
| `arrival_slot` | integer | The slot the engine stamped on arrival. |

## Streaming alternative

Polling `GET /orders/{order_id}` is fine for a one-off check or to reconcile after
a missed event. For a trading client that needs to react to fills, subscribe to
the [Orders Channel](../websocket/orders-channel): the engine pushes a lifecycle
event (partial fill, full fill, expiry) the moment an order's state changes,
without a request per check.

## Errors

| Condition | Status |
|---|---|
| Malformed `order_id` hex | `400` |
| Missing or invalid bearer token | `401` |
| No order with that id is currently tracked | `404` |

:::note Terminal orders age out
The book tracks resting and recently-terminal orders. A long-since-filled,
expired, or cancelled order may no longer be queryable here; recover fill details
from your durable fill history (see [Fills Channel](../websocket/fills-channel))
and on-chain settlement status.
:::
