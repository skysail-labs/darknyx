---
sidebar_position: 3
title: Modify Order
description: Replace a resting order atomically — an in-place cancel-and-replace with no window where you hold neither order.
---

# Modify Order

:::info TL;DR
`PUT /orders/{order_id}` modifies a resting order as an **atomic cancel +
replace**. The body carries a signed cancel of the old order plus a full,
independently-signed replacement order. The swap happens under one lock with both
preconditions checked first, so there is never a moment where you hold neither
order.
:::

```text
PUT /orders/{order_id}
```

Auth: `Authorization: Bearer <token>` **and** two signatures (a cancel of the old
order and a full new order), both from the **same** trading key.

## Why modify instead of cancel-then-place

Cancelling and re-placing as two separate calls leaves a gap: between the cancel
landing and the new order arriving, you have *no* order resting — and a batch may
clear in that gap. `PUT /orders/{order_id}` closes the gap. It verifies both
sides, then applies the cancel and the replacement atomically: either the swap
happens whole, or nothing changes.

## Path parameters

| Parameter | Type | Description |
|---|---|---|
| `order_id` | string | The 16-byte id (hex) of the OLD order to replace. |

## Request body

```json
{
  "cancel_signature": "…",
  "cancel_nonce": 2,
  "replacement": { "… a full Place Order body …" }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `cancel_signature` | string | Yes | 64-byte hex. Ed25519 signature over the canonical cancel body of the OLD order — proves ownership of what is being replaced. |
| `cancel_nonce` | integer | Yes | The cancel nonce bound into `cancel_signature`. |
| `replacement` | object | Yes | A complete, independently-signed [Place Order](./place-order) body. It carries its own collateral note and input proof. |

The trading key that signs the cancel **must** be the key that signs the
replacement. The replacement may reuse the old order's note and proof while that
proof's root is still in the on-chain root window, or it may point at a different
note — it is a normal place-order body either way.

### Reprice in place

If the replacement's `order_id` equals the path `order_id`, the modify is a
"reprice in place": the cancel frees the id and the replacement reclaims it, so
the logical order keeps its identity. If the replacement uses a new `order_id`,
the old id is retired and a `cancelled` event is emitted for it on the orders
stream.

## Example

```bash
curl -s -X PUT "$GATEWAY/orders/$OLD_ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cancel_signature": "…",
    "cancel_nonce": 2,
    "replacement": { "symbol": "SOL-USDC", "side": "bid", "…": "…" }
  }'
```

## Success response

```json
{
  "old_order_id": "aa00000000000000000000000000000001",
  "order_id": "aa00000000000000000000000000000002",
  "status": "modified",
  "arrival_slot": 309482140
}
```

| Field | Type | Description |
|---|---|---|
| `old_order_id` | string | The replaced order's id. |
| `order_id` | string | The new order's id (equals `old_order_id` on a reprice in place). |
| `status` | string | `"modified"`. |
| `arrival_slot` | integer | The slot stamped on the replacement order. |

## Atomicity guarantees

Both preconditions are checked **before** anything mutates:

1. The old order exists and is owned by the signing trading key.
2. The replacement's `order_id` is not already booked (unless it equals the old
   id — the reprice-in-place case).

If either fails, the call returns an error and **neither** order is touched. Only
when both hold does the engine cancel the old order and book the replacement under
the same lock — no batch can clear between the two.

## Errors

| Condition | Status |
|---|---|
| Malformed fields / the replacement fails place-order verification | `400` |
| Missing or invalid bearer token | `401` |
| A signature does not verify, or the caller does not own the old order | `403` |
| The old order does not exist | `404` |
| The replacement's `order_id` is already booked | `409` |
