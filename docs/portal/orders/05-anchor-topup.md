---
sidebar_position: 5
title: Anchor Top-Up
description: Replenish a partially-filled order's continuation anchor pool so it can keep filling without being re-submitted.
---

# Anchor Top-Up

:::info TL;DR
A resting order carries a pool of pre-supplied **continuation anchors** that let
the engine settle partial fills and re-lock the remainder automatically. A
long-lived, frequently-filled order can exhaust that pool. `POST
/orders/{order_id}/anchors` appends a fresh batch of anchors so the order resumes
filling — no cancel-and-replace, no new proof.
:::

```text
POST /orders/{order_id}/anchors
```

Auth: `Authorization: Bearer <token>` **and** a trading-key signature in the body.

## Background: the anchor pool

When an order partially fills, the unfilled remainder needs to keep resting as a
*new* note (the previous collateral note is consumed by the fill). To do that
without a round-trip to you on every fill, you pre-supply a small pool of
**continuation anchors** when you place the order — each anchor is the secret
material for one future change note. The engine consumes one anchor per partial
fill to mint the remainder note and keep the order working. See
[The Anchor Pool](../trading-concepts/anchor-pool) for the full mechanism.

A pool is finite. An order that fills in many small increments can drain it; when
it does, the engine pauses the order's continuation rather than guess at note
material it does not have. Topping the pool up resumes it.

## Path parameters

| Parameter | Type | Description |
|---|---|---|
| `order_id` | string | The 16-byte id (hex) of the live order to top up. |

## Request body

```json
{
  "anchors": [ { "inner_hash": "…", "nullifier": "…" }, "… 5 total …" ],
  "topup_nonce": 1,
  "trading_key": "…",
  "trading_key_signature": "…"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `anchors` | array | Yes | Exactly **5** fresh `{ inner_hash, nullifier }` anchors (both 32-byte hex), continuing the order's anchor sequence. |
| `topup_nonce` | integer | Yes | A strictly-increasing per-order counter (replay protection). Must exceed the last accepted top-up nonce for this order. |
| `trading_key` | string | Yes | 32-byte hex. Must own the order. |
| `trading_key_signature` | string | Yes | 64-byte hex. Ed25519 signature over the canonical top-up body — `{ order_id, hash-of-the-new-anchors, topup_nonce }`. |

## Example

```bash
curl -s -X POST "$GATEWAY/orders/$ORDER_ID/anchors" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "anchors": [ { "inner_hash": "…", "nullifier": "…" }, "… 5 total …" ],
    "topup_nonce": 1,
    "trading_key": "…",
    "trading_key_signature": "…"
  }'
```

## Success response

```json
{
  "order_id": "aa00000000000000000000000000000001",
  "status": "topped_up",
  "remaining": 15
}
```

| Field | Type | Description |
|---|---|---|
| `order_id` | string | The order's id. |
| `status` | string | `"topped_up"`. |
| `remaining` | integer | Anchors not yet consumed after the append. |

Appending also clears the paused state, so the engine resumes the order's
continuation on the next batch.

## Errors

| Condition | Status |
|---|---|
| Wrong anchor count, malformed hex, or a non-canonical anchor value | `400` |
| Missing or invalid bearer token | `401` |
| The signature does not verify, or the key does not own the order | `403` |
| The order is gone (filled / cancelled / expired) | `404` |
| `topup_nonce` did not advance past the last accepted value | `409` |

:::tip Top up before you run dry
The order's status and the pool's remaining count let you top up *before* an
order pauses, so it never stops filling. A market maker keeping a quote resting
across many fills should monitor the remaining anchors and replenish proactively.
:::
