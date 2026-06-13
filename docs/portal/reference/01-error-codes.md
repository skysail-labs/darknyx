---
sidebar_position: 1
title: Error Codes
description: How Nyx signals failure — HTTP status codes and the conditions that produce them — and how to handle them.
---

# Error Codes

:::info TL;DR
REST errors are signaled by HTTP **status code** plus a human-readable message
describing the specific reason. WebSocket frame errors carry the same
HTTP-equivalent status as a `code` field. Branch on the status; log the message.
:::

## Error shape

A failed REST request returns a non-2xx HTTP status and a message:

```json
{ "error": "trading_key_signature does not verify against the canonical body" }
```

A failed `/ws/trading` frame returns an `error` reply whose `code` is the
HTTP-equivalent status and whose `message` is the same reason string:

```json
{ "op": "error", "request_id": "r2", "code": 403, "message": "not the order owner" }
```

## Status reference

| Status | Class | Typical conditions |
|---|---|---|
| `400 Bad Request` | Malformed input | Invalid hex; wrong field width; a hashed field that is not a valid field element; a zero `order_id`; a bid with `price_limit = 0`; an opening that does not re-derive the signed note commitment; collateral below the required floor; wrong anchor count. |
| `401 Unauthorized` | Auth | Missing bearer token; expired or revoked token; invalid credentials on `POST /auth/token`. |
| `403 Forbidden` | Ownership | The trading-key signature did not verify over the canonical body; the trading key does not own the order being cancelled / modified / topped up. |
| `404 Not Found` | Missing resource | No such order (already filled / expired / cancelled), batch, or instrument. |
| `409 Conflict` | State conflict | Duplicate `order_id`; a modify whose replacement id is already booked; a top-up nonce that did not advance. |
| `429 Too Many Requests` | Rate limit | Operational rate limit exceeded — back off and retry. |
| `503 Service Unavailable` | Subsystem down | Matching or settlement is not available; see [`/system/status`](./system-status). |

## Conditions by endpoint

### Authentication
- `401` — bad credentials (`POST /auth/token`), or a missing / expired / revoked
  token on an authenticated request.

### Place order
- `400` — malformed fields, a failed field-element check, a zero order id, a bid
  with zero price, an opening that does not match the signed commitment, or
  collateral below the required (nominal + fee) floor.
- `403` — the trading-key signature does not verify.
- `409` — the `order_id` is already in the book.

### Cancel / modify / top-up
- `403` — signature does not verify, or the key does not own the order.
- `404` — the order is not resting (filled / expired / cancelled).
- `409` (modify) — the replacement `order_id` is already booked.
- `409` (top-up) — the `topup_nonce` did not advance.

### Reads (orders, settlement, tree)
- `400` — malformed id / parameter hex.
- `404` — unknown order / batch / note.

## Handling errors

| Status | Recommended client behavior |
|---|---|
| `400` | A bug in request construction — fix and do not blindly retry. |
| `401` | Refresh the bearer token and retry once. |
| `403` | Check you signed with the correct trading key over the correct canonical body. |
| `404` (on cancel/modify) | Treat as "no longer resting"; reconcile via `GET /orders/{id}` or the orders stream. |
| `409` | For a duplicate order id, use a fresh id; for a stale nonce, advance it. |
| `429` | Back off with jitter; prefer the WebSocket trading socket for high-frequency management. |
| `503` | Poll `/system/status`; resume when matching/settlement is available. |

:::tip Make cancels idempotent in your logic
A cancel that races a fill returns `404` once the order has matched. Treat
`404`-on-cancel as success-equivalent ("the order is gone") and reconcile state,
rather than as a hard error.
:::
