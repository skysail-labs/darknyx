---
sidebar_position: 1
title: Error Codes
description: How Darknyx signals failure, covering the HTTP status codes, the conditions that produce them, and how to handle them.
---

# Error Codes

:::info TL;DR
Every error response is a small JSON **envelope**, `{ code, message }`, with a
mapped HTTP status. `code` is a **stable numeric error code** you can branch on;
`message` is the human-readable reason. Every response (success and error)
carries an **`x-request-id`** header for correlating with server logs. Success
responses are not enveloped; their typed body is returned directly.
:::

## Error shape

A failed REST request returns a non-2xx HTTP status and the envelope:

```json
{ "code": 1102, "message": "trading_key_signature does not verify against the canonical body" }
```

A failed `/v1/stream` order frame returns an `error` reply carrying the **same**
numeric `code` and `message` the REST path would have returned:

```json
{ "op": "error", "request_id": "r2", "code": 1103, "message": "not the order owner" }
```

Every response includes an `x-request-id` header:

```text
x-request-id: req_a3f19c7b21d40e8a
```

Quote it when reporting an issue; it ties your request to the server's log line.

## Code catalogue

Codes are grouped by class. The HTTP status is derived from the class.

| Code | HTTP | Meaning |
|---|---|---|
| `1000` | 400 | Generic bad request. |
| `1001` | 400 | Malformed input: bad hex, wrong width, zero/illegal id, or invalid field combination. |
| `1002` | 400 | A hashed field is not a canonical field element (BN254 Fr-unsafe). |
| `1003` | 400 | Collateral below the order's nominal cost + fee. |
| `1004` | 400 | Order amount below the market minimum. |
| `1005` | 400 | A bid with a zero price limit. |
| `1006` | 400 | The note opening does not re-derive the signed `note_commitment`. |
| `1007` | 400 | `expiry_slot` exceeds the maximum lock lifetime. |
| `1008` | 400 | The X25519 viewing key is low-order or otherwise non-contributory. |
| `1101` | 401 | Missing / invalid / expired / revoked token, or bad credentials. |
| `1102` | 403 | The trading-key signature did not verify. |
| `1103` | 403 | The trading key does not own the targeted order. |
| `1150` | 403 | Forbidden (e.g. admin-only route). |
| `1201` | 409 | Duplicate order id (a different order already holds it). |
| `1202` | 409 | A replay-protection nonce did not advance. |
| `1203` | 409 | A modify's replacement id is already booked. |
| `1204` | 409 | The collateral note commitment is already reserved by a live or settlement-pending order. |
| `1205` | 409 | The order targets a stale or unrelated CVM boot session. |
| `1301` | 404 | No such order / batch / instrument / note. |
| `1401` | 429 | Rate limited; back off and retry. |
| `5001` | 503 | A required subsystem (matching / settlement) is unavailable. |
| `5000` | 500 | Internal error. |

Codes are stable: branch on the number, not the message text (which may change).

## Status reference

| Status | Class | Typical conditions |
|---|---|---|
| `400 Bad Request` | Malformed input | Invalid hex; wrong field width; a non-canonical field element; zero `order_id`; zero-price bid; invalid viewing key; excessive expiry; bad opening; or insufficient collateral. |
| `401 Unauthorized` | Auth | Missing bearer token; expired or revoked token; invalid credentials on `POST /auth/token`. |
| `403 Forbidden` | Ownership | The trading-key signature did not verify over the canonical body, or the trading key does not own the order being cancelled or modified. |
| `404 Not Found` | Missing resource | No such order (already filled / expired / cancelled), batch, or instrument. |
| `409 Conflict` | State conflict | Duplicate `order_id`; stale arrival nonce or boot session; collateral already reserved; or a modify whose replacement id is already booked. |
| `429 Too Many Requests` | Rate limit | Operational rate limit exceeded; back off and retry. |
| `503 Service Unavailable` | Subsystem down | Matching or settlement is not available; see [`/system/status`](./system-status). |

## Conditions by endpoint

### Authentication
- `401`: bad credentials (`POST /auth/token`), or a missing / expired / revoked
  token on an authenticated request.

### Place order
- `400`: malformed fields, a failed field-element check, a zero order id, a bid
  with zero price, an opening that does not match the signed commitment, or
  collateral below the required (nominal + fee) floor.
- `403`: the trading-key signature does not verify.
- `409`: the `order_id` is already in the book, or the collateral commitment is
  reserved by another live/pending order.

### Cancel / modify
- `403`: signature does not verify, or the key does not own the order.
- `404`: the order is not resting (filled / expired / cancelled).
- `409` (modify): the replacement `order_id` is already booked.

### Reads (orders, settlement, tree)
- `400`: malformed id / parameter hex.
- `404`: unknown order / batch / note. `GET /orders/{id}` intentionally returns
  this same response for a foreign account's order.

## Handling errors

| Status | Recommended client behavior |
|---|---|
| `400` | A bug in request construction; fix and do not blindly retry. |
| `401` | Refresh the bearer token and retry once. |
| `403` | Check you signed with the correct trading key over the correct canonical body. |
| `404` (on cancel/modify) | Treat as "no longer resting"; reconcile via `GET /orders/{id}` or the orders stream. |
| `409` | For a duplicate order id, use a fresh id; for a stale nonce, advance it. |
| `429` | Back off with jitter; prefer one shared `/v1/stream` session for high-frequency management. |
| `503` | Poll `/system/status`; resume when matching/settlement is available. |

:::tip Make cancels idempotent in your logic
A cancel that races a fill returns `404` once the order has matched. Treat
`404`-on-cancel as success-equivalent ("the order is gone") and reconcile state,
rather than as a hard error.
:::
