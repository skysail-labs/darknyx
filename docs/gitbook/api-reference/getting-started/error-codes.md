---
description: "How Darknyx signals failure, covering the HTTP status codes, the conditions that produce them, and how to handle them."
---


# Error Codes

{% hint style="info" %}
**TL;DR**

Every error response is a small JSON **envelope**, `{ code, message }`, with a
mapped HTTP status. `code` is a **stable numeric error code** you can branch on;
`message` is the human-readable reason. Every response (success and error)
carries an **`x-request-id`** header for correlating with server logs. Success
responses are not enveloped; their typed body is returned directly.
{% endhint %}

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
| `1002` | — | **Retired.** Rejected a `user_commitment` whose top byte was non-zero — a field that no longer exists, behind a rule that was not Fr-safety (audit 2026-07-25, T-07). Never reused, so a stale reference reads as "gone". Canonicality of the values that ARE hashed is enforced by the opening re-derivation and surfaces as `1006`. |
| `1003` | 400 | Collateral below the order's nominal cost + fee. |
| `1004` | 400 | Order amount below the market minimum. |
| `1005` | 400 | A bid with a zero price limit. |
| `1006` | 400 | The note opening does not re-derive the signed `note_commitment`. |
| `1007` | 400 | `expiry_slot` exceeds the maximum lock lifetime. |
| `1008` | 400 | The X25519 viewing key is low-order or otherwise non-contributory. |
| `1009` | 400 | A non-zero price limit is not an integer multiple of the market tick. |
| `1010` | 400 | The `merkle_root` your collateral proof was built against is no longer in the venue's recent-root window. Re-prove against a current root and resubmit. |
| `1011` | 400 | The collateral proof did not verify. |
| `1012` | 400 | `expiry_slot` is already expired or does not leave the required settlement buffer. Read `/time` and submit a future absolute slot. |
| `1101` | 401 | Missing / invalid / expired / revoked token, or bad credentials. Also returned when an operator has invalidated the tokens an account was holding. |
| `1102` | 403 | The trading-key signature did not verify. |
| `1103` | 403 | The trading key does not own the targeted order. |
| `1150` | 403 | Forbidden: an admin-only route, or **the account is suspended**. A suspended account also gets `403` from `POST /auth/token`, so re-authenticating does not clear it. |
| `1201` | 409 | Duplicate order id (a different order already holds it). |
| `1202` | 409 | A replay-protection nonce did not advance. |
| `1203` | 409 | A modify's replacement id is already booked. |
| `1204` | 409 | The collateral note commitment is already reserved by a live or settlement-pending order. |
| `1205` | 409 | The order targets a stale or unrelated CVM boot session. |
| `1206` | 409 | An administrative change was refused because it would leave the venue with no enabled admin account. |
| `1301` | 404 | No such order / batch / instrument / note. |
| `1401` | 429 | Rate limited; back off and retry. Order-operation responses include `Retry-After`; authentication messages include an approximate delay. Authentication is per-account, so this reflects your own usage rather than someone else's. |
| `1402` | 503 | Credential verification is momentarily at capacity. Shed rather than queued, so it clears quickly—use a short, jittered retry. |
| `5000` | 500 | Internal error. |
| `5001` | 503 | A required subsystem (matching / settlement) is unavailable. |
| `5002` | 503 | The selected Merkle mirror diverges from on-chain state. Do not build a proof from it; read the tree from Solana until the venue cold-resyncs. |

Codes are stable: branch on the number, not the message text (which may change).

## Status reference

| Status | Class | Typical conditions |
|---|---|---|
| `400 Bad Request` | Malformed input | Invalid hex; wrong field width; a non-canonical field element; zero `order_id`; zero-price bid; invalid viewing key; excessive expiry; bad opening; or insufficient collateral. |
| `401 Unauthorized` | Auth | Missing bearer token; expired or revoked token; invalid credentials on `POST /auth/token`. |
| `403 Forbidden` | Ownership or account state | The trading-key signature did not verify over the canonical body; the trading key does not own the order being cancelled or modified; or the account is suspended. |
| `404 Not Found` | Missing resource | No such order (already filled / expired / cancelled), batch, or instrument. |
| `409 Conflict` | State conflict | Duplicate `order_id`; stale arrival nonce or boot session; collateral already reserved; or a modify whose replacement id is already booked. |
| `429 Too Many Requests` | Rate limit | Operational rate limit exceeded; back off and retry. Order operations and authentication are metered separately, and both are per-account. |
| `503 Service Unavailable` | Subsystem down, unsafe mirror, or auth at capacity | Matching or settlement is not available (see [`/system/status`](../system/system-status.md)); a tree mirror is unsafe (`5002`); or credential verification is momentarily saturated (`1402`). |

## Conditions by endpoint

### Authentication
- `401`: bad credentials (`POST /auth/token`); a missing, expired, or revoked
  token on an authenticated request; or a token an operator invalidated. Token
  expiry is **exact** — there is no grace period past `expires_in`.
- `403` (`1150`): the account is suspended. Returned both on authenticated
  requests and on `POST /auth/token`, so re-authenticating does not clear it.
  Not retryable.
- `429` (`1401`): this account's authentication allowance is exhausted. An
  unrecognised `api_key` is refused before any verification work, so it consumes
  no allowance.
- `503` (`1402`): verification is at capacity; requests are refused rather than
  queued. Retry after a short, jittered delay.

Authenticate **once per token lifetime**, not once per action — a client that
caches its token for the `expires_in` window will not meet these limits.

### Place order
- `400`: malformed fields, a failed field-element check, a zero order id, a bid
  with zero price, an off-tick non-zero price, an opening that does not match the
  signed commitment, or collateral below the required (nominal + fee) floor.
- `400` (`1010` / `1011`): the collateral proof was rejected **at intake** —
  either its Merkle root has aged out of the recent-root window, or the proof
  itself did not verify. Rebuild against a current root and resubmit.
- `403`: the trading-key signature does not verify.
- `409`: the `order_id` is already in the book, or the collateral commitment is
  reserved by another live/pending order.

### Cancel / modify
- `403`: signature does not verify, or the key does not own the order.
- `404`: the order is not resting (filled / expired / cancelled).
- `409`: cancel nonce or boot session is stale.
- `409` (modify): the replacement `order_id` is already booked.

### Reads (orders, settlement, tree)
- `400`: malformed id / parameter hex.
- `404`: unknown order / batch / note. `GET /orders/{id}` intentionally returns
  this same response for a foreign account's order.
- `503` (`5002`, tree only): the mirror disagrees with Solana. Read the selected
  `MerkleTree` account and leaves from chain; do not keep retrying the unsafe
  mirror.

{% hint style="success" %}
**A rejected order is better than an accepted one that cannot settle**

Collateral proofs are verified when the order is submitted, not when it
settles. An order whose proof is stale or invalid is refused immediately with
`1010` / `1011` and costs you nothing.

Previously such an order was booked, matched, and only rejected on-chain — at
which point the whole batch failed, taking an honest counterparty's collateral
down with it into a locked state neither of you chose. Seeing these codes means
that no longer happens: rebuild the proof against a current root and resubmit.
{% endhint %}

## Handling errors

| Status | Recommended client behavior |
|---|---|
| `400` | A bug in request construction; fix and do not blindly retry. |
| `401` | Refresh the bearer token and retry once. |
| `403` | For `1102`/`1103`, check the trading key and canonical body. For `1150 account disabled`, stop retrying and contact the operator. |
| `404` (on cancel/modify) | Treat as "no longer resting"; reconcile via `GET /orders/{id}` or the orders stream. |
| `409` | For a duplicate order id, use a fresh id; for a stale nonce, advance it. |
| `429` | Back off with jitter; prefer one shared `/v1/stream` session for high-frequency management. |
| `503` | For `1402`, retry authentication after a short jittered delay. For `5001`, poll `/system/status` and the target instrument. For `5002`, bypass the mirror and read the tree from Solana until the operator resyncs it. |

{% hint style="success" %}
**Make cancels idempotent in your logic**

A cancel that races a fill returns `404` once the order has matched. Treat
`404`-on-cancel as success-equivalent ("the order is gone") and reconcile state,
rather than as a hard error.
{% endhint %}
