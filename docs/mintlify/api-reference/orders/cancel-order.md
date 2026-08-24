---
description: "Cancel a resting order with a signed cancel request from the owning trading key."
---

# Cancel Order

{% hint style="info" %}
**TL;DR**

`DELETE /orders/{order_id}` removes a resting order. The body carries a fresh
**trading-key signature** over the order id, cancel nonce, and current boot
session, proving the caller owns the order. Only the trading key that placed the
order can cancel it.
{% endhint %}

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/orders/{order_id}" method="delete" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

Auth: `Authorization: Bearer <token>` **and** a trading-key cancel signature in
the body.

## Path parameters

| Parameter  | Type   | Description                           |
| ---------- | ------ | ------------------------------------- |
| `order_id` | string | The 16-byte order id (hex) to cancel. |

## Request body

```json
{
  "trading_key": "…",
  "cancel_nonce": "1",
  "session_id": "…",
  "trading_key_signature": "…"
}
```

| Field                   | Type           | Required | Description                                                                                                                                                                        |
| ----------------------- | -------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `trading_key`           | string         | Yes      | 32-byte hex. Must be the key that placed the order.                                                                                                                                |
| `cancel_nonce`          | decimal string | Yes      | A canonical `u64` decimal string bound into the signed cancel body. It must **strictly increase** per trading key; the string form avoids JavaScript precision loss.               |
| `session_id`            | string         | Yes      | Current 32-byte `/info.boot_session_id`, hex. It scopes the cancel to one engine boot. Programmatic clients verify the same value in the transport-attestation manifest; a substituted value only makes the engine reject the request. |
| `trading_key_signature` | string         | Yes      | 64-byte hex. Ed25519 signature over the canonical cancel body: `{ order_id, trading_key, cancel_nonce, session_id }`.                                                              |

The cancel nonce is part of the signed bytes, so a captured cancel request cannot
be replayed to cancel a _different_ (later, same-id) order, because the canonical body,
and therefore the signature, differs.

The canonical body also binds the **boot session**, and the nonce must strictly
advance per trading key. Together these scope a signed cancel to one venue boot:
a cancel captured before a restart cannot be replayed against the session that
follows it, and one captured within a session cannot be replayed at all.

The session id is the same value place orders bind — the current
`/info.boot_session_id`. If you sign cancels yourself rather than through the
SDK, read it once per session and include it; a body missing it will not verify.
A CVM restart changes it, so refresh it before signing anything further.

## Example

```bash
curl -s -X DELETE "$GATEWAY/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trading_key": "…",
    "cancel_nonce": "1",
    "session_id": "…",
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

| Field      | Type   | Description               |
| ---------- | ------ | ------------------------- |
| `order_id` | string | The cancelled order's id. |
| `status`   | string | `"cancelled"`.            |

When an order is cancelled, the engine releases its collateral reservation and
drops the in-enclave note opening. A `cancelled` event is also emitted on the
[Orders Channel](../websocket/orders-channel.md) so a streaming client sees the
order leave without polling.

## Errors

| Condition                                                                | Status |
| ------------------------------------------------------------------------ | ------ |
| Malformed `order_id` / `trading_key` / signature hex                     | `400`  |
| Missing or invalid bearer token                                          | `401`  |
| The signature does not verify, or the key does not own the order         | `403`  |
| No such (resting) order, already filled, expired, or cancelled           | `404`  |
| The cancel nonce did not advance, or the session belongs to another boot | `409`  |

{% hint style="info" %}
**Cancelling races the match**

An order can match in a batch between when you decide to cancel and when the
cancel lands. If the order has already left the book, the cancel returns `404`.
Treat a `404` on cancel as "the order is no longer resting" and reconcile via
[`GET /orders/{order_id}`](./get-order.md) or the orders stream.
{% endhint %}
