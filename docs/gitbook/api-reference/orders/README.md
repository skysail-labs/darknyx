---
description: "Place, inspect, modify and cancel hidden orders. Every operation is authenticated; writes are signed by your trading key."
---

# Orders

The order lifecycle. All four operations require a bearer token. Place, modify,
and cancel additionally require your trading-key signature over their canonical
intent; the read operation does not.

An order here is not a message the venue takes on trust. It is fully
collateralized by a note you already deposited, and it carries a zero-knowledge
proof that the note exists and is yours to spend. The engine can therefore match
and settle it without ever learning your identity, and without a per-order
on-chain transaction.

| Operation | Endpoint | Notes |
|---|---|---|
| [Place Order](place-order.md) | `POST /orders` | Carries the collateral commitment, input proof and viewing key. |
| [Get Order](get-order.md) | `GET /orders/{order_id}` | Current status while the order remains in bounded server retention. |
| [Modify Order](modify-order.md) | `PUT /orders/{order_id}` | Atomic cancel + replace. |
| [Cancel Order](cancel-order.md) | `DELETE /orders/{order_id}` | Signed cancel intent. |

{% hint style="info" %}
You do not assemble the cryptographic fields by hand. The
[TypeScript SDK](/documentation/sdk/typescript-client) takes your keys and a
spendable note and produces a ready-to-sign request.
{% endhint %}

`GET /orders/{order_id}` is a live reconciliation aid, not permanent history.
Terminal orders age out and then return `404`. Consume the orders stream for
fast lifecycle updates; recover durable terminal fills from the client seed and
finalized chain.

## See also

- [Order Types](/documentation/trading-concepts/order-types)
- [Time in Force](/documentation/trading-concepts/time-in-force)
- [Self-Trade Prevention](/documentation/trading-concepts/self-trade-prevention)
