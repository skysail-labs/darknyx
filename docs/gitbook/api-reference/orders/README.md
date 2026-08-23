---
description: "Place, inspect, modify and cancel hidden orders. Every operation is authenticated and signed by your trading key."
---

# Orders

The order lifecycle. Four operations, all authenticated with a bearer token
**and** signed by your trading key over the canonical order intent.

An order here is not a message the venue takes on trust. It is fully
collateralized by a note you already deposited, and it carries a zero-knowledge
proof that the note exists and is yours to spend. The engine can therefore match
and settle it without ever learning your identity, and without a per-order
on-chain transaction.

| Operation | Endpoint | Notes |
|---|---|---|
| [Place Order](place-order.md) | `POST /orders` | Carries the collateral commitment, input proof and viewing key. |
| [Get Order](get-order.md) | `GET /orders/{order_id}` | Server-side status; the authority after a stream gap. |
| [Modify Order](modify-order.md) | `PUT /orders/{order_id}` | Atomic cancel + replace. |
| [Cancel Order](cancel-order.md) | `DELETE /orders/{order_id}` | Signed cancel intent. |

{% hint style="info" %}
You do not assemble the cryptographic fields by hand. The
[TypeScript SDK](/documentation/sdk/typescript-client) takes your keys and a
spendable note and produces a ready-to-sign request.
{% endhint %}

## See also

- [Order Types](/documentation/trading-concepts/order-types)
- [Time in Force](/documentation/trading-concepts/time-in-force)
- [Self-Trade Prevention](/documentation/trading-concepts/self-trade-prevention)
