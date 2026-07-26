---
description: "How long an order stays working (GTC, GTT, IOC, and FOK), expressed through the order type and a slot-based expiry."
---


# Time in Force

{% hint style="info" %}
**TL;DR**

Time-in-force on Darknyx is expressed two ways: the **order type** decides whether an
order may rest (limit rests; IOC and FOK do not), and **`expiry_slot`** decides
how long a resting order lives. Order expiry is measured in **Solana slots**, not
wall-clock time.
{% endhint %}

## The two controls

| Control | Field | Effect |
|---|---|---|
| May it rest? | `order_type` | `limit` rests; `ioc` and `fok` execute immediately and never rest. |
| How long may it rest? | `expiry_slot` | The slot past which a resting order auto-expires. |

Every order carries an `expiry_slot`, bounded by the protocol's maximum so a
note cannot be locked forever. The current ceiling is 4,500 slots (roughly 30
minutes at 400 ms slots). A resting order is swept when the chain passes its
expiry.

## Available behaviors

### GTC: Good-til-Cancelled

A **limit** order whose `expiry_slot` is at the venue's allowed horizon. It
rests until it fills, you cancel it, or it reaches that bounded expiry. This is
“good until cancelled” within the protocol's maximum order lifetime, not an
indefinite order.

### GTT: Good-til-Time

A **limit** order with an `expiry_slot` chosen to match a wall-clock deadline. To
place "good for the next ten minutes," read [`/time`](../api/base-urls.md) for the
current slot and project your deadline onto a slot (Solana targets roughly 400 ms
per slot). The SDK does this conversion for you:

```text
expiry_slot = current_slot + ceil((deadline_ms - now_ms) / slot_ms)
```

When the chain passes `expiry_slot`, the order is swept and an `expired` event is
emitted on the [Orders Channel](../websocket/orders-channel.md).

### IOC: Immediate-or-Cancel

An `ioc` order. Fills what it can in its arrival batch, cancels the rest. It
never rests, but its `expiry_slot` must still leave enough time for the match
and settlement pipeline.

### FOK: Fill-or-Kill

A `fok` order. Fills its whole size in its arrival batch or is dropped. It never
rests and never partially fills, but still carries a settlement-safe expiry.

## Summary

| TIF | Expressed as | Rests? |
|---|---|---|
| GTC | `limit` + maximum allowed `expiry_slot` | Yes, until fill / cancel / bounded expiry |
| GTT | `limit` + deadline-derived `expiry_slot` | Yes, until the deadline slot |
| IOC | `ioc` | No |
| FOK | `fok` | No |

{% hint style="info" %}
**Slots, not timestamps**

Because settlement is on Solana, expiry is anchored to the chain's clock, the
slot, so it stays consistent with on-chain state. `/time` gives you both the slot
and the wall-clock instant so you can convert between them. See
[Order Types](./order-types.md) for how the type controls resting, and
[Execution Attributes](./execution-attributes.md) for fill-size constraints.
{% endhint %}
