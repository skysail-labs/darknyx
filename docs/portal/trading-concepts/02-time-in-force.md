---
sidebar_position: 2
title: Time in Force
description: How long an order stays working — GTC, GTT, IOC, and FOK — expressed through the order type and a slot-based expiry.
---

# Time in Force

:::info TL;DR
Time-in-force on Nyx is expressed two ways: the **order type** decides whether an
order may rest (limit rests; IOC and FOK do not), and **`expiry_slot`** decides
how long a resting order lives. Order expiry is measured in **Solana slots**, not
wall-clock time.
:::

## The two controls

| Control | Field | Effect |
|---|---|---|
| May it rest? | `order_type` | `limit` rests; `ioc` and `fok` execute immediately and never rest. |
| How long may it rest? | `expiry_slot` | The slot past which a resting order auto-expires. |

Every order carries an `expiry_slot`, bounded by the market's maximum so a note
cannot be locked forever. A resting order is swept when the chain passes that
slot.

## Available behaviors

### GTC — Good-til-Cancelled

A **limit** order with a far-future `expiry_slot`. It rests until it fills, you
cancel it, or it eventually hits its (distant) expiry. This is the standard
resting order.

### GTT — Good-til-Time

A **limit** order with an `expiry_slot` chosen to match a wall-clock deadline. To
place "good for the next ten minutes," read [`/time`](../api/base-urls) for the
current slot and project your deadline onto a slot (Solana targets roughly 400 ms
per slot). The SDK does this conversion for you:

```text
expiry_slot = current_slot + ceil((deadline_ms - now_ms) / slot_ms)
```

When the chain passes `expiry_slot`, the order is swept and an `expired` event is
emitted on the [Orders Channel](../websocket/orders-channel).

### IOC — Immediate-or-Cancel

An `ioc` order. Fills what it can in its arrival batch, cancels the rest. Never
rests, so `expiry_slot` is moot for it.

### FOK — Fill-or-Kill

A `fok` order. Fills its whole size in its arrival batch or is dropped. Never
rests and never partially fills.

## Summary

| TIF | Expressed as | Rests? |
|---|---|---|
| GTC | `limit` + far `expiry_slot` | Yes, until fill / cancel / expiry |
| GTT | `limit` + deadline-derived `expiry_slot` | Yes, until the deadline slot |
| IOC | `ioc` | No |
| FOK | `fok` | No |

:::note Slots, not timestamps
Because settlement is on Solana, expiry is anchored to the chain's clock — the
slot — so it stays consistent with on-chain state. `/time` gives you both the slot
and the wall-clock instant so you can convert between them. See
[Order Types](./order-types) for how the type controls resting, and
[Execution Attributes](./execution-attributes) for fill-size constraints.
:::
