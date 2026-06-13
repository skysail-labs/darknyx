---
sidebar_position: 1
title: Order Types
description: The order types Nyx supports — limit, IOC, and FOK — plus the market and all-or-none conventions built on top of them.
---

# Order Types

:::info TL;DR
Nyx has three native order types: **limit**, **IOC**, and **FOK**. A **market**
order is a convention — an IOC with a price cap — and an **all-or-none** order is
a limit with its minimum fill size set to the full amount. Every order clears at
the batch's single oracle-anchored price.
:::

## How matching works here

Nyx is a **batch auction**, not a continuous order book. Each tick, the engine
collects the resting orders that cross and clears them at a **single uniform
price** anchored to the market's oracle (see [Clearing Price](./clearing-price)).
There is no maker/taker ordering *within* a batch — both sides of every match get
the same price. The order type controls how long an order is willing to wait and
whether it may rest.

## Native types

### Limit

```text
order_type: "limit"
```

A resting order with a worst-acceptable `price_limit`. It stays in the book across
batches until it fills, reaches its `expiry_slot`, or you cancel it. It fills only
at a clearing price at least as good as its limit. This is the default for
providing liquidity.

- A **bid** limit fills at the clearing price if that price is `<= price_limit`.
- An **ask** limit fills if the clearing price is `>= price_limit`.

### IOC — Immediate-or-Cancel

```text
order_type: "ioc"
```

Takes whatever it can in the batch it arrives in, then cancels any remainder. It
never rests. Use it to cross the spread *now* without leaving a resting order
behind. A bid IOC names a `price_limit` as its worst price; an ask IOC may use `0`
to accept any clearing price.

### FOK — Fill-or-Kill

```text
order_type: "fok"
```

All-or-nothing, immediately. It fills its *entire* size in its arrival batch or is
dropped — it never rests and never partially fills. Use it when a partial
execution is worse than none.

## Conventions built on the native types

These are not separate wire types — they are well-known configurations of the
native fields. The SDK exposes a builder for each so you do not hand-encode them.

### Market

A **market order** is an **IOC with a price cap**:

- A market **bid** is an IOC whose `price_limit` is the worst price you will pay
  (your collateral note must cover it).
- A market **ask** is an IOC with `price_limit = 0` — sell into any clearing
  price.

Because it is IOC, the residual auto-cancels; a market order never rests and never
pins a note in the book.

### All-or-None (resting)

An **all-or-none** order is a **limit with `min_fill_size = amount`**. It rests
like a normal limit but only fills if the batch can fill its *entire* size at its
limit or better; otherwise it waits. Unlike FOK (which is immediate), an AON limit
keeps resting until a batch can satisfy it whole. See
[Execution Attributes](./execution-attributes).

## Summary

| Type | Rests? | Partial fills? | Use it for |
|---|---|---|---|
| Limit | Yes | Yes | Providing liquidity at a price. |
| Limit + AON | Yes | No (all-or-none) | Resting liquidity you only want filled whole. |
| Market (IOC + cap) | No | Yes | Crossing now, up to a price cap. |
| IOC | No | Yes | Taking available liquidity, no resting remainder. |
| FOK | No | No (all-or-none) | Immediate, whole, or nothing. |

See [Order Compatibility](./order-compatibility) for which combinations of type,
time-in-force, and execution attributes are valid.
