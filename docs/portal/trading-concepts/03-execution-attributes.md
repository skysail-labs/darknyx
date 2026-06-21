---
sidebar_position: 3
title: Execution Attributes
description: Constrain how an order fills — all-or-none and minimum fill size — independent of its type and time in force.
---

# Execution Attributes

:::info TL;DR
Execution attributes constrain *how* an order fills, on top of its type. Nyx
supports a **minimum fill size** — reject any execution smaller than a threshold —
and **all-or-none**, which is the special case where the threshold equals the full
order amount.
:::

## Minimum fill size

```text
min_fill_size: <integer base units>
```

`min_fill_size` rejects any single execution smaller than the given amount. A
batch may only include the order if it can fill at least `min_fill_size` of it.
Use it to avoid being filled in dust-sized increments — useful when each fill
produces a change note you would rather not accumulate.

- Default `0` — any partial fill is acceptable.
- Set it to a positive value to require executions of at least that size.

## All-or-None (AON)

All-or-none is `min_fill_size == amount`: the order fills *completely* or not at
all in any given batch. Because it is expressed through `min_fill_size`, an AON
order can still **rest** — a limit order with `min_fill_size = amount` keeps
waiting, batch after batch, until one batch can fill it whole at its price.

```text
amount = 100, min_fill_size = 100   →  fills 100 or nothing, but keeps resting
```

This is the resting cousin of [FOK](./order-types#fok): FOK demands whole
execution *immediately* and is dropped otherwise; an AON limit demands whole
execution but is patient.

## AON vs. min_fill_size

| You want | Set |
|---|---|
| Accept any partial fill | `min_fill_size = 0` (default) |
| Avoid dust fills, accept larger partials | `min_fill_size = <threshold>` |
| Fill whole or not at all, but keep waiting | `min_fill_size = amount` (AON limit) |
| Fill whole or not at all, immediately | `order_type = "fok"` |

## Interaction with order type

| Type | `min_fill_size` honored? | Notes |
|---|---|---|
| `limit` | Yes | The general case; AON is `min_fill_size = amount`. |
| `ioc` | Yes | Constrains the immediate take; the residual cancels regardless. |
| `fok` | Implicit | FOK is already whole-or-nothing; `min_fill_size` adds nothing. |

See [Order Compatibility](./order-compatibility) for the full validity matrix.
