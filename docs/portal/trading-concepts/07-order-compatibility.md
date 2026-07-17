---
sidebar_position: 6
title: Order Compatibility
description: Which combinations of order type, time in force, execution attribute, and price field are valid.
---

# Order Compatibility

:::info TL;DR
Not every combination of type, time-in-force, and execution attribute makes
sense. This page is the validity matrix; read it before assembling an order
programmatically.
:::

## Type × Time in Force

| Type | GTC / GTT (rests) | IOC | FOK |
|---|---|---|---|
| `limit` | Yes, the standard resting order | n/a (use `ioc`) | n/a (use `fok`) |
| `ioc` | No; IOC never rests | Yes | n/a |
| `fok` | No; FOK never rests | n/a | Yes |

Time-in-force on Darknyx is carried by the order type plus `expiry_slot`: a resting
order is a `limit` with an expiry; an immediate order is `ioc` or `fok`. See
[Time in Force](./time-in-force).

## Type × Execution Attributes

| Type | `min_fill_size` | All-or-none (`min_fill_size = amount`) |
|---|---|---|
| `limit` | Yes | Yes, rests until a batch can fill it whole |
| `ioc` | Yes | Yes, takes whole-or-nothing immediately, residual cancels |
| `fok` | Redundant | Implicit; FOK is already whole-or-nothing |

## Type × Price field

| Type | `price_limit` |
|---|---|
| `limit` | Required, the worst acceptable price. |
| `ioc` (bid) | Required, the price cap (a "market bid" is an IOC with a cap). |
| `ioc` (ask) | Optional; `0` accepts any clearing price (a "market ask"). |
| `fok` | Required, the whole order must clear at this price or better. |

A bid always needs a positive `price_limit` (a buy at price zero is meaningless,
and the collateral must cover the worst case). An ask may set `price_limit = 0` to
sell into any clearing price.

## Modifiability

| Action | Supported |
|---|---|
| Cancel a resting order | Yes, [Cancel Order](../orders/cancel-order) |
| Modify a resting order (atomic cancel + replace) | Yes, [Modify Order](../orders/modify-order) |

IOC and FOK orders do not rest, so there is nothing to cancel or modify
after they execute.

## Quick validity examples

| Intent | Type | Price | `min_fill_size` | Expiry |
|---|---|---|---|---|
| Resting bid at a price (GTC) | `limit` | required | `0` | far |
| Resting bid, good for 10 min (GTT) | `limit` | required | `0` | deadline slot |
| Resting bid, fill-whole-or-wait (AON) | `limit` | required | `= amount` | far |
| Cross now up to a cap (market bid) | `ioc` | cap | `0` | n/a |
| Sell now at any price (market ask) | `ioc` | `0` | `0` | n/a |
| Immediate, whole, or nothing | `fok` | required | n/a | n/a |
