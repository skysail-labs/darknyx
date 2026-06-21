---
sidebar_position: 6
title: The Anchor Pool
description: How a partially-filled order keeps working — the pre-supplied continuation anchors that let the engine re-lock the remainder without a round-trip.
---

# The Anchor Pool

:::info TL;DR
A partial fill consumes your order's collateral note, so the unfilled remainder
needs a *new* note to keep resting. Rather than ask you for one on every fill, you
pre-supply a small pool of **continuation anchors** — secret material for future
change notes — when you place the order. The engine consumes one per partial fill
to mint the remainder note and keep your order working, with no per-fill
round-trip.
:::

## The problem it solves

On Nyx an order is backed by a specific note. When a batch partially fills the
order, that note is consumed and its value splits — part to your counterparty, the
rest into a **change note** that should keep backing your still-resting order.

Minting that change note needs secret material only you can produce (it has to be a
note *you* own and can later spend). A naive design would pause the order after
each partial fill and ask you for the next note — a round-trip per fill, fatal to a
working order in a fast market.

## The mechanism

You break the round-trip by supplying the material *ahead of time*. Each order
carries a pool of **continuation anchors**: each anchor is the `{ inner_hash,
nullifier }` pair for one future change note, derived deterministically from your
seed so you can always regenerate it.

```text
place order  ──►  collateral note + anchor pool [a0, a1, a2, … a9]
                              │
   partial fill 1  ──► consume a0  ──► mint change note (you own it) ──► order keeps resting
   partial fill 2  ──► consume a1  ──► mint change note               ──► order keeps resting
        …
```

The hash of the pool is bound into your order signature, so the engine cannot
substitute its own anchors — it can only use the ones you authorized. After each
fill, the engine sends you a **fill memo** (see
[Fills Channel](../websocket/fills-channel)) naming which anchor it consumed, so
you can recover and later spend the change note.

## Deterministic, not stored

Because each anchor is derived from `(your seed, order_id, index)`, you never have
to persist the pool. From your seed alone you can regenerate every anchor — and
therefore recover every change note an order produced — even on a fresh device.
That is also what lets the fills channel hand you just an index: you re-derive the
rest.

## Topping up

A pool is finite (ten anchors per order). An order that fills in many small
increments can drain it. When it does, the engine **pauses** the order's
continuation rather than guess at material it does not have, and you replenish the
pool with [`POST /orders/{order_id}/anchors`](../orders/anchor-topup) — five fresh
anchors, signed, continuing the sequence. The order resumes immediately.

```text
remaining anchors → 0   →   order paused   →   POST …/anchors (5 fresh)   →   resumes
```

:::tip Replenish proactively
Watch the remaining-anchor count and top up *before* it hits zero so a working
order never stops. A market maker resting a quote across many fills should treat
anchor replenishment as routine, the same way it tops up inventory.
:::

## Why it matters

The anchor pool is what makes a *resting, repeatedly-fillable* order possible in a
private, note-collateralized model. Without it, partial fills would each need a
client round-trip; with it, your order behaves like an ordinary resting order that
just keeps working — while every change note stays private and provably yours.
