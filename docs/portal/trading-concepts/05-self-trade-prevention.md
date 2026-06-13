---
sidebar_position: 5
title: Self-Trade Prevention
description: Two orders signed by the same trading key never match each other — preventing accidental wash trades.
---

# Self-Trade Prevention

:::info TL;DR
Orders signed by the **same trading key** never match each other. If your bid and
your ask would cross in a batch, the engine skips that self-pair and matches each
against other traders instead. This prevents accidental wash trading.
:::

## The rule

The matching engine identifies an order's owner by its **trading key**. When two
crossing orders in a batch share the same trading key, the engine does not pair
them — it skips the self-pair and continues matching each order against other
counterparties.

```text
your bid  ⨯  your ask     →  skipped (same trading key)
your bid  ✓  other ask    →  eligible to match
other bid ✓  your ask     →  eligible to match
```

The result: every execution you receive is against a *different* counterparty.

## Why a single behavior

On a continuous order book, self-trade prevention comes in flavors — cancel the
resting side, cancel the incoming side, cancel both — because there is a maker and
a taker to choose between. A Nyx batch has no maker/taker ordering: all crossing
orders clear together at one price (see [Clearing Price](./clearing-price)). There
is no "resting vs. incoming" side to pick, so the honest behavior is a single
rule — **two orders from one key never match each other** — and the orders remain
available to match against everyone else in the same batch.

## What it protects

- **No accidental wash trades.** A market maker quoting both sides cannot
  accidentally trade with itself and manufacture fake volume or churn fees.
- **Clean execution records.** Every fill is against a genuine third party.

## What it is not

Self-trade prevention is scoped to the **trading key**, which is the cryptographic
order identity. Two *different* trading keys — even if operated by the same
account or the same person — are distinct counterparties and may match. If you
want strict no-self-matching across a fleet, sign the orders you want mutually
excluded with the same trading key.
