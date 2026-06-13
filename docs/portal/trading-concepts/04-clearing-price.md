---
sidebar_position: 4
title: Clearing Price
description: How Nyx prices a batch — one uniform, oracle-anchored clearing price for every match, with a hard on-chain circuit breaker.
---

# Clearing Price

:::info TL;DR
Every match in a batch settles at **one uniform price**, anchored to the market's
oracle. There is no maker/taker spread to game and no separate "peg" order type —
the fair mid is already baked into how every batch clears. A hard circuit breaker,
enforced inside the settlement proof, caps how far the clearing price may move
from the oracle.
:::

## One price per batch

Nyx clears each tick as a batch auction. The engine collects the orders that
cross and computes a **single clearing price** for that batch, anchored to the
market's oracle reference. Every match in the batch — both sides — settles at that
one price.

```text
        bids                     asks
   ┌──────────────┐         ┌──────────────┐
   │ resting bids │         │ resting asks │
   │ that cross   │         │ that cross   │
   └──────┬───────┘         └──────┬───────┘
          │                        │
          └────────────┬───────────┘
                       ▼
        clearing price = oracle-anchored, within the circuit-breaker band
                       │
                       ▼
        every match in the batch settles at this single price
```

A trader's `price_limit` is a *bound*, not the execution price: a bid fills only
if the clearing price is at or below its limit, an ask only if at or above. When
you fill, you get the batch's uniform clearing price — never worse than your
limit, and the same price as your counterparty.

## Why there is no maker/taker

In a continuous order book, the *order* in which orders arrive and match decides
who pays the spread, which creates room for front-running and last-look games. A
batch auction removes that surface: within a batch there is no ordering to
exploit, no first-mover advantage, and no spread to cross — there is just the one
clearing price. Combined with order privacy (no one sees your resting order),
there is nothing for a counterparty to fade or sandwich.

## Why there is no "peg" order type

On a continuous venue you peg an order to the mid (or bid/ask) and continuously
reprice it so it tracks the market. Nyx does not need a peg order type, for two
reasons:

1. **A dark pool has no public bid/ask to peg to.** Resting orders are hidden;
   there is no visible book to track.
2. **The clearing price is already the fair mid.** Every batch clears at an
   oracle-anchored price. The benefit a peg order chases — "always trade at the
   current fair price" — is native to every match. You express your willingness to
   trade with a `price_limit`, and the batch gives you the oracle-anchored
   clearing price whenever it is within your limit.

So the honest analog of "peg to mid" on Nyx is simply: place a limit at the worst
price you will accept, and let the uniform clearing price do the rest.

## The circuit breaker

Each instrument names a `circuit_breaker_bps` — the maximum deviation, in basis
points, of the clearing price from the oracle reference (see
[Instruments](../reference-data/instruments)). This bound is enforced **inside the
zero-knowledge settlement proof**, not merely as a server-side policy: a batch
whose clearing price falls outside the band cannot produce a valid settlement
proof and is rejected on-chain.

The practical effect: if the oracle is stale or the market gaps, Nyx **does not
clear** rather than clearing at a price far from fair. Your order waits for a batch
that prices within the band.

:::tip What this means for you
You do not — and cannot — set an execution price; you set a `price_limit` bound and
receive the batch's uniform, oracle-anchored clearing price when it is within your
bound and the circuit-breaker band. No spread, no last look, no peg to maintain.
:::
