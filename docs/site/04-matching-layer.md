---
sidebar_position: 3
title: Matching layer
description: How Nyx matches hidden orders — a frequent batch auction at a uniform clearing price, inside an attested TDX enclave, with oracle-banded pricing and round-free partial-fill continuations.
---

# Matching layer

:::info TL;DR
Hidden orders cross inside an attested Intel TDX enclave running a **frequent
batch auction**: every couple of seconds, all resting orders clear at a single
**uniform price**. Batching plus a uniform price removes the per-order timing
games — there's no advantage to being first within a batch, and no clearing
price the enclave can quietly distort, because it's constrained to an oracle
band and re-proved on-chain.
:::

## Why match in an enclave

Matching is stateful and must see your order to fill it. The question is *who
else* sees it. On-chain order books and rollups expose every resting order to a
sequencer or validator — the exact leak Nyx exists to close. An **attested
enclave** is the one place matching can run where order intent is visible only
to a specific, measured compiled image — and that image is pinned on-chain, so
only it can produce settlements the vault accepts. The operator running the
hardware cannot read inside it. (How that's enforced and verified:
[Trust model](./trust-model).)

## The frequent batch auction

Instead of a continuous, first-come-first-served book, Nyx runs a **batch
auction** on a short interval (about every 2 seconds). At each tick:

1. All resting bids and asks that cross are collected.
2. A single **uniform clearing price** is computed for the whole batch.
3. Crossing orders fill at that one price; ties at a price break by FIFO.
4. The batch is proved and settled as one unit (see
   [Settlement pipeline](./settlement-pipeline)).

```text
   resting book (hidden)            batch tick
   ┌───────────────────┐            ─────────────────────────────
   │ bids   asks        │     ──▶    compute one clearing price p*
   │  …      …          │            fill all crossing orders @ p*
   └───────────────────┘            FIFO tie-break, then prove + settle
```

Two properties fall out of this design:

- **No intra-batch race.** Every order in a batch clears at the same price and
  the same instant, so there's no edge to landing first within the tick — the
  sandwich and latency games that plague continuous books have nothing to grab.
- **No quiet price distortion.** The clearing price isn't whatever the operator
  says — it's constrained to a band around a verified oracle price, and the
  whole batch is re-proved on-chain. A bad price fails verification.

## Oracle-banded pricing

The matcher reads a verified market price each tick. Nyx pulls a signed **Pyth**
price update and verifies its signature *inside the enclave* before the matcher
trusts it; a staleness window rejects prices that are too old. The clearing
price must fall within a band around this oracle reference — a circuit-breaker
that bounds how far any single batch can clear from the true market, even in
thin conditions.

## Partial fills, without round-trips

A large order rarely fills in one batch. Traditionally that means a round-trip:
the venue fills part, hands you a residual, and you re-submit. Nyx removes the
round-trip with the **anchor pool**.

When you place an order, you submit a small set of pre-committed continuation
tags (the nullifiers for your *future* change notes — possible because the
spend-tag is amount-independent; see [Cryptography](./cryptography)). If the
order fills partially, the matcher rotates the residual **in place** using the
next anchor and re-matches it on the following tick — no client involvement, no
new order. You learn about each fill over the live fills stream and the SDK
reconstructs the change notes.

:::tip This is what makes hidden continuous trading practical
Without it, every partial fill would leak a fresh order and a fresh round-trip.
The anchor pool lets a single hidden order keep working across many batches as
quietly as it started.
:::

## Trading larger than any single note

Because value is held as discrete notes, an order can only be as large as the
note backing it. To trade more, you **merge** several notes into one first — a
client-side operation proved by `VALID_MERGE` and settled as a plain vault
transaction. Merging consolidates fragmented balances (including the change
notes that accumulate from partial fills) into a single note big enough to back
the order you want.

## Self-trade prevention

The matcher will not cross two orders from the same account against each other.
This is enforced inside the matching algorithm itself — wash trades can't be
constructed through the venue.

## The matcher is the single source of truth

The matching algorithm — the clearing-price computation, the FIFO tie-break, the
fee accounting, the continuation logic — lives in one place and is consumed
directly by the enclave. The same code that decides a match also produces the
witness that gets proved on-chain, so what's settled is exactly what was matched.

## How it composes with settlement

The matcher emits a batch of matches; the settle scheduler proves the batch and
drives it onto Solana. Matching is private and fast; settlement is public and
trustless. The handoff between them — and how a batch's settles co-include in a
single block — is the [Settlement pipeline](./settlement-pipeline).
</content>
